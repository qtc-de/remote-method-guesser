package eu.tneitzel.rmg.operations;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.springframework.remoting.support.RemoteInvocation;

import eu.tneitzel.rmg.internal.ExceptionHandler;
import eu.tneitzel.rmg.internal.MethodArguments;
import eu.tneitzel.rmg.internal.MethodCandidate;
import eu.tneitzel.rmg.internal.RMGOption;
import eu.tneitzel.rmg.io.Logger;
import eu.tneitzel.rmg.utils.ProgressBar;
import eu.tneitzel.rmg.utils.RMGUtils;
import eu.tneitzel.rmg.utils.RemoteInvocationHolder;
import eu.tneitzel.rmg.utils.SpringRemotingWrapper;
import eu.tneitzel.rmg.utils.UnicastWrapper;
import javassist.CannotCompileException;
import javassist.NotFoundException;

/**
 * The MethodGuesser class is used to brute force available remote methods on Java RMI endpoints. It uses
 * low level Java RMI functions to invoke methods parsed from a wordlist with incorrect argument types. The
 * server-side exception can be used as an indicator whether the invoked method exists on the server.
 *
 * When a RMI client calls a remote method, it establishes a TCP connection to the remote endpoint
 * and sends (among others) the following information:
 *
 *         - The ObjID of the RemoteObject that should receive the call
 *         - A method hash, that identifies the remote method to be called
 *         - A collection of method arguments to be used for the call
 *
 * During method guessing, remote-method-guesser uses a wordlist of Java methods and computes their hash
 * values. The corresponding hashes are then sent to the server, together with invalid method arguments.
 * If the remote method does not exist, the server throws an exception complaining about an unknown method
 * hash. On the other hand, if the remote method exists, the server will complain about the invalid method
 * arguments.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class MethodGuesser
{
    private int padding = 0;
    private final ProgressBar progressBar;

    private Set<MethodCandidate> candidates;
    private List<RemoteObjectClient> clientList;
    private List<RemoteObjectClient> knownClientList;
    private List<Set<MethodCandidate>> candidateSets;
    private Set<RemoteInvocationHolder> invocationHolders;
    private List<Set<RemoteInvocationHolder>> invocationHolderSets;

    /**
     * To create a MethodGuesser you need to pass the references for remote objects you want to guess on.
     * These are usually obtained from the RMI registry and can be passed as an array of UnicastWrapper.
     * Furthermore, you need to specify a Set of MethodCandidates that represents the methods you want
     * to guess.
     *
     * If one of the UnicastWrapper objects within the array is a SpringRemotingWrapper, the set of
     * MethodCandidates gets cloned and transformed into a set of RemoteInvocation. Both sets are still
     * available and the guessing procedure decides based on the wrapper type which set should be used.
     *
     * @param remoteObjects Array of looked up remote objects from the RMI registry
     * @param candidates MethodCandidates that should be guessed
     */
    public MethodGuesser(UnicastWrapper[] remoteObjects, Set<MethodCandidate> candidates)
    {
        this.candidates = candidates;

        this.knownClientList = new ArrayList<RemoteObjectClient>();
        this.candidateSets = RMGUtils.splitSet(candidates, RMGOption.THREADS.getValue());

        if (SpringRemotingWrapper.containsSpringRemotingClient(remoteObjects))
        {
            invocationHolders = SpringRemotingWrapper.getInvocationHolders(candidates);
            invocationHolderSets = RMGUtils.splitSet(invocationHolders, RMGOption.THREADS.getValue());
        }

        if (!RMGOption.GUESS_FORCE_GUESSING.getBool())
        {
            remoteObjects = handleKnownMethods(remoteObjects);
        }

        this.clientList = initClientList(remoteObjects);
        int workCount = 0;

        for (RemoteObjectClient client : clientList)
        {
            if (client.remoteObject instanceof SpringRemotingWrapper)
            {
                workCount += invocationHolders.size();
            }

            else
            {
                workCount += candidates.size();
            }
        }

        this.progressBar = new ProgressBar(workCount, 37);
    }

    /**
     * This function is basically used to prevent guessing on duplicate classes. Some RMI endpoints bind
     * multiple instances of the same remote class to the registry. Guessing each of them is usually not
     * what you want, as they use the same implementation. This function checks the bound class names for
     * duplicates and handles them according to the RMGOption.GUESS_DUPLICATES value.
     *
     * If guessing duplicates was requested, the function creates a new RemoteObjectClient for each bound name.
     * If guessing duplicates was not requested, only the first boundName is used to create a RemoteObjectClient
     * and all other bound names that are based on the same class are registered as duplicates.
     *
     * @param remoteObjects Array of looked up remote objects from the RMI registry
     */
    private List<RemoteObjectClient> initClientList(UnicastWrapper[] remoteObjects)
    {
        List<RemoteObjectClient> remoteObjectClients = new ArrayList<RemoteObjectClient>();
        setPadding(remoteObjects);

        if (!RMGOption.GUESS_DUPLICATES.getBool())
        {
            remoteObjects = UnicastWrapper.handleDuplicates(remoteObjects);
        }

        for (UnicastWrapper o : remoteObjects)
        {
            RemoteObjectClient client = new RemoteObjectClient(o);
            remoteObjectClients.add(client);
        }

        if (UnicastWrapper.hasDuplicates(remoteObjects))
        {
            printDuplicates(remoteObjects);
        }

        return remoteObjectClients;
    }

    /**
     * This function is just used for displaying the result. It is called when iterating over the boundNames
     * and saves the length of the longest boundName. This is used as a padding value for the other boundNames.
     *
     * @param remoteObjects List containing all UnicastWrapper used during the guess operation
     */
    private void setPadding(UnicastWrapper[] remoteObjects)
    {
        for (UnicastWrapper o : remoteObjects)
        {
            if (padding < o.boundName.length())
            {
                padding = o.boundName.length();
            }
        }
    }

    /**
     * This function prints a short info text that multiple bound names on the RMI server implement
     * the same class / interface and that only one of them is used during method guessing. The
     * output is disabled by default and only enabled if --verbose was used.
     *
     * @param remoteObjects List containing all UnicastWrapper used during the guess operation
     */
    private void printDuplicates(UnicastWrapper[] remoteObjects)
    {
        Logger.disableIfNotVerbose();
        Logger.printInfoBox();

        Logger.println("The following bound names use the same remote class:");
        Logger.lineBreak();
        Logger.increaseIndent();

        for (UnicastWrapper remoteObject : remoteObjects)
        {
            String[] duplicates = remoteObject.getDuplicateBoundNames();

            if (duplicates.length == 0)
            {
                continue;
            }

            Logger.printlnMixedBlue("-", remoteObject.boundName);
            Logger.increaseIndent();

            for (String dup : duplicates)
            {
                Logger.printlnMixedYellow("-->", dup);
            }

            Logger.decreaseIndent();
        }

        Logger.decreaseIndent();
        Logger.lineBreak();
        Logger.printlnMixedBlue("Method guessing", "is skipped", "for duplicate remote classes.");
        Logger.printlnMixedYellow("You can use", "--guess-duplicates", "to guess them anyway.");
        Logger.decreaseIndent();
        Logger.enable();
    }

    /**
     * When known remote objects are encountered and --force-guessing was not used, the corresponding remote methods
     * are added automatically to the list of guessed methods. This function performs this task and also prints according
     * information for the user.
     *
     * @param remoteObjects Array of looked up remote objects from the RMI registry
     * @return Array of unknown remote objects
     */
    private UnicastWrapper[] handleKnownMethods(UnicastWrapper[] remoteObjects)
    {
        ArrayList<UnicastWrapper> unknown = new ArrayList<UnicastWrapper>();

        for (UnicastWrapper o : remoteObjects)
        {
            if (!o.isKnown())
            {
                unknown.add(o);
            }

            else
            {
                List<MethodCandidate> knownMethods = new ArrayList<MethodCandidate>();
                RemoteObjectClient knownClient = new RemoteObjectClient(o);

                for (String method : o.knownEndpoint.getRemoteMethods())
                {
                    try
                    {
                        knownMethods.add(new MethodCandidate(method));
                    }

                    catch (CannotCompileException | NotFoundException e)
                    {
                        Logger.printlnMixedYellowFirst("Internal Error", "- Unable to compile known method with signature: " + method);
                    }
                }

                knownClient.addRemoteMethods(knownMethods);
                knownClientList.add(knownClient);
            }
        }

        if (knownClientList.size() != 0)
        {
            Logger.disableIfNotVerbose();
            Logger.printInfoBox();

            Logger.println("The following bound names use a known remote object class:");
            Logger.lineBreak();
            Logger.increaseIndent();

            for (RemoteObjectClient o : knownClientList)
            {
                Logger.printlnMixedBlue("-", o.getBoundName() + " (" + o.getBoundName() + ")");
            }

            Logger.decreaseIndent();
            Logger.lineBreak();
            Logger.printlnMixedBlue("Method guessing", "is skipped", "and known methods are listed instead.");
            Logger.printlnMixedYellow("You can use", "--force-guessing", "to guess methods anyway.");
            Logger.decreaseIndent();
            Logger.lineBreak();
            Logger.enable();
        }

        return unknown.toArray(new UnicastWrapper[0]);
    }

    /**
     * Helper function that prints some visual text when the guesser is started. Just contains information
     * on the number of methods that are guessed or the concrete method signature (if specified).
     */
    public void printGuessingIntro()
    {
        int count = candidates.size();

        if (count == 0)
        {
            Logger.eprintlnMixedYellow("List of candidate methods contains", "0", "elements.");
            Logger.eprintln("Please use a valid and non empty wordlist file.");
            RMGUtils.exit();
        }

        else if (clientList.size() == 0)
        {
            return;
        }

        Logger.lineBreak();
        Logger.printlnMixedYellow("Starting Method Guessing on", String.valueOf(count), "method signature(s).");

        if (count == 1)
        {
            Logger.printlnMixedBlue("Method signature:", ((MethodCandidate)candidates.toArray()[0]).getSignature() + ".");
        }
    }

    /**
     * This method starts the actual guessing process. It creates a GuessingWorker for each remoteClient in the clientList
     * and for each Set of MethodCandidates in the candidateSets. If the underlying RemoteObjectWrapper type of a client
     * is a SpringRemotingWrapper, the spring remoting compatible SpringGuessingWorker will be used.
     *
     * @return List of RemoteObjectClient containing the successfully guessed methods. Only clients containing
     *         guessed methods are returned. Clients without guessed methods are filtered.
     */
    public List<RemoteObjectClient> guessMethods()
    {
        Logger.lineBreak();

        if (clientList.size() == 0)
        {
            clientList.addAll(knownClientList);
            return clientList;
        }

        Logger.increaseIndent();
        Logger.printlnYellow("MethodGuesser is running:");
        Logger.increaseIndent();
        Logger.printlnBlue("--------------------------------");

        ExecutorService pool = Executors.newFixedThreadPool(RMGOption.THREADS.getValue());

        for (RemoteObjectClient client : clientList)
        {
            if (client.remoteObject instanceof SpringRemotingWrapper)
            {
                for (Set<RemoteInvocationHolder> invoHolder : invocationHolderSets)
                {
                    Runnable r = new SpringGuessingWorker(client, invoHolder);
                    pool.execute(r);
                }
            }

            else
            {
                for (Set<MethodCandidate> candidates : candidateSets)
                {
                    Runnable r = new GuessingWorker(client, candidates);
                    pool.execute(r);
                }
            }
        }

        try
        {
            pool.shutdown();
            pool.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);
        }

        catch (InterruptedException e)
        {
             Logger.eprintln("Interrupted!");
        }

        Logger.decreaseIndent();
        Logger.lineBreak();
        Logger.printlnYellow("done.");
        Logger.lineBreak();

        clientList = RemoteObjectClient.filterEmpty(clientList);
        clientList.addAll(knownClientList);

        return clientList;
    }

    /**
     * The GuessingWorker class performs the actual method guessing in terms of RMI calls. It implements Runnable and
     * is intended to be run within a thread pool. Each GuessingWorker gets assigned a Set of MethodCandidates and iterates
     * over the corresponding set. It uses the obtained RemoteObjectClient object to dispatch a call to the candidates and
     * inspects the server-side exception to determine whether the method exists on the remote object.
     *
     * @author Tobias Neitzel (@qtc_de)
     */
    private class GuessingWorker implements Runnable
    {
        protected String boundName;
        protected Set<MethodCandidate> candidates;
        protected RemoteObjectClient client;

        /**
         * Initialize the guessing worker with all the required information.
         *
         * @param client RemoteObjectClient to the targeted remote object
         * @param candidates MethodCandidates to guess
         */
        public GuessingWorker(RemoteObjectClient client, Set<MethodCandidate> candidates)
        {
            this.client = client;
            this.boundName = client.getBoundName();
            this.candidates = candidates;
        }

        /**
         * This function is called when a guessed MethodCandidate exists. It creates a corresponding log entry and
         * saves the candidate within the results map.
         *
         * @param candidate MethodCandidate that was successfully guessed
         */
        protected void logHit(MethodCandidate candidate)
        {
            String prefix = Logger.blue("[ " + Logger.padRight(boundName, padding) + " ] ");
            Logger.printlnMixedYellow(prefix + "HIT! Method with signature", candidate.getSignature(), "exists!");
            client.addRemoteMethod(candidate);
        }

        /**
         * Invokes the assigned MethodCandidates. Methods are invoked by using a specially crafting argument array.
         * The array is crafted in a way that method calls will never be fully dispatched on the server side while
         * simultaneously preventing corruption of the underlying TCP stream. This allows to reuse the TCP connection
         * during method guessing which makes the process much faster, especially on TLS protected connections.
         */
        public void run()
        {
            for (MethodCandidate candidate : candidates)
            {
                try
                {
                    client.guessingCall(candidate);
                    logHit(candidate); // If there was no exception, the method exists (zero arg / valid call)
                }

                catch (java.rmi.ServerException e)
                {
                    Throwable cause = ExceptionHandler.getCause(e);

                    /*
                     * In case of an existing method, the specially crafted argument array that is used during guessing calls
                     * will always lead to one of the following exceptions. These are caught and indicate an existing method.
                     * One could also attempt to catch the 'unrecognized method hash' exception from the server to match non
                     * existing methods, but this requires an additional string compare that might be slower.
                     */
                    if (cause instanceof java.io.OptionalDataException || cause instanceof java.io.StreamCorruptedException)
                    {
                        logHit(candidate);
                    }
                }

                catch (java.rmi.UnmarshalException e)
                {
                    /*
                     * When running with multiple threads, from time to time, stream corruption can be observed.
                     * This seems to be non deterministically and only appears in certain setups. In my current
                     * setup, it seems always to break on the "String selectSurname(String email)" method. In
                     * future, this should be debugged. However, as in a run of 3000 methods this only occurs one
                     * or two times, it is probably not that important.
                     */
                    if (RMGOption.GLOBAL_VERBOSE.getBool())
                    {
                        String info = "Caught unexpected " + e.getClass().getName() + " while guessing the " + candidate.getSignature() + "method.\n"
                                +"[-]" + Logger.getIndent() + "This occurs sometimes when guessing with multiple threads.\n"
                                +"[-]" + Logger.getIndent() + "You can retry with --threads 1 or just ignore the exception.";
                        Logger.eprintlnBlue(info);
                        ExceptionHandler.showStackTrace(e);
                    }
                }

                catch(Exception e)
                {
                    /*
                     * If we end up here, an unexpected exception was raised that indicates a general error.
                     */
                    StringWriter writer = new StringWriter();
                    e.printStackTrace(new PrintWriter(writer));

                    String info = "Caught unexpected " + e.getClass().getName() + " during method guessing.\n"
                                 +"[-]" + Logger.getIndent() + "Please report this to improve rmg :)\n"
                                 +"[-]" + Logger.getIndent() + "Stack-Trace:\n"
                                 +writer.toString();

                    Logger.eprintlnBlue(info);
                }

                finally
                {
                    progressBar.taskDone();
                }
            }
        }
    }

    /**
     * The SpringGuessingWorker does basically the same as the GuessingWorker, but for spring remoting :)
     *
     * @author Tobias Neitzel (@qtc_de)
     */
    private class SpringGuessingWorker implements Runnable
    {
        protected String boundName;
        protected RemoteObjectClient client;
        protected Set<RemoteInvocationHolder> invocationHolders;

        /**
         * Initialize the spring guessing worker with all the required information.
         *
         * @param client RemoteObjectClient to the targeted remote object
         * @param invocationHolders  set of RemoteInvocationHolders that contain the RemoteInvocations to guess
         */
        public SpringGuessingWorker(RemoteObjectClient client, Set<RemoteInvocationHolder> invocationHolders)
        {
            this.client = client;
            this.boundName = client.getBoundName();
            this.invocationHolders = invocationHolders;
        }

        /**
         * This function is called when a guessed RemoteInvocation exists. It creates a corresponding log entry and
         * saves the candidate within the results map.
         *
         * @param invoHolder  RemoteInvocationHolder that contains the RemoteInvocation that lead to an successful method call
         */
        protected void logHit(RemoteInvocationHolder invoHolder)
        {
            MethodCandidate existingMethod = invoHolder.getCandidate();

            String prefix = Logger.blue("[ " + Logger.padRight(boundName, padding) + " ] ");
            Logger.printlnMixedYellow(prefix + "HIT! Method with signature", SpringRemotingWrapper.getSignature(existingMethod), "exists!");
            client.addRemoteMethod(existingMethod);
        }

        /**
         * Sends the assigned RemoteInvocations to the spring remoting endpoint and inspects the response.
         * RemoteInvocations send by the guesser are always malformed. They contain a method name, a list of
         * argument types and a list of argument values. The argument values are purposely chosen to not match
         * the argument types. This prevents actual method calls that could perform dangerous stuff. However,
         * based on the thrown exeception it is still possible to identify existing methods.
         */
        public void run()
        {
            for (RemoteInvocationHolder invocationHolder : invocationHolders)
            {
                try
                {
                    client.unmanagedCall(SpringRemotingWrapper.getInvokeMethod(), new MethodArguments(invocationHolder.getInvo(), RemoteInvocation.class));

                    /*
                     * We always provide an invalid argument count for our SpringRemoting calls.
                     * We should never endup here, which would indicate a successful call.
                     */
                    unexpectedError(invocationHolder, null);
                }

                catch (java.lang.IllegalArgumentException e)
                {
                    /*
                     * Since SpringRemoting calls exposed methods via reflection, we can always provide an incorrect
                     * argument count during the call. If the method exists, this leads to an IllegalArgumentException,
                     * which is used to identify valid methods.
                     */
                    logHit(invocationHolder);
                }

                catch (java.lang.NoSuchMethodException e)
                {
                    /*
                     * SpringRemoting resolves remote methods via reflection. If the requested method does not
                     * exist, it throws a java.lang.NoSuchMethodException. So this branch means that the guessed
                     * method simply does not exist and we can continue.
                     */
                }

                catch (java.rmi.ServerException e)
                {
                    Throwable cause = ExceptionHandler.getCause(e);

                    if (cause instanceof java.lang.ClassNotFoundException)
                    {
                        /*
                         * Since SpringRemoting requires valid RMI calls, guessed methods may contain classes that
                         * are not known on the server side. In this case, ClassNotFoundExceptions are expected. This
                         * means that the method does not exist and we can continue.
                         */
                    }

                    else if (cause instanceof java.rmi.UnmarshalException)
                    {
                        /*
                         * When running with multiple threads, from time to time, stream corruption can be observed.
                         * This seems to be non deterministically and only appears in certain setups. In my current
                         * setup, it seems always to break on the "String selectSurname(String email)" method. In
                         * future, this should be debugged. However, as in a run of 3000 methods this only occurs one
                         * or two times, it is probably not that important.
                         */
                        if (RMGOption.GLOBAL_VERBOSE.getBool())
                        {
                            String info = "Caught unexpected " + e.getClass().getName() + " while guessing the " + SpringRemotingWrapper.getSignature(invocationHolder.getCandidate()) + " method.\n"
                                    +"[-]" + Logger.getIndent() + "This occurs sometimes when guessing with multiple threads.\n"
                                    +"[-]" + Logger.getIndent() + "You can retry with --threads 1 or just ignore the exception.";
                            Logger.eprintlnBlue(info);
                            ExceptionHandler.showStackTrace(e);
                        }
                    }

                    else
                    {
                        /*
                         * If we end up here, an unexpected exception was raised that indicates a general error.
                         */
                        unexpectedError(invocationHolder, e);
                    }
                }

                catch (java.rmi.UnmarshalException e)
                {
                    /*
                     * When running with multiple threads, from time to time, stream corruption can be observed.
                     * This seems to be non deterministically and only appears in certain setups. In my current
                     * setup, it seems always to break on the "String selectSurname(String email)" method. In
                     * future, this should be debugged. However, as in a run of 3000 methods this only occurs one
                     * or two times, it is probably not that important.
                     */
                    if (RMGOption.GLOBAL_VERBOSE.getBool())
                    {
                        String info = "Caught unexpected " + e.getClass().getName() + " while guessing the " + SpringRemotingWrapper.getSignature(invocationHolder.getCandidate()) + " method.\n"
                                +"[-]" + Logger.getIndent() + "This occurs sometimes when guessing with multiple threads.\n"
                                +"[-]" + Logger.getIndent() + "You can retry with --threads 1 or just ignore the exception.";
                        Logger.eprintlnBlue(info);
                        ExceptionHandler.showStackTrace(e);
                    }
                }

                catch(Exception e)
                {
                    /*
                     * If we end up here, an unexpected exception was raised that indicates a general error.
                     */
                    unexpectedError(invocationHolder, e);
                }

                finally
                {
                    progressBar.taskDone();
                }
            }
        }

        /**
         * If an unexpected exception was thrown, this method is called. It prints a warning message to the user,
         * but does not interrupt the guessing procedure.
         *
         * @param invoHolder  the RemoteInvocationHolder that caused the exception
         * @param e  the thrown Exception
         */
        private void unexpectedError(RemoteInvocationHolder invoHolder, Exception e)
        {
            String info = "";
            StringWriter writer = new StringWriter();

            Logger.printlnYellow(invoHolder.getCandidate().getSignature());

            if (e != null)
            {
                e.printStackTrace(new PrintWriter(writer));

                info = "Caught unexpected " + e.getClass().getName() + " during method guessing.\n"
                             +"[-]" + Logger.getIndent() + "Please report this to improve rmg :)\n"
                             +"[-]" + Logger.getIndent() + "Stack-Trace:\n"
                             +writer.toString();
            }

            else
            {
                info = "Spring Remoting call did not cause an exception. This is not expected.";
            }

            Logger.eprintlnBlue(info);
        }
    }
}
