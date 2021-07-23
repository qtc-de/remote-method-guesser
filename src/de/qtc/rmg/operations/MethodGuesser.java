package de.qtc.rmg.operations;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import de.qtc.rmg.internal.ExceptionHandler;
import de.qtc.rmg.internal.MethodCandidate;
import de.qtc.rmg.internal.RMGOption;
import de.qtc.rmg.io.Logger;
import de.qtc.rmg.networking.RMIWhisperer;
import de.qtc.rmg.utils.RMGUtils;
import de.qtc.rmg.utils.RemoteObjectWrapper;

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
public class MethodGuesser {

    private int padding = 0;

    private RMIWhisperer rmiEndpoint;
    private Set<MethodCandidate> candidates;
    private List<RemoteObjectClient> clientList;
    private List<RemoteObjectClient> knownClientList;
    private List<Set<MethodCandidate>> candidateSets;

    /**
     * To create a MethodGuesser object, you usually pass the obtained information from an RMI registry endpoint.
     * This includes the RMIWhisperer to the registry itself together with an Array of the looked up bound objects.
     * Moreover, the method candidates to be guessed are required.
     *
     * Passing the RMIWhisperer is only required, because the methods to dispatch raw RMI calls are currently defined
     * in this class. In future, this will probably be relocated.
     *
     * @param rmi RMIWhisperer for the current registry
     * @param remoteObjects Array of looked up remote objects from the RMI registry
     * @param candidates MethodCandidates that should be guessed
     */
    public MethodGuesser(RMIWhisperer rmi, RemoteObjectWrapper[] remoteObjects, Set<MethodCandidate> candidates)
    {
        this.rmiEndpoint = rmi;
        this.candidates = candidates;

        this.knownClientList = new ArrayList<RemoteObjectClient>();
        this.candidateSets = RMGUtils.splitSet(candidates, RMGOption.THREADS.getInt());

        if( !RMGOption.FORCE_GUESSING.getBool() )
            remoteObjects = handleKnownMethods(remoteObjects);

        this.clientList = initClientList(remoteObjects);
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
    private List<RemoteObjectClient> initClientList(RemoteObjectWrapper[] remoteObjects)
    {
        List<RemoteObjectClient> remoteObjectClients = new ArrayList<RemoteObjectClient>();
        setPadding(remoteObjects);

        if( !RMGOption.GUESS_DUPLICATES.getBool() )
            remoteObjects = RemoteObjectWrapper.handleDuplicates(remoteObjects);

        for( RemoteObjectWrapper o : remoteObjects ) {

            RemoteObjectClient client = new RemoteObjectClient(rmiEndpoint, o);
            remoteObjectClients.add(client);
        }

        if( RemoteObjectWrapper.hasDuplicates(remoteObjects) )
            printDuplicates(remoteObjects);

        return remoteObjectClients;
    }

    /**
     * This function is just used for displaying the result. It is called when iterating over the boundNames
     * and saves the length of the longest boundName. This is used as a padding value for the other boundNames.
     *
     * @param value String to obtain the length from
     */
    private void setPadding(RemoteObjectWrapper[] list)
    {
        for(RemoteObjectWrapper o : list) {

            if( padding < o.boundName.length() )
                padding = o.boundName.length();
        }
    }

    /**
     * This function prints a short info text that multiple bound names on the RMI server implement
     * the same class / interface and that only one of them is used during method guessing. The
     * output is disabled by default and only enabled if --verbose was used.
     */
    private void printDuplicates(RemoteObjectWrapper[] remoteObjects)
    {
        Logger.disableIfNotVerbose();
        Logger.printInfoBox();

        Logger.println("The following bound names use the same remote class:");
        Logger.lineBreak();
        Logger.increaseIndent();

        for( RemoteObjectWrapper remoteObject : remoteObjects ) {

            Logger.printlnMixedBlue("-", remoteObject.boundName);
            Logger.increaseIndent();

            for(String dup : remoteObject.getDuplicateBoundNames() ) {
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
    private RemoteObjectWrapper[] handleKnownMethods(RemoteObjectWrapper[] remoteObjects)
    {
        ArrayList<RemoteObjectWrapper> unknown = new ArrayList<RemoteObjectWrapper>();

        for(RemoteObjectWrapper o : remoteObjects) {

            if(!o.isKnown)
                unknown.add(o);

            else {
                RemoteObjectClient knownClient = new RemoteObjectClient(rmiEndpoint, o);
                knownClient.addRemoteMethods(RMGUtils.getKnownMethods(o.className));

                knownClientList.add(knownClient);
            }
        }

        if(knownClientList.size() != 0) {

            Logger.disableIfNotVerbose();
            Logger.printInfoBox();

            Logger.println("The following bound names use a known remote object class:");
            Logger.lineBreak();
            Logger.increaseIndent();

            for(RemoteObjectClient o : knownClientList)
                Logger.printlnMixedBlue("-", o.getBoundName() + " (" + o.getBoundName() + ")");

            Logger.decreaseIndent();
            Logger.lineBreak();
            Logger.printlnMixedBlue("Method guessing", "is skipped", "and known methods are listed instead.");
            Logger.printlnMixedYellow("You can use", "--force-guessing", "to guess methods anyway.");
            Logger.decreaseIndent();
            Logger.lineBreak();
            Logger.enable();
        }

        return unknown.toArray(new RemoteObjectWrapper[0]);
    }

    /**
     * Helper function that prints some visual text when the guesser is started. Just contains information
     * on the number of methods that are guessed or the concrete method signature (if specified).
     */
    public void printGuessingIntro()
    {
        int count = candidates.size();

        if(count == 0) {
            Logger.eprintlnMixedYellow("List of candidate methods contains", "0", "elements.");
            Logger.eprintln("Please use a valid and non empty wordlist file.");
            RMGUtils.exit();

        } else if( clientList.size() == 0 ) {
            return;
        }

        Logger.lineBreak();
        Logger.printlnMixedYellow("Starting Method Guessing on", String.valueOf(count), "method signature(s).");

        if( count == 1 ) {
            Logger.printlnMixedBlue("Method signature:", ((MethodCandidate)candidates.toArray()[0]).getSignature() + ".");
        }
    }

    /**
     * This method starts the actual guessing process. It creates a GuessingWorker for each remoteClient in the clientList
     * and for each Set of MethodCandidates in the candidateSets.
     *
     * @return List of RemoteObjectClient containing the successfully guessed methods. Only clients containing
     *         guessed methods are returned. Clients without guessed methods are filtered.
     */
    public List<RemoteObjectClient> guessMethods()
    {
        Logger.lineBreak();

        if( clientList.size() == 0 ) {
            clientList.addAll(knownClientList);
            return clientList;
        }

        Logger.increaseIndent();
        Logger.printlnYellow("MethodGuesser is running:");
        Logger.increaseIndent();
        Logger.printlnBlue("--------------------------------");

        ExecutorService pool = Executors.newFixedThreadPool(RMGOption.THREADS.getInt());

        for( RemoteObjectClient client : clientList ) {
            for( Set<MethodCandidate> candidates : candidateSets ) {
                Runnable r = new GuessingWorker(client, candidates);
                pool.execute(r);
            }
        }

        try {
            pool.shutdown();
            pool.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);

        } catch (InterruptedException e) {
             Logger.eprintln("Interrupted!");
        }

        Logger.decreaseIndent();
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
    private class GuessingWorker implements Runnable {

        private String boundName;
        private Set<MethodCandidate> candidates;
        private RemoteObjectClient client;

        /**
         * Initialize the guessing worker with all the required information.
         *
         * @param client RemoteObjectClient to the targeted remote object
         * @param candidate MethodCanidates to guess
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
        private void logHit(MethodCandidate candidate)
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
        public void run() {

            for( MethodCandidate candidate : candidates ) {

                try {
                    client.guessingCall(candidate);
                    logHit(candidate); // If there was no exception, the method exists (zero arg / valid call)

                } catch(java.rmi.ServerException e) {

                    Throwable cause = ExceptionHandler.getCause(e);

                    /*
                     * In case of an existing method, the specially crafted argument array that is used during guessing calls
                     * will always lead to one of the following exceptions. These are caught and indicate an existing method.
                     * One could also attempt to catch the 'unrecognized method hash' exception from the server to match non
                     * existing methods, but this requires an additional string compare that might be slower.
                     */
                    if( cause instanceof java.io.OptionalDataException || cause instanceof java.io.StreamCorruptedException) {
                        logHit(candidate);
                    }

                } catch(Exception e) {

                    /*
                     * If we end up here, an unexpected exception was raised that indicates a general error.
                     */
                    StringWriter writer = new StringWriter();
                    e.printStackTrace(new PrintWriter(writer));

                    String info = "Caught unexpected " + e.getClass().getName() + " during method guessing.\n"
                                 +"Please report this to improve rmg :)\n"
                                 +"Stack-Trace:\n"
                                 +writer.toString();

                    Logger.println(info);
                }
            }
        }
    }
}
