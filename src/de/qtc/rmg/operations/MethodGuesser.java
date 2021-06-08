package de.qtc.rmg.operations;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import de.qtc.rmg.internal.ExceptionHandler;
import de.qtc.rmg.internal.MethodCandidate;
import de.qtc.rmg.io.Logger;
import de.qtc.rmg.utils.RMGUtils;

/**
 * The method guesser is used to brute force available remote methods on a Java RMI endpoint. It
 * uses the regular Java RMI API to obtain a RemoteObject from the RMI registry, but then uses
 * low level Java RMI calls to enumerate valid methods.
 *
 * When a RMI client calls a remote method, it establishes a TCP connection to the remote endpoint
 * and sends (among others) the following information:
 *
 *         - The ObjID of the RemoteObject that should receive the call
 *         - A method hash, that identifies the remote method to be called
 *         - A collection of method arguments to be used for the call
 *
 * During method guessing, remote-method-guesser uses a wordlist of Java methods and computes their hash
 * values. The corresponding hashes are then sent to the server, together with an collection of argument types
 * that do NOT match the expected argument types by the actual remote method. If a remote method does not
 * exist, the server throws an exception complaining about an unknown hash value. On the other hand, if the
 * remote method exists, the server will complain about the mismatch of argument types.
 *
 * This allows to reliably detect remote methods without the risk of causing unwanted actions on the server
 * side by actually invoking them. The idea for such a guessing approach was not invented by remote-method-guesser,
 * but was, to the best of our knowledge, first implemented by the rmiscout project. However, remote-method-guesser
 * takes this approach further and implements the mismatch of argument types in a way that prevents the underlying
 * TCP stream from being corrupted. This allows remote-method-guesser to reuse already established TCP connection
 * which provied a great performance boost, especially on TLS protected endpoints.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class MethodGuesser {

    private int threads;
    private boolean zeroArg;
    private RemoteObjectClient client;
    private HashSet<MethodCandidate> candidates;


    /**
     * The MethodGuesser relies on a RemoteObjectClient object to dispatch raw RMI calls. This object needs to be created
     * in advance and has to be passed to the constructor. Other requirements are a HashSet of MethodCandidates to guess,
     * the number of threads to use for guessing and a boolean indicating whether zero argument methods should be guessed.
     * The problem with zero argument methods is, that they lead to real calls on the server side.
     *
     * @param client RemoteObjectClient for the targeted RMI object
     * @param candidates HashSet of MethodCandidates to guess
     * @param threads number of threads to use
     * @param zeroArg whether or not to guess zero argument methods
     */
    public MethodGuesser(RemoteObjectClient client, HashSet<MethodCandidate> candidates, int threads, boolean zeroArg)
    {
        this.client = client;
        this.candidates = candidates;

        this.threads = threads;
        this.zeroArg = zeroArg;
    }

    /**
     * Helper function that prints some visual text when the guesser is started. Just contains information
     * on the number of methods that are guessed or the concrete method signature (if specified).
     *
     * @param candidates HashSet of MethodCandidates to guess
     */
    public static void printGuessingIntro(HashSet<MethodCandidate> candidates)
    {
        int count = candidates.size();

        if(count == 0) {
            Logger.eprintlnMixedYellow("List of candidate methods contains", "0", "elements.");
            Logger.eprintln("Please use a valid and non empty wordlist file.");
            RMGUtils.exit();
        }

        Logger.println("");
        Logger.printlnMixedYellow("Starting Method Guessing on", String.valueOf(count), "method signature(s).");

        if( count == 1 ) {
            Logger.printlnMixedBlue("Method signature:", ((MethodCandidate)candidates.toArray()[0]).getSignature() + ".");
        }

        Logger.println("");
        Logger.increaseIndent();
    }

    /**
     * This method starts the actual guessing process. The Set of possible MethodCandidates is split into as many
     * junks as threads are used. For each thread, one GuessingWorker is created that performs a method call for each
     * method defined in it's corresponding method set. Each GuessingWorker uses a separate RemoteObjectClient and
     * therefore a dedicated TCPChannel.
     *
     * Each GuessingWorker obtains a reference to an ArrayList of MethodCandidates. Guessing workers are expected to
     * push successfully guessed methods into this ArrayList.
     *
     * @return ArrayList of successfully guessed methods
     */
    public ArrayList<MethodCandidate> guessMethods()
    {
        Logger.printlnMixedYellow("Guessing methods on bound name:", client.getBoundName(), "...");
        Logger.println("");
        Logger.increaseIndent();

        ArrayList<MethodCandidate> existingMethods = new ArrayList<MethodCandidate>();
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        List<Set<MethodCandidate>> methodLists = RMGUtils.splitSet(this.candidates, threads);

        for( Set<MethodCandidate> methods : methodLists ) {
            Runnable r = new GuessingWorker(client.clone(), methods, existingMethods);
            pool.execute(r);
        }

        try {
            pool.shutdown();
            pool.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);
        } catch (InterruptedException e) {
             Logger.eprintln("Interrupted!");
        }

        Logger.decreaseIndent();
        Logger.println("");

        return existingMethods;
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

        private Set<MethodCandidate> candidates;
        private RemoteObjectClient client;
        private ArrayList<MethodCandidate> existingMethods;

        /**
         * Initialize the guessing worker with all the required information.
         *
         * @param client RemoteObjectClient to the targeted remote object
         * @param candidate MethodCanidate to guess
         * @param existingMethods ArrayList of existing methods. If candidate exists, it is pushed here
         */
        public GuessingWorker(RemoteObjectClient client, Set<MethodCandidate> candidates, ArrayList<MethodCandidate> existingMethods)
        {
            this.client = client;
            this.candidates = candidates;
            this.existingMethods = existingMethods;
        }

        /**
         * Invokes the assigned MethodCandidates. Methods are invoked by using a specially crafting argument array.
         * The array is crafted in a way that method calls will never be fully dispatched on the server side while
         * simultaneously preventing corruption of the underlying TCP stream. This allows to reuse the TCP connection
         * during method guessing which makes the proccess much faster, especially on TLS protected connections.
         */
        public void run() {

            for( MethodCandidate candidate : candidates ) {

                if( candidate.isVoid() && !zeroArg ) {
                    Logger.printlnMixedBlue("Skipping zero arguments method:", candidate.getSignature());
                    continue;
                }

                try {
                    client.guessingCall(candidate);

                } catch(java.rmi.ServerException e) {

                    Throwable cause = ExceptionHandler.getCause(e);
                    if( cause instanceof java.rmi.UnmarshalException && cause.getMessage().startsWith("unrecognized")) {
                        /*
                         * An RMI server throws the UnmarshalException for different reasons while unmarshalling
                         * the call. One of them is the absence of the transmitted method hash in the method hash
                         * table stored on the server side. This Exception can safely be ignored, as it just means
                         * that the guessed method is not available. However, other cases include the unmarshalling
                         * of the call headers, which could occur when the stream is corrupted. Therefore, we should
                         * check whether the Exception is a UnmarshalException and verify that it contains the expected
                         * "unrecognized method hash" message.
                         */
                        continue;
                    }

                } catch(Exception e) {
                    /*
                     * All other exceptions cause an error message, but are interpreted as an existing method. The
                     * idea behind this is that a false-positive is usually better than a false-negative.
                     */

                    StringWriter writer = new StringWriter();
                    e.printStackTrace(new PrintWriter(writer));

                    String info = "Caught unexpected " + e.getClass().getName() + " during method guessing.\n"
                                 +"Method is marked as existent, but this is probably not true.\n"
                                 +"Please report this to improve rmg :)\n"
                                 +"Stack-Trace:\n"
                                 +writer.toString();

                    Logger.println(info);
                }

                /*
                 * Successfully guessed methods cause a java.rmi.ServerException that is caught above, but not handled.
                 * The inner cause of these exceptions is expected to be one of java.io.StreamCorruptedException (expected
                 * for methods that accept primitive arguments only) or java.io.OptionalDataException (expected for methods
                 * that accept at least one non primitive argument). The exceptions are not caught explicitly, which could
                 * lead to false positives, but we never observed this in practice so far.
                 */
                Logger.printlnMixedYellow("HIT! Method with signature", candidate.getSignature(), "exists!");
                existingMethods.add(candidate);
            }
        }
    }
}
