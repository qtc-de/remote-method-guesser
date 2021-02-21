package de.qtc.rmg.operations;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.HashSet;
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
 * but was, to the best of our knowledge first implemented by the rmi-scout project.
 *
 * The MethodGuesser class was one of the first operation classes in rmg and is therefore not fully optimized
 * to the currently available other utility classes. It may be restructured in future.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class MethodGuesser {

    private int threads;
    private boolean zeroArg;
    private RemoteObjectClient client;
    private HashSet<MethodCandidate> candidates;

    /**
     * The MethodGuesser makes use of the official RMI API to obtain the RemoteObject from the RMI registry.
     * Afterwards, it needs access to the underlying UnicastRemoteRef to perform customized RMi calls. Depending
     * on the RMI version of the server (current proxy approach or legacy stub objects), this requires access to
     * a different field within the Proxy or RemoteObject class. Both fields are made accessible within the constructor
     * to make the actual guessing code more clean.
     *
     * @param rmiRegistry registry to perform lookup operations
     * @param unknownClasses list of unknown classes per bound name
     * @param candidates list of method candidates to guess
     */
    public MethodGuesser(RemoteObjectClient client, HashSet<MethodCandidate> candidates, int threads, boolean zeroArg)
    {
        this.client = client;
        this.candidates = candidates;

        this.threads = threads;
        this.zeroArg = zeroArg;
    }

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
     * This lengthy function is used for method guessing. If targetName is not null, guessing is only performed on
     * the specified bound name, otherwise all bound names within the registry are targeted. The function starts of
     * with some initialization and then tries to determine the legacy status of the server. This status is required
     * to decide whether to create the remote classes as interface or stub classes on the client side. Within legacy
     * RMI, stub classes are required on the client side, but current RMI implementations only need an interface that
     * is assigned to a Proxy.
     *
     * Depending on the determined legacy status, an interface or legacy stub class is now created dynamically.
     * With the corresponding class now available on the class path, the RemoteObject can be looked up on the
     * registry. From the obtained object, the RemoteRef is then extracted by using reflection. With this remote
     * reference, customized RMI calls can now be dispatched.
     *
     * This low level RMI access is required to call methods with invalid argument types. During method guessing,
     * you want to call possibly existing remote methods with invalid argument types to prevent their actual execution.
     * When using ordinary RMI to make a call, Java would refuse to use anything other than the expected argument types,
     * as it would violate the interface or method definition. With low level RMI access, the call arguments can be
     * manually written to the OutputStream which allows to use arbitrary arguments for a call.
     *
     * To implement this confusion of argument types, the dynamically created classes for the RemoteObjects are
     * constructed with two (interface)methods. The first, rmgInvokeObject, expects a String as first parameter,
     * whereas the second, rmgInvokePrimitive, expects an int. Depending on the method signature that is currently
     * guessed, rmgInvokeObject or rmgInvokePrimitive is used for the call. If the method signature expects a
     * primitive as its first argument, rmgInvokeObject is used to cause the confusion. Otherwise, rmgInvokePrimitive
     * will be used. During the call, the methodHash of rmgInvokeObject or rmgInvokePrimitive is replaced by the
     * methodHash of the currently guessed method signature. This approach allows testing for arbitrary method signatures
     * without manually exchanging the call parameters.
     *
     * @param targetName bound name to target. If null, target all available bound names
     * @param threads number of threads to use for the operation
     * @param zeroArg whether or not to also guess zero argument methods (are really invoked)
     * @param legacyMode whether to enforce legacy stubs. 0 -> auto, 1 -> enforce legacy, 2 -> enforce normal
     * @return List of successfully guessed methods per bound name
     */

    public ArrayList<MethodCandidate> guessMethods()
    {
        Logger.printlnMixedYellow("Guessing methods on bound name:", client.getBoundName(), "...");
        Logger.println("");
        Logger.increaseIndent();

        ArrayList<MethodCandidate> existingMethods = new ArrayList<MethodCandidate>();
        ExecutorService pool = Executors.newFixedThreadPool(threads);

        for( MethodCandidate method : this.candidates ) {

            if( method.isVoid() && !zeroArg ) {
                Logger.printlnMixedBlue("Skipping zero arguments method:", method.getSignature());
                continue;
            }

            Runnable r = new GuessingWorker(client, method, existingMethods);
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

    private class GuessingWorker implements Runnable {

        private MethodCandidate candidate;
        private RemoteObjectClient client;
        private ArrayList<MethodCandidate> existingMethods;

        /**
         * Initialize the guessing worker with all the required information.
         *
         * @param candidate method that is actually guessed
         * @param existingMethods array of existing methods. Identified methods need to be appended
         */
        public GuessingWorker(RemoteObjectClient client, MethodCandidate candidate, ArrayList<MethodCandidate> existingMethods)
        {
            this.client = client;
            this.candidate = candidate;
            this.existingMethods = existingMethods;
        }

        /**
         * Starts the method invocation. The RemoteObject that is used by this worker is actually a dummy
         * object. It pretends to implement the remote class/interface, but actually has only two dummy methods
         * defined. One of these dummy methods get invoked during this call, but with an exchanged method hash
         * of the actual method in question.
         *
         * The selected method for the guessing expects either a primitive or non primitive type. This decision
         * is made based on the MethodCandidate in question and with the goal of always causing a type confusion.
         * E.g. when the MethodCandidate expects a primitive type as first argument, the method that expects a
         * non primitive type is selected. Therefore, when the remote object attempts to unmarshal the call
         * arguments, it will always find a type mismatch on the first argument, which causes an exception.
         * This exception is used to identify valid methods.
         */
        public void run() {

            try {
                client.rawCallNoReturn(candidate, candidate.getConfusedArgument());

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
                    return;
                }

            } catch(java.rmi.UnmarshalException e) {
                /*
                 * This occurs on invocation of methods taking zero arguments. Since the call always succeeds,
                 * the remote method returns some value that probably not matches the expected return value of
                 * the lookup method. However, it is still a successful invocation and the method exists.
                 */

            } catch(java.rmi.MarshalException e) {
                /*
                 * This one is may thrown on the client side why marshalling the call arguments. It should actually
                 * never occur and if it does, it is probably an internal error.
                 */
                StringWriter writer = new StringWriter();
                e.printStackTrace(new PrintWriter(writer));

                String info = "Caught unexpected MarshalException during method guessing.\n"
                             +"Please report this to improve rmg :)\n"
                             +"Stack-Trace:\n"
                             +writer.toString();

                Logger.println(info);
                return;

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
             * Successfully guessed methods cause either an EOFException (object passed instead of primitive
             * or two few arguments) or an OptionalDataException (primitive passed for instead of object). As
             * these exceptions are not caught, we end up here.
             */
            Logger.printlnMixedYellow("HIT! Method with signature", candidate.getSignature(), "exists!");
            existingMethods.add(candidate);
        }
    }

}
