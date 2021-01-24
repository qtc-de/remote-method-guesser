package de.qtc.rmg.internal;

import java.lang.reflect.Method;
import java.rmi.Remote;
import java.rmi.server.RemoteRef;
import java.util.ArrayList;

import de.qtc.rmg.io.Logger;

/**
 * Remote method guessing is a time consuming processes that usually benefits from
 * threading. Therefore, each guessing call is executed within a separate thread.
 * The GuessingWorker class implements Runnable and can be used for this purpose.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class GuessingWorker implements Runnable {

    private Method method;
    private RemoteRef instance;
    private Remote remote;
    private MethodCandidate candidate;
    private ArrayList<MethodCandidate> existingMethods;

    /**
     * Initialize the guessing worker with all the required information.
     *
     * @param method remote method that should be invoked (different from the methods that is guessed :D)
     * @param remote remote object to invoke the method on
     * @param instance remote reference (usually UnicastRef) to dispatch the call
     * @param existingMethods array of existing methods. Identified methods need to be appended
     * @param candidate method that is actually guessed
     */
    public GuessingWorker(Method method, Remote remote, RemoteRef instance, ArrayList<MethodCandidate> existingMethods, MethodCandidate candidate) {
        this.method = method;
        this.instance = instance;
        this.existingMethods = existingMethods;
        this.candidate = candidate;
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
            instance.invoke(remote, method, candidate.getConfusedArgument(), candidate.getHash());

        } catch( java.rmi.ServerException e ) {

            Throwable cause = ExceptionHandler.getCause(e);
            if( cause != null ) {

                if( cause instanceof java.rmi.UnmarshalException) {
                    /*
                     * This server-exception is thrown when the supplied method hash does not match any
                     * remote method. Therefore, we just continue from here.
                     */
                    return;

                } else if( cause instanceof java.rmi.UnknownHostException  ) {
                    Logger.eprintlnMixedYellow("Warning! Object tries to connect to unknown host:", cause.getCause().getMessage());
                    ExceptionHandler.showStackTrace(e);
                    return;

                } else if( cause instanceof java.rmi.ConnectException  ) {
                    Logger.eprintln((cause.getMessage().split(";"))[0]);
                    ExceptionHandler.showStackTrace(e);
                    return;
                }
            }

        } catch (java.rmi.UnmarshalException e) {
            /*
             * This occurs on invocation of methods taking zero arguments. Since the call always succeeds,
             * the remote method returns some value that probably not matches the expected return value of
             * the lookup method. However, it is still a successful invocation and the method exists.
             */

        } catch (Exception e) {
            /*
             * All other exceptions cause an error message, but are interpreted as an existing method. The
             * idea behind this is that a false-positive is usually better than a false-negative.
             */
            Logger.eprintlnMixedBlue("Caught unexpected Exception while guessing:", e.getMessage());
            Logger.eprintlnMixedBlue("Method is marked as", "existent", "but this is probably not true.");
            Logger.println("Please report this to improve rmg :)");
            ExceptionHandler.stackTrace(e);
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
