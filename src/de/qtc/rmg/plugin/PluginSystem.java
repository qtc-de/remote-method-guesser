package de.qtc.rmg.plugin;

import java.io.File;
import java.io.FileInputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.jar.JarInputStream;
import java.util.jar.Manifest;

import de.qtc.rmg.exceptions.MalformedPluginException;
import de.qtc.rmg.internal.ExceptionHandler;
import de.qtc.rmg.io.Logger;
import de.qtc.rmg.operations.Operation;
import de.qtc.rmg.utils.RMGUtils;

public class PluginSystem {

    private static String manifestAttribute = "RmgPluginClass";

    private static IPayloadProvider payloadProvider = null;
    private static IResponseHandler responseHandler = null;
    private static IArgumentProvider argumentProvider = null;

    public static void init(String pluginPath)
    {
        DefaultProvider provider = new DefaultProvider();
        payloadProvider = provider;
        argumentProvider = provider;

        if(pluginPath != null)
            loadPlugin(pluginPath);
    }

    private static void loadPlugin(String pluginPath)
    {
        boolean inUse = false;
        Object pluginInstance = null;
        String pluginClassName = null;
        JarInputStream jarStream = null;
        File pluginFile = new File(pluginPath);

        if(!pluginFile.exists()) {
            Logger.eprintlnMixedYellow("Specified plugin path", pluginPath, "does not exist.");
            RMGUtils.exit();
        }

        try {
            jarStream = new JarInputStream(new FileInputStream(pluginFile));
            Manifest mf = jarStream.getManifest();
            pluginClassName = mf.getMainAttributes().getValue(manifestAttribute);
            jarStream.close();

            if(pluginClassName == null)
                throw new MalformedPluginException();

        } catch(Exception e) {
            Logger.eprintlnMixedYellow("Caught", e.getClass().getName(), "while reading the Manifest of the specified plugin.");
            Logger.eprintlnMixedBlue("Plugins need to be valid JAR files that contain the", manifestAttribute, "attribute.");
            RMGUtils.exit();
        }

        try {
            URLClassLoader ucl = new URLClassLoader(new URL[] {pluginFile.toURI().toURL()});
            Class<?> pluginClass = Class.forName(pluginClassName, true, ucl);
            pluginInstance = pluginClass.newInstance();
        } catch(Exception e) {
            Logger.eprintMixedYellow("Caught", e.getClass().getName(), "while reading plugin file ");
            Logger.printlnPlainBlue(pluginPath);
            ExceptionHandler.showStackTrace(e);
            RMGUtils.exit();
        }

        if(pluginInstance instanceof IPayloadProvider) {
            payloadProvider = (IPayloadProvider) pluginInstance;
            inUse = true;

        } if(pluginInstance instanceof IResponseHandler) {
            responseHandler = (IResponseHandler) pluginInstance;
            inUse = true;

        } if(pluginInstance instanceof IArgumentProvider) {
            argumentProvider = (IArgumentProvider) pluginInstance;
            inUse = true;
        }

        if(!inUse) {
            Logger.eprintMixedBlue("Plugin", pluginPath, "was successfully loaded, but is ");
            Logger.eprintlnPlainYellow("not in use.");
            Logger.eprintlnMixedYellow("Plugins should extend at least one of the", "IPayloadProvider, IResponseHandler, IArgumentProvider", "interfaces.");
        }
    }

    public static void handleResponse(Object o)
    {
        responseHandler.handleResponse(o);
    }

    public static Object getPayloadObject(Operation action, String name, String args)
    {
        return payloadProvider.getPayloadObject(action, name, args);
    }

    public static Object[] getArgumentArray(String argumentString)
    {
        return argumentProvider.getArgumentArray(argumentString);
    }

    public static boolean hasResponseHandler()
    {
        return responseHandler instanceof IResponseHandler;
    }

    public static boolean hasPayloadProvider()
    {
        return payloadProvider instanceof IPayloadProvider;
    }

    public static boolean hasArgumentProvider()
    {
        return argumentProvider instanceof IArgumentProvider;
    }
}
