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

/**
 * The PluginSystem class allows rmg to be extended by user defined classes. It can be used to setup
 * payload and argument providers that are used to create call arguments and to setup response handlers
 * that process return values of RMI calls. Plugins can be loaded by using the --plugin option on the
 * command line.
 *
 * By default, rmg uses the DefaultProvider as plugin, which implements the IPayloadProvider and
 * IArgumentProvider interfaces.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class PluginSystem {

    private static String manifestAttribute = "RmgPluginClass";

    private static IPayloadProvider payloadProvider = null;
    private static IResponseHandler responseHandler = null;
    private static IArgumentProvider argumentProvider = null;

    /**
     * Initializes the plugin system. By default, the payloadProvider and argumentProvider get a DefaultProvider
     * instance assigned. The responseHandler is not initialized by default and stays at null. If a user specified
     * pluginPath was specified, the plugin is attempted to be loaded and may overwrite previous settings.
     *
     * @param pluginPath user specified plugin path or null
     */
    public static void init(String pluginPath)
    {
        DefaultProvider provider = new DefaultProvider();
        payloadProvider = provider;
        argumentProvider = provider;

        if(pluginPath != null)
            loadPlugin(pluginPath);
    }

    /**
     * Attempts to load the plugin from the user specified plugin path. Plugins are expected to be JAR files that
     * contain the 'RmgPluginClass' attribute within their manifest. The corresponding attribute needs to contain the
     * class name of the class that actually implements the plugin.
     *
     * rmg will attempt to load the specified class using an URLClassLoader. It then attempts to identify which interfaces
     * are implemented by the class. E.g. if the class implements the IPayloadProvider interface, the default
     * payloadProvider of the PluginSystem class gets overwritten with the class from the plugin.
     *
     * @param pluginPath file system path to the plugin to load
     */
    @SuppressWarnings("deprecation")
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

    /**
     * Is called on incoming server responses if a response handler is defined. Just forwards the call to the
     * responseHandler plugin.
     *
     * @param o return value of a RMI method call
     */
    public static void handleResponse(Object o)
    {
        responseHandler.handleResponse(o);
    }

    /**
     * Is called from each action that requires a payload object. Just forwards the call to the corresponding plugin.
     *
     * @param action action that requests the payload object
     * @param name name of the payload that is requested
     * @param args arguments that should be used for the payload
     * @return generated payload object
     */
    public static Object getPayloadObject(Operation action, String name, String args)
    {
        return payloadProvider.getPayloadObject(action, name, args);
    }

    /**
     * Is called during rmg's 'call' action to obtain the Object argument array. Just forwards the call to the corresponding
     * plugin.
     *
     * @param argumentString as specified on the command line
     * @return Object array to use for the call
     */
    public static Object[] getArgumentArray(String argumentString)
    {
        return argumentProvider.getArgumentArray(argumentString);
    }

    /**
     * Checks whether a responseHandler was registered.
     *
     * @return true or false
     */
    public static boolean hasResponseHandler()
    {
        return responseHandler instanceof IResponseHandler;
    }

    /**
     * Checks whether a payloadProvider was registered.
     *
     * @return true or false
     */
    public static boolean hasPayloadProvider()
    {
        return payloadProvider instanceof IPayloadProvider;
    }

    /**
     * Checks whether a argumentProvider was registered.
     *
     * @return true or false
     */
    public static boolean hasArgumentProvider()
    {
        return argumentProvider instanceof IArgumentProvider;
    }
}
