package eu.tneitzel.rmg.plugin;

import java.io.File;
import java.io.FileInputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.rmi.server.RMIClientSocketFactory;
import java.rmi.server.RMISocketFactory;
import java.util.jar.JarInputStream;
import java.util.jar.Manifest;

import eu.tneitzel.rmg.exceptions.MalformedPluginException;
import eu.tneitzel.rmg.internal.ExceptionHandler;
import eu.tneitzel.rmg.internal.RMGOption;
import eu.tneitzel.rmg.io.Logger;
import eu.tneitzel.rmg.operations.Operation;
import eu.tneitzel.rmg.utils.RMGUtils;

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
public class PluginSystem
{
    private static String manifestAttribute = "RmgPluginClass";

    private static IPayloadProvider payloadProvider = null;
    private static IResponseHandler responseHandler = null;
    private static IArgumentProvider argumentProvider = null;
    private static ISocketFactoryProvider socketFactoryProvider = null;

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
        socketFactoryProvider = provider;

        if (RMGOption.GENERIC_PRINT.getBool())
        {
            responseHandler = new GenericPrint();
        }

        if (pluginPath != null)
        {
            loadPlugin(pluginPath);
        }
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

        if (!pluginFile.exists())
        {
            Logger.eprintlnMixedYellow("Specified plugin path", pluginPath, "does not exist.");
            RMGUtils.exit();
        }

        try
        {
            jarStream = new JarInputStream(new FileInputStream(pluginFile));
            Manifest mf = jarStream.getManifest();
            pluginClassName = mf.getMainAttributes().getValue(manifestAttribute);
            jarStream.close();

            if (pluginClassName == null)
            {
                throw new MalformedPluginException();
            }
        }

        catch (Exception e)
        {
            Logger.eprintlnMixedYellow("Caught", e.getClass().getName(), "while reading the Manifest of the specified plugin.");
            Logger.eprintlnMixedBlue("Plugins need to be valid JAR files that contain the", manifestAttribute, "attribute.");
            RMGUtils.exit();
        }

        try
        {
            URLClassLoader ucl = new URLClassLoader(new URL[] {pluginFile.toURI().toURL()});
            Class<?> pluginClass = Class.forName(pluginClassName, true, ucl);
            pluginInstance = pluginClass.newInstance();
        }

        catch (Exception e)
        {
            Logger.eprintMixedYellow("Caught", e.getClass().getName(), "while reading plugin file ");
            Logger.printlnPlainBlue(pluginPath);
            ExceptionHandler.showStackTrace(e);
            RMGUtils.exit();
        }

        if (pluginInstance instanceof IPayloadProvider)
        {
            payloadProvider = (IPayloadProvider)pluginInstance;
            inUse = true;
        }

        if (pluginInstance instanceof IResponseHandler)
        {
            responseHandler = (IResponseHandler)pluginInstance;
            inUse = true;
        }

        if(pluginInstance instanceof IArgumentProvider)
        {
            argumentProvider = (IArgumentProvider)pluginInstance;
            inUse = true;
        }

        if(pluginInstance instanceof ISocketFactoryProvider)
        {
            socketFactoryProvider = (ISocketFactoryProvider)pluginInstance;
            inUse = true;
        }

        if (!inUse)
        {
            Logger.eprintMixedBlue("Plugin", pluginPath, "was successfully loaded, but is ");
            Logger.eprintlnPlainYellow("not in use.");
            Logger.eprintlnMixedYellow("Plugins should implement at least one of the", "IPayloadProvider, IResponseHandler, IArgumentProvider or ISocketFactoryProvider", "interfaces.");
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
     * Returns the RMIClientSocketFactory that is used for RMI connections. The factory returned by this function
     * is used for all direct RMI calls. So e.g. if you call the registry or another RMI endpoint directly. If you
     * first lookup a bound name and use the obtained reference to make calls on the object, another factory is used
     * (check the getDefaultClientSocketFactory function for more details).
     *
     * @param host
     * @param port
     *
     * @return RMIClientSocketFactory that is used for direct RMI calls
     */
    public static RMIClientSocketFactory getClientSocketFactory(String host, int port)
    {
        return socketFactoryProvider.getClientSocketFactory(host, port);
    }

    /**
     * Returns the RMISocketFactory that is used for all RMI connections that use the default RMISocketFactory. The
     * factory returned by this function is used when you perform RMI actions on a remote object reference that was
     * obtained from the RMI registry and the RMI server did not assign a custom socket factory to the object.
     *
     * @param host
     * @param port
     *
     * @return RMISocketFactory that is used for "after lookup" RMI calls
     */
    public static RMISocketFactory getDefaultSocketFactory(String host, int port)
    {
        return socketFactoryProvider.getDefaultSocketFactory(host, port);
    }

    /**
     * Java RMI also contains a default implementation for SSL protected RMI communication. If the server uses the
     * corresponding SocketFactory on the server side, the RMI client does too and the only way to overwrite the default
     * SSLSocketFactory is by setting a Java property. Therefore, this function should return the name of a class that
     * you want to use as your default SSLSocketFactory. Notice that the factory needs to be available on the class path
     * and it is not sufficient to define it within the plugin.
     *
     * @param host
     * @param port
     *
     * @return String that indicates the desired SSLSocketFactories class name
     */
    public static String getDefaultSSLSocketFactory(String host, int port)
    {
        return socketFactoryProvider.getDefaultSSLSocketFactory(host, port);
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

    /**
     * Returns the currently set ResponseHandler
     *
     * @return currently set ResponseHandler
     */
    public static IResponseHandler getResponseHandler()
    {
        return responseHandler;
    }

    /**
     * Sets a new ResponseHandler.
     *
     * @param handler the new ResponseHandler to set
     */
    public static void setResponeHandler(IResponseHandler handler)
    {
        responseHandler = handler;
    }
}
