package eu.tneitzel.rmg.plugin;

import java.rmi.server.RMIClientSocketFactory;
import java.rmi.server.RMISocketFactory;

import eu.tneitzel.argparse4j.global.IAction;
import eu.tneitzel.rmg.operations.Operation;

/**
 * The Template class represents a template to develop remote-method-guesser plugins.
 * It implements all the available plugin interfaces, but only uses placeholder implementations.
 * If you want to build a plugin from it, remove the interfaces and methods that you do not
 * intend to use. Other methods need to be overwritten with actual useful implementations.
 *
 * When changing the class name, make sure to also change the RmgPluginClass entry within the
 * pom.xml file.
 */
public class Template implements IPayloadProvider, IArgumentProvider, IResponseHandler, IActionProvider, ISocketFactoryProvider
{
    /**
     * Construct the client socket factory to use. This factory is used to create sockets
     * for direct RMI communication (e.g. when connecting to the RMI registry).
     *
     * @param host  remote host
     * @param port  remote port
     * @return RMIClientSocketFactory to use
     */
    public RMIClientSocketFactory getClientSocketFactory(String host, int port)
    {
        // TODO Override with something useful or remove
        return null;
    }

    /**
     * Construct the RMI socket factory to use. This factory is used for implicit RMI
     * connections, e.g. when calling a method on a previously obtained remote object.
     *
     * @param host  remote host
     * @param port  remote port
     * @return RMISocketFactory to use
     */
    public RMISocketFactory getDefaultSocketFactory(String host, int port)
    {
        // TODO Override with something useful or remove
        return null;
    }

    /**
     * Return the SSL socket factory class that should be used for implicit RMI connections.
     *
     * @param host  remote host
     * @param port  remote port
     * @return name of the SSL socket factory class to use for SSL connections.
     */
    public String getDefaultSSLSocketFactory(String host, int port)
    {
        // TODO Override with something useful or remove
        return null;
    }

    /**
     * Is called by remote-method-guesser if the user specified an action that was defined
     * by the plugin.
     *
     * @param action the action specified by the user
     */
    public void dispatch(IAction arg0)
    {
        // TODO Override with something useful or remove
    }

    /**
     * Return all actions that get added by the plugin.
     *
     * @return actions that are added by the plugin
     */
    public IAction[] getActions()
    {
        // TODO Override with something useful or remove
        return null;
    }

    /**
     * Handle the response of an RMI call.
     *
     * @param responseObject the object that was returned by the server.
     */
    public void handleResponse(Object responseObject)
    {
        // TODO Override with something useful or remove
    }

    /**
     * Provide an argument array for remote method calls.
     *
     * @param argumentString the argument string specified on the command line
     * @return argument array for a remote method call
     */
    public Object[] getArgumentArray(String argumentString)
    {
        // TODO Override with something useful or remove
        return null;
    }

    /**
     * Provide a payload object for deserialization attacks.
     *
     * @param action the current RMG action that requested the gadget
     * @param name the name of the gadget being requested
     * @param args the arguments provided for the gadget
     * @return a payload object to use for deserialization attacks
     */
    public Object getPayloadObject(Operation action, String name, String args)
    {
        // TODO Override with something useful or remove
        return null;
    }
}
