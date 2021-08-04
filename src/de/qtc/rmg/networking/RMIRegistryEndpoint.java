package de.qtc.rmg.networking;

import java.io.IOException;
import java.rmi.NotBoundException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.RMISocketFactory;
import java.util.HashMap;
import java.util.Map;

import de.qtc.rmg.exceptions.SSRFException;
import de.qtc.rmg.internal.ExceptionHandler;
import de.qtc.rmg.internal.RMGOption;
import de.qtc.rmg.io.Logger;
import de.qtc.rmg.plugin.PluginSystem;
import de.qtc.rmg.utils.RMGUtils;
import de.qtc.rmg.utils.RemoteObjectWrapper;
import javassist.tools.reflect.Reflection;

/**
 * The RMIRegistryEndpoint represents an RMI Registry endpoint on the remote server. The class can be used
 * to perform some more high level RMI registry access like list and lookup operations. However, as it extends
 * RMIEndpoint, all low level RMI functionality is also available.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class RMIRegistryEndpoint extends RMIEndpoint {

    private Registry rmiRegistry;
    private Map<String,Remote> remoteObjectCache;

    /**
     * The main purpose of this constructor function is to setup the different socket factories.
     * During the initial connect to the registry, a socket factory can be specified manually and
     * will be used. This is done by the RMIEndpoint class already. However, for the communication
     * to looked up remote objects, the socket factory that was configured on the server side will
     * be used.
     *
     * For most cases this will be either RMISocketFactory or SslRMIClientSocketFactory. To implement
     * stuff like automatic redirection, we need to overwrite the default implementations of these
     * classes. This is done by this constructor.
     *
     * @param host RMI registry host
     * @param port RMI registry port
     */
    public RMIRegistryEndpoint(String host, int port)
    {
        super(host, port);

        this.remoteObjectCache = new HashMap<String,Remote>();

        try {
            RMISocketFactory.setSocketFactory(PluginSystem.getDefaultSocketFactory(host, port));

        } catch (IOException e) {
            Logger.eprintlnMixedBlue("Unable to set custom", "RMISocketFactory.", "Host redirection will probably not work.");
            ExceptionHandler.showStackTrace(e);
            Logger.eprintln("");
        }

        java.security.Security.setProperty("ssl.SocketFactory.provider", PluginSystem.getDefaultSSLSocketFactory(host, port));

        try {
            this.rmiRegistry = LocateRegistry.getRegistry(host, port, csf);

        } catch( RemoteException e ) {
            ExceptionHandler.internalError("RMIRegistryEndpoint.locateRegistry", "Caught unexpected RemoteException.");
            ExceptionHandler.stackTrace(e);
            RMGUtils.exit();
        }
    }

    /**
     * If a bound name was specified on the command line, return this bound name immediately. Otherwise,
     * obtain a list of bound names from the RMI registry. This is basically a wrapper around the list
     * function of the RMI registry, but has error handling implemented.
     *
     * @return String array of available bound names.
     */
    public String[] getBoundNames() throws java.rmi.NoSuchObjectException
    {
        if( RMGOption.BOUND_NAME.notNull() )
            return new String[] { RMGOption.BOUND_NAME.getString() };

        String[] boundNames = null;

        try {
            boundNames = rmiRegistry.list();

        } catch( java.rmi.ConnectIOException e ) {

            Throwable t = ExceptionHandler.getCause(e);

            if( t instanceof java.io.EOFException ) {
                ExceptionHandler.eofException(e, "list", "call");

            } else if( t instanceof java.net.NoRouteToHostException) {
                ExceptionHandler.noRouteToHost(e, "list", "call");

            } else if( e.getMessage().equals("non-JRMP server at remote endpoint")) {
                ExceptionHandler.noJRMPServer(e, "list", "call");

            } else if( t instanceof java.net.SocketException && t.getMessage().contains("Network is unreachable")) {
                ExceptionHandler.networkUnreachable(e, "list", "call");

            } else {
                ExceptionHandler.unexpectedException(e, "list", "call", true);
            }

        } catch( RemoteException e ) {

            Throwable t = ExceptionHandler.getCause(e);

            if( t instanceof java.net.NoRouteToHostException ) {
                ExceptionHandler.noRouteToHost(e, "list", "call");

            } else if( t instanceof java.net.ConnectException ) {
                ExceptionHandler.connectionRefused(e, "list", "call");

            } else if( t instanceof java.rmi.ConnectIOException && t.getMessage().equals("non-JRMP server at remote endpoint")) {
                ExceptionHandler.noJRMPServer(e, "list", "call");

            } else if( t instanceof javax.net.ssl.SSLException && t.getMessage().contains("Unsupported or unrecognized SSL message") ) {
                ExceptionHandler.sslError(e, "list", "call");

            } else if( t instanceof java.rmi.NoSuchObjectException ) {
                throw (java.rmi.NoSuchObjectException)t;

            } else if( t instanceof SSRFException ) {
                SSRFSocket.printContent(host, port);

            } else {
                ExceptionHandler.unexpectedException(e, "list", "call", true);
            }
        }

        return boundNames;
    }

    /**
     * Performs the RMI registries lookup operation to obtain a remote reference for the specified
     * bound names. The corresponding remote objects are wrapped inside the RemoteObjectWrapper class
     * and returned as an array.
     *
     * @param boundNames list of bound names to determine the classes from
     * @return List of wrapped remote objects
     * @throws Reflection related exceptions. RMI related once are caught by the other lookup function.
     */
    public RemoteObjectWrapper[] lookup(String[] boundNames) throws IllegalArgumentException, IllegalAccessException, NoSuchFieldException, SecurityException
    {
        RemoteObjectWrapper[] remoteObjects = new RemoteObjectWrapper[boundNames.length];

        for(int ctr = 0; ctr < boundNames.length; ctr++) {

            Remote remoteObject = this.lookup(boundNames[ctr]);
            remoteObjects[ctr] = new RemoteObjectWrapper(remoteObject, boundNames[ctr]);
        }

        return remoteObjects;
    }

    /**
     * Just a wrapper around the lookup method of the RMI registry. Performs exception handling
     * and caches remote objects that have already been looked up.
     *
     * @param boundName name to lookup within the registry
     * @return Remote representing the requested remote object
     */
    public Remote lookup(String boundName)
    {
        Remote remoteObject = remoteObjectCache.get(boundName);

        if( remoteObject == null ) {

            try {

                remoteObject = rmiRegistry.lookup(boundName);
                remoteObjectCache.put(boundName, remoteObject);

            } catch( RemoteException e ) {

                Throwable cause = ExceptionHandler.getCause(e);

                if( cause instanceof ClassNotFoundException ) {
                    ExceptionHandler.lookupClassNotFoundException(cause.getMessage());

                } else {
                    ExceptionHandler.unexpectedException(e, "lookup", "call", false);
                }

            } catch( NotBoundException e) {
                Logger.eprintMixedYellow("Caught", "NotBoundException", "on bound name ");
                Logger.printlnPlainBlue(boundName + ".");
                Logger.eprintln("The specified bound name is not bound to the registry.");
                RMGUtils.exit();

            }
        }

        return remoteObject;
    }

    /**
     * Return the Remote for the specified bound name from cache or null if it is not available.
     *
     * @param boundName name to lookup within the cache
     * @return Remote representing the requested remote object
     */
    public Remote getFromCache(String boundName)
    {
        return remoteObjectCache.get(boundName);
    }
}
