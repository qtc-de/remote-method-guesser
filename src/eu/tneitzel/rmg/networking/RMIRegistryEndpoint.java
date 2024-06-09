package eu.tneitzel.rmg.networking;

import java.io.IOException;
import java.io.InvalidClassException;
import java.io.StreamCorruptedException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.UnmarshalException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.RMISocketFactory;
import java.util.HashMap;
import java.util.Map;

import eu.tneitzel.rmg.exceptions.SSRFException;
import eu.tneitzel.rmg.internal.CodebaseCollector;
import eu.tneitzel.rmg.internal.ExceptionHandler;
import eu.tneitzel.rmg.internal.RMGOption;
import eu.tneitzel.rmg.io.Logger;
import eu.tneitzel.rmg.plugin.PluginSystem;
import eu.tneitzel.rmg.utils.EmptyWrapper;
import eu.tneitzel.rmg.utils.RMGUtils;
import eu.tneitzel.rmg.utils.RemoteObjectWrapper;

/**
 * The RMIRegistryEndpoint represents an RMI Registry endpoint on the remote server. The class can be used
 * to perform some more high level RMI registry access like list and lookup operations. However, as it extends
 * RMIEndpoint, all low level RMI functionality is also available.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class RMIRegistryEndpoint extends RMIEndpoint
{
    private Registry rmiRegistry;
    private Map<String,Remote> remoteObjectCache;

    private static int lookupCount = 0;
    private static final int maxLookupCount = 5;

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

        try
        {
            RMISocketFactory.setSocketFactory(PluginSystem.getDefaultSocketFactory(host, port));
        }

        catch (IOException e)
        {
            Logger.eprintlnMixedBlue("Unable to set custom", "RMISocketFactory.", "Host redirection will probably not work.");
            ExceptionHandler.showStackTrace(e);
            Logger.eprintln("");
        }

        java.security.Security.setProperty("ssl.SocketFactory.provider", PluginSystem.getDefaultSSLSocketFactory(host, port));

        try
        {
            this.rmiRegistry = LocateRegistry.getRegistry(host, port, csf);
        }

        catch (RemoteException e)
        {
            ExceptionHandler.internalError("RMIRegistryEndpoint.locateRegistry", "Caught unexpected RemoteException.");
            ExceptionHandler.stackTrace(e);
            RMGUtils.exit();
        }
    }

    /**
     * Alternative constructor that creates the RMIRegistryEndpoint from an already existing RMIEndpoint.
     *
     * @param rmi RMIEndpoint
     */
    public RMIRegistryEndpoint(RMIEndpoint rmi)
    {
        this(rmi.host, rmi.port);
    }

    /**
     * If a bound name was specified on the command line, return this bound name immediately. Otherwise,
     * obtain a list of bound names from the RMI registry. This is basically a wrapper around the list
     * function of the RMI registry, but has error handling implemented.
     *
     * @return String array of available bound names.
     * @throws java.rmi.NoSuchObjectException if the remote endpoint is not an RMI registry
     */
    public String[] getBoundNames() throws java.rmi.NoSuchObjectException
    {
        if (RMGOption.TARGET_BOUND_NAME.notNull())
        {
            return new String[] { RMGOption.TARGET_BOUND_NAME.getValue() };
        }

        String[] boundNames = null;

        try
        {
            boundNames = rmiRegistry.list();
        }

        catch (java.rmi.ConnectIOException e)
        {
            ExceptionHandler.connectIOException(e, "list");
        }

        catch (java.rmi.ConnectException e)
        {
            ExceptionHandler.connectException(e, "list");
        }

        catch (java.rmi.UnknownHostException e)
        {
            ExceptionHandler.unknownHost(e, host, true);
        }

        catch (java.rmi.NoSuchObjectException e)
        {
            throw e;
        }


        catch (Exception e)
        {
            Throwable cause = ExceptionHandler.getCause(e);

            if (cause instanceof SSRFException)
            {
                SSRFSocket.printContent(host, port);
            }

            else
            {
                ExceptionHandler.unexpectedException(e, "list", "call", true);
            }
        }

        return boundNames;
    }

    /**
     * Performs the RMI registries lookup operation to obtain a remote reference for the specified
     * bound names. The main benefit of using this method is, that it performs exception handling.
     *
     * @param boundNames list of bound names to determine the classes from
     * @return List of remote objects looked up from the remote registry
     * @throws UnmarshalException if unmarshaling the return value fails
     */
    public Remote[] lookup(String[] boundNames) throws UnmarshalException
    {
        Remote[] remoteObjects = new Remote[boundNames.length];

        for (int ctr = 0; ctr < boundNames.length; ctr++)
        {
            remoteObjects[ctr] = this.lookup(boundNames[ctr]);
        }

        return remoteObjects;
    }

    /**
     * Just a wrapper around the lookup method of the RMI registry. Performs exception handling
     * and caches remote objects that have already been looked up.
     *
     * @param boundName name to lookup within the registry
     * @return Remote representing the requested remote object
     * @throws UnmarshalException if unmarshalling the return value fails
     */
    public Remote lookup(String boundName) throws UnmarshalException
    {
        Remote remoteObject = remoteObjectCache.get(boundName);

        if (remoteObject == null)
        {
            try
            {
                remoteObject = rmiRegistry.lookup(boundName);
                remoteObjectCache.put(boundName, remoteObject);
                lookupCount = 0;
            }

            catch (java.rmi.ConnectIOException e)
            {
                ExceptionHandler.connectIOException(e, "lookup");
            }

            catch (java.rmi.ConnectException e)
            {
                ExceptionHandler.connectException(e, "lookup");
            }

            catch (java.rmi.UnknownHostException e)
            {
                ExceptionHandler.unknownHost(e, host, true);
            }

            catch (java.rmi.NoSuchObjectException e)
            {
                ExceptionHandler.noSuchObjectException(e, "registry", true);
            }

            catch (java.rmi.NotBoundException e)
            {
                ExceptionHandler.notBoundException(e, boundName);
            }

            catch (Exception e)
            {
                Throwable cause = ExceptionHandler.getCause(e);

                if (e instanceof UnmarshalException && cause instanceof InvalidClassException)
                {
                    InvalidClassException invalidClassException = (InvalidClassException)cause;

                    if (lookupCount > maxLookupCount || !cause.getMessage().contains("serialVersionUID"))
                    {
                        ExceptionHandler.invalidClassException(invalidClassException);
                    }

                    try
                    {
                        String className = RMGUtils.getClass(invalidClassException);
                        long serialVersionUID = RMGUtils.getSerialVersionUID(invalidClassException);

                        CodebaseCollector.addSerialVersionUID(className, serialVersionUID);
                        lookupCount += 1;
                    }

                    catch (Exception e1)
                    {
                        ExceptionHandler.invalidClassException(invalidClassException);
                    }

                    return this.lookup(boundName);
                }

                else if (e instanceof UnmarshalException && e.getMessage().contains("Transport return code invalid"))
                {
                    throw (UnmarshalException)e;
                }

                else if (e instanceof UnmarshalException && ExceptionHandler.getCause(e) instanceof StreamCorruptedException)
                {
                    throw (UnmarshalException)e;
                }

                if( cause instanceof ClassNotFoundException )
                {
                    ExceptionHandler.lookupClassNotFoundException(e, cause.getMessage());
                }

                else if( cause instanceof SSRFException )
                {
                    SSRFSocket.printContent(host, port);
                }

                else
                {
                    ExceptionHandler.unexpectedException(e, "lookup", "call", true);
                }
            }
        }

        return remoteObject;
    }

    /**
     * It was observed that using --serial-version-uid option can cause an invalid transport return code
     * exception during lookup. This seems to be some kind of race condition and cannot be reproduced reliably.
     * We currently believe that RMI / Java does not clear the ObjectInput stream when reading an unknown class
     * from it. The remaining bytes are left within the stream. Since RMI uses connection pooling, the next
     * operation encounters the invalid bytes and fails. If this is the case, we just retry a few times.
     *
     * @param boundName  the bound name to lookup
     * @param maxRetries  the maximum amount of retries to perform
     * @return Remote object if lookup was successful. null otherwise.
     */
    public Remote lookupWithRetries(String boundName, int maxRetries)
    {
        int retryCount = 0;

        while (retryCount < maxRetries)
        {
            try
            {
                return this.lookup(boundName);
            }

            catch (java.rmi.UnmarshalException e)
            {
                retryCount += 1;
            }

            catch (Exception e)
            {
                ExceptionHandler.unexpectedException(e, "lookup", "operation", true);
            }
        }

        return null;
    }

    /**
     * Same as the lookup action, but returns a RemoteObjectWrapper.
     *
     * @param boundName name to lookup within the registry
     * @return RemoteObjectWrapper for the remote object
     * @throws IllegalArgumentException if reflective access fails
     * @throws IllegalAccessException if reflective access fails
     * @throws NoSuchFieldException if reflective access fails
     * @throws SecurityException if reflective access fails
     * @throws UnmarshalException if unmarshalling the return value fails
     */
    public RemoteObjectWrapper lookupWrapper(String boundName)
    {
        Remote remoteObject = lookupWithRetries(boundName, 5);

        if (remoteObject != null)
        {
            try
            {
                return RemoteObjectWrapper.getInstance(remoteObject, boundName);
            }

            catch (IllegalArgumentException | IllegalAccessException | NoSuchFieldException | SecurityException e) {}
        }

        return new EmptyWrapper(boundName);
    }

    /**
     * Same as the lookup action, but returns an array of RemoteObjectWrapper.
     *
     * @param boundName name to lookup within the registry
     * @return RemoteObjectWrapper for the remote object
     * @throws IllegalArgumentException if reflective access fails
     * @throws IllegalAccessException if reflective access fails
     * @throws NoSuchFieldException if reflective access fails
     * @throws SecurityException if reflective access fails
     * @throws UnmarshalException if unmarshalling the return value fails
     */
    public RemoteObjectWrapper[] lookupWrappers(String[] boundNames)
    {
        RemoteObjectWrapper[] wrappers = new RemoteObjectWrapper[boundNames.length];

        for (int ctr = 0; ctr < boundNames.length; ctr++)
        {
            wrappers[ctr] = lookupWrapper(boundNames[ctr]);
        }

        return wrappers;
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
