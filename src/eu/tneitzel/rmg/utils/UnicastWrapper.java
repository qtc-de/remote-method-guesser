package eu.tneitzel.rmg.utils;

import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.rmi.Remote;
import java.rmi.server.ObjID;
import java.rmi.server.RMIClientSocketFactory;
import java.rmi.server.RMIServerSocketFactory;
import java.rmi.server.RemoteObjectInvocationHandler;
import java.util.ArrayList;
import java.util.List;

import eu.tneitzel.rmg.internal.ExceptionHandler;
import sun.rmi.server.UnicastRef;
import sun.rmi.transport.LiveRef;
import sun.rmi.transport.tcp.TCPEndpoint;

/**
 * The UnicastWrapper class extends RemoteObjectWrapper and is used for wrapping UnicastRef.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
@SuppressWarnings("restriction")
public class UnicastWrapper extends RemoteObjectWrapper
{
    public final ObjID objID;
    public final TCPEndpoint endpoint;
    public final UnicastRef unicastRef;

    public final RMIClientSocketFactory csf;
    public final RMIServerSocketFactory ssf;

    public List<UnicastWrapper> duplicates;

    /**
     * Create a new UnicastWrapper from a RemoteObject. The third argument seems superfluous, as the
     * UnicastRef is already contained within the remote object. However, UnicastWrappers should be
     * created by using the getInstance method of RemoteObjectWrapper. This one extracts the reference
     * from the remote object anyway to check whether it is a UnicastRef or ActivatableRef. Therefore,
     * we can reuse this extracted ref instead of performing another extraction.
     *
     * @param remoteObject Incoming RemoteObject, usually obtained by an RMI lookup call
     * @param boundName The bound name that the remoteObject uses inside the RMI registry
     * @param ref UnicastRef to build the wrapper around
     * @throws many Exceptions - These only occur if some reflective access fails
     */
    public UnicastWrapper(Remote remoteObject, String boundName, UnicastRef ref) throws IllegalArgumentException, IllegalAccessException, NoSuchFieldException, SecurityException
    {
        super(boundName, remoteObject);
        this.unicastRef = ref;

        LiveRef lRef = unicastRef.getLiveRef();
        duplicates = new ArrayList<UnicastWrapper>();

        Field endpointField = LiveRef.class.getDeclaredField("ep");
        endpointField.setAccessible(true);

        objID = lRef.getObjID();
        endpoint = (TCPEndpoint)endpointField.get(lRef);

        csf = lRef.getClientSocketFactory();
        ssf = lRef.getServerSocketFactory();
    }

    /**
     * Returns the host name associated with the UnicastWrapper.
     *
     * @return host name the Wrapper is pointing to
     */
    public String getHost()
    {
        return endpoint.getHost();
    }

    /**
     * Returns the port number associated with the UnicastWrapper.
     *
     * @return port number the Wrapper is pointing to
     */
    public int getPort()
    {
        return endpoint.getPort();
    }

    /**
     * Returns a string that combines the host name and port in the 'host:port' notation.
     *
     * @return host:port the Wrapper is pointing to
     */
    public String getTarget()
    {
        return getHost() + ":" + getPort();
    }

    /**
     * Checks whether the Wrapper has any duplicates (other remote objects that implement the same
     * remote interface).
     *
     * @return true if duplicates are present
     */
    public boolean hasDuplicates()
    {
        if (this.duplicates.size() == 0)
        {
            return false;
        }

        return true;
    }

    /**
     * Add a duplicate to the UnicastWrapper. This should be a wrapper that implements the same
     * remote interface as the original wrapper.
     *
     * @param o duplicate UnicastWrapper that implements the same remote interface
     */
    public void addDuplicate(UnicastWrapper o)
    {
        this.duplicates.add(o);
    }

    /**
     * Iterates over the list of registered duplicates and returns the associated bound names as an array.
     *
     * @return array of String that contains duplicate bound names
     */
    public String[] getDuplicateBoundNames()
    {
        List<String> duplicateNames = new ArrayList<String>();

        for (UnicastWrapper o : this.duplicates)
        {
            duplicateNames.add(o.boundName);
        }

        return duplicateNames.toArray(new String[0]);
    }

    /**
     * Create a new UnicastWrapper from a RemoteRef. This function creates a Proxy that implements
     * the specified interface and uses a RemoteObjectInvocationHandler to forward method invocations to
     * the specified RemoteRef.
     *
     * @param remoteRef RemoteRef to the targeted RemoteObject
     * @param intf Interface that is implemented by the RemoteObject
     * @throws many Exceptions...
     */
    public static UnicastWrapper fromRef(UnicastRef unicastRef, Class<?> intf) throws IllegalArgumentException, IllegalAccessException, NoSuchFieldException, SecurityException
    {
        if (!Remote.class.isAssignableFrom(intf))
        {
            ExceptionHandler.internalError("UnicastWrapper.fromRef", "Specified interface is not valid");
        }

        RemoteObjectInvocationHandler remoteObjectInvocationHandler = new RemoteObjectInvocationHandler(unicastRef);
        Remote remoteObject = (Remote)Proxy.newProxyInstance(intf.getClassLoader(), new Class[] { intf }, remoteObjectInvocationHandler);

        return new UnicastWrapper(remoteObject, null, unicastRef);
    }

    /**
     * Takes a list of UnicastWrapper and looks for duplicates within it. The return value
     * is a list of unique UnicastWrapper that have the corresponding duplicates assigned.
     *
     * @param list UnicastWrapper to search for duplicates
     * @return Unique UnicastWrapper with duplicates assigned
     */
    public static UnicastWrapper[] handleDuplicates(UnicastWrapper[] list)
    {
        List<UnicastWrapper> unique = new ArrayList<UnicastWrapper>();

        outer: for (UnicastWrapper current : list)
        {
            for (UnicastWrapper other : unique)
            {
                if (other.getInterfaceName().equals(current.getInterfaceName()))
                {
                    other.addDuplicate(current);
                    continue outer;
                }
            }

            unique.add(current);
        }

        return unique.toArray(new UnicastWrapper[0]);
    }

    /**
     * Takes a list of UnicastWrapper and checks whether one of them contains duplicates.
     *
     * @param list UnicastWrapper to check for duplicates
     * @return true if at least one UnicastWrapper contains a duplicate
     */
    public static boolean hasDuplicates(UnicastWrapper[] list)
    {
        for (UnicastWrapper o : list)
        {
            if (o.hasDuplicates())
            {
                return true;
            }
        }

        return false;
    }
}
