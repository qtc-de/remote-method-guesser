package de.qtc.rmg.utils;

import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.rmi.Remote;
import java.rmi.server.ObjID;
import java.rmi.server.RMIClientSocketFactory;
import java.rmi.server.RMIServerSocketFactory;
import java.rmi.server.RMISocketFactory;
import java.rmi.server.RemoteObjectInvocationHandler;
import java.rmi.server.RemoteRef;
import java.util.ArrayList;
import java.util.List;

import javax.rmi.ssl.SslRMIClientSocketFactory;

import de.qtc.rmg.endpoints.KnownEndpoint;
import de.qtc.rmg.endpoints.KnownEndpointHolder;
import de.qtc.rmg.internal.ExceptionHandler;
import sun.rmi.server.UnicastRef;
import sun.rmi.transport.LiveRef;
import sun.rmi.transport.tcp.TCPEndpoint;

/**
 * The RemoteObjectWrapper class represents a wrapper around the ordinary RMI remote object related classes.
 * It stores the basic information that is required to use the remote object as usual, but adds additional
 * fields that allow to obtain meta information more easily.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
@SuppressWarnings("restriction")
public class RemoteObjectWrapper {

    public ObjID objID;
    public String className;
    public String boundName;
    public Remote remoteObject;
    public UnicastRef remoteRef;
    public TCPEndpoint endpoint;
    public RMIClientSocketFactory csf;
    public RMIServerSocketFactory ssf;
    public KnownEndpoint knownEndpoint;

    public List<RemoteObjectWrapper> duplicates;

    /**
     * This constructor is only used for special purposes during the enum action. The resulting
     * RemoteObjectWrapper is not fully functional and should not be used for other purposes than
     * displaying the bound name.
     *
     * @param boundName as used in the RMI registry
     */
    public RemoteObjectWrapper(String boundName)
    {
        this.boundName = boundName;
    }

    /**
     * Create a new RemoteObjectWrapper from a RemoteObject.
     *
     * @param remoteObject Incoming RemoteObject, usually obtained by an RMI lookup call
     * @throws many Exceptions - These only occur if some reflective access fails
     */
    public RemoteObjectWrapper(Remote remoteObject) throws IllegalArgumentException, IllegalAccessException, NoSuchFieldException, SecurityException
    {
        this(remoteObject, null);
    }

    /**
     * Create a new RemoteObjectWrapper from a RemoteObject.
     *
     * @param remoteObject Incoming RemoteObject, usually obtained by an RMI lookup call
     * @param boundName The bound name that the remoteObject uses inside the RMI registry
     * @throws many Exceptions - These only occur if some reflective access fails
     */
    public RemoteObjectWrapper(Remote remoteObject, String boundName) throws IllegalArgumentException, IllegalAccessException, NoSuchFieldException, SecurityException
    {
        this.boundName = boundName;
        this.remoteObject = remoteObject;
        this.remoteRef = (UnicastRef)RMGUtils.extractRef(remoteObject);

        LiveRef lRef = remoteRef.getLiveRef();

        Field endpointField = LiveRef.class.getDeclaredField("ep");
        endpointField.setAccessible(true);

        this.objID = lRef.getObjID();
        this.endpoint = (TCPEndpoint)endpointField.get(lRef);

        this.csf = lRef.getClientSocketFactory();
        this.ssf = lRef.getServerSocketFactory();

        this.className = RMGUtils.getClassName(remoteObject);

        this.duplicates = new ArrayList<RemoteObjectWrapper>();
        this.knownEndpoint = KnownEndpointHolder.getHolder().lookup(className);
    }

    /**
     * Create a new RemoteObjectWrapper from a RemoteRef. This function creates a Proxy that implements
     * the specified interface and uses a RemoteObjectInvocationHandler to forward method invocations to
     * the specified RemoteRef.
     *
     * @param remoteRef RemoteRef to the targeted RemoteObject
     * @param intf Interface that is implemented by the RemoteObject
     * @throws many Exceptions...
     */
    public static RemoteObjectWrapper fromRef(RemoteRef remoteRef, Class<?> intf) throws IllegalArgumentException, IllegalAccessException, NoSuchFieldException, SecurityException
    {
        if( !Remote.class.isAssignableFrom(intf) )
            ExceptionHandler.internalError("RemoteObjectWrapper.fromRef", "Specified interface is not valid");

        RemoteObjectInvocationHandler remoteObjectInvocationHandler = new RemoteObjectInvocationHandler(remoteRef);
        Remote remoteObject = (Remote)Proxy.newProxyInstance(intf.getClassLoader(), new Class[] { intf }, remoteObjectInvocationHandler);

        return new RemoteObjectWrapper(remoteObject);
    }

    /**
     * Check whether the endpoint is a known endpoint.
     *
     * @return True of the endpoint is known.
     */
    public boolean isKnown()
    {
        if( knownEndpoint == null )
            return false;

        return true;
    }

    /**
     * Returns the host name associated with the RemoteObjectWrapper
     *
     * @return host name the Wrapper is pointing to
     */
    public String getHost()
    {
        return endpoint.getHost();
    }

    /**
     * Returns the port number associated with the RemoteObjectWrapper
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
        if( this.duplicates.size() == 0 )
            return false;

        return true;
    }

    /**
     * Checks whether the socket factory used by the remote object is TLS protected. This function
     * returns 1 if the default SslRMIClientSocketFactory class is used. -1 if the default RMISocketFactory
     * class is used and 0 if none of the previously mentioned cases applies. Notice that a client
     * socket factory with a value of null implies the default socket factory (RMISocketFactory).
     *
     * @return 1 -> SslRMIClientSocketFactory, -1 -> RMISocketFactory, 0 -> Unknown
     */
    public int isTLSProtected()
    {
        if( csf != null ) {

            Class<?> factoryClass = csf.getClass();

            if( factoryClass == SslRMIClientSocketFactory.class )
                return 1;

            if( factoryClass == RMISocketFactory.class )
                return -1;

        } else if( remoteObject != null ) {
            return -1;
        }

        return 0;
    }

    /**
     * Add a duplicate to the RemoteObjectWrapper. This should be a wrapper that implements the same
     * remote interface as the original wrapper.
     *
     * @param o duplicate RemoteObjectWrapper that implements the same remote interface
     */
    public void addDuplicate(RemoteObjectWrapper o)
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

        for(RemoteObjectWrapper o : this.duplicates)
            duplicateNames.add(o.boundName);

        return duplicateNames.toArray(new String[0]);
    }

    /**
     * Searches a supplied list of RemoteObjectWrapper objects for the Wrapper that is associated to the
     * specified bound name.
     *
     * @param boundName associated bound name to look for
     * @param list RemoteObjectWrapper objects to search in
     * @return RemoteObjectWrapper that matches the specified bound name or null
     */
    public static RemoteObjectWrapper getByName(String boundName, RemoteObjectWrapper[] list)
    {
        for(RemoteObjectWrapper o : list)
        {
            if( o != null && o.boundName.equals(boundName) )
                return o;
        }

        return null;
    }

    /**
     * Takes a list of RemoteObjectWrappers and looks for duplicates within it. The return value
     * is a list of unique RemoteObjectWrappers that have the corresponding duplicates assigned.
     *
     * @param list RemoteObjectWrappers to search for duplicates
     * @return Unique RemoteObjectWrappers with duplicates assigned
     */
    public static RemoteObjectWrapper[] handleDuplicates(RemoteObjectWrapper[] list)
    {
        List<RemoteObjectWrapper> unique = new ArrayList<RemoteObjectWrapper>();

        outer: for(RemoteObjectWrapper current : list) {

            for(RemoteObjectWrapper other : unique) {

                if(other.className.equals(current.className)) {
                    other.addDuplicate(current);
                    continue outer;
                }
            }

            unique.add(current);
        }

        return unique.toArray(new RemoteObjectWrapper[0]);
    }

    /**
     * Takes a list of RemoteObjectWrappers and checks whether one of them contains duplicates.
     *
     * @param list RemoteObjectWrappers to check for duplicates
     * @return true if at least one RemoteObjectWrapper contains a duplicate
     */
    public static boolean hasDuplicates(RemoteObjectWrapper[] list)
    {
        for(RemoteObjectWrapper o : list) {

            if( o.hasDuplicates() )
                return true;
        }

        return false;
    }

    /**
     * Creates an array of RemoteObjectWrapper from an array of bound names. The resulting RemoteObjectWrappers
     * are dummy objects that just contain the associated bound name. This should only be used during rmg's enum
     * action to display bound names using the Formatter class.
     *
     * @param boundNames Array of String to create the RemoteObjectWrapper from
     * @return Array of RemoteObjectWrapper associated to the specified bound names
     */
    public static RemoteObjectWrapper[] fromBoundNames(String[] boundNames)
    {
        RemoteObjectWrapper[] returnValue = new RemoteObjectWrapper[boundNames.length];

        for(int ctr = 0; ctr < boundNames.length; ctr++)
            returnValue[ctr] = new RemoteObjectWrapper(boundNames[ctr]);

        return returnValue;
    }
}
