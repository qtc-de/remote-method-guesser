package de.qtc.rmg.utils;

import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.rmi.Remote;
import java.rmi.server.ObjID;
import java.rmi.server.RMIClientSocketFactory;
import java.rmi.server.RMIServerSocketFactory;
import java.util.ArrayList;
import java.util.List;

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
    public boolean isKnown;
    public String className;
    public String boundName;
    public Remote remoteObject;
    public UnicastRef remoteRef;
    public TCPEndpoint endpoint;
    public RMIClientSocketFactory csf;
    public RMIServerSocketFactory ssf;

    public List<RemoteObjectWrapper> duplicates;

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

        if( Proxy.isProxyClass(remoteObject.getClass()) )
            this.className = remoteObject.getClass().getInterfaces()[0].getName();
        else
            this.className = remoteObject.getClass().getName();

        this.isKnown = !RMGUtils.dynamicallyCreated(className);
        this.duplicates = new ArrayList<RemoteObjectWrapper>();
    }

    public String getHost()
    {
        return endpoint.getHost();
    }

    public int getPort()
    {
        return endpoint.getPort();
    }

    public String getTarget()
    {
        return getHost() + ":" + getPort();
    }

    public boolean hasDuplicates()
    {
        if( this.duplicates.size() == 0 )
            return false;

        return true;
    }

    public void addDuplicate(RemoteObjectWrapper o)
    {
        this.duplicates.add(o);
    }

    public String[] getDuplicateBoundNames()
    {
        List<String> duplicateNames = new ArrayList<String>();

        for(RemoteObjectWrapper o : this.duplicates)
            duplicateNames.add(o.boundName);

        return duplicateNames.toArray(new String[0]);
    }

    public static RemoteObjectWrapper getByName(String boundName, RemoteObjectWrapper[] list)
    {
        for(RemoteObjectWrapper o : list)
        {
            if( o != null && o.boundName.equals(boundName) )
                return o;
        }

        return null;
    }

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

    public static boolean hasDuplicates(RemoteObjectWrapper[] list)
    {
        for(RemoteObjectWrapper o : list) {

            if( o.hasDuplicates() )
                return true;
        }

        return false;
    }
}
