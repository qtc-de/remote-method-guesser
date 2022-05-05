package de.qtc.rmg.utils;

import java.lang.reflect.Field;
import java.rmi.Remote;
import java.rmi.server.ObjID;
import java.rmi.server.RMIClientSocketFactory;
import java.rmi.server.RMIServerSocketFactory;
import java.rmi.server.RMISocketFactory;

import javax.rmi.ssl.SslRMIClientSocketFactory;

import sun.rmi.server.UnicastRef;
import sun.rmi.transport.LiveRef;
import sun.rmi.transport.tcp.TCPEndpoint;

@SuppressWarnings("restriction")
public class UnicastWrapper extends RemoteObjectWrapper
{
    public final ObjID objID;
    public final TCPEndpoint endpoint;
    public final UnicastRef unicastRef;

    public final RMIClientSocketFactory csf;
    public final RMIServerSocketFactory ssf;

    /**
     * Create a new RemoteObjectWrapper from a RemoteObject.
     *
     * @param remoteObject Incoming RemoteObject, usually obtained by an RMI lookup call
     * @param boundName The bound name that the remoteObject uses inside the RMI registry
     * @throws many Exceptions - These only occur if some reflective access fails
     */
    public UnicastWrapper(Remote remoteObject, String boundName, UnicastRef ref) throws IllegalArgumentException, IllegalAccessException, NoSuchFieldException, SecurityException
    {
        super(boundName, remoteObject);
        this.unicastRef = ref;

        LiveRef lRef = unicastRef.getLiveRef();

        Field endpointField = LiveRef.class.getDeclaredField("ep");
        endpointField.setAccessible(true);

        this.objID = lRef.getObjID();
        this.endpoint = (TCPEndpoint)endpointField.get(lRef);

        this.csf = lRef.getClientSocketFactory();
        this.ssf = lRef.getServerSocketFactory();
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
}
