package de.qtc.rmg.utils;

import java.lang.reflect.Field;
import java.rmi.Remote;
import java.rmi.server.ObjID;
import java.rmi.server.RMIClientSocketFactory;
import java.rmi.server.RMIServerSocketFactory;

import sun.rmi.server.UnicastRef;
import sun.rmi.transport.LiveRef;
import sun.rmi.transport.tcp.TCPEndpoint;


/**
 * The AccessibleLiveRef class represents a wrapper around the ordinary LiveRef RMI class. In
 * contrast to LiveRef, AccessibleLiveRef makes some of the internal fields accessinle, so that
 * they can be easily consumed by other functions.
 * 
 * @author Tobias Neitzel (@qtc_de)
 */
@SuppressWarnings("restriction")
public class AccessibleLiveRef {

	public ObjID objID; 
	public TCPEndpoint endpoint;
	public RMIClientSocketFactory csf;
	public RMIServerSocketFactory ssf;
	
	/**
	 * Create a new AccessibleLiveRef from a RemoteObject.
	 * 
	 * @param remoteObject Incoming RemoteObject, usually obtained by an RMI lookup call
	 * @throws many Exceptions - These only occur if some reflective access fails
	 */
	public AccessibleLiveRef(Remote remoteObject) throws IllegalArgumentException, IllegalAccessException, NoSuchFieldException, SecurityException
	{
		UnicastRef uRef = (UnicastRef)RMGUtils.extractRef(remoteObject);
		LiveRef lRef = uRef.getLiveRef();
		
        Field endpointField = LiveRef.class.getDeclaredField("ep");
        endpointField.setAccessible(true);
        
		this.objID = lRef.getObjID();
		this.endpoint = (TCPEndpoint)endpointField.get(lRef);
		
		this.csf = lRef.getClientSocketFactory();
		this.ssf = lRef.getServerSocketFactory();
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
}
