import java.io.Serializable;
import java.rmi.Remote;
import java.util.Collection;
import java.util.Map;

import de.qtc.rmg.io.Logger;
import de.qtc.rmg.utils.RMGUtils;
import de.qtc.rmg.utils.RemoteObjectWrapper;
import de.qtc.rmg.plugin.IResponseHandler;

/**
 * GenericPrint is an rmg ResponseHandler plugin that attempts to print all incoming
 * server responses. It compares the incoming object to some known data types and chooses
 * reasonable defaults to visualize them.
 * 
 * @author Tobias Neitzel (@qtc_de)
 */
public class GenericPrint implements IResponseHandler {

	/**
	 * The handleResponse function is called with the incoming responseObject from the
	 * RMI server. Depending on the corresponding class, a different print action is
	 * chosen.
	 * 
	 * @param responseObject Incoming object from an RMI server response
	 */
	public void handleResponse(Object responseObject)
    {
        Class<?> responseClass = responseObject.getClass();

        if(responseObject instanceof Collection<?>)
        	handleCollection(responseObject);

        else if(responseObject instanceof Map<?,?>)
        	handleMap(responseObject);

        else if(responseClass.isArray())
        	handleArray(responseObject);

        else if(Remote.class.isAssignableFrom(responseClass))
        	handleRemote(responseObject);
        	
        else
        	handleDefault(responseObject);
    }
	
	/**
	 * For each item within an collection, call handleResponse on the corresponding
	 * item value.
	 * 
	 * @param o Object of the Collection type
	 */
	public void handleCollection(Object o)
	{
		for(Object item: (Collection<?>)o)
            handleResponse(item);
	}
	
	/**
	 * For each entry within a map, handleResponse is called on the entry key and value.
	 * Furthermore, an arrow is printed in an attempt to visualize their relationship.
	 * 
	 * @param o Object of the Map type
	 */
	public void handleMap(Object o)
	{
        Map<?,?> map = (Map<?,?>)o;
        
        for(Object item: map.keySet()) {
            handleResponse(item);
            System.out.print("  --> ");
            handleResponse(item);
        }
	}
    
	/**
	 * For each item within an array, call the handleResponse function.
	 * 
	 * @param o Object of the Array type
	 */
	public void handleArray(Object o)
	{
	    for(Object item: (Object[])o)
	        handleResponse(item);
	}
	
    /**
     * For all objects that extend Remote, the details of the remote reference are printed.
     * This includes the class name, the remote TCP endpoint, the assigned ObjID and the
     * configured socket factories.
     * 
     * @param o Object that extends the Remote type
     */
    public void handleRemote(Object o)
    {
    	try {
			RemoteObjectWrapper liveRef = new RemoteObjectWrapper((Remote)o);
			
			Logger.printlnYellow("Printing RemoteObject:");
			Logger.increaseIndent();
			
			String csf = "default";
			String ssf = "default";
			
			if(liveRef.csf != null)
				csf = liveRef.csf.getClass().getName();
			
			if(liveRef.ssf != null)
				ssf = liveRef.ssf.getClass().getName();
			
			Logger.printlnMixedBlue("Remote Class:\t\t", liveRef.className);
			Logger.printlnMixedBlue("Endpoint:\t\t", liveRef.getTarget());
			Logger.printlnMixedBlue("ObjID:\t\t\t", liveRef.objID.toString());
			Logger.printlnMixedBlue("ClientSocketFactory:\t", csf);
			Logger.printlnMixedBlue("ServerSocketFactory:\t", ssf);
			
			Logger.decreaseIndent();

		} catch (Exception e) {
			Logger.eprintlnMixedYellow("Caught", e.getClass().getName(), "when constructing AccesibleLiveRef.");
			RMGUtils.exit();
		}
    }
	
	/**
	 * The default action for each object is to print it using it's toString method.
	 * 
	 * @param o Object that did not matched one of the previously mentioned types.
	 */
	public void handleDefault(Object o)
	{
        Logger.println(o.toString());
	}
}
