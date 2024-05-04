package eu.tneitzel.rmg.plugin;

import java.util.HashMap;

import eu.tneitzel.rmg.operations.Operation;

/**
 * Simple plugin to test the plugin system. Currently only covers a subset of available
 * plugin provider interfaces.
 * 
 * @author Tobias Neitzel (@qtc_de)
 */
public class Test implements IPayloadProvider, IArgumentProvider
{
	private static DefaultProvider defProv = new DefaultProvider();
	
	/**
	 * Return a HashMap containing username and password when the argument
	 * string "login" is used. Otherwise, return the default provider value.
	 * 
	 * @param argumentString  argument string specified on the cmdline
	 * 
	 * @retrun Objects to use as call arguments
	 */
	public Object[] getArgumentArray(String argumentString)
	{	 
		if (argumentString.equals("login"))
		{
		    HashMap<String,String> credentials =  new HashMap<String,String>();
		    credentials.put("username", "admin");
		    credentials.put("password", "admin");
		
		    return new Object[]{credentials};
		}

		else
		{
		    return defProv.getArgumentArray(argumentString);
		}
	}
	 
	/**
	 * Return the CommonsCollections6 payload when the gadget name custom was specified.
	 * Otherwise, just use the default provider.
	 * 
	 * @param action  currently running rmg action
	 * @param name	requested gadget name
	 * @param args	specified gadget args
	 * 
	 * @return Gadget object to pass to the server
	 */
	public Object getPayloadObject(Operation action, String name, String args)
	{	 
        if (name.equals("custom"))
        {
            return defProv.getPayloadObject(action, "CommonsCollections6", args);
        }

        else
        {
            return defProv.getPayloadObject(action, name, args);
        }
    }
}
