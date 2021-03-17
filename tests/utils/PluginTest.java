import java.util.HashMap;

import de.qtc.rmg.operations.Operation;
import de.qtc.rmg.plugin.DefaultProvider;
import de.qtc.rmg.plugin.IResponseHandler;
import de.qtc.rmg.plugin.IPayloadProvider;
import de.qtc.rmg.plugin.IArgumentProvider;


public class PluginTest implements IResponseHandler, IPayloadProvider, IArgumentProvider {

    private static DefaultProvider defProv = new DefaultProvider();

	public void handleResponse(Object responseObject)
    {
        System.out.println(responseObject);
    }

	public Object[] getArgumentArray(String argumentString)
    {
        if( argumentString.equals("login") ) {

            HashMap<String,String> credentials =  new HashMap<String,String>();
            credentials.put("username", "admin");
            credentials.put("password", "admin");

            return new Object[]{credentials};

        } else {
            return defProv.getArgumentArray(argumentString);
        }
    }

    public Object getPayloadObject(Operation action, String name, String args)
    {
        if( name.equals("custom") ) {
            return "id";
        
        } else {
            return defProv.getPayloadObject(action, name, args);
        }
    }
}
