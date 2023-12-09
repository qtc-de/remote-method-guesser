import java.util.Map;
import java.util.HashMap;
import java.util.Collection;

import eu.tneitzel.rmg.operations.Operation;
import eu.tneitzel.rmg.plugin.DefaultProvider;
import eu.tneitzel.rmg.plugin.IResponseHandler;
import eu.tneitzel.rmg.plugin.IPayloadProvider;
import eu.tneitzel.rmg.plugin.IArgumentProvider;


public class PluginTest implements IResponseHandler, IPayloadProvider, IArgumentProvider {

    private static DefaultProvider defProv = new DefaultProvider();

    public void handleResponse(Object responseObject)
    {
        if(responseObject instanceof Collection<?>) {

            for(Object o: (Collection<?>)responseObject) {
                System.out.println(o.toString());
            }

        } else if(responseObject instanceof Map<?,?>) {

            Map<?,?> map = (Map<?,?>)responseObject;

            for(Object o: map.keySet()) {
                System.out.print(o.toString());
                System.out.println(" --> " + map.get(o).toString());
            }

        } else if(responseObject.getClass().isArray()) {

            for(Object o: (Object[])responseObject) {
                System.out.println(o.toString());
            }

        } else {

            System.out.println(responseObject.toString());
        }
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
            return defProv.getPayloadObject(action, "CommonsCollections6", args);

        } else {
            return defProv.getPayloadObject(action, name, args);
        }
    }
}
