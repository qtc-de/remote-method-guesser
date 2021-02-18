import java.util.Map;
import java.util.Collection;

import de.qtc.rmg.plugin.IResponseHandler;

public class GenericPrint implements IResponseHandler {

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
}
