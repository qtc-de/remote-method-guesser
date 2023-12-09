package eu.tneitzel.rmg.plugin;

/**
 * ReturnValueProvider is a helper class that can be used to capture return values of custom
 * RMI calls. Normally these return values are ignored and users can define a custom IResponseHandler
 * to process it. For some use cases (e.g. spring remoting) remote-method-guesser also requires
 * access to return values. This can be achieved by temporarily using this provider, that stores
 * the return value of a call within a static variable.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class ReturnValueProvider implements IResponseHandler
{
    private Object value = null;

    /**
     * Just store the return value within a static class variable.
     *
     * @param responseObject  object returned by the RMI call
     */
    public void handleResponse(Object responseObject)
    {
        value = responseObject;
    }

    /**
     * Obtain the currently set value.
     *
     * @return currently saved response object
     */
    public Object getValue()
    {
        return value;
    }
}
