package de.qtc.rmg.plugin;

public class ReturnValueProvider implements IResponseHandler
{
    private Object value = null;

    public void handleResponse(Object responseObject)
    {
        value = responseObject;
    }

    public Object getValue()
    {
        return value;
    }
}
