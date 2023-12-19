package eu.tneitzel.rmg.utils;

/**
 * EmptyWrapper is basically a dummy class that extends RemoteWrapper. It is only used
 * during the enum action as a container for the obtained bound names. In previous versions
 * of remote-method-guesser, an instance of RemoteObjectWrapper was directly used for this
 * purpose, but since critical properties like the associated remote object are missing, this
 * class was created to make it more transparent that this is not a fully working wrapper.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class EmptyWrapper extends RemoteObjectWrapper
{
    /**
     * Create an EmptyWrapper by simply using RemoteObjectWrappers boundName constructor.
     *
     * @param boundName the bound name to associate with the wrapper
     */
    public EmptyWrapper(String boundName)
    {
        super(boundName);
    }
}
