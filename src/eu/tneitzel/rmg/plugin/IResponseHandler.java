package eu.tneitzel.rmg.plugin;

/**
 * The IResponseHandler interface is used during rmg's 'call' action to handle the return value of an invoked method.
 * Implementors are expected to implement the handleResponse method that is called with the return object obtained by the
 * server.
 *
 * This interface is not implemented by default and server responses are ignored when no plugin was specified manually.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public interface IResponseHandler {
    void handleResponse(Object responseObject);
}
