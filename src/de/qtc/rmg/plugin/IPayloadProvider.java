package de.qtc.rmg.plugin;

import de.qtc.rmg.operations.Operation;

/**
 * The IPayloadProvider interface is used during all rmg actions that send payload objects to the remote server.
 * This includes all actions that perform desrialization attacks, but also the bind, rebind and unbind actions.
 * Implementors are expected to implement the getPayloadObject function, that is called to obtain the actual payload
 * object. The function takes the current rmg action (in case you want to provide different gadgets for different calls)
 * and the gadget name and gadget arguments that were specified on the command line.
 *
 * This interface is implemented by rmg's DefaultProvider class by default.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public interface IPayloadProvider {
    Object getPayloadObject(Operation action, String name, String args);
}
