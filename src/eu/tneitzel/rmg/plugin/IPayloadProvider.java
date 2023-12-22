package eu.tneitzel.rmg.plugin;

import eu.tneitzel.rmg.operations.Operation;

/**
 * The IPayloadProvider interface is used during all rmg actions that send payload objects to the remote server.
 * This includes all actions that perform deserialization attacks, but also the bind, rebind and unbind actions.
 * Implementors are expected to implement the getPayloadObject function, that is called to obtain the actual payload
 * object. The function takes the current rmg action (in case you want to provide different gadgets for different calls)
 * and the gadget name and gadget arguments that were specified on the command line.
 *
 * This interface is implemented by rmg's DefaultProvider class by default.
 *
 * @author Tobias Neitzel (@qtc_de)
 */

public interface IPayloadProvider
{
    /**
     * Provide a payload object for deserialization attacks.
     *
     * @param action the current RMG action that requested the gadget
     * @param name the name of the gadget being requested
     * @param args the arguments provided for the gadget
     * @return a payload object to use for deserialization attacks
     */
    Object getPayloadObject(Operation action, String name, String args);
}
