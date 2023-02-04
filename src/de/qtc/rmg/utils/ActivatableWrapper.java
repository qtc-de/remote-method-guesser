package de.qtc.rmg.utils;

import java.io.IOException;
import java.lang.reflect.Field;
import java.rmi.MarshalledObject;
import java.rmi.Remote;
import java.rmi.server.RemoteRef;
import java.rmi.server.UID;

import de.qtc.rmg.internal.ExceptionHandler;
import de.qtc.rmg.internal.RMGOption;
import de.qtc.rmg.networking.RMIEndpoint;
import de.qtc.rmg.operations.ActivationClient;
import de.qtc.rmg.plugin.IResponseHandler;
import de.qtc.rmg.plugin.PluginSystem;
import sun.rmi.server.UnicastRef;
import sun.rmi.transport.LiveRef;
import sun.rmi.transport.tcp.TCPEndpoint;

/**
 * The ActivatableWrapper class extends RemoteObjectWrapper and is used for wrapping ActivatableRef.
 * By using the activate method of ActivatableWrapper, it is possible to turn it into an UnicastWrapper.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
@SuppressWarnings("restriction")
public class ActivatableWrapper extends RemoteObjectWrapper
{
    public final UID activationUID;
    private final Object activationIDObj;
    private final RMIEndpoint activatorEndpoint;
    private final UnicastRef activatorUnicastRef;

    private RemoteRef activatableRef = null;
    private UnicastWrapper activatedRef = null;

    /**
     * ActivatableWrapper is constructed from a remote object. It expects the underlying RemoteRef to
     * be an ActivatableRef and attempts to extract the ActivationID from it. The ActivationID is then
     * used to obtain the actual UID used for activation and the reference to the Activator.
     *
     * To provide compatibility to newer Java versions, the constructor uses reflection to perform operations
     * on classes that are contained in the activation system. This allows them to be dynamically generated
     * if they are missing.
     *
     * During the enum action, it is possible to use the RMGOptions.ACTIVATE option to activate an
     * ActivatableWrapper and to display properties of the UnicastRef that is obtained during activation.
     * For all other operations, activation is done implicitly.
     *
     * The third argument seems superfluous, as the ref is already contained in the remote object. However,
     * ActivatableWrapper should be created by using the getInstance method of RemoteObjectWrapper. This one
     * extracts the reference from the remote object anyway to check whether it is a UnicastRef or ActivatableRef.
     * Therefore, we can reuse this extracted ref instead of performing another extraction.
     *
     * @param remoteObject Incoming RemoteObject, usually obtained by an RMI lookup call
     * @param boundName The bound name that the remoteObject uses inside the RMI registry
     * @param ref ActivatableRef to wrap around
     * @throws many Exceptions - These only occur if some reflective access fails
     */
    public ActivatableWrapper(Remote remoteObject, String boundName, RemoteRef ref) throws IllegalArgumentException, IllegalAccessException, NoSuchFieldException, SecurityException
    {
        super(boundName, remoteObject);

        Class<?> activationIDClass = null;
        Class<?> activatableRefClass = null;

        try {
            activationIDClass = Class.forName("java.rmi.activation.ActivationID");
            activatableRefClass = Class.forName("sun.rmi.server.ActivatableRef");

        } catch (ClassNotFoundException e) {
            ExceptionHandler.unexpectedException(e, "ActivatableWrapper", "constructor", true);
        }

        Field activationIDField = activatableRefClass.getDeclaredField("id");
        Field uidField = activationIDClass.getDeclaredField("uid");
        Field activatorField = activationIDClass.getDeclaredField("activator");
        Field endpointField = LiveRef.class.getDeclaredField("ep");

        for( Field field : new Field[] { activationIDField, uidField, activatorField, endpointField })
            field.setAccessible(true);

        this.activatableRef = ref;
        activationIDObj = activationIDField.get(activatableRef);
        activationUID = (UID) uidField.get(activationIDObj);

        Remote activator = (Remote) activatorField.get(activationIDObj);
        activatorUnicastRef = (UnicastRef) RMGUtils.extractRef(activator);

        LiveRef lRef = activatorUnicastRef.getLiveRef();
        TCPEndpoint endpoint = (TCPEndpoint)endpointField.get(lRef);

        activatorEndpoint = new RMIEndpoint(endpoint.getHost(), endpoint.getPort());

        if (RMGOption.ACTIVATION.getBool())
            this.activate();
    }

    /**
     * Activate the ActivatableWrapper. Sends an activate call to the associated Activator and attempts
     * to obtain a UnicastRef for the desired remote object.
     *
     * @return UnicastWrapper that contains the activated reference
     * @throws Reflection related exceptions
     */
    public UnicastWrapper activate() throws IllegalArgumentException, IllegalAccessException, NoSuchFieldException, SecurityException
    {
        if (activatedRef != null && !RMGOption.FORCE_ACTIVATION.getBool())
            return activatedRef;

        ActivationClient activationClient = new ActivationClient(activatorEndpoint);
        ActivationResponseHandler handler = new ActivationResponseHandler();

        IResponseHandler cachedHandler = PluginSystem.getResponseHandler();
        PluginSystem.setResponeHandler(handler);

        Class<?> activatableRefClass = null;

        try {
            activationClient.regularActivateCall(activationIDObj, RMGOption.FORCE_ACTIVATION.getBool(), activatorUnicastRef);
            activatableRefClass = Class.forName("sun.rmi.server.ActivatableRef");

        } catch (Exception e) {
            ExceptionHandler.unexpectedException(e, "activate", "call", true);
        }

        Field activationRefField = activatableRefClass.getDeclaredField("ref");
        activationRefField.setAccessible(true);

        PluginSystem.setResponeHandler(cachedHandler);
        Remote activatedObject = handler.getRemote();
        activatableRef = RMGUtils.extractRef(activatedObject);

        activatedRef = new UnicastWrapper(activatedObject, boundName, (UnicastRef) activationRefField.get(activatableRef));

        return activatedRef;
    }

    /**
     * Return the currently set activatedRef. This is probably null, if the wrapper was not previously activated.
     * Use the activate method instead, if you want to ensure activation.
     *
     * @return activatedRef or null
     */
    public UnicastWrapper getActivated()
    {
        return activatedRef;
    }

    /**
     * Return a formatted string in host:port format for the Activator endpoint.
     *
     * @return String representation of the activator endpoint
     */
    public String getActivatorEndpoint()
    {
        return activatorEndpoint.host + ":" + activatorEndpoint.port;
    }

    /**
     * remote-method-guesser performs activation by calling the associated remote method of the
     * Activator manually, using its already implemented genericCall method from the RMIEndpoint
     * class. The downside of this approach is that this method was never intended to return the
     * return value of a call directly, but uses the PluginSystem to obtain return values via a
     * ResponseHandler. Therefore, we need to setup a ResponseHandler and register it on the
     * PluginSystem to obtain the result of the call.
     *
     * @author Tobias Neitzel (@qtc_de)
     */
    class ActivationResponseHandler implements IResponseHandler
    {
        private MarshalledObject<? extends Remote> activatedObject;

        /**
         * Required ResponseHandler function for handling the return value of the call. We simply
         * save it within the activatedObject property.
         */
        public void handleResponse(Object responseObject)
        {
            activatedObject = (MarshalledObject<? extends Remote>) responseObject;
        }

        /**
         * This function should be called after the response was handled. It takes the activatedObject
         * and attempts to extract the remote out of it. This object is then returned.
         * @return
         */
        public Remote getRemote()
        {
            try {
                return activatedObject.get();

            } catch (ClassNotFoundException | IOException e) {
                ExceptionHandler.unexpectedException(e, "activate", "call", true);
            }

            return null;
        }
    }
}
