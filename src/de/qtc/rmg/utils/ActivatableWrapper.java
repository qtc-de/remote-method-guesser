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

@SuppressWarnings("restriction")
public class ActivatableWrapper extends RemoteObjectWrapper
{
    public final UID activationUID;
    private final Object activationIDObj;
    private final RMIEndpoint activatorEndpoint;
    private final UnicastRef activatorUnicastRef;

    private RemoteRef activatableRef = null;
    private UnicastWrapper activatedRef = null;

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
        Remote activedObject = handler.getRemote();
        activatableRef = RMGUtils.extractRef(activedObject);

        activatedRef = new UnicastWrapper(activedObject, boundName, (UnicastRef) activationRefField.get(activatableRef));

        return activatedRef;
    }

    public UnicastWrapper getActivated()
    {
        return activatedRef;
    }

    public String getActivatorEndpoint()
    {
        return activatorEndpoint.host + ":" + activatorEndpoint.port;
    }

    class ActivationResponseHandler implements IResponseHandler
    {
        private MarshalledObject<? extends Remote> activatedObject;

        public void handleResponse(Object responseObject)
        {
            activatedObject = (MarshalledObject<? extends Remote>) responseObject;
        }

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