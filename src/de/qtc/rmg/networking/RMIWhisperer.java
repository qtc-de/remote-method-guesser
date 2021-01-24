package de.qtc.rmg.networking;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.ObjID;
import java.rmi.server.RMIClientSocketFactory;
import java.rmi.server.RMISocketFactory;
import java.rmi.server.RemoteRef;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.rmi.ssl.SslRMIClientSocketFactory;

import de.qtc.rmg.internal.ExceptionHandler;
import de.qtc.rmg.io.Logger;
import de.qtc.rmg.io.MaliciousOutputStream;
import de.qtc.rmg.utils.RMGUtils;
import sun.rmi.server.UnicastRef;
import sun.rmi.transport.Endpoint;
import sun.rmi.transport.LiveRef;
import sun.rmi.transport.StreamRemoteCall;
import sun.rmi.transport.tcp.TCPEndpoint;

/**
 * The RMIWhisperer class is used to handle the RMI communication. It sets up
 * the required socket factories, is used to obtain bound names and their corresponding
 * classes and also supports methods to dispatch raw RMI calls.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
@SuppressWarnings("restriction")
public final class RMIWhisperer {

    public int port;
    public String host;

    private Registry rmiRegistry;
    private RMIClientSocketFactory csf;

    /**
     * The main purpose of this constructor function is to setup the different socket factories.
     * First of all, a LoopbackSocketFactory is constructed that is used when --ssl was not specified.
     * This socket factory makes sure that all RMI calls are redirected to the specified target, even
     * if the bound names are configured to use a different IP or hostname.
     *
     * Afterwards, a LoopbackSslSocketFactory is constructed, which has certificate validation disabled
     * and implements the same target redirection as the plain LoopbackSocketFactory. Notice that this step
     * is required, independent from the setting of --ssl. Remote objects are may bound to a plaintext
     * registry, but use a SslSocketFactory as their RMIClientSocketFactory.
     *
     * If --ssl was specified, the LoopbackSslSocketFactory is additionally used as the RMIClientSocketFactory
     * for contacting the RMI registry.
     *
     * @param host RMI registry host
     * @param port RMI registry port
     * @param ssl if true, use SSL for registry communication
     * @param followRedirects if true, do not redirect calls to the specified target
     */
    public RMIWhisperer(String host, int port, boolean ssl, boolean followRedirects)
    {
         this.host = host;
         this.port = port;

         RMISocketFactory fac = RMISocketFactory.getDefaultSocketFactory();
         RMISocketFactory my = new LoopbackSocketFactory(host, fac, followRedirects);

         try {
             RMISocketFactory.setSocketFactory(my);
         } catch (IOException e) {
             Logger.eprintlnMixedBlue("Unable to set custom", "RMISocketFactory.", "Host redirection will probably not work.");
             ExceptionHandler.showStackTrace(e);
             Logger.eprintln("");
         }

         try {
             SSLContext ctx = SSLContext.getInstance("TLS");
             ctx.init(null, new TrustManager[] { new DummyTrustManager() }, null);
             SSLContext.setDefault(ctx);

             LoopbackSslSocketFactory.host = host;
             LoopbackSslSocketFactory.fac = ctx.getSocketFactory();
             LoopbackSslSocketFactory.followRedirect = followRedirects;
             java.security.Security.setProperty("ssl.SocketFactory.provider", "de.qtc.rmg.networking.LoopbackSslSocketFactory");

         } catch (NoSuchAlgorithmException | KeyManagementException e) {
             Logger.eprintlnMixedBlue("Unable to set", "TrustManager", "for SSL connections.");
             Logger.eprintln("SSL connections to untrusted hosts might fail.");
             ExceptionHandler.showStackTrace(e);
         }

         if( ssl )
             csf = new SslRMIClientSocketFactory();
         else
             csf = my;
    }

    /**
     * Just a wrapper around LocateRegistry.getRegistry. Actually not really useful :D
     */
    public void locateRegistry()
    {
        try {
            this.rmiRegistry = LocateRegistry.getRegistry(host, port, csf);

        } catch( RemoteException e ) {
            ExceptionHandler.internalError("RMGWhisperer.locateRegistry", "Caught unexpected RemoteException.");
            ExceptionHandler.stackTrace(e);
            RMGUtils.exit();
        }
    }

    /**
     * Obtains a list of bound names. This is basically a wrapper around the list function of the RMI registry,
     * but it has error handling implemented.
     *
     * @return list of available bound names.
     */
    public String[] getBoundNames()
    {
        String[] boundNames = null;

        try {
            boundNames = rmiRegistry.list();

        } catch( java.rmi.NoSuchObjectException e) {
            Logger.eprintlnMixedYellow("Caugth", "NoSuchObjectException", "while listing bound names.");
            Logger.eprintlnMixedYellow("Remote endpoint is probably", "not an RMI registry.");
            ExceptionHandler.showStackTrace(e);
            RMGUtils.exit();

        } catch( java.rmi.ConnectIOException e ) {

            Throwable t = ExceptionHandler.getCause(e);

            if( t instanceof java.io.EOFException ) {
                ExceptionHandler.eofException(e, "list", "call");

            } else if( t instanceof java.net.NoRouteToHostException) {
                ExceptionHandler.noRouteToHost(e, "list", "call");

            } else if( e.getMessage().equals("non-JRMP server at remote endpoint")) {
                ExceptionHandler.noJRMPServer(e, "list", "call");

            } else {
                ExceptionHandler.unexpectedException(e, "list", "call", true);
            }

        } catch( RemoteException e ) {

            Throwable t = ExceptionHandler.getCause(e);

            if( t instanceof java.net.NoRouteToHostException ) {
                ExceptionHandler.noRouteToHost(e, "list", "call");

            } else if( t instanceof java.net.ConnectException ) {
                ExceptionHandler.connectionRefused(e, "list", "call");

            } else if( t instanceof java.rmi.ConnectIOException && t.getMessage().equals("non-JRMP server at remote endpoint")) {
                ExceptionHandler.noJRMPServer(e, "list", "call");

            } else if( t instanceof javax.net.ssl.SSLException && t.getMessage().contains("Unsupported or unrecognized SSL message") ) {
                ExceptionHandler.sslError(e, "list", "call");

            } else {
                ExceptionHandler.unexpectedException(e, "list", "call", true);
            }
        }

        return boundNames;
    }

    /**
     * When called with null as parameter, this function just obtains a list of bound names from the registry.
     * If a string was specified instead, it returns a list that only contains that String. Not very useful,
     * but it allows to write the main function of rmg a little bit more straigt forward.
     *
     * @param boundName specified by the user. Is simply returned if not null
     * @return list of bound names or the user specified bound name
     */
    public String[] getBoundNames(String boundName)
    {
        if( boundName == null )
            return getBoundNames();

        return new String[] {boundName};
    }

    /**
     * Attempt to obtain the class name for each available bound name. This function simply
     * attempts to lookup the specified bound names and catches the ClassNotFoundException.
     * From the exception, the class name can be obtained.
     *
     * If no ClassNotFoundException was thrown, the class is known and available within the
     * current classpath. These classes are reported separately.
     *
     * @param boundNames list of bound names to determine the classes from
     * @return HashMaps of bound name -> class name pairs. Returns two HashMaps, one for
     *            known and one for unknown classes
     */
    public ArrayList<HashMap<String, String>> getClassNames(String[] boundNames)
    {
        ArrayList<HashMap<String, String>> returnList = new ArrayList<HashMap<String, String>>();

        HashMap<String, String> knownClasses = new HashMap<String,String>();
        HashMap<String, String> unknownClasses = new HashMap<String,String>();

        Object object = null;

        for( String className : boundNames ) {

          try {

              object = rmiRegistry.lookup(className);
              knownClasses.put(className, object.getClass().getName());

          } catch( RemoteException e ) {

              Throwable cause = ExceptionHandler.getCause(e);
              if( cause instanceof ClassNotFoundException ) {

                  /*
                   * Expected exception message is: <CLASSNAME> (no security manager: RMI class loader disabled).
                   * This is always true, as long as no security manager is used when starting rmg. As the exception
                   * is thrown on the client-side, server-side security managers are not important here.
                   * Since class names cannot contain spaces, cutting on the first space should be sufficient.
                   */
                  String message = cause.getMessage();
                  int end = message.indexOf(" ");

                  message = message.substring(0, end);
                  unknownClasses.put(className, message);

              } else {
                  ExceptionHandler.unexpectedException(e, "lookup", "call", false);
              }

          } catch( NotBoundException e) {
              Logger.eprintMixedYellow("Caught", "NotBoundException", "on boundname ");
              Logger.printlnPlainBlue(className + ".");
              Logger.eprintln("Boundname seems to be no longer available.");
          }
        }

        returnList.add(knownClasses);
        returnList.add(unknownClasses);
        return returnList;
    }

    /**
     * Constructs a TCPEndpoint (class used by internal RMI communication) using the specified
     * host, port and csf values.
     *
     * @return newly constructed TCPEndpoint
     */
    public TCPEndpoint getEndpoint()
    {
        return new TCPEndpoint(host, port, csf, null);
    }

    /**
     * @return the underlying registry object
     */
    public Registry getRegistry()
    {
        return this.rmiRegistry;
    }

    /**
     * Wrapper around the genericCall function specified below.
     */
    public void genericCall(ObjID objID, int callID, long methodHash, Object[] callArguments, boolean locationStream, String callName) throws Exception
    {
        genericCall(objID, callID, methodHash, callArguments, locationStream, callName, null);
    }

    /**
     * Dispatches a raw RMI call. Having such a function available is important for some low level RMI operations like the localhost bypass or even
     * just calling the registry with serialization gadgets. This method provides full access to almost all relevant parts of the actual RMI calls.
     *
     * The target remote objects can be either specified by their ObjID or by using an already existing RemoteRef. The first approach is suitable
     * for communicating with well known RMI objects like the registry, the DGC or the Activator. The second approach can be useful, when you just
     * looked up an object using regular RMI functions and now want to dispatch a raw RMI call to the already obtain RemoteObject.
     *
     * Within the current RMI protocol, you invoke methods by specifying an ObjID to identify the RemoteObject you want to talk with and a method hash
     * to identify the method you want to invoke. In legacy RMI, methods were instead identified by using a callID. This callID is basically the position
     * of the method within the class definition and is therefore a positive number for legacy RMI calls. Within modern RMI, this method should be always
     * negative (except when attempting localhost bypasses :P). The currently used method hash is replaced by an interface hash in the legacy implementation.
     *
     * The internal RMI communication (DGC and Registry) still use the legacy calling convention today, as you can check by searching for the corresponding
     * Skeleton classes within the Java RMI source code.
     *
     * @param objID identifies the RemoteObject you want to communicate with. Registry = 0, Activator = 1, DGC = 2 or custom once...
     * @param callID callID that is used for legacy calls. Basically specifies the position of the method
     * @param methodHash hash value of the method to call or interface hash for legacy calls
     * @param callArguments Object array of method arguments to used within the call
     * @param locationStream if true, uses the MaliciousOutpuStream class to write custom annotation objects
     * @param callName the name of the RMI call you want to dispatch (only used for logging)
     * @param remoteRef optional remote reference to use for the call. If null, the specified ObjID and the host and port of this class are used.
     * @throws Exception connection related exceptions are caught, but anything what can go wrong on the server side is thrown
     */
    @SuppressWarnings("deprecation")
    public void genericCall(ObjID objID, int callID, long methodHash, Object[] callArguments, boolean locationStream, String callName, RemoteRef remoteRef) throws Exception
    {
        try {

            if(remoteRef == null) {
                Endpoint endpoint = this.getEndpoint();
                remoteRef = new UnicastRef(new LiveRef(objID, endpoint, false));
            }

            StreamRemoteCall call = (StreamRemoteCall)remoteRef.newCall(null, null, callID, methodHash);
            try {
                ObjectOutputStream out = (ObjectOutputStream)call.getOutputStream();

                if(locationStream)
                    out = new MaliciousOutputStream(out);

                for(Object o : callArguments) {
                    if(o.getClass() == Long.class)
                        out.writeLong((long) o);

                    else if(o.getClass() == Boolean.class)
                        out.writeBoolean((boolean) o);

                    else
                        out.writeObject(o);
                }

            } catch(java.io.IOException e) {
                throw new java.rmi.MarshalException("error marshalling arguments", e);
            }

            remoteRef.invoke(call);
            remoteRef.done(call);

        } catch(java.rmi.ConnectException e) {

            Throwable t = ExceptionHandler.getCause(e);

            if( t instanceof java.net.ConnectException && t.getMessage().contains("Connection refused")) {
                ExceptionHandler.connectionRefused(e, callName, "call");

            } else {
                ExceptionHandler.unexpectedException(e, callName, "call", true);
            }

        } catch(java.rmi.ConnectIOException e) {

            Throwable t = ExceptionHandler.getCause(e);

            if( t instanceof java.net.NoRouteToHostException) {
                ExceptionHandler.noRouteToHost(e, callName, "call");

            } else if( t instanceof java.rmi.ConnectIOException && t.getMessage().contains("non-JRMP server")) {
                ExceptionHandler.noJRMPServer(e, callName, "call");

            } else if( t instanceof javax.net.ssl.SSLException && t.getMessage().contains("Unsupported or unrecognized SSL message")) {
                ExceptionHandler.sslError(e, callName, "call");

            } else {
                ExceptionHandler.unexpectedException(e, callName, "call", true);
            }
        }
    }
}
