package de.qtc.rmg.networking;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.lang.reflect.Proxy;
import java.rmi.NotBoundException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.ObjID;
import java.rmi.server.RMIClientSocketFactory;
import java.rmi.server.RMISocketFactory;
import java.rmi.server.RemoteRef;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.rmi.ssl.SslRMIClientSocketFactory;

import de.qtc.rmg.exceptions.SSRFException;
import de.qtc.rmg.internal.ExceptionHandler;
import de.qtc.rmg.internal.MethodArguments;
import de.qtc.rmg.internal.MethodCandidate;
import de.qtc.rmg.internal.Pair;
import de.qtc.rmg.internal.RMGOption;
import de.qtc.rmg.io.Logger;
import de.qtc.rmg.io.MaliciousOutputStream;
import de.qtc.rmg.io.RawObjectInputStream;
import de.qtc.rmg.plugin.PluginSystem;
import de.qtc.rmg.utils.RMGUtils;
import javassist.CtClass;
import javassist.CtPrimitiveType;
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
    private Map<String,Remote> remoteObjectCache;

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
    public RMIWhisperer(String host, int port)
    {
         this.host = host;
         this.port = port;

         RMISocketFactory fac = RMISocketFactory.getDefaultSocketFactory();
         RMISocketFactory my = new LoopbackSocketFactory(host, fac, RMGOption.FOLLOW.getBool());

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
             LoopbackSslSocketFactory.followRedirect = RMGOption.FOLLOW.getBool();
             java.security.Security.setProperty("ssl.SocketFactory.provider", "de.qtc.rmg.networking.LoopbackSslSocketFactory");

         } catch (NoSuchAlgorithmException | KeyManagementException e) {
             Logger.eprintlnMixedBlue("Unable to set", "TrustManager", "for SSL connections.");
             Logger.eprintln("SSL connections to untrusted hosts might fail.");
             ExceptionHandler.showStackTrace(e);
         }

         if( RMGOption.SSL.getBool() ) {
             csf = new SslRMIClientSocketFactory();

         } else if( RMGOption.SSRF.getBool() ) {
             csf = new SSRFSocketFactory();

         } else if( RMGOption.SSRFResponse.notNull() ) {
             byte[] content = RMGUtils.hexToBytes(RMGOption.SSRFResponse.getString());
             csf = new SSRFResponseSocketFactory(content);

         } else {
             csf = my;
         }

         remoteObjectCache = new HashMap<String,Remote>();
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
     * but has error handling implemented.
     *
     * @return list of available bound names.
     */
    public String[] getBoundNames() throws java.rmi.NoSuchObjectException
    {
        String[] boundNames = null;

        try {
            boundNames = rmiRegistry.list();

        } catch( java.rmi.ConnectIOException e ) {

            Throwable t = ExceptionHandler.getCause(e);

            if( t instanceof java.io.EOFException ) {
                ExceptionHandler.eofException(e, "list", "call");

            } else if( t instanceof java.net.NoRouteToHostException) {
                ExceptionHandler.noRouteToHost(e, "list", "call");

            } else if( e.getMessage().equals("non-JRMP server at remote endpoint")) {
                ExceptionHandler.noJRMPServer(e, "list", "call");

            } else if( t instanceof java.net.SocketException && t.getMessage().contains("Network is unreachable")) {
                ExceptionHandler.networkUnreachable(e, "list", "call");

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

            } else if( t instanceof java.rmi.NoSuchObjectException ) {
                throw (java.rmi.NoSuchObjectException)t;

            } else if( t instanceof SSRFException ) {
                SSRFSocket.printContent(host, port);

            } else {
                ExceptionHandler.unexpectedException(e, "list", "call", true);
            }
        }

        return boundNames;
    }

    /**
     * When called with null as parameter, this function just obtains a list of bound names from the registry.
     * If a string was specified instead, it returns a list that only contains that String.
     *
     * @param boundName specified by the user. Is simply returned if not null
     * @return list of bound names or the user specified bound name
     */
    public String[] getBoundNames(String boundName) throws java.rmi.NoSuchObjectException
    {
        if( boundName == null )
            return getBoundNames();

        return new String[] {boundName};
    }

    /**
     * Performs the RMI registries lookup operation to obtain a remote reference for the specified
     * bound names. However, the main purpose of this function is not to obtain the remote references
     * them self's, but the associated class names. These are returned within an array of HashMaps, where
     * the first element contains "known" classes (available within the current class path), whereas the
     * second one contains "unknown" classes. Nonetheless, the function stores already obtained remote
     * references within the remoteObjectCache, so that later lookups have not to be performed again.
     *
     * @param boundNames list of bound names to determine the classes from
     * @return Array of HashMap - HashMap[0] -> Known classes, HashMap[1] -> Unknown classes
     */
    @SuppressWarnings("unchecked")
    public HashMap<String, String>[] lookup(String[] boundNames)
    {
        HashMap<String, String>[] returnList = (HashMap<String, String>[])new HashMap[2];

        returnList[0] = new HashMap<String,String>();
        returnList[1] = new HashMap<String,String>();

        Remote object = null;
        String className = null;

        for( String boundName : boundNames ) {

            object = this.lookup(boundName);

            if( Proxy.isProxyClass(object.getClass()) )
                className = object.getClass().getInterfaces()[0].getName();
            else
                className = object.getClass().getName();

            if( RMGUtils.dynamicallyCreated(className) )
                returnList[1].put(boundName, className);
            else
                returnList[0].put(boundName, className);
        }

        return returnList;
    }

    /**
     * Just a wrapper around the lookup method of the RMI registry. Performs exception handling
     * and caches remote objects that have already been looked up.
     *
     * @param boundName name to lookup within the registry
     * @return Remote representing the requested remote object
     */
    public Remote lookup(String boundName)
    {
        Remote remoteObject = remoteObjectCache.get(boundName);

        if( remoteObject == null ) {

            try {

                remoteObject = rmiRegistry.lookup(boundName);
                remoteObjectCache.put(boundName, remoteObject);

            } catch( RemoteException e ) {

                Throwable cause = ExceptionHandler.getCause(e);

                if( cause instanceof ClassNotFoundException ) {
                    ExceptionHandler.lookupClassNotFoundException(cause.getMessage());

                } else {
                    ExceptionHandler.unexpectedException(e, "lookup", "call", false);
                }

            } catch( NotBoundException e) {
                Logger.eprintMixedYellow("Caught", "NotBoundException", "on bound name ");
                Logger.printlnPlainBlue(boundName + ".");
                Logger.eprintln("The specified bound name is not bound to the registry.");
                RMGUtils.exit();

            }
        }

        return remoteObject;
    }

    /**
     * Return the specified boundname from cache or null if it is not available.
     *
     * @param boundName name to lookup within the cache
     * @return Remote representing the requested remote object
     */
    public Remote getFromCache(String boundName)
    {
        return remoteObjectCache.get(boundName);
    }

    /**
     * Constructs a RemoteRef (class used by internal RMI communication) using the specified
     * host, port, csf and objID values..
     *
     * @return newly constructed RemoteRef
     */
    public RemoteRef getRemoteRef(ObjID objID)
    {
        Endpoint endpoint = new TCPEndpoint(host, port, csf, null);
        return new UnicastRef(new LiveRef(objID, endpoint, false));
    }

    /**
     * Constructs a RemoteRef (class used by internal RMI communication) using the specified
     * host, port, csf and objID values.
     *
     * @return newly constructed RemoteRef
     */
    public RemoteRef getRemoteRef(ObjID objID, int port, RMIClientSocketFactory csf)
    {
        Endpoint endpoint = new TCPEndpoint(host, port, csf, null);
        return new UnicastRef(new LiveRef(objID, endpoint, false));
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
    public void genericCall(ObjID objID, int callID, long methodHash, MethodArguments callArguments, boolean locationStream, String callName) throws Exception
    {
        genericCall(objID, callID, methodHash, callArguments, locationStream, callName, null, null);
    }

    /**
     * Wrapper around the genericCall function specified below.
     */
    public void genericCall(ObjID objID, int callID, long methodHash, MethodArguments callArguments, boolean locationStream, String callName, RemoteRef ref) throws Exception
    {
        genericCall(objID, callID, methodHash, callArguments, locationStream, callName, ref, null);
    }

    /**
     * Dispatches a raw RMI call. Having such a function available is important for some low level RMI operations like
     * the localhost bypass or even just calling the registry with serialization gadgets. This method provides full
     * access to almost all relevant parts of the actual RMI calls.
     *
     * The target remote objects can be either specified by their ObjID or by using an already existing RemoteRef. The
     * first approach is suitable for communicating with well known RMI objects like the registry, the DGC or the Activator.
     * The second approach can be useful, when you just looked up an object using regular RMI functions and now want to
     * dispatch a raw RMI call to the already obtain RemoteObject.
     *
     * Within the current RMI protocol, you invoke methods by specifying an ObjID to identify the RemoteObject you want to
     * talk with and a method hash to identify the method you want to invoke. In legacy RMI, methods were instead identified
     * by using a callID. This callID is basically the position of the method within the class definition and is therefore a
     * positive number for legacy RMI calls. Within modern RMI, this method should be always negative (except when attempting
     * localhost bypasses :P). The currently used method hash is replaced by an interface hash in the legacy implementation.
     * The internal RMI communication (DGC and Registry) still use the legacy calling convention today, as you can check by
     * searching for the corresponding Skeleton classes within the Java RMI source code.
     *
     * By default, the genericCall function just ignores responses from the RMI server. Responses are only parsed if an
     * expected return type was specified during the function call and a ResponseHandler was registered by using the plugin
     * system.
     *
     * @param objID identifies the RemoteObject you want to communicate with. Registry = 0, Activator = 1, DGC = 2 or
     *                 custom once...
     * @param callID callID that is used for legacy calls. Basically specifies the position of the method to call in legacy
     *                 rmi calls. For current calling convention, it should be negative
     * @param methodHash hash value of the method to call or interface hash for legacy calls
     * @param callArguments map of arguments for the call. Each argument must also ship a class it desires to be serialized to
     * @param locationStream if true, uses the MaliciousOutpuStream class to write custom annotation objects
     * @param callName the name of the RMI call you want to dispatch (only used for logging)
     * @param remoteRef optional remote reference to use for the call. If null, the specified ObjID and the host and port
     *                 of this class are used
     * @param rtype return type of the remote method. If specified, the servers response is forwarded to the ResponseHandler
     *                 plugin (if registered to the plugin system)
     * @throws Exception connection related exceptions are caught, but anything what can go wrong on the server side is thrown
     */
    @SuppressWarnings({ "deprecation", "rawtypes" })
    public void genericCall(ObjID objID, int callID, long methodHash, MethodArguments callArguments, boolean locationStream, String callName, RemoteRef remoteRef, CtClass rtype) throws Exception
    {
        try {

            if(remoteRef == null) {
                remoteRef = this.getRemoteRef(objID);
            }

            StreamRemoteCall call = (StreamRemoteCall)remoteRef.newCall(null, null, callID, methodHash);

            try {
                ObjectOutputStream out = (ObjectOutputStream)call.getOutputStream();
                if(locationStream)
                    out = new MaliciousOutputStream(out);

                for(Pair<Object,Class> p : callArguments) {
                    marshalValue(p.right(), p.left(), out);
                }

            } catch(java.io.IOException e) {
                throw new java.rmi.MarshalException("error marshalling arguments", e);
            }

            remoteRef.invoke(call);

            if(rtype != null && rtype != CtPrimitiveType.voidType && PluginSystem.hasResponseHandler()) {

                try {
                    ObjectInputStream in = (ObjectInputStream)call.getInputStream();
                    Object returnValue = unmarshalValue(rtype, in);
                    PluginSystem.handleResponse(returnValue);

                } catch( IOException | ClassNotFoundException e ) {
                    ((StreamRemoteCall)call).discardPendingRefs();
                    throw new java.rmi.UnmarshalException("error unmarshalling return", e);

                } finally {
                    try {
                        remoteRef.done(call);
                    } catch (IOException e) {
                        ExceptionHandler.unexpectedException(e, "done", "operation", true);
                    }
                }
            }

            remoteRef.done(call);

        } catch(java.rmi.ConnectException e) {
            ExceptionHandler.connectException(e, callName);

        } catch(java.rmi.ConnectIOException e) {
            ExceptionHandler.connectIOException(e, callName);

        } catch(java.rmi.NoSuchObjectException e) {
            ExceptionHandler.noSuchObjectException(e, "such", true);

        } catch( SSRFException e ) {
            SSRFSocket.printContent(host, port);
        }
    }

    /**
     * guessingCall is basically a copy of the genericCall method, that is optimized for method guessing. It takes
     * less parameters and offers only limited control to the caller. Methods are called with a specially prepared
     * set of arguments. In case of a method that accepts non primitive arguments, the function sends as many primitive
     * bytes over the network as it is required to reach the first non primitive argument. The advantage of this technique
     * is that all data is send within one BLOCKDATA block in the ObjectOutputStream (same block that contains the method hash).
     * The RMI server will read and drop the complete BLOCKDATA block in any case (method exists / method does not exist)
     * and the stream is clean and ready for the next invocation. In case of methods that take only primitive arguments,
     * the ObjectOutputStream is modified to send a RMI ping message that cuts of the BLOCKDATA array that contains the
     * regular calling arguments. This will lead to a second dispatch within the RMI server if the method does not exist.
     * If it does exist, the server picks up the RMI ping and throws an StreamCorruptedException. In the second case, the
     * next RMI call can directly being dispatched. In the first case, the RMI ping response need to be read from the
     * ObjectInputStream.
     *
     * @param candidate Candidate method to guess
     * @param callName Name of the method for logging purposes
     * @param remoteRef Remote Reference to guess on
     * @throws Exception connection related exceptions are caught, but anything what can go wrong on the server side is thrown
     */
    @SuppressWarnings("deprecation")
    public void guessingCall(MethodCandidate candidate, String callName, RemoteRef remoteRef) throws Exception
    {
        try {

            StreamRemoteCall call = (StreamRemoteCall)remoteRef.newCall(null, null, -1, candidate.getHash());

            try {

                ObjectOutputStream out = (ObjectOutputStream)call.getOutputStream();
                candidate.sendArguments(out);
                call.executeCall();

            } catch( Exception e ) {

                Throwable t = ExceptionHandler.getCause(e);
                if( !(t instanceof java.io.StreamCorruptedException) && candidate.primitiveSize() == -1 ) {

                    ObjectInputStream in = (ObjectInputStream)call.getInputStream();
                    RawObjectInputStream rin = new RawObjectInputStream(in);
                    rin.skip(1);
                }

                remoteRef.done(call);
                throw e;
            }

        } catch(java.rmi.ConnectException e) {
            ExceptionHandler.connectException(e, callName);

        } catch(java.rmi.ConnectIOException e) {
            ExceptionHandler.connectIOException(e, callName);
        }
    }

    /**
     * Marshals the specified object value to the corresponding type and writes it to the specified
     * output stream. This is basically a copy from the default RMI implementation of this function.
     * The type values are obtained by the method signature and the object values come from the argument
     * array.
     *
     * @param type data type to marshal to
     * @param value object to be marshalled
     * @param out output stream to marshal to
     * @throws IOException in case of a failing write operation to the stream
     */
    private static void marshalValue(Class<?> type, Object value, ObjectOutput out) throws IOException
    {
        if (type.isPrimitive()) {
            if (type == int.class) {
                out.writeInt(((Integer) value).intValue());
            } else if (type == boolean.class) {
                out.writeBoolean(((Boolean) value).booleanValue());
            } else if (type == byte.class) {
                out.writeByte(((Byte) value).byteValue());
            } else if (type == char.class) {
                out.writeChar(((Character) value).charValue());
            } else if (type == short.class) {
                out.writeShort(((Short) value).shortValue());
            } else if (type == long.class) {
                out.writeLong(((Long) value).longValue());
            } else if (type == float.class) {
                out.writeFloat(((Float) value).floatValue());
            } else if (type == double.class) {
                out.writeDouble(((Double) value).doubleValue());
            } else {
                throw new Error("Unrecognized primitive type: " + type);
            }
        } else {
            out.writeObject(value);
        }
    }

    /**
     * Unmarshals an object from the specified ObjectInput according to the data type specified
     * in the type parameter. This is required to read the result of RMI calls, as different types
     * are written differently to the ObjectInput by the RMI server. The expected type is taken from
     * the return value of the method signature.
     *
     * @param type data type that is expected from the stream
     * @param in ObjectInput to read from.
     * @return unmarshalled object
     * @throws IOException if reading the ObjectInput fails
     * @throws ClassNotFoundException if the read in class is unknown.
     */
    private static Object unmarshalValue(CtClass type, ObjectInput in) throws IOException, ClassNotFoundException
    {
        if (type.isPrimitive()) {
            if (type == CtPrimitiveType.intType) {
                return Integer.valueOf(in.readInt());
            } else if (type == CtPrimitiveType.booleanType) {
                return Boolean.valueOf(in.readBoolean());
            } else if (type == CtPrimitiveType.byteType) {
                return Byte.valueOf(in.readByte());
            } else if (type == CtPrimitiveType.charType) {
                return Character.valueOf(in.readChar());
            } else if (type == CtPrimitiveType.shortType) {
                return Short.valueOf(in.readShort());
            } else if (type == CtPrimitiveType.longType) {
                return Long.valueOf(in.readLong());
            } else if (type == CtPrimitiveType.floatType) {
                return Float.valueOf(in.readFloat());
            } else if (type == CtPrimitiveType.doubleType) {
                return Double.valueOf(in.readDouble());
            } else {
                throw new Error("Unrecognized primitive type: " + type);
            }
        } else {
            return in.readObject();
        }
    }
}
