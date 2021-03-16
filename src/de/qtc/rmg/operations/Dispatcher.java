package de.qtc.rmg.operations;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

import de.qtc.rmg.annotations.Parameters;
import de.qtc.rmg.exceptions.UnexpectedCharacterException;
import de.qtc.rmg.internal.ArgumentParser;
import de.qtc.rmg.internal.ExceptionHandler;
import de.qtc.rmg.internal.MethodCandidate;
import de.qtc.rmg.io.Formatter;
import de.qtc.rmg.io.Logger;
import de.qtc.rmg.io.SampleWriter;
import de.qtc.rmg.io.WordlistHandler;
import de.qtc.rmg.networking.RMIWhisperer;
import de.qtc.rmg.utils.RMGUtils;
import de.qtc.rmg.utils.YsoIntegration;
import javassist.CannotCompileException;
import javassist.NotFoundException;

public class Dispatcher {

    private RMIWhisperer rmi;
    private ArgumentParser p;

    private String[] boundNames = null;
    private MethodCandidate candidate = null;
    private HashMap<String,String> allClasses = null;
    private ArrayList<HashMap<String,String>> boundClasses = null;

    public Dispatcher(ArgumentParser p)
    {
        this.p = p;
        rmi = new RMIWhisperer(p.getHost(), p.getPort(), (boolean)p.get("ssl"), (boolean)p.get("follow"));

        if(p.containsMethodSignature())
            this.createMethodCandidate();
    }

    @SuppressWarnings("unchecked")
    private void obtainBoundNames() throws java.rmi.NoSuchObjectException
    {
        if(boundNames != null && boundClasses != null && allClasses != null)
            return;

        rmi.locateRegistry();
        boundNames = rmi.getBoundNames((String)p.get("bound-name"));

        boundClasses = rmi.getClassNames(boundNames);
        allClasses = (HashMap<String, String>)boundClasses.get(0).clone();
        allClasses.putAll(boundClasses.get(1));
    }

    private void createMethodCandidate()
    {
        String signature = (String)p.get("signature");

        try {
            candidate = new MethodCandidate(signature);

        } catch (CannotCompileException | NotFoundException e) {
            ExceptionHandler.invalidSignature(signature);
        }
    }

    private RemoteObjectClient getRemoteObjectClient(String boundName)
    {
        Object objID = p.get("objid");

        if(objID != null) {
            return new RemoteObjectClient(rmi, (int)objID, p.getLegacyMode());

        } else {

            try {
                obtainBoundNames();
            } catch( java.rmi.NoSuchObjectException e ) {
                ExceptionHandler.noSuchObjectException(e, "registry", true);
            }

            return new RemoteObjectClient(rmi, boundName, allClasses.get(boundName), p.getLegacyMode());
        }
    }

    private void writeSamples(HashMap<String,ArrayList<MethodCandidate>> results)
    {
        String templateFolder = (String)p.get("template-folder");
        String sampleFolder = (String)p.get("sample-folder");
        boolean sslValue = (boolean)p.get("ssl");
        boolean followRedirect = (boolean)p.get("follow");
        int legacyMode = p.getLegacyMode();

        Logger.println("");
        Logger.println("Starting creation of sample files:");
        Logger.println("");
        Logger.increaseIndent();

        try {
            String className;
            SampleWriter writer;
            writer = new SampleWriter(templateFolder, sampleFolder, sslValue, followRedirect, legacyMode);

            for(String name : results.keySet()) {

                Logger.printlnMixedYellow("Creating samples for bound name", name + ".");
                Logger.increaseIndent();

                className = boundClasses.get(1).get(name);
                writer.createInterface(name, className, (List<MethodCandidate>)results.get(name));
                writer.createSamples(name, className, (List<MethodCandidate>)results.get(name), rmi);

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

    private HashSet<MethodCandidate> getCandidates()
    {
        HashSet<MethodCandidate> candidates = new HashSet<MethodCandidate>();

        String wordlistFile = (String)p.get("wordlist-file");
        String wordlistFolder = (String)p.get("wordlist-folder");
        boolean updateWordlist = (boolean)p.get("update");

        if( candidate != null ) {
            candidates.add(candidate);

        } else {

            try {
                WordlistHandler wlHandler = new WordlistHandler(wordlistFile, wordlistFolder, updateWordlist);
                candidates = wlHandler.getWordlistMethods();
            } catch( IOException e ) {
                Logger.eprintlnMixedYellow("Caught", "IOException", "while reading wordlist file(s).");
                ExceptionHandler.stackTrace(e);
                RMGUtils.exit();
            }
        }

        return candidates;
    }

    public void dispatchListen()
    {
        p.checkArgumentCount(4);

        String gadget = p.getPositionalString(3);
        String command = p.getPositionalString(4);
        YsoIntegration.createJRMPListener(p.getHost(), p.getPort(), gadget, command);
    }

    @Parameters(count=4)
    public void dispatchActivator()
    {
        ActivationClient act = new ActivationClient(rmi);
        act.gadgetCall(p.getGadget());
    }

    @Parameters(count=4)
    public void dispatchRegistry()
    {
        String regMethod = p.validateRegMethod();
        boolean localhostBypass = (boolean)p.get("localhost-bypass");

        RegistryClient reg = new RegistryClient(rmi);
        reg.gadgetCall(p.getGadget(), regMethod, localhostBypass);
    }

    @Parameters(count=4)
    public void dispatchDGC()
    {
        String dgcMethod = p.validateDgcMethod();

        DGCClient dgc = new DGCClient(rmi);
        dgc.gadgetCall(dgcMethod, p.getGadget());
    }

    @Parameters(count=3, requires= {"bound-name|objid","signature"})
    public void dispatchMethod()
    {
        int argumentPosition = (int)p.get("argument-position");

        RemoteObjectClient client = getRemoteObjectClient((String)p.get("bound-name"));
        client.gadgetCall(candidate, p.getGadget(), argumentPosition);
    }

    @Parameters(count=3, requires= {"bound-name|objid","signature"})
    public void dispatchCall()
    {
        Object[] argumentArray = p.getCallArguments();

        RemoteObjectClient client = getRemoteObjectClient((String)p.get("bound-name"));
        client.genericCall(candidate, argumentArray);
    }

    @SuppressWarnings("deprecation")
    @Parameters(count=4, requires= {"signature"})
    public void dispatchCodebase()
    {
        String className = p.getPositionalString(3);
        RMGUtils.setCodebase(p.getPositionalString(4));

        String signature = (String)p.get("signature");
        int argumentPosition = (int)p.get("argument-position");

        Object payload = null;

        try {
            payload = RMGUtils.makeSerializableClass(className);
            payload = ((Class<?>)payload).newInstance();

        } catch (CannotCompileException | InstantiationException | IllegalAccessException e) {
            ExceptionHandler.unexpectedException(e, "payload", "creation", true);
        }

        if( candidate != null ) {
            String boundName = (String)p.get("bound-name");

            if( boundName == null ) {
                ExceptionHandler.missingBoundName("codebase");
            }

            RemoteObjectClient client = getRemoteObjectClient(boundName);
            client.codebaseCall(candidate, payload, argumentPosition);

        } else if( signature.matches("dgc") ) {

            DGCClient dgc = new DGCClient(rmi);
            dgc.codebaseCall((String)p.get("dgc-method"), payload);

        } else if( signature.matches("reg") ) {
            RegistryClient reg = new RegistryClient(rmi);
            reg.codebaseCall(payload, (String)p.get("reg-method"), (boolean)p.get("localhost-bypass"));

        } else if( signature.matches("act") ) {
            ActivationClient act = new ActivationClient(rmi);
            act.codebaseCall(payload);

        } else {
            ExceptionHandler.internalError("dispatchCodebase", "Unknown signature value " + signature + " was passed.");
        }
    }

    @Parameters(count=4, requires= {"bound-name"})
    public void dispatchBind()
    {
        String boundName = (String)p.get("bound-name");

        RegistryClient reg = new RegistryClient(rmi);
        reg.bindObject(boundName, p.getGadget(), (boolean)p.get("localhost-bypass"));
    }

    @Parameters(count=4, requires= {"bound-name"})
    public void dispatchRebind()
    {
        String boundName = (String)p.get("bound-name");

        RegistryClient reg = new RegistryClient(rmi);
        reg.rebindObject(boundName, p.getGadget(), (boolean)p.get("localhost-bypass"));
    }

    @Parameters(requires= {"bound-name"})
    public void dispatchUnbind()
    {
        String boundName = (String)p.get("bound-name");

        RegistryClient reg = new RegistryClient(rmi);
        reg.unbindObject(boundName, (boolean)p.get("localhost-bypass"));
    }

    public void dispatchEnum()
    {
        RMGUtils.enableCodebase();
        RegistryClient registryClient = new RegistryClient(rmi);

        String regMethod = p.validateRegMethod();
        String dgcMethod = p.validateDgcMethod();
        boolean localhostBypass = (boolean)p.get("localhost-bypass");

        boolean enumJEP290Bypass = true;
        boolean marshal = true;

        try {
            obtainBoundNames();

            Formatter format = new Formatter();
            format.listBoundNames(boundClasses);

            Logger.println("");
            format.listCodeases();

            Logger.println("");
            marshal = registryClient.enumerateStringMarshalling();

            Logger.println("");
            registryClient.enumCodebase(marshal, regMethod, localhostBypass);

            Logger.println("");
            registryClient.enumLocalhostBypass();

        } catch( java.rmi.NoSuchObjectException e ) {
            ExceptionHandler.noSuchObjectExceptionRegistryEnum();
            enumJEP290Bypass = false;
        }

        Logger.println("");
        DGCClient dgc = new DGCClient(rmi);
        dgc.enumDGC(dgcMethod);

        Logger.println("");
        dgc.enumJEP290(dgcMethod);

        if(enumJEP290Bypass) {
            Logger.println("");
            registryClient.enumJEP290Bypass(regMethod, localhostBypass, marshal);
        }

        Logger.println("");
        ActivationClient activationClient = new ActivationClient(rmi);
        activationClient.enumActivator();
    }

    public void dispatchGuess()
    {
        boolean createSamples = (boolean)p.get("create-samples");

        int threadCount = (int)p.get("threads");
        boolean zeroArg = (boolean)p.get("zero-arg");
        Formatter format = new Formatter();

        HashSet<MethodCandidate> candidates = getCandidates();
        HashMap<String,ArrayList<MethodCandidate>> results = new HashMap<String,ArrayList<MethodCandidate>>();

        try {
            obtainBoundNames();
        } catch( java.rmi.NoSuchObjectException e ) {
            ExceptionHandler.noSuchObjectException(e, "registry", true);
        }

        MethodGuesser.printGuessingIntro(candidates);

        for(String boundName : this.boundNames) {

            RemoteObjectClient client = getRemoteObjectClient(boundName);
            MethodGuesser guesser = new MethodGuesser(client, candidates, threadCount, zeroArg);
            ArrayList<MethodCandidate> methods = guesser.guessMethods();

            results.put(boundName, methods);
        }

        Logger.decreaseIndent();

        RMGUtils.addKnownMethods(boundClasses.get(0), results);
        format.listGuessedMethods(results);

        if(createSamples)
            this.writeSamples(results);
    }
}
