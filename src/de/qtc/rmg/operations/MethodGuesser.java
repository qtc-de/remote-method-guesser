package de.qtc.rmg.operations;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.rmi.Remote;
import java.rmi.server.RemoteObject;
import java.rmi.server.RemoteObjectInvocationHandler;
import java.rmi.server.RemoteRef;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import de.qtc.rmg.internal.GuessingWorker;
import de.qtc.rmg.internal.MethodCandidate;
import de.qtc.rmg.io.Logger;
import de.qtc.rmg.utils.RMGUtils;
import de.qtc.rmg.utils.RMIWhisperer;
import javassist.CannotCompileException;

public class MethodGuesser {

    private RMIWhisperer rmi;
    private HashMap<String,String> classes;
    private HashSet<MethodCandidate> candidates;

    private Field proxyField;
    private Field remoteField;

    public MethodGuesser(RMIWhisperer rmiRegistry, HashMap<String,String> unknownClasses, HashSet<MethodCandidate> candidates)
    {
        this.rmi = rmiRegistry;
        this.classes = unknownClasses;
        this.candidates = candidates;

        try {
            this.proxyField = Proxy.class.getDeclaredField("h");
            this.remoteField = RemoteObject.class.getDeclaredField("ref");
            proxyField.setAccessible(true);
            remoteField.setAccessible(true);

        } catch(NoSuchFieldException | SecurityException e) {
            Logger.eprintlnMixedYellow("Unexpected Exception caught during", "MethodGuesser", "instantiation.");
            RMGUtils.stackTrace(e);
            RMGUtils.exit();
        }
    }

    public HashMap<String,ArrayList<MethodCandidate>> guessMethods(int threads, boolean writeSamples, boolean zeroArg)
    {
        return this.guessMethods(null, threads, writeSamples, zeroArg, 0);
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    public HashMap<String,ArrayList<MethodCandidate>> guessMethods(String targetName, int threads, boolean writeSamples, boolean zeroArg, int legacyMode)
    {
        HashMap<String,ArrayList<MethodCandidate>> results = new HashMap<String,ArrayList<MethodCandidate>>();

        int count = this.candidates.size();
        if( count == 0 ) {
            Logger.eprintlnMixedYellow("List of candidate methods contains", "0", "elements.");
            Logger.eprintln("No guessing required.");
            return results;
        }

        Logger.println("\n[+] Starting RMG Attack");
        Logger.increaseIndent();

        if( targetName != null )
            Logger.printlnMixedBlue("Target name specified. Only guessing on bound name:", targetName);
        else
            Logger.printlnMixedBlue("No target name specified. Guessing on", "all", "available bound names.");

        Logger.printlnMixedYellow("Guessing", String.valueOf(count), "method signature(s).");
        if( count == 1 ) {
            Logger.printlnMixedBlue("Method signature:", ((MethodCandidate)candidates.toArray()[0]).getSignature());
        }
        Logger.println("");

        Iterator<Entry<String, String>> it = this.classes.entrySet().iterator();
        while (it.hasNext()) {

            Map.Entry pair = (Map.Entry)it.next();
            String boundName = (String)pair.getKey();
            String className = (String)pair.getValue();

            if( targetName != null && !targetName.equals(boundName) ) {
                Logger.printlnMixedBlue("Skipping bound name", boundName);
                continue;
            }

            Logger.printlnMixedYellow("Current bound name:", boundName);
            boolean isLegacy = RMGUtils.isLegacy(className, legacyMode, true);
            Logger.increaseIndent();

            Remote instance = null;
            Class remoteClass = null;

            try {

                if( !isLegacy )
                    remoteClass = RMGUtils.makeInterface(className);

                else
                    remoteClass = RMGUtils.makeLegacyStub(className);

            } catch(CannotCompileException e) {
                Logger.eprintlnMixedYellow("Caught", "CannotCompileException", "during interface creation.");
                Logger.eprintlnMixedYellow("Exception message:", e.getMessage());
                RMGUtils.showStackTrace(e);
                Logger.decreaseIndent();
                continue;
            }

            RemoteRef remoteRef = null;
            try {
                instance = rmi.getRegistry().lookup(boundName);

                if( !isLegacy ) {
                    RemoteObjectInvocationHandler ref = (RemoteObjectInvocationHandler)proxyField.get(instance);
                    remoteRef = ref.getRef();
                } else {
                    remoteRef = (RemoteRef)remoteField.get(instance);
                }

            } catch( Exception e ) {
                Logger.eprintlnMixedYellow("Error: Unable to get instance for", boundName, ".");
                Logger.eprintlnMixedYellow("The following exception was caught:", e.getMessage());
                RMGUtils.showStackTrace(e);
                Logger.decreaseIndent();
                continue;
            }

            Logger.println("Guessing methods...\n[+]");
            Logger.increaseIndent();

            Method rmgInvokeObject = null;
            Method rmgInvokePrimitive = null;
            ArrayList<MethodCandidate> existingMethods = new ArrayList<MethodCandidate>();

            try {
                rmgInvokeObject = remoteClass.getMethod("rmgInvokeObject", String.class);
                rmgInvokePrimitive = remoteClass.getMethod("rmgInvokePrimitive", int.class);
            } catch (NoSuchMethodException | SecurityException e) {
                Logger.eprintlnMixedYellow("Caught unexpected", e.getClass().getName(), "during method lookup.");
                Logger.println("Please report this to improve rmg :)");
                RMGUtils.stackTrace(e);
                RMGUtils.exit();
            }

            ExecutorService pool = Executors.newFixedThreadPool(threads);
            for( MethodCandidate method : this.candidates ) {

                Runnable r;
                if( method.isVoid() && !zeroArg ) {
                    Logger.printlnMixedBlue("Skipping zero arguments method:", method.getSignature());
                    continue;
                }

                if( method.isPrimitive() ) {
                    r = new GuessingWorker(rmgInvokeObject, instance, remoteRef, existingMethods, method);
                } else {
                    r = new GuessingWorker(rmgInvokePrimitive, instance, remoteRef, existingMethods, method);
                }

                pool.execute(r);
            }

            pool.shutdown();

            try {
                 pool.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);
            } catch (InterruptedException e) {
                 Logger.eprintln("Interrupted!");
            }

            Logger.decreaseIndent();
            Logger.println("");

            if( results.containsKey(boundName) ) {
                ArrayList<MethodCandidate> tmp = results.get(boundName);
                tmp.addAll(existingMethods);
            } else {
                results.put(boundName, existingMethods);
            }

            Logger.decreaseIndent();
        }

        Logger.decreaseIndent();
        return results;
    }
}
