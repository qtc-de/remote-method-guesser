package de.qtc.rmg;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.rmi.Remote;
import java.rmi.server.RemoteObject;
import java.rmi.server.RemoteObjectInvocationHandler;
import java.rmi.server.RemoteRef;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import de.qtc.rmg.internal.MethodCandidate;
import de.qtc.rmg.io.Logger;
import de.qtc.rmg.utils.RMGUtils;
import de.qtc.rmg.utils.RMIWhisperer;
import javassist.CannotCompileException;

public class MethodGuesser {

    private RMIWhisperer rmi;
    private HashMap<String,String> classes;
    private List<MethodCandidate> candidates;;

    private Field proxyField;
    private Field remoteField;

    public MethodGuesser(RMIWhisperer rmiRegistry, HashMap<String,String> unknownClasses, List<MethodCandidate> candidates) {
        this.rmi = rmiRegistry;
        this.classes = unknownClasses;
        this.candidates = candidates;

        try {
            this.proxyField = Proxy.class.getDeclaredField("h");
            this.remoteField = RemoteObject.class.getDeclaredField("ref");
            proxyField.setAccessible(true);
            remoteField.setAccessible(true);

        } catch(NoSuchFieldException | SecurityException e) {
            Logger.eprintlnMixedYellow("Unexpected Exception caught during MethodGuesser instantiation:", e.getMessage());
            Logger.eprintln("Cannot continue from here");
            System.exit(1);
        }
    }

    public HashMap<String,ArrayList<MethodCandidate>> guessMethods(int threads, boolean writeSamples) {
        return this.guessMethods(null, threads, writeSamples);
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    public HashMap<String,ArrayList<MethodCandidate>> guessMethods(String targetName, int threads, boolean writeSamples) {

        HashMap<String,ArrayList<MethodCandidate>> results = new HashMap<String,ArrayList<MethodCandidate>>();
        Logger.println("\n[+] Starting RMG Attack");
        Logger.increaseIndent();


        Logger.printlnMixedYellow("Guessing", String.valueOf(this.candidates.size()), "methods on each bound name.");

        Iterator<Entry<String, String>> it = this.classes.entrySet().iterator();
        while (it.hasNext()) {

            Map.Entry pair = (Map.Entry)it.next();
            String boundName = (String) pair.getKey();
            String className = (String) pair.getValue();

            if( targetName != null && !targetName.equals(boundName) ) {
                continue;
            }

            Logger.increaseIndent();
            Logger.printlnMixedBlue("Attacking boundName", boundName, ".");

            Remote instance = null;
            Class remoteClass = null;

            try {
                remoteClass = RMGUtils.makeInterface(className);
            } catch(CannotCompileException e) {
                Logger.eprintlnMixedYellow("Caught", "CannotCompileException", "during interface creation.");
                Logger.eprintlnMixedYellow("Exception message:", e.getMessage());
                Logger.decreaseIndent();
                continue;
            }

            RemoteRef remoteRef = null;
            try {
                instance = rmi.getRegistry().lookup(boundName);

                RemoteObjectInvocationHandler ref = (RemoteObjectInvocationHandler)proxyField.get(instance);
                remoteRef = ref.getRef();

            } catch( Exception e ) {
                Logger.eprintlnMixedYellow("Error: Unable to get instance for", boundName, ".");
                Logger.eprintlnMixedYellow("The following exception was caught:", e.getMessage());
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
                e.printStackTrace();
            }

            ExecutorService pool = Executors.newFixedThreadPool(threads);
            for( MethodCandidate method : this.candidates ) {
                Runnable r;
                if( method.isPrimitive() ) {
                    r = new Threader(rmgInvokeObject, instance, remoteRef, existingMethods, method);
                } else {
                    r = new Threader(rmgInvokePrimitive, instance, remoteRef, existingMethods, method);
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
        return results;
    }
}

class Threader implements Runnable {

    private Method method;
    private RemoteRef instance;
    private Remote remote;
    private MethodCandidate candidate;
    private ArrayList<MethodCandidate> existingMethods;

    public Threader(Method method, Remote remote, RemoteRef instance, ArrayList<MethodCandidate> existingMethods, MethodCandidate candidate) {
        this.method = method;
        this.instance = instance;
        this.existingMethods = existingMethods;
        this.candidate = candidate;
    }

    public void run() {

        try {

            instance.invoke(remote, method, candidate.getConfusedArgument(), candidate.getHash());

        } catch( java.rmi.ServerException e ) {

            Throwable cause = getCause(e);
            if( cause != null ) {

                if( cause instanceof java.rmi.UnmarshalException) {
                    /*
                     * This server-exception is thrown when the supplied method hash does not match any
                     * remote method. Therefore, we just continue from here.
                     */
                    return;

                } else if( cause instanceof java.rmi.UnknownHostException  ) {
                    Logger.eprintln("Warning! Object tries to connect to unknown host: " + cause.getCause().getMessage());
                    return;

                } else if( cause instanceof java.rmi.ConnectException  ) {
                    Logger.eprintln((cause.getMessage().split(";"))[0]);
                    return;
                }
            }

        } catch (java.rmi.UnmarshalException e) {
            /*
             * This occurs on invocation of methods taking zero arguments. Since the call always succeeds,
             * the remote method returns some value that probably not matches the expected return value of
             * the lookup method.
             */
            return;

        } catch (Exception e) {
            Logger.eprintlnMixedBlue("Caught unexpected exception while guessing:", e.getMessage());
            Logger.eprintln("StackTrace:");
            e.printStackTrace();
        }

        /*
         * Successfully guessed methods cause either an EOFException (object passed instead of primitive
         * or two few arguments) or an OptionalDataException (primitive passed for instead of object). As
         * these exceptions are not caught, we end up here.
         */
        Logger.printlnMixedYellow("HIT! Method with signature", candidate.getSignature(), "exists!");
        existingMethods.add(candidate);
    }

    private Throwable getCause(Throwable e) {
        Throwable cause = null;
        Throwable result = e;

        while(null != (cause = result.getCause())  && (result != cause) ) {
            result = cause;
        }
        return result;
    }
}
