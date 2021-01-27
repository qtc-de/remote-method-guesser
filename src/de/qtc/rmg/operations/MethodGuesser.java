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

import de.qtc.rmg.internal.ExceptionHandler;
import de.qtc.rmg.internal.GuessingWorker;
import de.qtc.rmg.internal.MethodCandidate;
import de.qtc.rmg.io.Logger;
import de.qtc.rmg.networking.RMIWhisperer;
import de.qtc.rmg.utils.RMGUtils;

/**
 * The method guesser is used to brute force available remote methods on a Java RMI endpoint. It
 * uses the regular Java RMI API to obtain a RemoteObject from the RMI registry, but then uses
 * low level Java RMI calls to enumerate valid methods.
 *
 * When a RMI client calls a remote method, it establishes a TCP connection to the remote endpoint
 * and sends (among others) the following information:
 *
 *         - The ObjID of the RemoteObject that should receive the call
 *         - A method hash, that identifies the remote method to be called
 *         - A collection of method arguments to be used for the call
 *
 * During method guessing, remote-method-guesser uses a wordlist of Java methods and computes their hash
 * values. The corresponding hashes are then sent to the server, together with an collection of argument types
 * that do NOT match the expected argument types by the actual remote method. If a remote method does not
 * exist, the server throws an exception complaining about an unknown hash value. On the other hand, if the
 * remote method exists, the server will complain about the mismatch of argument types.
 *
 * This allows to reliably detect remote methods without the risk of causing unwanted actions on the server
 * side by actually invoking them. The idea for such a guessing approach was not invented by remote-method-guesser,
 * but was, to the best of our knowledge first implemented by the rmi-scout project.
 *
 * The MethodGuesser class was one of the first operation classes in rmg and is therefore not fully optimized
 * to the currently available other utility classes. It may be restructured in future.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class MethodGuesser {

    private RMIWhisperer rmi;
    private HashMap<String,String> classes;
    private HashSet<MethodCandidate> candidates;

    private Field proxyField;
    private Field remoteField;

    /**
     * The MethodGuesser makes use of the official RMI API to obtain the RemoteObject from the RMI registry.
     * Afterwards, it needs access to the underlying UnicastRemoteRef to perform customized RMi calls. Depending
     * on the RMI version of the server (current proxy approach or legacy stub objects), this requires access to
     * a different field within the Proxy or RemoteObject class. Both fields are made accessible within the constructor
     * to make the actual guessing code more clean.
     *
     * @param rmiRegistry registry to perform lookup operations
     * @param unknownClasses list of unknown classes per bound name
     * @param candidates list of method candidates to guess
     */
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
            ExceptionHandler.stackTrace(e);
            RMGUtils.exit();
        }
    }

    /**
     * This lengthy function is used for method guessing. If targetName is not null, guessing is only performed on
     * the specified bound name, otherwise all bound names within the registry are targeted. The function starts of
     * with some initialization and then tries to determine the legacy status of the server. This status is required
     * to decide whether to create the remote classes as interface or stub classes on the client side. Within legacy
     * RMI, stub classes are required on the client side, but current RMI implementations only need an interface that
     * is assigned to a Proxy.
     *
     * Depending on the determined legacy status, an interface or legacy stub class is now created dynamically.
     * With the corresponding class now available on the class path, the RemoteObject can be looked up on the
     * registry. From the obtained object, the RemoteRef is then extracted by using reflection. With this remote
     * reference, customized RMI calls can now be dispatched.
     *
     * This low level RMI access is required to call methods with invalid argument types. During method guessing,
     * you want to call possibly existing remote methods with invalid argument types to prevent their actual execution.
     * When using ordinary RMI to make a call, Java would refuse to use anything other than the expected argument types,
     * as it would violate the interface or method definition. With low level RMI access, the call arguments can be
     * manually written to the OutputStream which allows to use arbitrary arguments for a call.
     *
     * To implement this confusion of argument types, the dynamically created classes for the RemoteObjects are
     * constructed with two (interface)methods. The first, rmgInvokeObject, expects a String as first parameter,
     * whereas the second, rmgInvokePrimitive, expects an int. Depending on the method signature that is currently
     * guessed, rmgInvokeObject or rmgInvokePrimitive is used for the call. If the method signature expects a
     * primitive as its first argument, rmgInvokeObject is used to cause the confusion. Otherwise, rmgInvokePrimitive
     * will be used. During the call, the methodHash of rmgInvokeObject or rmgInvokePrimitive is replaced by the
     * methodHash of the currently guessed method signature. This approach allows testing for arbitrary method signatures
     * without manually exchanging the call parameters.
     *
     * @param targetName bound name to target. If null, target all available bound names
     * @param threads number of threads to use for the operation
     * @param zeroArg whether or not to also guess zero argument methods (are really invoked)
     * @param legacyMode whether to enforce legacy stubs. 0 -> auto, 1 -> enforce legacy, 2 -> enforce normal
     * @return List of successfully guessed methods per bound name
     */
    @SuppressWarnings({ "rawtypes", "unchecked" })
    public HashMap<String,ArrayList<MethodCandidate>> guessMethods(String targetName, int threads, boolean zeroArg, int legacyMode)
    {
        HashMap<String,ArrayList<MethodCandidate>> results = new HashMap<String,ArrayList<MethodCandidate>>();

        int count = this.candidates.size();
        if( count == 0 ) {
            Logger.eprintlnMixedYellow("List of candidate methods contains", "0", "elements.");
            Logger.eprintln("No guessing required.");
            return results;
        }

        Logger.println("\n[+] Starting Method Guessing:");
        Logger.increaseIndent();

        if( targetName != null )
            Logger.printlnMixedBlue("Target name specified. Only guessing on bound name:", targetName + ".");
        else
            Logger.printlnMixedBlue("No target name specified. Guessing on", "all", "available bound names.");

        Logger.printlnMixedYellow("Guessing", String.valueOf(count), "method signature(s).");
        if( count == 1 ) {
            Logger.printlnMixedBlue("Method signature:", ((MethodCandidate)candidates.toArray()[0]).getSignature() + ".");
        }
        Logger.println("");

        Iterator<Entry<String, String>> it = this.classes.entrySet().iterator();
        while (it.hasNext()) {

            Map.Entry pair = (Map.Entry)it.next();
            String boundName = (String)pair.getKey();
            String className = (String)pair.getValue();

            if( targetName != null && !targetName.equals(boundName) ) {
                Logger.printlnMixedBlue("Skipping bound name", boundName + ".");
                continue;
            }

            Logger.printlnMixedYellow("Current bound name:", boundName + ".");
            boolean isLegacy = RMGUtils.isLegacy(className, legacyMode, true);
            Logger.increaseIndent();

            Remote instance = null;
            Class remoteClass = null;

            try {

                if( !isLegacy )
                    remoteClass = RMGUtils.makeInterface(className);

                else
                    remoteClass = RMGUtils.makeLegacyStub(className);

            } catch(Exception e) {
                ExceptionHandler.unexpectedException(e, "interface", "creation", false);
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
                ExceptionHandler.unexpectedException(e, "lookup", "operation", false);
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
                ExceptionHandler.stackTrace(e);
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
