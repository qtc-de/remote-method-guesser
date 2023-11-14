package de.qtc.rmg.utils;

import java.rmi.Remote;
import java.util.HashSet;
import java.util.Set;

import org.springframework.remoting.support.RemoteInvocation;

import de.qtc.rmg.endpoints.KnownEndpointHolder;
import de.qtc.rmg.internal.ExceptionHandler;
import de.qtc.rmg.internal.MethodCandidate;
import de.qtc.rmg.operations.RemoteObjectClient;
import de.qtc.rmg.plugin.IResponseHandler;
import de.qtc.rmg.plugin.PluginSystem;
import de.qtc.rmg.plugin.ReturnValueProvider;
import javassist.CannotCompileException;
import javassist.CtClass;
import javassist.NotFoundException;
import sun.rmi.server.UnicastRef;

/**
 * SpringRemoting represents a wrapper around regular Java RMI. Exposed methods are not directly available via
 * RemoteObjects, but are invoked using a dispatcher object that supports an invoke method. This class contains
 * functions to convert an ordinary RMI method call into a SpringRemoting call.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
@SuppressWarnings("restriction")
public class SpringRemotingWrapper extends UnicastWrapper
{
    public final static String invocationHandlerClass = "org.springframework.remoting.rmi.RmiInvocationHandler";
    public final static String methodGetStr = "java.lang.String getTargetInterfaceName()";
    public final static String methodInvokeStr = "java.lang.Object invoke(org.springframework.remoting.support.RemoteInvocation invo)";

    private static MethodCandidate methodGet;
    private static MethodCandidate methodInvoke;

    private static String remotingInterfaceName;

    /**
     * Within it's constructor, SpringRemotingWrapper already sends an RMI call to the server using the getTargetInterfaceName method.
     * This is required to tell remote-method-guesser what the underlying interface class is. This information is displayed within the
     * enum output and used for identifying potentialy known endpoints.
     *
     * @param remoteObject  the spring remoting remoteObject obtained from the registry
     * @param boundName     the boundName that is associated with the remoteObject
     * @param ref  a UnicastRef that can be used to call methods on the remoteObject
     */
    public SpringRemotingWrapper(Remote remoteObject, String boundName, UnicastRef ref) throws IllegalArgumentException, IllegalAccessException, NoSuchFieldException, SecurityException
    {
        super(remoteObject, boundName, ref);

        ReturnValueProvider respHandler = new ReturnValueProvider();
        IResponseHandler cachedHandler = PluginSystem.getResponseHandler();
        PluginSystem.setResponeHandler(respHandler);

        RemoteObjectClient client = new RemoteObjectClient(this);
        client.genericCall(getInterfaceNameMethod(), new Object[] {});

        remotingInterfaceName = (String)respHandler.getValue();
        knownEndpoint = KnownEndpointHolder.getHolder().lookup(remotingInterfaceName);

        PluginSystem.setResponeHandler(cachedHandler);
    }

    /**
     * Return a MethodCandidate for the getTargetInterfaceName method that is exposed by the RmiInvocationHandler
     * remote object.
     *
     * @return method candidate for the getTargetInterfaceName method
     */
    public static MethodCandidate getInterfaceNameMethod()
    {
        if (methodGet == null)
        {
            try
            {
                methodGet = new MethodCandidate(methodGetStr);
            }

            catch (CannotCompileException | NotFoundException e)
            {
                ExceptionHandler.internalError("SpringRemoting.getInterfaceMethod", e.getMessage());
            }
        }

        return methodGet;
    }

    /**
     * Return a MethodCandidate for the invoke method that is exposed by the RmiInvocationHandler
     * remote object.
     *
     * @return method candidate for the invoke method
     */
    public static MethodCandidate getInvokeMethod()
    {
        if (methodInvoke == null)
        {
            try
            {
                methodInvoke = new MethodCandidate(methodInvokeStr);
            }

            catch (CannotCompileException | NotFoundException e)
            {
                ExceptionHandler.internalError("SpringRemoting.getInterfaceMethod", e.getMessage());
            }
        }

        return methodInvoke;
    }

    /**
     * Determines whether the method to call is a known spring remoting method, that needs to be processed by the
     * remoting wrapper itself, or whether it is an RMI method implemented by the underlying object.
     *
     * @return true if the method needs to be dispatched using spring remoting
     */
    public boolean isRemotingCall(MethodCandidate targetMethod)
    {
        long targetHash = targetMethod.getHash();

        if (targetHash == getInvokeMethod().getHash() || targetHash == getInterfaceNameMethod().getHash())
        {
            return false;
        }

        return true;
    }

    /**
     * Return the interface name of the underlying interface class that can be accessed via spring remoting.
     *
     * @return interface name implemented by the underlying remote object
     */
    public String getInterfaceName()
    {
        return remotingInterfaceName;
    }

    /**
     * Prepare a RemoteInvocation object from a MethodCandidate and the user specified arguments. The resulting
     * object can be passed to the spring remoting endpoint in order to call the specified MethodCandidate.
     *
     * @param targetMethod    method that should be called via spring remoting
     * @param args  arguments that should be used for the call
     * @return RemoteInvocation that can be passed to the spring remoting server
     */
    public static RemoteInvocation buildRemoteInvocation(MethodCandidate targetMethod, Object[] args)
    {
        RemoteInvocation invo = new RemoteInvocation();

        try
        {
            CtClass[] argTypes = targetMethod.getParameterTypes();
            Class<?>[] parameterTypes = new Class<?>[argTypes.length];

            try
            {
                for (int ctr = 0; ctr < argTypes.length; ctr++)
                {
                    parameterTypes[ctr] = RMGUtils.ctClassToClass(argTypes[ctr]);
                }
            }

            catch (ClassNotFoundException e)
            {
                ExceptionHandler.internalError("SpringRemoting.buildRemoteInvocation", e.getMessage());
            }

            String methodName = targetMethod.getName();

            invo.setMethodName(methodName);
            invo.setArguments(args);
            invo.setParameterTypes(parameterTypes);
        }

        catch (CannotCompileException | NotFoundException e)
        {
            ExceptionHandler.cannotCompile(e, "while building", "Spring RemoteInvocation", true);
        }

        return invo;
    }

    /**
     * Transform a set of MethodCandidate to a set of RemoteInvocationHolders.
     *
     * @param candidates v set of MethodCandidate to transform
     * @return set of RemoteInvocationHolders
     */
    public static Set<RemoteInvocationHolder> getInvocationHolders(Set<MethodCandidate> candidates)
    {
        Set<RemoteInvocationHolder> invocationHolderSet = new HashSet<RemoteInvocationHolder>();

        for (MethodCandidate candidate : candidates)
        {
            Object[] args = new Object[] {};

            if (candidate.getArgumentCount() == 0)
            {
                args = new Object[] {1};
            }

            RemoteInvocationHolder invoHolder = new RemoteInvocationHolder(buildRemoteInvocation(candidate, args), candidate);
            invocationHolderSet.add(invoHolder);
        }

        return invocationHolderSet;
    }

    /**
     * Returns a method signature for the specified MethodCandidate that lacks the return value. The
     * return value is replaced with three question marks. The reason is that spring remoting treats
     * similar methods with different return values the same. Therefore, it is not possible to determine
     * the return value of a successfully guessed method.
     *
     * @param method  MethodCandidate to obtain the modified signature from
     * @return modified signature without a return value
     */
    public static String getSignature(MethodCandidate method)
    {
        String signature = method.getSignature();

        return "???" + signature.substring(signature.indexOf(' '));
    }

    /**
     * Helper function that checks whether a list of UnicastWrapper objects contains a SpringRemotingWrapper
     * (which is a child class of UnicastWrapper).
     *
     * @param wrappers  list of UnicastWrapper objects
     * @return true if at least one SpringRemotingWrapper is contained within the list
     */
    public static boolean containsSpringRemotingClient(UnicastWrapper[] wrappers)
    {
        for (UnicastWrapper wrapper : wrappers)
        {
            if (wrapper instanceof SpringRemotingWrapper)
            {
                return true;
            }
        }

        return false;
    }
}
