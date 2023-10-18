package de.qtc.rmg.utils;

import java.rmi.Remote;
import java.util.HashSet;
import java.util.Set;

import org.springframework.remoting.support.RemoteInvocation;

import de.qtc.rmg.endpoints.KnownEndpointHolder;
import de.qtc.rmg.internal.ExceptionHandler;
import de.qtc.rmg.internal.MethodCandidate;
import de.qtc.rmg.operations.RemoteObjectClient;
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

    public SpringRemotingWrapper(Remote remoteObject, String boundName, UnicastRef ref) throws IllegalArgumentException, IllegalAccessException, NoSuchFieldException, SecurityException
    {
        super(remoteObject, boundName, ref);

        ReturnValueProvider respHandler = new ReturnValueProvider();
        PluginSystem.setResponeHandler(respHandler);

        RemoteObjectClient client = new RemoteObjectClient(this);
        client.genericCall(getInterfaceNameMethod(), new Object[] {});

        remotingInterfaceName = (String)respHandler.getValue();
        knownEndpoint = KnownEndpointHolder.getHolder().lookup(remotingInterfaceName);
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

    public boolean isRemotingCall(MethodCandidate targetMethod)
    {
        long targetHash = targetMethod.getHash();

        if (targetHash == getInvokeMethod().getHash() || targetHash == getInterfaceNameMethod().getHash())
        {
            return false;
        }

        return true;
    }

    public String getInterfaceName()
    {
        return remotingInterfaceName;
    }

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

    public static String getSignature(MethodCandidate method)
    {
        String signature = method.getSignature();

        return "???" + signature.substring(signature.indexOf(' '));
    }

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
