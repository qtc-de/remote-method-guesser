package de.qtc.rmg.utils;

import org.springframework.remoting.support.RemoteInvocation;

import de.qtc.rmg.internal.ExceptionHandler;
import de.qtc.rmg.internal.MethodCandidate;
import de.qtc.rmg.internal.RMGOption;
import javassist.CannotCompileException;
import javassist.CtClass;
import javassist.NotFoundException;

/**
 * SpringRemoting represents a wrapper around regular Java RMI. Exposed methods are not directly available via
 * RemoteObjects, but are invoked using a dispatcher object that supports an invoke method. This class contains
 * functions to convert an ordinary RMI method call into a SpringRemoting call.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class SpringRemoting
{
    public final static String invocationHandlerClass = "org.springframework.remoting.rmi.RmiInvocationHandler";
    public final static String methodGetStr = "java.lang.String getTargetInterfaceName()";
    public final static String methodInvokeStr = "java.lang.Object invoke(org.springframework.remoting.support.RemoteInvocation invo)";

    private static MethodCandidate methodGet;
    private static MethodCandidate methodInvoke;

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

    public static boolean isRemotingCall(RemoteObjectWrapper remoteObject, MethodCandidate targetMethod)
    {
        if (RMGOption.SPRING_REMOTING.getBool())
        {
            return true;
        }

        if (remoteObject == null || !remoteObject.className.equals(invocationHandlerClass))
        {
            return false;
        }

        long targetHash = targetMethod.getHash();

        if (targetHash == getInvokeMethod().getHash() || targetHash == getInterfaceNameMethod().getHash())
        {
            return false;
        }

        return true;
    }

    public static RemoteInvocation buildRemoteInvocation(MethodCandidate targetMethod, Object[] args)
    {
        RemoteInvocation invo = new RemoteInvocation();

        try
        {
            String methodName = targetMethod.getName();
            CtClass[] argTypes = targetMethod.getParameterTypes();

            invo.setMethodName(methodName);
            Class<?>[] parameterTypes = new Class<?>[args.length];

            try
            {
                for (int ctr = 0; ctr < args.length; ctr++)
                {
                    Class<?> cls = Class.forName(argTypes[ctr].getName());
                    parameterTypes[ctr] = cls;
                }
            }

            catch (ClassNotFoundException e)
            {
                ExceptionHandler.internalError("SpringRemoting.buildRemoteInvocation", e.getMessage());
            }

            invo.setArguments(args);
            invo.setParameterTypes(parameterTypes);
        }

        catch (CannotCompileException | NotFoundException e)
        {
            ExceptionHandler.cannotCompile(e, "while building", "Spring RemoteInvocation", true);
        }

        return invo;
    }
}
