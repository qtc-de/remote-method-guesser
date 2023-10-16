package de.qtc.rmg.utils;

import java.rmi.Remote;

import org.springframework.remoting.support.RemoteInvocation;

import de.qtc.rmg.endpoints.KnownEndpointHolder;
import de.qtc.rmg.internal.ExceptionHandler;
import de.qtc.rmg.internal.MethodCandidate;
import de.qtc.rmg.io.Logger;
import de.qtc.rmg.operations.RemoteObjectClient;
import de.qtc.rmg.plugin.PluginSystem;
import de.qtc.rmg.plugin.ReturnValueProvider;
import javassist.CannotCompileException;
import javassist.CtClass;
import javassist.CtPrimitiveType;
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

    public static RemoteInvocation buildRemoteInvocation(MethodCandidate targetMethod, Object[] args)
    {
        RemoteInvocation invo = new RemoteInvocation();

        try
        {
            String methodName = targetMethod.getName();
            invo.setMethodName(methodName);

            CtClass[] argTypes = targetMethod.getParameterTypes();
            Class<?>[] parameterTypes = new Class<?>[argTypes.length];

            try
            {
                for (int ctr = 0; ctr < argTypes.length; ctr++)
                {
                    if (argTypes[ctr].isPrimitive())
                    {
                        if (argTypes[ctr] == CtPrimitiveType.intType) {
                            parameterTypes[ctr] = int.class;
                        } else if (argTypes[ctr] == CtPrimitiveType.booleanType) {
                            parameterTypes[ctr] = boolean.class;
                        } else if (argTypes[ctr] == CtPrimitiveType.byteType) {
                            parameterTypes[ctr] = byte.class;
                        } else if (argTypes[ctr] == CtPrimitiveType.charType) {
                            parameterTypes[ctr] = char.class;
                        } else if (argTypes[ctr] == CtPrimitiveType.shortType) {
                            parameterTypes[ctr] = short.class;
                        } else if (argTypes[ctr] == CtPrimitiveType.longType) {
                            parameterTypes[ctr] = long.class;
                        } else if (argTypes[ctr] == CtPrimitiveType.floatType) {
                            parameterTypes[ctr] = float.class;
                        } else if (argTypes[ctr] == CtPrimitiveType.doubleType) {
                            parameterTypes[ctr] = double.class;
                        } else {
                            throw new Error("unrecognized primitive type: " + argTypes[ctr]);
                        }

                    }

                    else
                    {
                        String className = argTypes[ctr].getName();
                        className = className.replaceAll("\\[\\]", "");

                        if (argTypes[ctr].isArray())
                        {
                            className = "[L" + className + ";";
                        }

                        Logger.printlnYellow(className);
                        Class<?> cls = Class.forName(className);
                        parameterTypes[ctr] = cls;
                    }
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

    public String getInterfaceName()
    {
        return remotingInterfaceName;
    }
}
