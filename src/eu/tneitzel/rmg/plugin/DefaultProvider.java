package eu.tneitzel.rmg.plugin;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.lang.reflect.Method;
import java.rmi.server.RMIClientSocketFactory;
import java.rmi.server.RMISocketFactory;

import eu.tneitzel.rmg.internal.ExceptionHandler;
import eu.tneitzel.rmg.internal.RMGOption;
import eu.tneitzel.rmg.io.Logger;
import eu.tneitzel.rmg.networking.DGCClientSocketFactory;
import eu.tneitzel.rmg.networking.LoopbackSocketFactory;
import eu.tneitzel.rmg.networking.SSRFResponseSocketFactory;
import eu.tneitzel.rmg.networking.SSRFSocketFactory;
import eu.tneitzel.rmg.networking.TrustAllSocketFactory;
import eu.tneitzel.rmg.operations.Operation;
import eu.tneitzel.rmg.operations.RegistryClient;
import eu.tneitzel.rmg.utils.RMGUtils;
import eu.tneitzel.rmg.utils.YsoIntegration;
import javassist.CannotCompileException;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;
import javassist.CtNewMethod;
import javassist.CtPrimitiveType;

/**
 * The DefaultProvider is a default implementation of an rmg plugin. It implements the IArgumentProvider,
 * IPayloadProvider and ISocketFactoryProvider interfaces and is always loaded when no user specified
 * plugin overwrites one of these interfaces.
 *
 * Within its IPayloadProvider override, it returns either a RMIServerImpl object as used by JMX (for bind, rebind
 * and unbind actions) or a ysoserial gadget (for basically all other actions). The IArgumentProvider override attempts
 * to evaluate the user specified argument string as Java code and attempts to create an Object array out of it that
 * is used for method calls. The ISocketFactoryProvider implementation returns remote-method-guesser's loopback
 * factories that prevent redirections from the server side.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class DefaultProvider implements IArgumentProvider, IPayloadProvider, ISocketFactoryProvider, IRmiMarshalProvider
{
    /**
     * Return an RMIServerImpl object as used by JMX endpoints when invoked from the bind, rebind or unbind
     * actions. In this case, name is expected to be 'jmx' or args is expected to be null. When the name is
     * 'jmx', the args parameter is expected to contain the address definition for the remote object (host:port).
     * Otherwise, if args is null and the name is not 'jmx', name is expected to contain the listener definition.
     * This allows to perform the bind like 'rmg 127.0.0.1 9010 bind jmx 127.0.0.1:4444' or like
     * 'rmg 127.0.0.1 9010 bind 127.0.0.1:4444'.
     *
     * Otherwise, pass the user specified gadget name and gadget arguments to ysoserial and return the
     * corresponding gadget.
     */
    @Override
    public Object getPayloadObject(Operation action, String name, String args)
    {
        switch(action)
        {
            case BIND:
            case REBIND:
            case UNBIND:

                if (name.equalsIgnoreCase("jmx"))
                {
                    String[] split = RMGUtils.splitListener(args);
                    return RegistryClient.prepareRMIServerImpl(split[0], Integer.valueOf(split[1]));
                }

                else if (args == null)
                {
                    String[] split = RMGUtils.splitListener(name);
                    return RegistryClient.prepareRMIServerImpl(split[0], Integer.valueOf(split[1]));
                }

                else
                {
                    Logger.eprintlnMixedYellow("The specified gadget", name, "is not supported for this action.");
                    RMGUtils.exit();
                }

                break;

            default:

                if (args == null)
                {
                    Logger.eprintlnMixedBlue("Specifying a", "gadget argument", "is required for this action.");
                    RMGUtils.exit();
                }

                return YsoIntegration.getPayloadObject(name, args);
        }

        return null;
    }

    /**
     * This function performs basically an eval operation on the user specified arguments. The argument string is
     * inserted into the following expression: return new Object[] { arg1, arg2, arg3, ... };
     * This expression is evaluated and the resulting Object array is returned by this function. For this to work it is
     * important that all arguments within the argumentString are valid Java Object definitions. E.g. one has to use
     * new Integer(5) instead of a plain 5.
     */
    @Override
    public Object[] getArgumentArray(String[] args)
    {
        if (args.length == 0)
        {
            return new Object[] {};
        }

        Object[] result = null;
        ClassPool pool = ClassPool.getDefault();

        String argumentString = prepareArgumentString(args);
        StringBuilder evalFunction = new StringBuilder();

        evalFunction.append("public static Object[] eval() { return new Object[] {");
        evalFunction.append(argumentString);
        evalFunction.append("};}");

        try
        {
            CtClass evaluator = pool.makeClass("eu.tneitzel.rmg.plugin.DefaultProviderEval");


            CtMethod me = CtNewMethod.make(evalFunction.toString(), evaluator);
            evaluator.addMethod(me);
            Class<?> evalClass = evaluator.toClass();

            Method m = evalClass.getDeclaredMethods()[0];
            result = (Object[]) m.invoke(evalClass, (Object[])null);
        }

        catch(VerifyError | CannotCompileException e)
        {
            Logger.eprintlnMixedYellow("Specified argument string", argumentString, "is invalid.");
            Logger.eprintlnMixedBlue("Argument string has to be a valid Java expression like:", "'\"id\", new Integer(4)'.");
            Logger.eprintMixedYellow("Make sure that each argument is an", "Object", "not a ");
            Logger.printlnPlainYellow("Primitive.");
            ExceptionHandler.showStackTrace(e);
            RMGUtils.exit();
        }

        catch (Exception e)
        {
            ExceptionHandler.unexpectedException(e, "argument array", "generation", true);
        }

        return result;
    }

    /**
     * Returns an RMIClientSocketFactory according to the specified options on the command line.
     */
    @Override
    public RMIClientSocketFactory getClientSocketFactory(String host, int port)
    {
        if (RMGOption.SSRF.getBool())
        {
            return new SSRFSocketFactory();
        }

        else if (RMGOption.SSRFRESPONSE.notNull())
        {
            byte[] content = RMGUtils.hexToBytes(RMGOption.SSRFRESPONSE.getValue());
            return new SSRFResponseSocketFactory(content);
        }

        else if (RMGOption.CONN_SSL.getBool())
        {
            return new TrustAllSocketFactory();
        }

        else
        {
            return RMISocketFactory.getDefaultSocketFactory();
        }
    }

    /**
     * The default RMISocketFactory used by remote-method-guesser is the LoopbackSocketFactory, which
     * redirects all connection to the original target and thus prevents unwanted RMI redirections.
     *
     * This function is only used for 'managed' RMI calls that rely on an RMI registry. Remote objects that
     * are looked up from the RMI registry use the RMISocketFactory.getDefaultSocketFactory function to
     * obtain a SocketFactory. This factory is then used for explicit calls (method invocations) and for
     * implicit calls (DGC actions like clean or dirty). When contacting an RMI endpoint directly (by
     * using the RMIEndpoint class) we do not need to call this function as we specify a socket factory
     * already during the call. When using the RMI registry (RMIRegistryEndpoint class), it is required.
     * In this case, this function should be called and the result should be used within the
     * RMISocketFactory.setSocketFactory function.
     *
     * When the --ssrf-response option is used, we do neither perform any explicit calls nor we want
     * DGC actions to take place. For this purpose, we use a custom socket factory that ignores writes
     * of outgoing DGC requests and simulates incoming DGC responses.
     *
     * Notice, that the --ssrf option does not affect this function. This is because sockets created
     * by this function are only used for 'managed' RMI calls. SSRF calls in remote-method-guesser are
     * always unmanaged.
     */
    @Override
    public RMISocketFactory getDefaultSocketFactory(String host, int port)
    {
        if (RMGOption.SSRFRESPONSE.notNull())
        {
            return new DGCClientSocketFactory();
        }

        return new LoopbackSocketFactory();
    }

    /**
     * The default SSLRMISocketFactory used by remote-method-guesser is the LoopbackSslSocketFactory, which
     * redirects all connection to the original target and thus prevents unwanted RMI redirections.
     *
     * As in the case of plain TCP connections, we use different socket factory if --ssrf-response
     * was specified on the command line. Check the getDefaultSocketFactory function for more details.
     *
     * Notice, that the --ssrf option does not affect this function. This is because sockets created
     * by this function are only used for 'managed' RMI calls. SSRF calls in remote-method-guesser are
     * always unmanaged.
     */
    @Override
    public String getDefaultSSLSocketFactory(String host, int port)
    {
        if (RMGOption.SSRFRESPONSE.notNull())
        {
            return "eu.tneitzel.rmg.networking.DGCClientSslSocketFactory";
        }

        return "eu.tneitzel.rmg.networking.LoopbackSslSocketFactory";
    }

    /**
     * Transforms an array of string arguments to a representation that can be used within new Object[] {}.
     *
     * @param args user specified arguments
     * @return prepared argument string
     */
    private static String prepareArgumentString(String[] args)
    {
        StringBuilder argString = new StringBuilder();

        for (String arg : args)
        {
            argString.append(arg);
            argString.append(",");
        }

        argString.setLength(argString.length() - 1);

        return argString.toString();
    }

    /**
     * Marshals the specified object value to the corresponding type and writes it to the specified
     * output stream. This is basically a copy from the default RMI implementation of this function.
     * The type values are obtained by the method signature and the object values come from the argument
     * array.
     *
     * @param type data type to marshal to
     * @param value object to be marshaled
     * @param out output stream to marshal to
     * @throws IOException in case of a failing write operation to the stream
     */
    public void marshalValue(Class<?> type, Object value, ObjectOutput out) throws IOException
    {
        if (type.isPrimitive()) {
            if (type == int.class) {
                out.writeInt(((Integer) value).intValue());
            } else if (type == boolean.class) {
                out.writeBoolean(((Boolean) value).booleanValue());
            } else if (type == byte.class) {
                out.writeByte(((Byte) value).byteValue());
            } else if (type == char.class) {
                out.writeChar(((Character) value).charValue());
            } else if (type == short.class) {
                out.writeShort(((Short) value).shortValue());
            } else if (type == long.class) {
                out.writeLong(((Long) value).longValue());
            } else if (type == float.class) {
                out.writeFloat(((Float) value).floatValue());
            } else if (type == double.class) {
                out.writeDouble(((Double) value).doubleValue());
            } else {
                throw new Error("Unrecognized primitive type: " + type);
            }
        } else {
            out.writeObject(value);
        }
    }

	/**
     * Unmarshals an object from the specified ObjectInput according to the data type specified
     * in the type parameter. This is required to read the result of RMI calls, as different types
     * are written differently to the ObjectInput by the RMI server. The expected type is taken from
     * the return value of the method signature.
     *
     * @param type data type that is expected from the stream
     * @param in ObjectInput to read from.
     * @return unmarshalled object
     * @throws IOException if reading the ObjectInput fails
     * @throws ClassNotFoundException if the read in class is unknown.
     */
    public Object unmarshalValue(CtClass type, ObjectInput in) throws IOException, ClassNotFoundException
    {
        if (type.isPrimitive()) {
            if (type == CtPrimitiveType.intType) {
                return Integer.valueOf(in.readInt());
            } else if (type == CtPrimitiveType.booleanType) {
                return Boolean.valueOf(in.readBoolean());
            } else if (type == CtPrimitiveType.byteType) {
                return Byte.valueOf(in.readByte());
            } else if (type == CtPrimitiveType.charType) {
                return Character.valueOf(in.readChar());
            } else if (type == CtPrimitiveType.shortType) {
                return Short.valueOf(in.readShort());
            } else if (type == CtPrimitiveType.longType) {
                return Long.valueOf(in.readLong());
            } else if (type == CtPrimitiveType.floatType) {
                return Float.valueOf(in.readFloat());
            } else if (type == CtPrimitiveType.doubleType) {
                return Double.valueOf(in.readDouble());
            } else {
                throw new Error("Unrecognized primitive type: " + type);
            }
        } else {
            return in.readObject();
        }
    }
}
