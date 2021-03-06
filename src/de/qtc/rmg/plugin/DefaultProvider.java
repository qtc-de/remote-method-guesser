package de.qtc.rmg.plugin;

import java.lang.reflect.Method;

import de.qtc.rmg.internal.ExceptionHandler;
import de.qtc.rmg.io.Logger;
import de.qtc.rmg.operations.Operation;
import de.qtc.rmg.operations.RegistryClient;
import de.qtc.rmg.utils.RMGUtils;
import de.qtc.rmg.utils.YsoIntegration;
import javassist.CannotCompileException;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;
import javassist.CtNewMethod;

/**
 * The DefaultProvider is a default implementation of an rmg plugin. It implements the IArgumentProvider
 * and IPayloadProvider and is always loaded when no user specified plugin overwrites one of these interfaces.
 *
 * Within its IPayloadProvider override, it returns either a RMIServerImpl object as used by JMX (for bind, rebind
 * and unbin actions) or a ysoserial gadget (for basically all other actions). The IArgumentProvider override attempts
 * to evaluate the user specified argument string as Java code and attempts to create an Object array out of it that
 * is used for method calls.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class DefaultProvider implements IArgumentProvider, IPayloadProvider {

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
        switch(action) {

            case BIND:
            case REBIND:
            case UNBIND:

                if(name.equalsIgnoreCase("jmx")) {
                    String[] split = RMGUtils.splitListener(args);
                    return RegistryClient.prepareRMIServerImpl(split[0], Integer.valueOf(split[1]));

                } else if(args == null) {
                    String[] split = RMGUtils.splitListener(name);
                    return RegistryClient.prepareRMIServerImpl(split[0], Integer.valueOf(split[1]));

                } else {
                    Logger.eprintlnMixedYellow("The specified gadget", name, "is not supported for this action.");
                    RMGUtils.exit();
                }

                break;

            default:

                if(args == null) {
                    Logger.eprintlnMixedBlue("Specifying a", "gadget argument", "is required for this action.");
                    RMGUtils.exit();
                }

                return YsoIntegration.getPayloadObject(name, args);
        }

        return null;
    }

    /**
     * This function performs basically an eval operation on the user specified argumentString. The argument string is
     * inserted into the following expression: return new Object[] { " + argumentString + "};
     * This expression is evaluated and the resulting Object array is returned by this function. For this to work it is
     * important that all arguments within the argumentString are valid Java Object definitions. E.g. one has to use
     * new Integer(5) instead of a plain 5.
     */
    @Override
    public Object[] getArgumentArray(String argumentString)
    {
        Object[] result = null;
        ClassPool pool = ClassPool.getDefault();

        try {
            CtClass evaluator = pool.makeClass("de.qtc.rmg.plugin.DefaultProviderEval");
            String evalFunction = "public static Object[] eval() {"
                                + "        return new Object[] { " + argumentString + "};"
                                + "}";

            CtMethod me = CtNewMethod.make(evalFunction, evaluator);
            evaluator.addMethod(me);
            Class<?> evalClass = evaluator.toClass();

            Method m = evalClass.getDeclaredMethods()[0];
            result = (Object[]) m.invoke(evalClass, (Object[])null);

        } catch(VerifyError | CannotCompileException e) {
            Logger.eprintlnMixedYellow("Specified argument string", argumentString, "is invalid.");
            Logger.eprintlnMixedBlue("Argument string has to be a valid Java expression like:", "'\"id\", new Integer(4)'.");
            Logger.eprintMixedYellow("Make sure that each argument is an", "Object", "not a ");
            Logger.printlnPlainYellow("Primitive.");
            RMGUtils.exit();

        } catch (Exception e) {
            ExceptionHandler.unexpectedException(e, "argument array", "generation", true);
        }

        return result;
    }
}
