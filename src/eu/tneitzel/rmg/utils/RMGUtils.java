package eu.tneitzel.rmg.utils;

import java.io.InvalidClassException;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.rmi.Remote;
import java.rmi.server.ObjID;
import java.rmi.server.RemoteObject;
import java.rmi.server.RemoteObjectInvocationHandler;
import java.rmi.server.RemoteRef;
import java.rmi.server.RemoteStub;
import java.rmi.server.UID;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import eu.tneitzel.rmg.internal.ExceptionHandler;
import eu.tneitzel.rmg.internal.MethodArguments;
import eu.tneitzel.rmg.internal.RMGOption;
import eu.tneitzel.rmg.internal.RMIComponent;
import eu.tneitzel.rmg.io.Logger;
import eu.tneitzel.rmg.io.MaliciousOutputStream;
import javassist.CannotCompileException;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtField;
import javassist.CtMethod;
import javassist.CtNewMethod;
import javassist.CtPrimitiveType;
import javassist.Modifier;
import javassist.NotFoundException;
import sun.rmi.server.UnicastRef;
import sun.rmi.server.UnicastServerRef;
import sun.rmi.transport.LiveRef;


/**
 * The RMGUtils class defines static helper functions that do not really fit into other categories.
 * Like it is always the case with such classes, it is quite overblown and may be separated in future.
 * Most of the functions in it are concerned about dynamic class creation via javassist. But over the
 * time many other utilities were included within this class.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
@SuppressWarnings({ "rawtypes", "deprecation", "restriction" })
public class RMGUtils
{
    private static ClassPool pool;
    private static CtClass dummyClass;
    private static CtClass remoteClass;
    private static CtClass serializable;
    private static CtClass remoteStubClass;
    private static Set<String> createdClasses;

    /**
     * The init function has to be called before the javassist library can be utilized via RMGUtils.
     * It initializes the class pool and creates CtClass objects for the Remote, RemoteStub and Serializable
     * classes. Furthermore, it creates a Dummy interface that is used for method creation. All this stuff
     * is stored within static variables and can be used by RMGUtils after initialization.
     */
    public static void init()
    {
        pool = ClassPool.getDefault();

        try
        {
            remoteClass = pool.getCtClass(Remote.class.getName());
            serializable = pool.getCtClass("java.io.Serializable");
            remoteStubClass = pool.getCtClass(RemoteStub.class.getName());
        }

        catch (NotFoundException e)
        {
            ExceptionHandler.internalError("RMGUtils.init", "Caught unexpected NotFoundException.");
        }

        dummyClass = pool.makeInterface("eu.tneitzel.rmg.Dummy");
        createdClasses = new HashSet<String>();
    }

    /**
     * Creates the specified class dynamically as an interface. The interfaces created by this function always
     * extend the Remote class and contain the rmgInvokeObject and rmgInvokePrimitive functions. These functions
     * are used during method guessing, as described in the MethodGuesser class documentation.
     *
     * If the specified class already exists, the class is resolved via Class.forName and is then just returned.
     * This case can occur when multiple bound names use the same RemoteObject class.
     *
     * @param className full qualified name of the class to create
     * @return created Class instance
     * @throws CannotCompileException can be thrown when e.g. the class name is invalid
     */
    public static Class makeInterface(String className) throws CannotCompileException
    {
        try {
            return Class.forName(className);
        } catch (ClassNotFoundException e) {}

        CtClass intf = pool.makeInterface(className, remoteClass);
        createdClasses.add(className);

        return intf.toClass();
    }

    /**
     * This function is basically like the makeInterface function, but for the legacy RMI stub mechanism. First,
     * it also creates an interface class that contains the methods rmgInvokeObject and rmgInvokePrimitive. However,
     * the interface class is not created with the actual specified class name, but with the name 'className + "Interface"'.
     * The actual specified class name is then created as a regular class that extends the RemoteStub class. Furthermore,
     * this class is configured to implement the previously created interface.
     *
     * Interestingly, it is not required to provide implementations for the interface methods when using javassist. However,
     * what needs to be done is adding a serialVersionUID that allows deserialization of the RMI RemoteStubs. In previous
     * versions of remote-method-guesser, this value was set to 2L per default, as this is also the default value when legacy
     * RMI stubs are compiled via rmic. However, edge cases were observed where legacy RMI stubs were compiled with a different
     * serialVersionUID, which caused exceptions in remote-method-guesser. Therefore, the serialVersionUID can now be dynamically
     * supplied.
     *
     * After everything is setup, the function returns the class object that extends RemoteStub.
     *
     * @param className full qualified class name to create the stub object for
     * @param serialVersionUID  the serialVersionUID to use for the new class
     * @return dynamically created stub Class object
     * @throws CannotCompileException may be thrown when the specified class name is invalid
     * @throws NotFoundException should never be thrown in practice
     */
    public static Class makeLegacyStub(String className, long serialVersionUID) throws CannotCompileException, NotFoundException
    {
        try {
            return Class.forName(className);
        } catch (ClassNotFoundException e) {}

        RMGUtils.makeInterface(className + "Interface");
        CtClass intf = pool.getCtClass(className + "Interface");

        CtClass ctClass = pool.makeClass(className, remoteStubClass);
        ctClass.setInterfaces(new CtClass[] { intf });
        addSerialVersionUID(ctClass, serialVersionUID);

        createdClasses.add(className);
        return ctClass.toClass();
    }

    /**
     * Dynamically creates a class with random class name. The class implements the Serializable interface
     * and can therefore be used during RMI calls. Random classes are used as canaries during method attacks.
     * The MethodAttacker sends gadgets always as an array of Object. The first item within this arrays is the
     * actual payload object, while the second one is a canary (random class). When the RMI server complains
     * about not knowing the random class name, one can be sure that the previous class was successfully loaded.
     * Furthermore, this also makes sure that even during method attacks, server side calls will not be dispatched
     * due to missing classes.
     *
     * @return Class object of a serializable class with random class name.
     * @throws CannotCompileException should never be thrown in practice
     */
    public static Class makeRandomClass() throws CannotCompileException
    {
        String classname = UUID.randomUUID().toString().replaceAll("-", "");
        CtClass ctClass = pool.makeClass(classname);
        ctClass.addInterface(serializable);
        return ctClass.toClass();
    }

    /**
     * Dynamically creates a serializable class that can be used within RMI calls. This function is used
     * to perform codebase attacks, where a serializable class with user controlled class name needs to be sent
     * to the remote RMI server.
     *
     * @param className name of the serializable class to generate
     * @param serialVersionUID  the serialVersionUID to use for the new class
     * @return Class object of a serializable class with specified class name
     * @throws CannotCompileException may be thrown if the specified class name is invalid
     */
    public static Class makeSerializableClass(String className, long serialVersionUID) throws CannotCompileException
    {
        try {
            return Class.forName(className);
        } catch (ClassNotFoundException e) {}

        CtClass ctClass = pool.makeClass(className);
        ctClass.addInterface(serializable);
        addSerialVersionUID(ctClass, serialVersionUID);

        return ctClass.toClass();
    }

    /**
     * Create required classes for the activation system. This function is called when the server
     * contains an ActivatableRef. It checks whether the class exists within the currently running
     * JVM and creates it otherwise.
     *
     * @return Class object for ActivatableRef
     * @throws CannotCompileException internal error
     */
    public static Class makeActivatableRef() throws CannotCompileException
    {
        try {
            return Class.forName("sun.rmi.server.ActivatableRef");
        } catch (ClassNotFoundException e) {
            // TODO needs to be implemented correctly
            Logger.eprintlnYellow("Not implemented yet!");
            RMGUtils.exit();
        }

        return null;
    }

    /**
     * Dynamically create a socket factory class that implements RMIClientSocketFactory. This function is used when
     * the RMI server uses a custom socket factory class. In this case, remote-method-guesser attempts to connect
     * with it's default LoopbackSslSocketFactory or LoopbackSocketFactory (depending on the value of the settings
     * --ssl, --socket-factory-ssl and --socket-factory-plain) which works if the custom socket factory provided by
     * the server is not too different.
     *
     * To achieve this, remote-method-guesser just clones LoopbackSslSocketFactory or LoopbackSocketFactory and assigns
     * it a new name. As in the case of Stub classes with unusual serialVersionUIDs, the serialVersionUID is determined
     * error based. The factory is first created using a default serialVersionUID. This should cause an exception revealing
     * the actual serialVersionUID. This is then used to recreate the class.
     *
     * Check the CodebaseCollector class documentation for more information.
     *
     * @param className name for the SocketFactoryClass
     * @param serialVersionUID for the SocketFactoryClass
     *
     * @return socket factory class that implements RMIClientSocketFactory
     * @throws CannotCompileException internal error
     */
    public static Class makeSocketFactory(String className, long serialVersionUID) throws CannotCompileException
    {
        try
        {
            return Class.forName(className);
        }

        catch (ClassNotFoundException e) {}

        CtClass ctClass = null;

        try
        {

            if (!RMGOption.SOCKET_FACTORY_PLAIN.getBool() && (RMGOption.CONN_SSL.getBool() || RMGOption.SOCKET_FACTORY_SSL.getBool()))
            {
                ctClass = pool.getAndRename("eu.tneitzel.rmg.networking.LoopbackSslSocketFactory", className);
            }

            else if (!RMGOption.SOCKET_FACTORY_SSL.getBool() && (!RMGOption.CONN_SSL.getBool() || RMGOption.SOCKET_FACTORY_PLAIN.getBool()))
            {
                ctClass = pool.getAndRename("eu.tneitzel.rmg.networking.LoopbackSocketFactory", className);
            }

            else
            {
                Logger.eprintlnYellow("Invalid combination of SSL related options.");
                exit();
            }

            ctClass.addInterface(serializable);
            addSerialVersionUID(ctClass, serialVersionUID);
        }

        catch (NotFoundException e) {}

        return ctClass.toClass();
    }

    /**
     * Creates a method from a signature string. Methods need to be assigned to a class, therefore the static
     * dummyClass is used that is created during the initialization of RMGUtils. The class relationship of the
     * created method is not really important, as the method is mainly used to compute the method hash and to
     * obtain the argument types.
     *
     * @param signature method signature as String
     * @return CtMethod compiled from the signature
     * @throws CannotCompileException is thrown when signature is invalid
     */
    public static CtMethod makeMethod(String signature) throws CannotCompileException
    {
        return CtNewMethod.make("public " + signature + ";", dummyClass);
    }

    /**
     * This function is a pretty primitive way to obtain the different Java classes (types) that are
     * contained within a method signature. This is required, as javassist needs all classes contained
     * in a method definition to be present before the compilation. Therefore, we need to create dummy
     * implementations for each class that is not already on the class path.
     *
     * @param signature method signature to collect the types from
     * @return List of types that were identified
     */
    public static List<String> getTypesFromSignature(String signature)
    {
        int functionStart = signature.indexOf(' ');
        int argumentsStart = signature.indexOf('(') + 1;
        int argumentsEnd = signature.indexOf(')');

        if(functionStart <= 0 || argumentsStart <= 1 || argumentsEnd <= 0)
            ExceptionHandler.invalidSignature(signature);

        List<String> types = new ArrayList<String>();
        types.add(signature.substring(0, functionStart));

        String argumentPart = signature.substring(argumentsStart, argumentsEnd);
        if( argumentPart.equals("") )
            return types;

        String[] argumentParts = argumentPart.split(" ");

        for(int ctr = 0; ctr < argumentParts.length; ctr += 2) {
            types.add(argumentParts[ctr]);
        }

        return types;
    }

    /**
     * Takes a list of strings that represent Java class names and replaces array and vararg definitions within
     * of it. When it tries to lookup each full qualified class name within the list. If the class is found,
     * just continues. If the class is not found, it dynamically creates the class using javassist.
     *
     * @param types list of Java class names
     * @throws CannotCompileException may be thrown when encountering invalid class names
     */
    public static void createTypesFromList(List<String> types) throws CannotCompileException
    {
        for(String type : types) {

            type = type.replace("[]","");
            type = type.replace("...","");

            if ( type.contains(".") ) {
                try {
                    Class.forName(type);
                } catch (ClassNotFoundException e) {
                    CtClass unknown = pool.makeClass(type);
                    unknown.toClass();
                }
            }
        }
    }

    /**
     * Just a helper function that combines getTypesFromSignature and createTypesFrom list. This function should
     * be called before a method signature is compiled, as it makes sure that all required classes are on the
     * class path.
     *
     * @param signature method signature to create types for
     * @throws CannotCompileException may be thrown when specifying invalid signatures
     */
    public static void createTypesFromSignature(String signature) throws CannotCompileException
    {
        List<String> types = getTypesFromSignature(signature);
        createTypesFromList(types);
    }

    /**
     * Takes a Class object and returns a valid instance for the corresponding class. For primitive types,
     * preconfigured default values will be returned. Non primitive types create always a null instance.
     *
     * @param type Class to create the instance for
     * @return instance depending on the value of type
     */
    public static Object getArgument(Class type)
    {
        if (type.isPrimitive()) {
            if (type == int.class) {
                return 1;
            } else if (type == boolean.class) {
                return true;
            } else if (type == byte.class) {
                return Byte.MAX_VALUE;
            } else if (type == char.class) {
                return Character.MAX_HIGH_SURROGATE;
            } else if (type == short.class) {
                return Short.MAX_VALUE;
            } else if (type == long.class) {
                return Long.MAX_VALUE;
            } else if (type == float.class) {
                return Float.MAX_VALUE;
            } else if (type == double.class) {
                return Double.MAX_VALUE;
            } else {
                throw new Error("unrecognized primitive type: " + type);
            }

        } else {
            return null;
        }
    }

    /**
     * Construct an argument array for the specified method. Returns an array of Objects, each being an instance
     * of the type that is expected by the method.
     *
     * @param method Method to create the argument array for
     * @return argument array that can be used to invoke the method
     */
    public static Object[] getArgumentArray(Method method)
    {
        Class[] types = method.getParameterTypes();
        Object[] argumentArray = new Object[types.length];

        for(int ctr = 0; ctr < types.length; ctr++) {
            argumentArray[ctr] = getArgument(types[ctr]);
        }

        return argumentArray;
    }

    /**
     * Takes a CtClass object and returns a valid instance for the corresponding class. For primitive types,
     * preconfigured default values will be returned. Non primitive types create always a null instance.
     *
     * @param type Class to create the instance for
     * @return instance depending on the value of type
     */
    public static Object getArgument(CtClass type)
    {
        if (type.isPrimitive()) {
            if (type == CtPrimitiveType.intType) {
                return 1;
            } else if (type == CtPrimitiveType.booleanType) {
                return true;
            } else if (type == CtPrimitiveType.byteType) {
                return Byte.MAX_VALUE;
            } else if (type == CtPrimitiveType.charType) {
                return Character.MAX_HIGH_SURROGATE;
            } else if (type == CtPrimitiveType.shortType) {
                return Short.MAX_VALUE;
            } else if (type == CtPrimitiveType.longType) {
                return Long.MAX_VALUE;
            } else if (type == CtPrimitiveType.floatType) {
                return Float.MAX_VALUE;
            } else if (type == CtPrimitiveType.doubleType) {
                return Double.MAX_VALUE;
            } else {
                throw new Error("unrecognized primitive type: " + type);
            }

        } else {
            return null;
        }
    }

    /**
     * Construct an argument array for the specified method. Returns an array of Objects, each being an instance
     * of the type that is expected by the method.
     *
     * @param method CtMethod to create the argument array for
     * @return argument array that can be used to invoke the method
     * @throws NotFoundException internal error
     */
    public static Object[] getArgumentArray(CtMethod method) throws NotFoundException
    {
        CtClass[] types = method.getParameterTypes();
        Object[] argumentArray = new Object[types.length];

        for(int ctr = 0; ctr < types.length; ctr++) {
            argumentArray[ctr] = getArgument(types[ctr]);
        }

        return argumentArray;
    }

    /**
     * This function is used to generate method argument strings that are used in samples. Actually, it is only required
     * for legacy stub samples, as the call arguments need to be packed manually for stubs. This means, that the Object array
     * needs to be manually constructed.
     *
     * When one of the argument types is a primitive like e.g. int, you cannot put it into an Object array without wrapping it
     * into an Integer. Therefore, this function replaces primitives by their corresponding Object compatible representations.
     * During ordinary RMI calls, this is done automatically by using the Proxy object, which also wraps primitive types into
     * their corresponding Object compatible representations before passing them to the invoke method. However, as legacy stubs
     * aren't invoked via a Proxy, we have to implement the wrapping ourselves.
     *
     * @param type the type of the argument in question
     * @param argName the name of the argument in question
     * @return string that can be used for the argument within the Object array
     */
    public static String getSampleArgument(CtClass type, String argName)
    {
        if (type.isPrimitive()) {
            if (type == CtPrimitiveType.intType) {
                return String.format("new Integer(%s)", argName);
            } else if (type == CtPrimitiveType.booleanType) {
                return String.format("new Boolean(%s)", argName);
            } else if (type == CtPrimitiveType.byteType) {
                return String.format("new Byte(%s)", argName);
            } else if (type == CtPrimitiveType.charType) {
                return String.format("new Character(%s)", argName);
            } else if (type == CtPrimitiveType.shortType) {
                return String.format("new Short(%s)", argName);
            } else if (type == CtPrimitiveType.longType) {
                return String.format("new Long(%s)", argName);
            } else if (type == CtPrimitiveType.floatType) {
                return String.format("new Float(%s)", argName);
            } else if (type == CtPrimitiveType.doubleType) {
                return String.format("new Double(%s)", argName);
            } else {
                throw new Error("unrecognized primitive type: " + type);
            }

        } else {
            return argName;
        }
    }

    /**
     * Another function that is required when creating samples for legacy stubs. It takes a CtClass and returns a
     * string that can be used to represent the corresponding class within of Java code. When CtClass is e.g. int,
     * the return string would be "Integer.TYPE". This function is required to generate the reflection lookups
     * within of legacy samples.
     *
     * Legacy samples use reflection to get access to the interface methods and need to know the argument types in
     * order to lookup methods. The strings returned by this function can just be used during this lookup operation.
     *
     * @param type argument type to create a class string for
     * @return class string for the specified type
     */
    public static String getTypeString(CtClass type)
    {
        if (type.isPrimitive()) {
            if (type == CtPrimitiveType.intType) {
                return "Integer.TYPE";
            } else if (type == CtPrimitiveType.booleanType) {
                return "Boolean.TYPE";
            } else if (type == CtPrimitiveType.byteType) {
                return "Byte.TYPE";
            } else if (type == CtPrimitiveType.charType) {
                return "Char.TYPE";
            } else if (type == CtPrimitiveType.shortType) {
                return "Short.TYPE";
            } else if (type == CtPrimitiveType.longType) {
                return "Long.TYPE";
            } else if (type == CtPrimitiveType.floatType) {
                return "Float.TYPE";
            } else if (type == CtPrimitiveType.doubleType) {
                return "Double.TYPE";
            } else {
                throw new Error("unrecognized primitive type: " + type);
            }

        } else {
            return type.getName() + ".class";
        }
    }

    /**
     * Takes a CtClass and returns a string that can be used within Java code to cast an object to the type
     * of the specified CtClass. This is another function required for creating legacy stubs.
     *
     * Legacy stubs use the invoke method of UnicastRemoteRef directly, which just returns an Object as result
     * of the RMI call. However, as the actual stub method most of the time asks for a different return type,
     * it is required to cast the result to the appropriate type. To get the correct string for this cast, this
     * function is used.
     *
     * @param type type to generate the cast string for
     * @return cast string for the specified type
     */
    public static String getCast(CtClass type)
    {
        String classString = getTypeString(type);
        int index = classString.lastIndexOf(".");
        return classString.substring(0, index);
    }

    /**
     * Just a wrapper around System.exit(1) that prints an information before quitting.
     */
    public static void exit()
    {
        Logger.eprintln("Cannot continue from here.");
        System.exit(1);
    }

    /**
     * Sets the useCodebaseOnly setting to false and configures the CodebaseCollector class as the RMIClassLoaderSpi.
     * This is required to get access to server side exposed codebases, which is one of the things that rmg reports during
     * its enum action.
     *
     * Setting useCodebaseOnly to false is generally dangerous, as it could potentially allow remote class loading. It
     * tells the RMI runtime that you are interested in server side codebases and want to load unknown classes from an URL
     * that may be specified by the server. Therefore, this setting can easily lead to remote code execution.
     *
     * In the case of remote-method-guesser, a remote class loading attack is prevented by two mechanisms:
     *
     *      1. Remote class loading is not allowed when no SecurityManager is defined. As rmg does not create a SecurityManager
     *         on its own, the code is in principle not vulnerable. Furthermore, even when the user specifies a SecurityManager
     *         manually, it would still require a security policy that allows class loading from the server side specified
     *         codebase. If you manually enable a SecurityManager with such a policy, it isn't really rmg's fault.
     *
     *      2. remote-method-guesser replaces the RMIClassLoaderSpi class with a custom implementation. RMIClassLoaderSpi is
     *         normally used to resolve unknown classes during RMI calls. It obtains the unknown class name and a reference
     *         to the codebase of the server that exposes the class. Within rmg, the codebase reference is simply collected and
     *         returned back to the user. Afterwards, it is set to null before continuing with the usual RMI functionality.
     *         This way, even when a codebase is used by the server, the client side RMI call should never notice anything
     *         of it.
     */
    public static void enableCodebase()
    {
        System.setProperty("java.rmi.server.RMIClassLoaderSpi", "eu.tneitzel.rmg.internal.CodebaseCollector");
        System.setProperty("java.rmi.server.useCodebaseOnly", "false");
    }

    /**
     * Since version 3.4.0 of remote-method-guesser, the CodebaseCollectorClass has the additional purpose of creating
     * unknown remote classes at runtime. This behavior needs to be always enabled, independently of the useCodebaseOnly
     * property.
     */
    public static void enableCodebaseCollector()
    {
        System.setProperty("java.rmi.server.RMIClassLoaderSpi", "eu.tneitzel.rmg.internal.CodebaseCollector");
    }

    /**
     * This code was copied from the following link and is just used to disable the annoying reflection warnings:
     *
     * https://stackoverflow.com/questions/46454995/how-to-hide-warning-illegal-reflective-access-in-java-9-without-jvm-argument
     */
    public static void disableWarning()
    {
        try {
            Field theUnsafe = sun.misc.Unsafe.class.getDeclaredField("theUnsafe");
            theUnsafe.setAccessible(true);
            sun.misc.Unsafe u = (sun.misc.Unsafe) theUnsafe.get(null);

            Class cls = Class.forName("jdk.internal.module.IllegalAccessLogger");
            Field logger = cls.getDeclaredField("logger");
            u.putObjectVolatile(cls, u.staticFieldOffset(logger), null);
        } catch (Exception e) {}
    }

    /**
     * Helper function that adds a serialVersionUID to a class. This is required for RMI legacy stubs that usually
     * use a serialVersionUID of 2L. Previous versions of remote-method-guesser used a value of 2L per default in
     * this function, but issues were reported that not all RMI legacy stubs are compiled with a serialVersionUID of
     * 2L. To resolve these issues, the serialVersionUID can now be dynamically supplied.
     *
     * @param ctClass class where the serialVersionUID should be added to
     * @param serialVersionUID  the serialVersionUID to add
     * @throws CannotCompileException should never be thrown in practice
     */
    private static void addSerialVersionUID(CtClass ctClass, long serialVersionUID) throws CannotCompileException
    {
        CtField serialID = new CtField(CtPrimitiveType.longType, "serialVersionUID", ctClass);
        serialID.setModifiers(Modifier.PRIVATE | Modifier.STATIC | Modifier.FINAL);
        ctClass.addField(serialID, CtField.Initializer.constant(serialVersionUID));
    }

    /**
     * Returns a human readable method signature of a CtMethod. Builtin methods only return the signature in
     * a non well formatted format. This function is used to display known remote methods as the result of a
     * guessing operation.
     *
     * @param method CtMethod to create the signature for
     * @return human readable method signature as String
     */
    public static String getSimpleSignature(CtMethod method)
    {
        StringBuilder simpleSignature = new StringBuilder();

        try {
            simpleSignature.append(method.getReturnType().getName() + " ");
            simpleSignature.append(method.getName() + "(");

            for(CtClass ct : method.getParameterTypes()) {
                simpleSignature.append(ct.getName() + " arg, ");
            }

            if(method.getParameterTypes().length > 0)
                simpleSignature.setLength(simpleSignature.length() - 2);

            simpleSignature.append(")");

        } catch(Exception e) {
            ExceptionHandler.unexpectedException(e, "signature", "generation", false);
        }

        return simpleSignature.toString();
    }

    /**
     * During regular RMI calls, method arguments are usually passed as Object array as methods are invoked using a
     * Proxy mechanism. However, on the network layer argument types need to be marshalled according to the expected
     * type from the method signature. E.g. an argument value might be an Integer, but is expected by the method as int.
     * Therefore, passing an Object array alone is not sufficient to correctly write the method arguments to the output
     * stream.
     *
     * This function takes the remote method that is going to be invoked and an Object array of parameters to use for
     * the call. It then creates a MethodArguments object, that contains Pairs that store the desired object value
     * together with their corresponding type that is expected by the remote method.
     *
     * @param method CtMethod that is going to be invoked
     * @param parameterArray array of arguments to use for the call
     * @return MethodArguments - basically a list of Object value -&gt; Type pairs
     * @throws NotFoundException internal error
     */
    public static MethodArguments applyParameterTypes(CtMethod method, Object[] parameterArray) throws NotFoundException
    {
        CtClass type;
        CtClass[] types = method.getParameterTypes();
        MethodArguments parameterMap = new MethodArguments(parameterArray.length);

        for(int ctr = 0; ctr < types.length; ctr++) {

            type = types[ctr];

            if (type.isPrimitive()) {
                if (type == CtPrimitiveType.intType) {
                    parameterMap.add(parameterArray[ctr], int.class);
                } else if (type == CtPrimitiveType.booleanType) {
                    parameterMap.add(parameterArray[ctr], boolean.class);
                } else if (type == CtPrimitiveType.byteType) {
                    parameterMap.add(parameterArray[ctr], byte.class);
                } else if (type == CtPrimitiveType.charType) {
                    parameterMap.add(parameterArray[ctr], char.class);
                } else if (type == CtPrimitiveType.shortType) {
                    parameterMap.add(parameterArray[ctr], short.class);
                } else if (type == CtPrimitiveType.longType) {
                    parameterMap.add(parameterArray[ctr], long.class);
                } else if (type == CtPrimitiveType.floatType) {
                    parameterMap.add(parameterArray[ctr], float.class);
                } else if (type == CtPrimitiveType.doubleType) {
                    parameterMap.add(parameterArray[ctr], double.class);
                } else {
                    throw new Error("unrecognized primitive type: " + type);
                }

            } else {
                parameterMap.add(parameterArray[ctr], Object.class);
            }
        }

        return parameterMap;
    }

    /**
     * Helper function that is called to split a string that contains a listener definition (host:port).
     * The main benefit of this function is, that it implements basic error handling.
     *
     * @param listener listener definition as string
     * @return split listener [host, port]
     */
    public static String[] splitListener(String listener)
    {
        String[] split = listener.split(":");

        if( split.length != 2 || !split[1].matches("\\d+") ) {
            ExceptionHandler.invalidListenerFormat(false);
        }

        return split;
    }

    /**
     * Enables a user specified codebase within the MaliciousOutputStream. If the user specified address does not start
     * with a protocol definition, 'http' is prefixed by default. Furthermore, if no typical java extension was specified,
     * a slash is added to the end of the URL.
     *
     * @param serverAddress user specified codebase address.
     */
    public static void setCodebase(String serverAddress)
    {
        if( !serverAddress.matches("^(https?|ftp|file)://.*$") )
            serverAddress = "http://" + serverAddress;

        if( !serverAddress.matches("^.+(.class|.jar|/)$") )
            serverAddress += "/";

        MaliciousOutputStream.setDefaultLocation(serverAddress);
    }

    /**
     * This code was copied from the org.hibernate.bytecode.enhance.internal.javassist package,
     * that is licensed under LGPL version 2.1 or later. According to the GPL compatibility matrix,
     * it is fine to include the code in a GPLv3 licensed project and to convey the license to GPLv3.
     * (https://www.gnu.org/licenses/gpl-faq.en.html#AllCompatibility)
     *
     * The code is used to implement isAssignableFrom for CtClasses. It checks whether thisCtClass is the same as,
     * extends or implements targetClassName. Or in other words: It checks whether targetClassName is the same as,
     * or is a superclass or superinterface of the class or interface represented by the thisCtClass parameter.
     *
     * @param thisCtClass class in question
     * @param targetClassName name of the class to compare against
     * @return true if targetClassName is the same as, or is a superclass or superinterface of thisCtClass
     */
    public static boolean isAssignableFrom(CtClass thisCtClass, String targetClassName)
    {
        if( thisCtClass == null )
            return false;

        if( thisCtClass.getName().equals(targetClassName) )
            return true;

        try {

            if( isAssignableFrom(thisCtClass.getSuperclass(), targetClassName) )
                return true;

            for( CtClass interfaceCtClass : thisCtClass.getInterfaces() ) {
                if( isAssignableFrom(interfaceCtClass, targetClassName) )
                    return true;
            }
        }
        catch (NotFoundException e) {}
        return false;
    }

    /**
     * Divide a Set into n separate Sets, where n is the number specified within the count argument.
     * Basically copied from: https://stackoverflow.com/questions/16449644/how-can-i-take-a-java-set-of-size-x-and-break-into-x-y-sets
     *
     * @param <T> inner type of the set
     * @param original Set that should be divided
     * @param count Number of Sets to divide into
     * @return List of n separate sets, where n is equal to count
     */
    public static <T> List<Set<T>> splitSet(Set<T> original, int count)
    {
        ArrayList<Set<T>> result = new ArrayList<Set<T>>(count);
        Iterator<T> it = original.iterator();

        int each = original.size() / count;

        for (int i = 0; i < count; i++) {

            HashSet<T> s = new HashSet<T>(original.size() / count + 1);
            result.add(s);

            for (int j = 0; j < each && it.hasNext(); j++) {
                s.add(it.next());
            }
        }

        for(int i = 0; i < count && it.hasNext(); i++) {
            result.get(i).add(it.next());
        }

        return result;
    }

    /**
     * Takes an array of types and returns the amount of bytes before the first non primitive type.
     * If all types are primitive, it returns -1.
     *
     * @param types Array of types
     * @return bytes before the first non primitive type. If all types are primitive, returns -1
     */
    public static int getPrimitiveSize(CtClass[] types)
    {
        int returnValue = 0;

        for(CtClass ct : types) {

            if (ct.isPrimitive()) {

                if (ct == CtPrimitiveType.intType) {
                    returnValue += Integer.BYTES;
                } else if (ct == CtPrimitiveType.booleanType) {
                    returnValue += 1;
                } else if (ct == CtPrimitiveType.byteType) {
                    returnValue += Byte.BYTES;
                } else if (ct == CtPrimitiveType.charType) {
                    returnValue += Character.BYTES;
                } else if (ct == CtPrimitiveType.shortType) {
                    returnValue += Short.BYTES;
                } else if (ct == CtPrimitiveType.longType) {
                    returnValue += Long.BYTES;
                } else if (ct == CtPrimitiveType.floatType) {
                    returnValue += Float.BYTES;
                } else if (ct == CtPrimitiveType.doubleType) {
                    returnValue += Double.BYTES;
                } else {
                    throw new Error("unrecognized primitive type: " + ct);
                }

            } else {
                return returnValue;
            }
        }

        return -1;
    }

    /**
     * Converts a byte array into a hex string. Copied from:
     * https://stackoverflow.com/questions/15429257/how-to-convert-byte-array-to-hexstring-in-java
     *
     * @param in byte array to convert
     * @return hex string representing the byte array
     */
    public static String bytesToHex(byte[] in)
    {
        final StringBuilder builder = new StringBuilder();

        for (byte b : in) {
            builder.append(String.format("%02x", b));
        }

        return builder.toString();
    }

    /**
     * Converts a hex string into a byte array. Copied from:
     * https://stackoverflow.com/questions/140131/convert-a-string-representation-of-a-hex-dump-to-a-byte-array-using-java
     *
     * @param s Hex string to convert from
     * @return byte array representation of the hex data
     */
    public static byte[] hexToBytes(String s)
    {
        s = s.replace("0x", "").replace("\\x", "").replace("%", "");

        int len = s.length();
        byte[] data = new byte[len / 2];

        for(int i = 0; i < len; i += 2) {
            data[i / 2] = (byte)((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));
        }

        return data;
    }

    /**
     * Checks whether the specified class name was generated dynamically by RMGUtils.
     *
     * @param className class to check for
     * @return true if it was generated dynamically
     */
    public static boolean dynamicallyCreated(String className)
    {
        if( createdClasses.contains(className) )
            return true;

        return false;
    }

    /**
     * Extracts the underlying RemoteRef within an instance of Remote. The RemoteRef contains
     * information regarding the actual TCP endpoint and the ObjID that is used within the call.
     *
     * @param instance An Instance of Remote - Usually obtained by the RMI lookup method
     * @return underlying RemoteRef that is used by the Remote instance
     * @throws IllegalArgumentException if reflective access fails
     * @throws IllegalAccessException if reflective access fails
     */
    public static RemoteRef extractRef(Remote instance) throws IllegalArgumentException, IllegalAccessException
    {
        Field proxyField = null;
        Field remoteField= null;
        RemoteRef remoteRef = null;

        try {
            proxyField = Proxy.class.getDeclaredField("h");
            remoteField = RemoteObject.class.getDeclaredField("ref");
            proxyField.setAccessible(true);
            remoteField.setAccessible(true);

        } catch(NoSuchFieldException | SecurityException e) {
            ExceptionHandler.unexpectedException(e, "reflective access in", "extractRef", true);
        }

        if( Proxy.isProxyClass(instance.getClass()) )
            remoteRef = ((RemoteObjectInvocationHandler)proxyField.get(instance)).getRef();

        else
            remoteRef = (RemoteRef)remoteField.get(instance);

        return remoteRef;
    }

    /**
     * Extracts the ObjID value from a UnicastRef.
     *
     * @param uref UnicastRef to extract the ObjID from
     * @return ObjID extracted from specified UnicastRef
     * @throws IllegalArgumentException if reflective access fails
     * @throws IllegalAccessException if reflective access fails
     */
    public static ObjID extractObjID(UnicastRef uref) throws IllegalArgumentException, IllegalAccessException
    {
        Field liveRefField = null;

        try {
            liveRefField = UnicastRef.class.getDeclaredField("ref");
            liveRefField.setAccessible(true);

        } catch(NoSuchFieldException | SecurityException e) {
            ExceptionHandler.unexpectedException(e, "reflective access in", "extractObjID", true);
        }

        LiveRef ref = (LiveRef)liveRefField.get(uref);
        return ref.getObjID();
    }

    /**
     * Extracts the ObjID value from an instance of Remote.
     *
     * @param remote Instance of Remote that contains an ref with assigned ObjID
     * @return ObjID extracted from specified instance of Remote
     * @throws IllegalArgumentException if reflective access fails
     * @throws IllegalAccessException if reflective access fails
     */
    public static ObjID extractObjID(Remote remote) throws IllegalArgumentException, IllegalAccessException
    {
        RemoteRef remoteRef = extractRef(remote);
        return extractObjID((UnicastRef)remoteRef);
    }

    /**
     * Parses an ObjID from a String. In previous versions of rmg, only well known ObjIDs were supported,
     * as it was only possible to specify the ObjNum property of an ObjID. For non well known RemoteObjects,
     * an UID is required too. This function accepts now both inputs. You can just specify a number like
     * 1, 2 or 3 to target one of the well known RMI components or a full ObjID string to target a different
     * RemoteObject. Full ObjID strings can be obtained by rmg's enum action and look usually like this:
     * [196e60b8:17ac2551248:-7ffc, -7934078052539650836]
     *
     * @param objIdString Either a plain number or an ObjID value formatted as String
     * @return ObjID object constructed from the specified input string
     */
    public static ObjID parseObjID(String objIdString)
    {
        ObjID returnValue = null;

        if( !objIdString.contains(":") ) {

            try {
                long objNum = Long.parseLong(objIdString);
                return new ObjID((int)objNum);

            } catch( java.lang.NumberFormatException e ) {
                ExceptionHandler.invalidObjectId(objIdString);
            }
        }

        Pattern pattern = Pattern.compile("\\[([0-9a-f-]+):([0-9a-f-]+):([0-9a-f-]+), ([0-9-]+)\\]");
        Matcher matcher = pattern.matcher(objIdString);

        if( !matcher.find() )
            ExceptionHandler.invalidObjectId(objIdString);

        try {
            Constructor<UID> conUID = UID.class.getDeclaredConstructor(int.class, long.class, short.class);
            Constructor<ObjID> conObjID = ObjID.class.getDeclaredConstructor(long.class, UID.class);

            int unique = Integer.parseInt(matcher.group(1), 16);
            long time = Long.parseLong(matcher.group(2), 16);
            short count = (short)Integer.parseInt(matcher.group(3), 16);
            long objNum = Long.parseLong(matcher.group(4));

            conUID.setAccessible(true);
            UID uid = conUID.newInstance(unique, time, count);

            conObjID.setAccessible(true);
            returnValue = conObjID.newInstance(objNum, uid);

        } catch (Exception e) {
            ExceptionHandler.invalidObjectId(objIdString);
        }

        return returnValue;
    }

    /**
     * Determines the className of an object that implements Remote. If the specified object is a Proxy,
     * the function returns the first implemented interface name that is not java.rmi.Remote.
     *
     * @param remoteObject Object to obtain the class from
     * @return Class name of the implementor or one of its interfaces in case of a Proxy
     */
    public static String getInterfaceName(Remote remoteObject)
    {
        if( Proxy.isProxyClass(remoteObject.getClass()) ) {

            Class<?>[] interfaces = remoteObject.getClass().getInterfaces();

            for(Class<?> intf : interfaces) {

                String intfName = intf.getName();

                if(!intfName.equals("java.rmi.Remote"))
                    return intfName;
            }
        }

        return remoteObject.getClass().getName();
    }

    /**
     * Print information contained in an ObjID to stdout.
     *
     * @param objID ObjID value to print information from
     */
    public static void printObjID(ObjID objID)
    {
        try {
            Field objNumField = objID.getClass().getDeclaredField("objNum");
            Field spaceField = objID.getClass().getDeclaredField("space");

            objNumField.setAccessible(true);
            spaceField.setAccessible(true);

            long objNum = objNumField.getLong(objID);
            UID uid = (UID)spaceField.get(objID);

            Field uniqueField = uid.getClass().getDeclaredField("unique");
            Field timeField = uid.getClass().getDeclaredField("time");
            Field countField = uid.getClass().getDeclaredField("count");

            uniqueField.setAccessible(true);
            timeField.setAccessible(true);
            countField.setAccessible(true);

            int unique = uniqueField.getInt(uid);
            long time = timeField.getLong(uid);
            short count = countField.getShort(uid);

            SimpleDateFormat dateFormat = new SimpleDateFormat(" (MMM dd,yyyy HH:mm)");
            Date date = new Date(time);

            Logger.printlnMixedBlue("Details for ObjID", objID.toString());

            Logger.lineBreak();
            Logger.printMixedBlueFirst("ObjNum:", "\t\t");
            Logger.printlnPlainYellow(String.valueOf(objNum));

            Logger.printlnBlue("UID:");
            Logger.increaseIndent();

            Logger.printMixedBlueFirst("Unique:", "\t");
            Logger.printlnPlainYellow(String.valueOf(unique));

            Logger.printMixedBlueFirst("Time:", "\t\t");
            Logger.printlnPlainYellow(String.valueOf(time) + dateFormat.format(date));

            Logger.printMixedBlueFirst("Count:", "\t\t");
            Logger.printlnPlainYellow(String.valueOf(count));

            Logger.decreaseIndent();

        } catch( Exception e ) {
            ExceptionHandler.unexpectedException(e, "parsing", "ObjID", true);
        }
    }

    /**
     * Provides a Java8+ compatible way to create an ObjectInputFilter using reflection. Using
     * ordinary class access does not work for projects that should be compatible with Java8 and
     * Java9+, since the ObjectInputFilter class is located in different packages.
     *
     * @param pattern Serial filter pattern as usually used for ObjectInputFilter
     * @return Either sun.misc.ObjectInputFilter or java.io.ObjectInputFilter depending on the Java environment
     * @throws IllegalArgumentException if reflective access fails
     * @throws IllegalAccessException if reflective access fails
     * @throws NoSuchMethodException if reflective access fails
     * @throws SecurityException if reflective access fails
     * @throws InvocationTargetException if reflective access fails
     */
    public static Object createObjectInputFilter(String pattern) throws NoSuchMethodException, SecurityException, IllegalAccessException, IllegalArgumentException, InvocationTargetException
    {
        Class<?> objectInputFilter = null;

        try {
            objectInputFilter = Class.forName("java.io.ObjectInputFilter$Config");

        } catch( ClassNotFoundException e ) {

            try {
                objectInputFilter = Class.forName("sun.misc.ObjectInputFilter$Config");

            } catch( ClassNotFoundException e2 ) {
                ExceptionHandler.internalError("createObjectInputFilter", "Unable to find ObjectInputFilter class.");
            }
        }

        Method createObjectInputFilter = objectInputFilter.getDeclaredMethod("createFilter", new Class<?>[] { String.class });
        return createObjectInputFilter.invoke(null, pattern);
    }

    /**
     * Inject an ObjectInputFilter into a UnicastServerRef. This is required for a Java8+ compatible
     * way of creating serial filters for RMI connections. See the createObjectInputFilter function for
     * more details.
     *
     * @param uref UnicastServerRef to inject the ObjectInputFilter on
     * @param filter ObjectInputFilter to inject
     * @throws IllegalArgumentException if reflective access fails
     * @throws IllegalAccessException if reflective access fails
     * @throws NoSuchFieldException if reflective access fails
     * @throws SecurityException if reflective access fails
     * @throws InvocationTargetException if reflective access fails
     */
    public static void injectObjectInputFilter(UnicastServerRef uref, Object filter) throws SecurityException, IllegalAccessException, IllegalArgumentException, InvocationTargetException, NoSuchFieldException
    {
        Field filterField = UnicastServerRef.class.getDeclaredField("filter");

        filterField.setAccessible(true);
        filterField.set(uref, filter);
    }

    /**
     * Returns the ObjID for the user specified RMI component,
     *
     * @param component the well known RMI component to return the Object ID for
     *
     * @return ObjID for the user specified RMI component.
     */
    public static ObjID getObjIDByComponent(RMIComponent component)
    {
        if( component == null )
            ExceptionHandler.internalError("RMGUtils.getObjIDByComponent", "Was called with null component.");

        ObjID returnValue = null;

        switch( component ) {

            case REGISTRY:
                returnValue = new ObjID(ObjID.REGISTRY_ID);
                break;
            case ACTIVATOR:
                returnValue = new ObjID(ObjID.ACTIVATOR_ID);
                break;
            case DGC:
                returnValue = new ObjID(ObjID.DGC_ID);
                break;

            default:
                ExceptionHandler.internalError("RMGUtils.getObjIDByComponent", "The specified component was invalid.");
        }

        return returnValue;
    }

    /**
     * Determines whether a ClassCastException was created by readString because of an non-String type being passed
     * to a call that expected String.
     *
     * @param msg Message of the ClassCastException
     * @return true if created by readString
     */
    public static boolean createdByReadString(String msg)
    {
        if( msg.equals("Cannot cast a class to java.lang.String") ||
            msg.equals("Cannot cast an array to java.lang.String") ||
            msg.equals("Cannot cast an enum to java.lang.String") ||
            msg.equals("Cannot cast an object to java.lang.String") ||
            msg.equals("Cannot cast an exception to java.lang.String")
        )
            return true;

        return false;
    }

    /**
     * Parse the class name from an InvalidClassException.
     *
     * @param e  the InvalidClassException
     * @return the class name of the invalid class
     */
    public static String getClass(InvalidClassException e)
    {
        String message = e.getMessage();

        return message.substring(0, message.indexOf(';'));
    }

    /**
     * Parse the SerialVersionUID of the foreign class from an an InvalidClassException.
     *
     * @param e  the InvalidClassException
     * @return the serialVersionUID of the foreign class
     */
    public static long getSerialVersionUID(InvalidClassException e)
    {
        String message = e.getMessage();
        message = message.substring(message.indexOf('=') + 2, message.indexOf(','));

        return Long.parseLong(message);
    }

    /**
     * Convert a CtClass back to an ordinary Class object. This method is intended to be called
     * for classes that are known to already exist within the JVM. No compilation is triggered but
     * the Class object is simply obtained by Class.forName (including handling for all the edge
     * cases).
     *
     * @param type  the CtClass that should be converted back to a Class object
     * @return Class associated to the specified CtClass
     * @throws ClassNotFoundException internal error
     * @throws NotFoundException internal error
     */
    public static Class<?> ctClassToClass(CtClass type) throws ClassNotFoundException, NotFoundException
    {
        if (type.isPrimitive())
        {
            if (type == CtPrimitiveType.intType) {
                return int.class;
            } else if (type == CtPrimitiveType.booleanType) {
                return boolean.class;
            } else if (type == CtPrimitiveType.byteType) {
                return byte.class;
            } else if (type == CtPrimitiveType.charType) {
                return char.class;
            } else if (type == CtPrimitiveType.shortType) {
                return short.class;
            } else if (type == CtPrimitiveType.longType) {
                return long.class;
            } else if (type == CtPrimitiveType.floatType) {
                return float.class;
            } else if (type == CtPrimitiveType.doubleType) {
                return double.class;
            } else {
                throw new Error("unrecognized primitive type: " + type);
            }
        }

        else if (type.isArray())
        {
            return Array.newInstance(ctClassToClass(type.getComponentType()), 0).getClass();
        }

        else
        {
            return Class.forName(type.getName());
        }
    }

    /**
     * Primitive argument parser for finding a single string value option on the command line.
     *
     * @param opt option name to find
     * @param args command line
     * @return the value of the specified option
     */
    public static String getOption(String opt, String[] args)
    {
        for (int ctr = 0; ctr < args.length - 1; ctr++)
        {
            if (args[ctr].equals(opt))
            {
                return args[ctr + 1];
            }
        }

        return null;
    }

    /**
     * Primitive argument parser for finding a single boolean value option on the command line.
     *
     * @param opt option name to find
     * @param args command line
     * @return true if option was found
     */
    public static boolean getBooleanOption(String opt, String[] args)
    {
        for (String arg : args)
        {
            if (arg.equals(opt))
            {
                return true;
            }
        }

        return false;
    }

    /**
     * Expand a leading ~/ with the users home directory.
     *
     * @param path  input path
     * @return expanded path
     */
    public static String expandPath(String path)
    {
        return path.replaceFirst("^~/", System.getProperty("user.home") + "/");
    }
}
