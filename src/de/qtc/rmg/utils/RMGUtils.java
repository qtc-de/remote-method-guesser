package de.qtc.rmg.utils;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.rmi.Remote;
import java.rmi.server.RemoteStub;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;

import de.qtc.rmg.internal.ExceptionHandler;
import de.qtc.rmg.internal.MethodArguments;
import de.qtc.rmg.internal.MethodCandidate;
import de.qtc.rmg.io.Logger;
import de.qtc.rmg.io.MaliciousOutputStream;
import javassist.CannotCompileException;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtField;
import javassist.CtMethod;
import javassist.CtNewMethod;
import javassist.CtPrimitiveType;
import javassist.Modifier;
import javassist.NotFoundException;

/**
 * The RMGUtils class defines static helper functions that do not really fit into other categories.
 * Like it is always the case with such classes, it is quite overblown and may be separated in future.
 * Most of the functions in it are concerned about dynamic class creation via javassist. But over the
 * time many other utilities were included within this class.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
@SuppressWarnings({ "rawtypes", "deprecation" })
public class RMGUtils {

    private static ClassPool pool;
    private static CtClass dummyClass;
    private static CtClass remoteClass;
    private static CtClass serializable;
    private static CtClass remoteStubClass;

    /**
     * The init function has to be called before the javassist library can be utilized via RMGUtils.
     * It initializes the class pool and creates CtClass objects for the Remote, RemoteStub and Serializable
     * classes. Furthermore, it creates a Dummy interface that is used for method creation. All this stuff
     * is stored within static variables and can be used by RMGUtils after initialization.
     */
    public static void init()
    {
        pool = ClassPool.getDefault();

        try {
            remoteClass = pool.getCtClass(Remote.class.getName());
            serializable = pool.getCtClass("java.io.Serializable");
            remoteStubClass = pool.getCtClass(RemoteStub.class.getName());
        } catch (NotFoundException e) {
            ExceptionHandler.internalError("RMGUtils.init", "Caught unexpected NotFoundException.");
        }

        dummyClass = pool.makeInterface("de.qtc.rmg.Dummy");
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
        CtMethod dummyMethod = CtNewMethod.make("public void rmgInvokeObject(String str) throws java.rmi.RemoteException;", intf);

        intf.addMethod(dummyMethod);
        dummyMethod = CtNewMethod.make("public void rmgInvokePrimitive(int i) throws java.rmi.RemoteException;", intf);
        intf.addMethod(dummyMethod);

        return intf.toClass();
    }

    /**
     * This function is basically equivalent to the previous makeInterface function, apart that it creates the interface
     * with a user specified MethodCandidate. This is required for the MethodAttacker class, which need to compile dynamic
     * remote interfaces that contain a user specified method signature.
     *
     * The function first checks whether the specified class does already exist and contains the requested method. If
     * this is the case, the corresponding Class object is simply returned. If the class exists, but the method is not
     * available, the class needs to be defrosted to allow modifications to it.
     *
     * For non existing and defrosted classes, the requested MethodCandidate is then added to the interface and the corresponding
     * interface class Object is returned by the function.
     *
     * @param className full qualified name of the class to create
     * @param candidate MethodCandidate to include within the created interface
     * @return Class object of the dynamically created class
     * @throws CannotCompileException may be thrown when an invalid class name or method signature was identified
     */
    public static Class makeInterface(String className, MethodCandidate candidate) throws CannotCompileException
    {
        CtClass intf = null;

        try {
            intf = pool.getCtClass(className);

            for(CtMethod method : intf.getDeclaredMethods()) {

                if(method.getSignature().equals(candidate.getMethod().getSignature()))
                    return Class.forName(className);
            }

            intf.defrost();

        } catch (ClassNotFoundException | NotFoundException e) {
            /*
             * className is not known and was not created before. This is usually expected.
             * In this case, we just create the class :)
             */
            intf = pool.makeInterface(className, remoteClass);
        }

        CtMethod dummyMethod = CtNewMethod.make("public " + candidate.getSignature() + " throws java.rmi.RemoteException;", intf);
        intf.addMethod(dummyMethod);

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
     * what needs to be done is adding a serialVersionUID of 2L, as this default value is expected for RMI RemoteStubs.
     * After everything is setup, the function returns the class object that extends RemoteStub.
     *
     * @param className full qualified class name to create the stub object for
     * @return dynamically created stub Class object
     * @throws CannotCompileException may be thrown when the specified class name is invalid
     * @throws NotFoundException should never be thrown in practice
     */
    public static Class makeLegacyStub(String className) throws CannotCompileException, NotFoundException
    {
        try {
            return Class.forName(className);
        } catch (ClassNotFoundException e) {}

        Class intfClass = RMGUtils.makeInterface(className + "Interface");
        CtClass intf = pool.getCtClass(className + "Interface");

        CtClass ctClass = pool.makeClass(className, remoteStubClass);
        ctClass.setInterfaces(new CtClass[] { intf });
        addSerialVersionUID(ctClass);

        ctClass.toClass();
        return intfClass;
    }

    /**
     * Basically the same function as the previously defined makeLegacyStub function, apart that it creates the interface
     * with a user specified MethodCandidate. This is required for the MethodAttacker class, which need to compile dynamic
     * remote interfaces that contain a user specified method signature.
     *
     * As the remote interface is created using the makeInterface method, we may do not need to care about defrosting. I'm
     * not totally sure how Java behaves when a class already exists and you change the interface that it implements.
     * However, at the current state of the remote-method-guesser, this should not happen anyway, as this method is only
     * used by MethodAttacker, which only accepts a single function signature.
     *
     * @param className full qualified name of the stub class to create
     * @param candidate MethodCandidate to include within the created interface
     * @return Class object of the dynamically created stub class
     * @throws CannotCompileException may be thrown when an invalid class name or method signature was identified
     * @throws NotFoundException should never be thrown in practice
     */
    public static Class makeLegacyStub(String className, MethodCandidate candidate) throws CannotCompileException, NotFoundException
    {
        try {
            return Class.forName(className);
        } catch (ClassNotFoundException e) {}

        Class intfClass = RMGUtils.makeInterface(className + "Interface", candidate);
        CtClass intf = pool.getCtClass(className + "Interface");

        CtClass ctClass = pool.makeClass(className, remoteStubClass);
        ctClass.setInterfaces(new CtClass[] { intf });
        addSerialVersionUID(ctClass);

        ctClass.toClass();
        return intfClass;
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
     * to perform codebase attacks, where a serializale class with user controlled class name needs to be send
     * to the remote RMI server.
     *
     * @param className name of the serializable class to generate
     * @return Class object of a serializable class with specified class name
     * @throws CannotCompileException may be thrown if the specified class name is invalid
     */
    public static Class makeSerializableClass(String className) throws CannotCompileException
    {
        try {
            return Class.forName(className);
        } catch (ClassNotFoundException e) {}

        CtClass ctClass = pool.makeClass(className);
        ctClass.addInterface(serializable);
        addSerialVersionUID(ctClass);

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
        CtMethod method = CtNewMethod.make("public " + signature + ";", dummyClass);
        return method;
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
     * Just a helper function that combines geTypesFromSignature and createTypesFrom list. This function should
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
     * @throws NotFoundException
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
     * are'nt invoked via a Proxy, we have to implement the wrapping ourself.
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
        System.setProperty("java.rmi.server.RMIClassLoaderSpi", "de.qtc.rmg.internal.CodebaseCollector");
        System.setProperty("java.rmi.server.useCodebaseOnly", "false");
    }

    /**
     * This code was copied from the following link and is just used to disable the annoying reflection warnings:
     *
     * https://stackoverflow.com/questions/46454995/how-to-hide-warning-illegal-reflective-access-in-java-9-without-jvm-argument
     */
    @SuppressWarnings("restriction")
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
     * Determines the legacy mode setting. Legacy mode decides whether to detect usage of legacy RMI objects automatically
     * (legacyMode = 0), to enforce usage of legacy objects (legacyMode = 1) or to treat all classes as non legacy classes
     * (legacyMode = 2).
     *
     * When automatic detection is used, the function checks for the "_Stub" suffix, which is usually present for legacy
     * stub objects. Otherwise, it just returns true or false depending on the value of legacyMode.
     *
     * Whenever legacyMode is enabled, a warning is printed to the user, as it might not be intended.
     *
     * @param className the class name to determine the legacy status from
     * @param legacyMode the user defined setting of legacyMode (0 is the default)
     * @param verbose whether or not to print the warning message
     * @return true if legacy mode should be used, false otherwise
     */
    public static boolean isLegacy(String className, int legacyMode, boolean verbose)
    {
        if( (className.endsWith("_Stub") && legacyMode == 0) || legacyMode == 1) {
            if( verbose) {
                Logger.printlnMixedBlue("Class", className, "is treated as legacy stub.");
                Logger.printlnMixedBlue("You can use", "--no-legacy", "to prevent this.");
            }
            return true;
        }

        return false;
    }

    /**
     * Helper function that adds the serialVersionUID of 2L to a class. This is required for certain RMI classes.
     *
     * @param ctClass class where the serialVersionUID should be added to
     * @throws CannotCompileException should never be thrown in practice
     */
    private static void addSerialVersionUID(CtClass ctClass) throws CannotCompileException
    {
        CtField serialID = new CtField(CtPrimitiveType.longType, "serialVersionUID", ctClass);
        serialID.setModifiers(Modifier.PRIVATE | Modifier.STATIC | Modifier.FINAL);
        ctClass.addField(serialID, CtField.Initializer.constant(2L));
    }

    /**
     * Helper method that adds remote methods present on known remote objects to the list of successfully guessed methods.
     * The known remote object classes are looked by by using the CtClassPool. Afterwards, all implemented interfaces
     * of the corresponding CtClass are iterated and it is checked whether the interface extends java.rmiRemote (this
     * is required for all methods, that can be called from remote). From these interface,s all methods are obtained
     * and added to the list of successfully guessed methods.
     *
     * @param boundName bound name that is using the known class
     * @param className name of the class implemented by the bound name
     * @param guessedMethods list of successfully guessed methods (bound name -> list)
     */
    public static void addKnownMethods(String boundName, String className, HashMap<String,ArrayList<MethodCandidate>> guessedMethods)
    {
        try {
            CtClass knownClass = pool.getCtClass(className);

            for(CtClass intf : knownClass.getInterfaces()) {

                if(! isAssignableFrom(intf, "java.rmi.Remote"))
                    continue;

                CtMethod[] knownMethods = intf.getDeclaredMethods();
                ArrayList<MethodCandidate> knownMethodCandidates = new ArrayList<MethodCandidate>();

                for(CtMethod knownMethod: knownMethods)
                    knownMethodCandidates.add(new MethodCandidate(knownMethod));

                guessedMethods.put(boundName, knownMethodCandidates);
            }

        } catch(Exception e) {
            ExceptionHandler.unexpectedException(e, "translation process", "of known remote methods", false);
        }
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
     * type from the method signature. E.g. an argument value might be an Integer, but is epxected by the method as int.
     * Therefore, passing an Object array alone is not sufficient to correctly write the method arguments to the output
     * stream.
     *
     * This function takes the remote method that is going to be invoked and an Object array of parameters to use for
     * the call. It then creates a MethodArguments object, that contains Pairs that store the desired object value
     * together with their corresponding type that is expected by the remote method.
     *
     * @param method CtMethod that is going to be invoked
     * @param parameterArray array of arguments to use for the call
     * @return MerhodArguments - basically a list of Object value -> Type pairs
     * @throws NotFoundException
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
}
