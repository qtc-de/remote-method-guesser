package de.qtc.rmg.utils;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.rmi.Remote;
import java.rmi.server.RemoteStub;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;
import java.util.UUID;

import de.qtc.rmg.Starter;
import de.qtc.rmg.internal.ExceptionHandler;
import de.qtc.rmg.internal.MethodCandidate;
import de.qtc.rmg.io.Logger;
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
    private static CtClass remoteStubClass;

    /**
     * The init function has to be called before the javassist library can be utilized via RMGUtils.
     * It initializes the class pool and creates CtClass objects for the Remote and RemoteStub classes.
     * Furthermore, it creates a Dummy interface that is used for method creation. All this stuff is stored
     * within static variables and can be used by RMGUtils after initialization.
     */
    public static void init()
    {
        pool = ClassPool.getDefault();

        try {
            remoteClass = pool.getCtClass(Remote.class.getName());
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
        CtClass intf = pool.getCtClass(className);

        CtClass ctClass = pool.makeClass(className, remoteStubClass);
        ctClass.setInterfaces(new CtClass[] { intf });

        CtField serialID = new CtField(CtPrimitiveType.longType, "serialVersionUID", ctClass);
        serialID.setModifiers(Modifier.PRIVATE | Modifier.STATIC | Modifier.FINAL);
        ctClass.addField(serialID, CtField.Initializer.constant(2L));

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
        CtClass intf = pool.getCtClass(className);

        CtClass ctClass = pool.makeClass(className, remoteStubClass);
        ctClass.setInterfaces(new CtClass[] { intf });

        CtField serialID = new CtField(CtPrimitiveType.longType, "serialVersionUID", ctClass);
        serialID.setModifiers(Modifier.PRIVATE | Modifier.STATIC | Modifier.FINAL);
        ctClass.addField(serialID, CtField.Initializer.constant(2L));

        ctClass.toClass();
        return intfClass;
    }

    public static Class makeRandomClass() throws CannotCompileException, NotFoundException
    {
        String classname = UUID.randomUUID().toString().replaceAll("-", "");
        CtClass ctClass = pool.makeClass(classname);
        ctClass.addInterface(pool.get("java.io.Serializable"));
        return ctClass.toClass();
    }

    public static Class makeSerializableClass(String classname) throws CannotCompileException, NotFoundException
    {
        try {
            return Class.forName(classname);
        } catch (ClassNotFoundException e) {}

        CtClass ctClass = pool.makeClass(classname);
        ctClass.addInterface(pool.get("java.io.Serializable"));

        CtField serialID = new CtField(CtPrimitiveType.longType, "serialVersionUID", ctClass);
        serialID.setModifiers(Modifier.PRIVATE | Modifier.STATIC | Modifier.FINAL);
        ctClass.addField(serialID, CtField.Initializer.constant(2L));

        return ctClass.toClass();
    }

    public static CtMethod makeMethod(String signature) throws CannotCompileException
    {
        CtMethod method = CtNewMethod.make("public " + signature + ";", dummyClass);
        return method;
    }

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

    public static void createTypesFromSignature(String signature) throws CannotCompileException
    {
        List<String> types = getTypesFromSignature(signature);
        createTypesFromList(types);
    }

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

    public static Object[] getArgumentArray(Method method)
    {
        Class[] types = method.getParameterTypes();
        Object[] argumentArray = new Object[types.length];

        for(int ctr = 0; ctr < types.length; ctr++) {
            argumentArray[ctr] = getArgument(types[ctr]);
        }

        return argumentArray;
    }

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

    public static String getCast(CtClass type)
    {
        String classString = getTypeString(type);
        int index = classString.lastIndexOf(".");
        return classString.substring(0, index);
    }

    public static void exit()
    {
        Logger.eprintln("Cannot continue from here.");
        System.exit(1);
    }

    public static void loadConfig(String filename, Properties prop, boolean extern)
    {
        InputStream configStream = null;
        try {

            if( extern )

                configStream = new FileInputStream(filename);
            else
                configStream = Starter.class.getResourceAsStream(filename);

            prop.load(configStream);
            configStream.close();

        } catch( IOException e ) {
            ExceptionHandler.unexpectedException(e, "loading", ".properties file", true);
        }
    }

    public static boolean containsUnknown(HashMap<String,String> unknownClasses)
    {
        if( unknownClasses.size() <= 0 ) {
            Logger.eprintln("No unknown classes identified.");
            Logger.eprintln("Guessing methods not necessary.");
            return false;
        }

        return true;
    }

    public static void enableCodebase()
    {
        System.setProperty("java.rmi.server.RMIClassLoaderSpi", "de.qtc.rmg.internal.CodebaseCollector");
        System.setProperty("java.rmi.server.useCodebaseOnly", "false");
    }

    /*
     * Taken from https://stackoverflow.com/questions/46454995/how-to-hide-warning-illegal-reflective-access-in-java-9-without-jvm-argument
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
        } catch (Exception e) {
            // ignore
        }
    }

    public static boolean isLegacy(String className, int legacyMode, boolean verbose)
    {
        if( (className.endsWith("_Stub") && legacyMode == 0) || legacyMode == 1) {
            if( verbose) {
                Logger.increaseIndent();
                Logger.printlnMixedBlue("Class", className, "is treated as legacy stub.");
                Logger.printlnMixedBlue("You can use", "--no-legacy", "to prevent this.");
                Logger.decreaseIndent();
            }
            return true;
        }

        return false;
    }
}
