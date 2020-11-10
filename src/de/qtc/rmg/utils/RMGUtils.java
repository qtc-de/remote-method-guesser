package de.qtc.rmg.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.rmi.Remote;
import java.rmi.server.RemoteStub;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;
import java.util.UUID;

import de.qtc.rmg.Starter;
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

@SuppressWarnings({ "rawtypes", "deprecation" })
public class RMGUtils {

    private static ClassPool pool;
    private static CtClass dummyClass;
    private static CtClass remoteClass;
    private static CtClass remoteStubClass;

    public static void init()
    {
        pool = ClassPool.getDefault();

        try {
            remoteClass = pool.getCtClass(Remote.class.getName());
            remoteStubClass = pool.getCtClass(RemoteStub.class.getName());
        } catch (NotFoundException e) {
            Logger.printlnMixedYellow("Caught", "NotFoundException", "during initialisation of RMGUtils.");
            RMGUtils.exit();
        }

        dummyClass = pool.makeInterface("de.qtc.rmg.Dummy");
    }

    public static Class makeInterface(String className) throws CannotCompileException
    {
        try {
            return Class.forName(className);
        } catch (ClassNotFoundException e) {
            /*
             * className is not known and was not created before. This is usually expected.
             * In this case, we just create the class :)
             */
        }

        CtClass intf = pool.makeInterface(className, remoteClass);
        CtMethod dummyMethod = CtNewMethod.make("public void rmgInvokeObject(String str) throws java.rmi.RemoteException;", intf);

        intf.addMethod(dummyMethod);
        dummyMethod = CtNewMethod.make("public void rmgInvokePrimitive(int i) throws java.rmi.RemoteException;", intf);
        intf.addMethod(dummyMethod);

        return intf.toClass();
    }

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
            /*gadget
             * className is not known and was not created before. This is usually expected.
             * In this case, we just create the class :)
             */
            intf = pool.makeInterface(className, remoteClass);
        }

        CtMethod dummyMethod = CtNewMethod.make("public " + candidate.getSignature() + " throws java.rmi.RemoteException;", intf);
        intf.addMethod(dummyMethod);

        return intf.toClass();
    }

    public static Class makeLegacyStub(String className) throws CannotCompileException
    {
        try {
            return Class.forName(className);
        } catch (ClassNotFoundException e) {
            /*
             * className is not known and was not created before. This is usually expected.
             * In this case, we just create the class :)
             */
        }

        CtClass intf = pool.makeInterface(className + "Interface", remoteClass);
        CtMethod dummyMethod = CtNewMethod.make("public void rmgInvokeObject(String str) throws java.rmi.RemoteException;", intf);

        intf.addMethod(dummyMethod);
        dummyMethod = CtNewMethod.make("public void rmgInvokePrimitive(int i) throws java.rmi.RemoteException;", intf);
        intf.addMethod(dummyMethod);
        intf.toClass();

        CtClass ctClass = pool.makeClass(className, remoteStubClass);
        ctClass.setInterfaces(new CtClass[] { intf });

        CtField serialID = new CtField(CtPrimitiveType.longType, "serialVersionUID", ctClass);
        serialID.setModifiers(Modifier.PRIVATE | Modifier.STATIC | Modifier.FINAL);
        ctClass.addField(serialID, CtField.Initializer.constant(2L));

        return ctClass.toClass();
    }

    public static Class makeLegacyStub(String className, MethodCandidate candidate) throws CannotCompileException
    {
        try {
            return Class.forName(className);
        } catch (ClassNotFoundException e) {}

        CtClass intf = pool.makeInterface(className + "Interface", remoteClass);
        CtMethod dummyMethod = CtNewMethod.make("public " + candidate.getSignature() + " throws java.rmi.RemoteException;", intf);
        intf.addMethod(dummyMethod);
        Class intfClass = intf.toClass();

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

        int tmp;
        String type;
        List<String> types = new ArrayList<String>();

        type = signature.substring(0, functionStart);
        types.add(type);

        if( signature.contains("()") )
            return types;

        while( argumentsStart > 1 ) {
            tmp = signature.indexOf(' ', argumentsStart);
            type = signature.substring(argumentsStart, tmp);
            types.add(type);
            argumentsStart = signature.indexOf(',', tmp) + 2;
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

    public static Object getPayloadObject(String ysoPath, String gadget, String command) {

        Object ysoPayload = null;
        File ysoJar = new File(ysoPath);

        if( !ysoJar.exists() ) {
            Logger.eprintlnMixedYellow("Error:", ysoJar.getAbsolutePath(), "does not exist.");
            RMGUtils.exit();
        }

        Logger.print("Creating ysoserial payload...");

        try {
            URLClassLoader ucl = new URLClassLoader(new URL[] {ysoJar.toURI().toURL()});

            Class<?> yso = Class.forName("ysoserial.payloads.ObjectPayload$Utils", true, ucl);
            Method method = yso.getDeclaredMethod("makePayloadObject", new Class[] {String.class, String.class});

            ysoPayload = method.invoke(null, new Object[] {gadget, command});

        } catch (MalformedURLException | ClassNotFoundException | NoSuchMethodException | SecurityException |
                IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {

            Throwable ex = e;
            if( e instanceof InvocationTargetException )
                ex = e.getCause();

            Logger.eprintlnMixedYellow("Error: Unable to create ysoserial gadget", gadget);
            Logger.eprintlnMixedYellow("Error message is:", ex.getMessage());
            RMGUtils.stackTrace(e);
            RMGUtils.exit();
        }

        Logger.printlnPlain("done.");
        return ysoPayload;
    }

    public static Throwable getCause(Throwable e)
    {
        Throwable cause = null;
        Throwable result = e;

        while(null != (cause = result.getCause())  && (result != cause) ) {
            result = cause;
        }
        return result;
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
            Logger.eprintlnMixedYellow("Unable to load properties file", filename);
            RMGUtils.stackTrace(e);
            RMGUtils.exit();
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

    public static void stackTrace(Exception e)
    {
        Logger.eprintln("StackTrace:");
        e.printStackTrace();
    }
}
