package de.qtc.rmg.utils;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.rmi.Remote;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import de.qtc.rmg.io.Logger;
import javassist.CannotCompileException;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;
import javassist.CtNewMethod;
import javassist.NotFoundException;

@SuppressWarnings("rawtypes")
public class RMGUtils {

    private static ClassPool pool;
    private static CtClass dummyClass;
    private static CtClass remoteClass;

    public static void init()
    {
        pool = ClassPool.getDefault();

        try {
            remoteClass = pool.getCtClass(Remote.class.getName());
        } catch (NotFoundException e) {
            Logger.printlnMixedYellow("Caught", "NotFoundException", "during initialisation of RMGUtils.");
            Logger.eprintln("Unable to continue from here.");
            System.exit(1);
        }

        dummyClass = pool.makeInterface("de.qtc.rmg.Dummy");
    }

    public static Class makeInterface(String className) throws CannotCompileException
    {
        CtClass intf = pool.makeInterface(className, remoteClass);
        CtMethod dummyMethod = CtNewMethod.make("public void rmgInvokeObject(String str) throws java.rmi.RemoteException;", intf);
        intf.addMethod(dummyMethod);
        dummyMethod = CtNewMethod.make("public void rmgInvokePrimitive(int i) throws java.rmi.RemoteException;", intf);
        intf.addMethod(dummyMethod);
        return intf.toClass();
    }

    public static Class makeInterface(String className, String methodSignature) throws CannotCompileException
    {
        CtClass intf = pool.makeInterface(className, remoteClass);
        CtMethod dummyMethod = CtNewMethod.make("public " + methodSignature + " throws java.rmi.RemoteException;", intf);
        intf.addMethod(dummyMethod);
        return intf.toClass();
    }

    public static Class makeRandomClass() throws CannotCompileException, NotFoundException
    {
        String classname = UUID.randomUUID().toString().replaceAll("-", "");
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
            System.exit(1);
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
            Logger.eprintln("StackTrace:");
            ex.printStackTrace();
            System.exit(1);
        }

        Logger.printlnPlain("done.");
        return ysoPayload;
    }


    public static Throwable getCause(Throwable e) {
        Throwable cause = null;
        Throwable result = e;

        while(null != (cause = result.getCause())  && (result != cause) ) {
            result = cause;
        }
        return result;
    }
}
