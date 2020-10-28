package de.qtc.rmg.utils;

import java.rmi.Remote;
import java.util.ArrayList;
import java.util.List;

import de.qtc.rmg.io.Logger;
import javassist.CannotCompileException;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;
import javassist.CtNewMethod;
import javassist.NotFoundException;

public class RMGUtils {

    private static ClassPool pool;
    private static CtClass remoteClass;
    private static String templateFolder;
    private static String methodTemplate;
    private static CtClass dummyClass;

    public static void init(String tmplFolder)
    {
        pool = ClassPool.getDefault();
        templateFolder = tmplFolder;
        methodTemplate = "public void dummy() throws java.rmi.RemoteException;";

        try {
            remoteClass = pool.getCtClass(Remote.class.getName());
        } catch (NotFoundException e) {
            Logger.printlnMixedYellow("Caught", "NotFoundException", "during initialisation of RMGUtils.");
            Logger.eprintln("Unable to continue from here.");
            System.exit(1);
        }
    }

    public static CtClass getDummyClass()
    {
        if( dummyClass != null )
            return dummyClass;

        dummyClass = pool.makeInterface("de.qtc.rmg.Dummy");
        return dummyClass;
    }

    @SuppressWarnings("rawtypes")
    public static Class makeInterface(String className) throws CannotCompileException
    {
        CtClass intf = pool.makeInterface(className, remoteClass);
        CtMethod dummyMethod = CtNewMethod.make(methodTemplate, intf);
        intf.addMethod(dummyMethod);
        return intf.toClass();
    }

    public static CtMethod makeMethod(String signature) throws CannotCompileException
    {
        CtClass dummyClass = RMGUtils.getDummyClass();
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
}
