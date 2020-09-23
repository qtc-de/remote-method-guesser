package de.qtc.rmg;

import java.io.File;
import java.io.FileNotFoundException;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.rmi.ServerException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import de.qtc.rmg.io.Logger;
import de.qtc.rmg.utils.ClassWriter;
import de.qtc.rmg.utils.JavaUtils;
import de.qtc.rmg.utils.RMIWhisperer;
import de.qtc.rmg.utils.UnexpectedCharacterException;

public class MethodGuesser {

    private RMIWhisperer rmi;
    private HashMap<String,String> classes;
    private ClassWriter classWriter;
    private JavaUtils javaUtils;

    public MethodGuesser(RMIWhisperer rmiRegistry, HashMap<String,String> unknownClasses, ClassWriter classWriter, JavaUtils javaUtils) {
        this.rmi = rmiRegistry;
        this.classes = unknownClasses;
        this.classWriter = classWriter;
        this.javaUtils = javaUtils;
    }

    public HashMap<String,ArrayList<Method>> guessMethods(int threads, boolean writeSamples) {
        return this.guessMethods(null, threads, writeSamples);
    }

    public HashMap<String,ArrayList<Method>> guessMethods(String targetName, int threads, boolean writeSamples) {

        HashMap<String,ArrayList<Method>> results = new HashMap<String,ArrayList<Method>>();

        File[] templateFiles = classWriter.getTemplateFiles();
        if( templateFiles == null || templateFiles.length == 0 ) {

            Logger.eprintln("Error: Could not find any template files");
            Logger.eprintln("Stopping RMG attack");
            System.exit(1);

        }

        Logger.println("\n[+] Starting RMG Attack");
        Logger.increaseIndent();
        Logger.println(templateFiles.length + " template files found.");

        String dummyPath = classWriter.templateFolder + "/LookupDummy.java";
        try {
            javaUtils.compile(dummyPath);
        } catch (FileNotFoundException | UnexpectedCharacterException e1) {
            Logger.eprintln("Unable to compile 'LookupDummy.java'.");
            Logger.eprintln("Cannot proceed from here.");
            Logger.eprintln("Stacktrace:");
            e1.printStackTrace();
        }

        for( File templateFile : templateFiles ) {
            URLClassLoader ucl = null;

            try {
                URL loadPath = new File(javaUtils.buildFolder).toURI().toURL();
                URL newClassPath[] = new URL[]{loadPath};
                ucl = new URLClassLoader(newClassPath);

            } catch ( Exception e ) {
                Logger.eprintln("Error: Unexpected exception was thrown: " + e.getMessage());
                System.exit(1);
            }

            String templateName = templateFile.getName();
            Logger.println("");
            Logger.println_bl("Current template file: '" + templateName + "'");
            Logger.println("");

            Iterator<Entry<String, String>> it = this.classes.entrySet().iterator();
            while (it.hasNext()) {

                @SuppressWarnings("rawtypes")
                Map.Entry pair = (Map.Entry)it.next();

                String boundName = (String) pair.getKey();
                String className = (String) pair.getValue();

                if( targetName != null && !targetName.equals(boundName) ) {
                    continue;
                }

                Logger.increaseIndent();
                Logger.println_bl("Attacking boundName '" + boundName + "'.");

                try {
                    classWriter.loadTemplate(templateName);
                    String newClass = classWriter.writeClass(className);
                    javaUtils.compile(newClass);
                } catch(UnexpectedCharacterException | FileNotFoundException e) {
                    Logger.eprintln("Error during class creation.");
                    Logger.eprint("Exception message: ");
                    Logger.eprintlnPlain_ye(e.getMessage());
                    continue;
                }

                Class<?> remoteClass = null;
                Class<?> lookupDummy = null;
                try {
                    remoteClass = ucl.loadClass(className);
                    lookupDummy = ucl.loadClass("de.qtc.rmg.LookupDummy");

                } catch( Exception e ) {
                    Logger.eprintln("Error: Unable to load required classes dynamically.");
                    Logger.eprint("The following exception was thrown: ");
                    Logger.eprintlnPlain_ye(e.getMessage());
                    System.exit(1);
                }

                Method[] lookupMethods = lookupDummy.getDeclaredMethods();
                Logger.println("Getting instance of '" + boundName + "'...");

                Object[] arguments = new Object[]{this.rmi.getRegistry(), boundName};
                Object instance = null;

                try {
                    instance = lookupMethods[0].invoke(lookupDummy, arguments);
                } catch( Exception e ) {
                    Logger.eprintln("Error: Unable to get instance for '" + boundName + "'.");
                    Logger.eprint("The following exception was thrown: ");
                    Logger.eprintlnPlain_ye(e.getMessage());
                    System.exit(1);
                }

                Logger.println("Guessing methods...\n[+]");
                Logger.increaseIndent();

                Method[] methodList = remoteClass.getDeclaredMethods();
                ArrayList<Method> existingMethods = new ArrayList<Method>();

                ExecutorService pool = Executors.newFixedThreadPool(threads);
                for( Method method : methodList ) {
                    Runnable r = new Threader(method, instance, existingMethods);
                    pool.execute(r);
                }

                pool.shutdown();

                try {
                     pool.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);
                } catch (InterruptedException e) {
                     Logger.eprintln("Interrupted!");
                }

                Logger.decreaseIndent();
                Logger.println("");
                Logger.println(existingMethods.size() + " valid method names were identified for '" + templateName + "'.");

                if ( writeSamples ) {

                    for( Method method : existingMethods ) {

                        Logger.println("Writing sample class for method '" + method.getName() + "'.");
                        Logger.increaseIndent();

                        String[] seperated = ClassWriter.splitNames(className);
                        String packageOnly = seperated[0];
                        String classOnly = seperated[1];

                        try {
                            String sampleClassName = classOnly + method.getName().substring(0,1).toUpperCase() + method.getName().substring(1) + "Sample";
                            classWriter.prepareSample(packageOnly, classOnly, boundName, method, sampleClassName, this.rmi.host, this.rmi.port);
                            classWriter.writeSample();

                        } catch(UnexpectedCharacterException e) {
                            Logger.eprintln("Error during sample creation.");
                            Logger.eprint("Exception message: ");
                            Logger.eprintlnPlain_ye(e.getMessage());
                        }

                        Logger.decreaseIndent();
                        Logger.println("");
                    }
                }

                if( results.containsKey(boundName) ) {
                    ArrayList<Method> tmp = results.get(boundName);
                    tmp.addAll(existingMethods);
                } else {
                    results.put(boundName, existingMethods);
                }

                Logger.decreaseIndent();
            }
        }
        return results;
    }
}

class Threader implements Runnable {

    private Method method;
    private Object instance;
    private ArrayList<Method> existingMethods;

    public Threader(Method method, Object instance, ArrayList<Method> existingMethods) {
        this.method = method;
        this.instance = instance;
        this.existingMethods = existingMethods;
    }

    public void run() {

        int parameterCount = method.getParameterCount();

        Object[] parameters = new Object[parameterCount];
        Class<?>[] classes = method.getParameterTypes();

        for(int ctr = 0; ctr < parameterCount; ctr++) {

            if( classes[ctr].isPrimitive() ) {

                if( classes[ctr] == Integer.TYPE ) {
                    parameters[ctr] = 0;
                } else if( classes[ctr] == Boolean.TYPE ) {
                    parameters[ctr] = true;
                }

            } else {
                parameters[ctr] = null;
            }
        }

        try {
            method.invoke(instance, parameters);

        } catch( Exception e ) {

            Throwable cause = e.getCause();
            if( cause != null ) {

                if( cause instanceof ServerException) {
                    if( cause.getCause() instanceof java.rmi.UnmarshalException)
                        return;

                } else if( cause instanceof java.rmi.UnknownHostException  ) {
                    Logger.eprintln("Warning! Object tries to connect to unknown host: " + cause.getCause().getMessage());
                    return;
                }
            }
        }

        Logger.println_ye("HIT: " + method.toGenericString() + " --> exists!");
        existingMethods.add(method);
    }
}
