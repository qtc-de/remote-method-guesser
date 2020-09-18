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

            System.err.println("[-] Error: Could not find any template files");
            System.err.println("[-] Stopping RMG attack");
            System.exit(1);

        }

        Logger.println("[+]\n[+] Starting RMG Attack");
        Logger.println("[+]\t\t" + templateFiles.length + " template files found.");

        String dummyPath = classWriter.templateFolder + "/LookupDummy.java";
        try {
            javaUtils.compile(dummyPath);
        } catch (FileNotFoundException | UnexpectedCharacterException e1) {
            System.err.println("[-] Unable to compile 'LookupDummy.java'.");
            System.err.println("[-] Cannot proceed from here.");
            System.err.println("[-] Stacktrace:");
            e1.printStackTrace();
        }

        for( File templateFile : templateFiles ) {

            URLClassLoader ucl = null;

            try {

                URL loadPath = new File(javaUtils.buildFolder).toURI().toURL();
                URL newClassPath[] = new URL[]{loadPath};
                ucl = new URLClassLoader(newClassPath);

            } catch ( Exception e ) {

                System.err.println("[-] Error: Unexpected exception was thrown: " + e.getMessage());
                System.exit(1);
            }

            String templateName = templateFile.getName();
            Logger.println("[+]");
            Logger.println_bl("\tCurrent template file: '" + templateName + "'");
            Logger.println("[+]");

            Iterator<Entry<String, String>> it = this.classes.entrySet().iterator();
            while (it.hasNext()) {

                @SuppressWarnings("rawtypes")
                Map.Entry pair = (Map.Entry)it.next();

                String boundName = (String) pair.getKey();
                String className = (String) pair.getValue();

                if( targetName != null && !targetName.equals(boundName) ) {
                    continue;
                }
                Logger.println_bl("\t\tAttacking boundName '" + boundName + "'.");

                try {
                    classWriter.loadTemplate(templateName);
                    String newClass = classWriter.writeClass(className);
                    javaUtils.compile(newClass);
                } catch(UnexpectedCharacterException | FileNotFoundException e) {
                    System.err.println("[-]\t\tError during class creation.");
                    System.err.println("[-]\t\tError message: " + e.getMessage());
                    continue;
                }

                Class<?> remoteClass = null;
                Class<?> lookupDummy = null;
                try {

                    remoteClass = ucl.loadClass(className);
                    lookupDummy = ucl.loadClass("de.qtc.rmg.LookupDummy");

                } catch( Exception e ) {

                    System.err.println("[-] Error: Unable to load required classes dynamically.");
                    System.err.println("[-] The following exception was thrown: " + e.getMessage());
                    System.exit(1);

                }

                Method[] lookupMethods = lookupDummy.getDeclaredMethods();
                Logger.print("[+]\t\tGetting instance of '" + boundName + "'... ");

                Object[] arguments = new Object[]{this.rmi.getRegistry(), boundName};
                Object instance = null;

                try {
                    instance = lookupMethods[0].invoke(lookupDummy, arguments);
                } catch( Exception e ) {
                    System.err.println("[-] Error: Unable to get instance for '" + boundName + "'.");
                    System.err.println("[-] The following exception was thrown: " + e.getMessage());
                    System.exit(1);
                }

                Logger.println("done.");
                Logger.println("[+]\t\tGuessing methods...\n[+]");

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
                     Logger.println("[/] Interrupted!");
                }

                Logger.println("[+]\n[+]\t\t" + existingMethods.size() + " valid method names were identified for '" + templateName + "'.");

                if ( writeSamples ) {

                    for( Method method : existingMethods ) {

                        Logger.println_ye("\t\tWriting sample class for method '" + method.getName() + "'.");
                        String[] seperated = ClassWriter.splitNames(className);
                        String packageOnly = seperated[0];
                        String classOnly = seperated[1];

                        try {
                            String sampleClassName = classOnly + method.getName().substring(0,1).toUpperCase() + method.getName().substring(1) + "Sample";
                            classWriter.prepareSample(packageOnly, classOnly, boundName, method, sampleClassName, this.rmi.host, this.rmi.port);
                            String samplePath = classWriter.writeSample();
                            javaUtils.compile(samplePath);
                            javaUtils.packJar(sampleClassName, sampleClassName + ".jar");

                        } catch(UnexpectedCharacterException | FileNotFoundException e) {
                            System.err.println("[-]\t\tError during sample creation.");
                            System.err.println("[-]\t\tError message: " + e.getMessage());
                        }

                        Logger.println("[+]");
                    }

                }

                if( results.containsKey(boundName) ) {
                    ArrayList<Method> tmp = results.get(boundName);
                    tmp.addAll(existingMethods);
                } else {
                    results.put(boundName, existingMethods);
                }
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
            if( e.getCause() != null && e.getCause() instanceof ServerException)
                if( e.getCause().getCause() instanceof java.rmi.UnmarshalException)
                    return;
        }

        Logger.println_ye("\t\t\tHIT: " + method.toGenericString() + " --> exists!");
        existingMethods.add(method);
    }
}
