package de.qtc.rmg.internal;

import java.net.MalformedURLException;
import java.rmi.server.RMIClassLoader;
import java.rmi.server.RMIClassLoaderSpi;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

public class CodebaseCollector extends RMIClassLoaderSpi {

    private static HashMap<String, Set<String>> codebases = new HashMap<String,Set<String>>();
    private static RMIClassLoaderSpi originalLoader = RMIClassLoader.getDefaultProviderInstance();

    public Class<?> loadClass(String codebase, String name, ClassLoader defaultLoader) throws MalformedURLException, ClassNotFoundException
    {
        if( codebase != null )
            addCodebase(codebase, name);

        codebase = null;
        return originalLoader.loadClass(codebase, name, defaultLoader);
    }

    public Class<?> loadProxyClass(String codebase, String[] interfaces, ClassLoader defaultLoader) throws MalformedURLException, ClassNotFoundException
    {
        if( codebase != null )
            addCodebase(codebase, interfaces[0]);

        codebase = null;
        return originalLoader.loadProxyClass(codebase, interfaces, defaultLoader);
    }

    public ClassLoader getClassLoader(String codebase) throws MalformedURLException
    {
        return originalLoader.getClassLoader(codebase);
    }

    public String getClassAnnotation(Class<?> cl) {
        return originalLoader.getClassAnnotation(cl);
    }

    public static HashMap<String,Set<String>> getCodebases()
    {
        return codebases;
    }

    private void addCodebase(String codebase, String className)
    {
        if( className.startsWith("java.") || className.contains("java.lang.") )
            return;

        if( codebases.containsKey(codebase) ) {
            Set<String> classNames = codebases.get(codebase);
            classNames.add(className);

        } else {
            Set<String> classNames = new HashSet<String>();
            classNames.add(className);
            codebases.put(codebase, classNames);
        }
    }
}
