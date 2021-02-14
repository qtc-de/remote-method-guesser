package de.qtc.rmg.internal;

import java.net.MalformedURLException;
import java.rmi.server.RMIClassLoader;
import java.rmi.server.RMIClassLoaderSpi;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

/**
 * The CodebaseCollector class is used to detect server specified codebases and to report
 * them to the user. Such a functionality sounds easy to implement, but it was surprisingly
 * difficult. Java RMI does not support programmatically access to an RMI servers codebase,
 * but only uses it internally for class loading purposes.
 *
 * The trick is to override the default class loader by using the java.rmi.server.RMIClassLoaderSpi
 * property. This property is used to determine the class that is actually used to perform the
 * class loading and its functions are called with the servers specified codebase (if available).
 * When a server side codebase is available, the codebase parameter for methods within RMIClassLoaderSpi
 * is a String that contains the corresponding codebase specification. If no codebase was specified,
 * the codebase parameter is set to null.
 *
 * This class is basically just a proxy to the default implementation of RMIClassLoaderSpi. Before handing
 * off the method calls to the default instance, the codebase is inspected and added to a HashMap for
 * latter output formatting. Additionally, the codebase is always set to null afterwards. This is a security
 * mechanism that is important if a client runs rmg with a SecurityManager. RMIClassLoaderSpi will only be used,
 * if the java.rmi.useCodebaseOnly property is set to false. This enables remote class loading on the client
 * side and could lead to dangerous situations when the client also uses a SecurityManager (required for
 * the actual class loading). However, by setting the codebase manually to null after inspecting it, all classes
 * are treated as no codebase was specified. This should effectively disable remote class loading, despite it
 * beeing enabled.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class CodebaseCollector extends RMIClassLoaderSpi {

    private static HashMap<String, Set<String>> codebases = new HashMap<String,Set<String>>();
    private static RMIClassLoaderSpi originalLoader = RMIClassLoader.getDefaultProviderInstance();

    /**
     * Just a proxy to the loadClass method of the default provider instance. If a codebase
     * was specified, it is added to the codebase list. Afterwards, the codebase is set to
     * null and the call is handed off to the default provider.
     */
    public Class<?> loadClass(String codebase, String name, ClassLoader defaultLoader) throws MalformedURLException, ClassNotFoundException
    {
        if( codebase != null )
            addCodebase(codebase, name);

        codebase = null;
        return originalLoader.loadClass(codebase, name, defaultLoader);
    }

    /**
     * Just a proxy to the loadProxyClass method of the default provider instance. If a codebase
     * was specified, it is added to the codebase list. Afterwards, the codebase is set to
     * null and the call is handed off to the default provider.
     */
    public Class<?> loadProxyClass(String codebase, String[] interfaces, ClassLoader defaultLoader) throws MalformedURLException, ClassNotFoundException
    {
        if( codebase != null )
            addCodebase(codebase, interfaces[0]);

        codebase = null;
        return originalLoader.loadProxyClass(codebase, interfaces, defaultLoader);
    }

    /**
     * Not entirely sure when this function is called (was not observed during any rmg action).
     * However, just null the codebase and pass calls to the default provider instance.
     */
    public ClassLoader getClassLoader(String codebase) throws MalformedURLException
    {
        codebase = null;
        return originalLoader.getClassLoader(codebase);
    }

    /**
     * This function is explicitly called by MarshalOutputStream when serializing RMI objects to
     * obtain the client specified codebase. If the client specified java.rmi.server.codebase,
     * the corresponding string would be returned here.
     *
     * Theoretically, this function could be used for rmg's different codebase attack options.
     * We could always return the user defined codebase here and it would be fine. However, during
     * our research we also attempted to use arbitrary Objects (non String) as annotation. This
     * is surprisingly supported by RMI, as the annotation is always read via readObject and checked
     * for valid String types only afterwards. We thought that this might be usable to bypass the new
     * String unmarshalling of modern RMI servers, but it is not the case. Nonetheless, using this
     * function to return the codebase only supports String types. The currently selected approach
     * of rmg (which is the MaliciousOutputStream class) allows arbitrary objects and is therefore
     * more flexible.
     */
    public String getClassAnnotation(Class<?> cl)
    {
        return originalLoader.getClassAnnotation(cl);
    }

    /**
     * Returns a HashMap that contains all enumerated codebases. The keys of the HashMap
     * represent the actual codebase values. The values of the HashMap represent the classes
     * that were found for the corresponding codebase. Usually, an RMI server should only
     * expose one codebase that is used by all classes. However, just in case...
     *
     * @return HashMap of the collected codebases.
     */
    public static HashMap<String,Set<String>> getCodebases()
    {
        return codebases;
    }

    /**
     * Adds the codebase - className pair into a HashMap. If the codebase was already
     * added before, the className is appended to the Set within the value of the
     * HashMap. Classes that are part of common default packages like java.* are
     * ignored.
     *
     * @param codebase value enumerated by the loader
     * @param className that should be loaded from the codebase
     */
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
