package de.qtc.rmg.internal;

import java.net.MalformedURLException;
import java.rmi.server.RMIClassLoader;
import java.rmi.server.RMIClassLoaderSpi;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import de.qtc.rmg.utils.RMGUtils;
import javassist.CannotCompileException;
import javassist.NotFoundException;

/**
 * The CodebaseCollector class is used to detect server specified codebases and to report
 * them to the user. Such a functionality sounds easy to implement, but it was surprisingly
 * difficult. Java RMI does not support programmatically access to an RMI servers codebase,
 * but only uses it internally for class loading purposes.
 *
 * The trick is to override the default class loader by using the java.rmi.server.RMIClassLoaderSpi
 * property. This property is used to determine the class that is actually used to perform the
 * class loading and it's functions are called with the servers specified codebase (if available).
 * When a server side codebase is available, the codebase parameter for methods within RMIClassLoaderSpi
 * is a String that contains the corresponding codebase URL. If no codebase was specified, the codebase
 * parameter is set to null. However, this is only true if the client is running with useCodebaseOnly=false,
 * since otherwise the codebase is always set to null. Therefore, you need to enable remote class loading
 * within the client to obtain the codebase. To prevent security vulnerabilities related to remote class
 * loading, this implementation sets the codebase always to null after extracting the codebase URL.
 *
 * This class is basically just a proxy to the default implementation of RMIClassLoaderSpi. That being said,
 * since remote-method-guesser version 3.4.0, we also implement dynamic class creating right over here. The
 * RMIClassLoaderSpi is always used on MarshalInputStream to resolve classes. Each object that is read from this
 * stream is therefore passing this function. This allows us to catch unknown RMI stub and interface classes
 * and create them dynamically using Javassist. Handling the dynamic class creating in this function has many
 * advantages. The probably biggest one is that you have no longer to distinguish between modern proxy-like
 * remote objects and legacy stubs manually, as they are loaded using different calls (loadClass vs loadProxyClass).
 *
 * Summarized:
 *
 *  1. Extract server specified codebases and store them within a HashMap for later use
 *  2. Set the codebase to null to prevent remote class loading even with useCodebaseOnly=false
 *  3. Check if the requested class is known by the client and dynamically create it if this is not the case.
 *  4. Load the class using the regular class loader and return it.
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
        Class<?> resolvedClass = null;

        addCodebase(codebase, name);
        codebase = null;

        try {

            if( name.endsWith("_Stub") )
                RMGUtils.makeLegacyStub(name);

            resolvedClass = originalLoader.loadClass(codebase, name, defaultLoader);

        } catch (CannotCompileException | NotFoundException e) {
            ExceptionHandler.internalError("loadClass", "Unable to compile unknown stub class.");
        }

        return resolvedClass;
    }

    /**
     * Just a proxy to the loadProxyClass method of the default provider instance. If a codebase
     * was specified, it is added to the codebase list. Afterwards, the codebase is set to
     * null and the call is handed off to the default provider.
     */
    public Class<?> loadProxyClass(String codebase, String[] interfaces, ClassLoader defaultLoader) throws MalformedURLException, ClassNotFoundException
    {
        Class<?> resolvedClass = null;

        try {

            for(String intf : interfaces) {
                RMGUtils.makeInterface(intf);
                addCodebase(codebase, intf);
            }

            codebase = null;
            resolvedClass = originalLoader.loadProxyClass(codebase, interfaces, defaultLoader);

        } catch (CannotCompileException e) {
            ExceptionHandler.internalError("loadProxyClass", "Unable to compile unknown interface class.");
        }

        return resolvedClass;
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
        if( codebase == null )
            return;

        if( className.startsWith(".java") || className.startsWith("[Ljava") )
            codebases.put(codebase, new HashSet<String>());

        else if( codebases.containsKey(codebase) ) {
            Set<String> classNames = codebases.get(codebase);
            classNames.add(className);

        } else {
            Set<String> classNames = new HashSet<String>();
            classNames.add(className);
            codebases.put(codebase, classNames);
        }
    }
}
