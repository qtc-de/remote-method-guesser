package de.qtc.rmg.server.utils;

import java.net.MalformedURLException;
import java.rmi.server.RMIClassLoader;
import java.rmi.server.RMIClassLoaderSpi;

public class CodebaseLogger extends RMIClassLoaderSpi {

    private static RMIClassLoaderSpi originalLoader = RMIClassLoader.getDefaultProviderInstance();

    public Class<?> loadClass(String codebase, String name, ClassLoader defaultLoader) throws MalformedURLException, ClassNotFoundException
    {
        Logger.printlnMixedBlueYellow("[CodebaseLogger]", "Classname:", name);
        Logger.printlnMixedBlueFirst("[CodebaseLogger]", "Codebase:", codebase);

        return originalLoader.loadClass(codebase, name, defaultLoader);
    }

    public Class<?> loadProxyClass(String codebase, String[] interfaces, ClassLoader defaultLoader) throws MalformedURLException, ClassNotFoundException
    {
        Logger.printlnMixedBlueYellow("[CodebaseLogger]", "Classname:", interfaces[0]);
        Logger.printlnMixedBlueFirst("[CodebaseLogger]", "Codebase:", codebase);

        return originalLoader.loadProxyClass(codebase, interfaces, defaultLoader);
    }

    public ClassLoader getClassLoader(String codebase) throws MalformedURLException
    {
        return originalLoader.getClassLoader(codebase);
    }

    public String getClassAnnotation(Class<?> cl) {
        return originalLoader.getClassAnnotation(cl);
    }
}
