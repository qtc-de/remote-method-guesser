package de.qtc.rmg.server.utils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.rmi.AccessException;
import java.rmi.AlreadyBoundException;
import java.rmi.NotBoundException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.registry.Registry;
import java.rmi.server.RMIServerSocketFactory;
import java.rmi.server.RemoteObject;

import sun.rmi.server.Activation;

@SuppressWarnings("restriction")
public class Utils
{
    private static PrintStream output = null;

    public static String readFromProcess(Process p) throws IOException
    {
        StringBuilder result = new StringBuilder();

        BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String line = reader.readLine();

        while (line != null) {
            result.append(line);
            line = reader.readLine();
        }

        reader = new BufferedReader(new InputStreamReader(p.getErrorStream()));
        line = reader.readLine();

        while (line != null) {
            result.append(line);
            line = reader.readLine();
        }

        return result.toString();
    }

    /**
     * Copied from https://stackoverflow.com/questions/46454995/how-to-hide-warning-illegal-reflective-access-in-java-9-without-jvm-argument
     */
    public static void disableWarnings()
    {
        try {
            Field theUnsafe = sun.misc.Unsafe.class.getDeclaredField("theUnsafe");
            theUnsafe.setAccessible(true);
            sun.misc.Unsafe u = (sun.misc.Unsafe) theUnsafe.get(null);

            Class<?> cls = Class.forName("jdk.internal.module.IllegalAccessLogger");
            Field logger = cls.getDeclaredField("logger");
            u.putObjectVolatile(cls, u.staticFieldOffset(logger), null);
        } catch (Exception e) {}
    }

    public static RemoteObject getActivator(int port, RMIServerSocketFactory ssf) throws Exception
    {
        disableWarnings();

        Class<?> activationClass = Class.forName("sun.rmi.server.Activation");
        Constructor<?> constructor = activationClass.getDeclaredConstructor(new Class[] {});

        constructor.setAccessible(true);
        Object activation = constructor.newInstance();

        Class<?> activatorImplClass = Class.forName("sun.rmi.server.Activation$ActivatorImpl");
        constructor = activatorImplClass.getDeclaredConstructor(new Class[] {Activation.class, int.class, RMIServerSocketFactory.class});
        constructor.setAccessible(true);

        RemoteObject activator = (RemoteObject)constructor.newInstance(activation, port, ssf);
        return activator;
    }

    public static void startActivation(int port, RMIServerSocketFactory ssf, String logName, String[] args) throws Exception
    {
        disableWarnings();

        Class<?> activationClass = Class.forName("sun.rmi.server.Activation");
        Method startActivation = activationClass.getDeclaredMethod("startActivation", new Class<?>[] { int.class, RMIServerSocketFactory.class, String.class, String[].class } );
        startActivation.setAccessible(true);
        startActivation.invoke(null, port, ssf, logName, new String[] {});
    }

    public static void toogleOutput()
    {
        if (output == null) {
            output = System.err;
            System.setErr(new PrintStream(new OutputStream() { public void write(int arg0) throws IOException {} }));

        } else {
            System.setErr(output);
        }
    }

    public static void bindToRegistry(Remote object, Registry registry, String boundName) throws AccessException, RemoteException, AlreadyBoundException, NotBoundException
    {
        Logger.increaseIndent();
        Logger.printlnMixedYellow("Binding Object as", boundName);
        registry.bind(boundName, object);

        Object o = registry.lookup(boundName);
        String className = o.getClass().getInterfaces()[0].getSimpleName();
        Logger.printMixedYellow("Boundname", boundName);
        Logger.printlnPlainMixedBlue(" with interface", className, "is ready.");
        Logger.decreaseIndent();
    }
}
