package de.qtc.rmg.server.activation;

import java.rmi.AccessException;
import java.rmi.AlreadyBoundException;
import java.rmi.NotBoundException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.activation.Activatable;
import java.rmi.activation.ActivationDesc;
import java.rmi.activation.ActivationGroup;
import java.rmi.activation.ActivationGroupDesc;
import java.rmi.activation.ActivationGroupID;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.util.Properties;

import de.qtc.rmg.server.interfaces.IPlainServer;
import de.qtc.rmg.server.operations.PlainServer;
import de.qtc.rmg.server.utils.Logger;
import de.qtc.rmg.server.utils.Utils;

/**
 * Create an ActivationServer. This class does basically the same as rmid, but skips some configuration
 * steps and does only the necessary once. The resulting server seems to work fine, but it is possible
 * that it is not fully functional due to some missing configuration steps.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
@SuppressWarnings("unused")
public class ActivationServer
{
    private static int activationSystemPort = 1098;
    private static Remote remoteObject1 = null;
    private static Remote remoteObject2 = null;
    private static Remote remoteObject3 = null;

    private final static String codebase = "file:///opt/example-server.jar";

    /**
     * Create the RMI registry and the Activator and bind an ActivationSystem to it. Afterwards, an activation
     * group is created and two activatable RMI services are bound to the registry. Additionally, we bind one
     * non activatable service.
     */
    public static void init()
    {
        Logger.increaseIndent();

        try {
            Logger.printMixedBlue("Creating", "ActivationSystem", "on port ");
            Logger.printlnPlainYellow(String.valueOf(activationSystemPort));
            Utils.startActivation(activationSystemPort, null, "/tmp/activation-log", null);

            Properties props = new Properties();
            props.put("java.security.policy", "/opt/policy");
            props.put("java.security.debug", "");

            ActivationGroupDesc groupDesc = new ActivationGroupDesc(props, null);

            /*
             * In the following we register the activation group. For some reason, this creates a ThreadDump,
             * although the operation finished and the group is registered correctly. I have no idea where this
             * ThreadDump comes from. If someone knows, please create an issue that explains it :)
             *
             * The code below disables stderr temporarily to prevent the ThreadDump to confuse users. Here is
             * the StackTrace that would be shown otherwise:
             *       java.lang.Exception: Stack trace
             *      at java.lang.Thread.dumpStack(Thread.java:1336)
             *      at sun.rmi.server.Activation$ActivationSystemImpl.registerGroup(Activation.java:538)
             *      at sun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
             *      at sun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)
             *      at sun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)
             *      at java.lang.reflect.Method.invoke(Method.java:498)
             *      at sun.rmi.server.UnicastServerRef.dispatch(UnicastServerRef.java:357)
             *      at sun.rmi.transport.Transport$1.run(Transport.java:200)
             *      at sun.rmi.transport.Transport$1.run(Transport.java:197)
             *      at java.security.AccessController.doPrivileged(Native Method)
             *      at sun.rmi.transport.Transport.serviceCall(Transport.java:196)
             *      at sun.rmi.transport.tcp.TCPTransport.handleMessages(TCPTransport.java:573)
             *      at sun.rmi.transport.tcp.TCPTransport$ConnectionHandler.run0(TCPTransport.java:834)
             *      at sun.rmi.transport.tcp.TCPTransport$ConnectionHandler.lambda$run$0(TCPTransport.java:688)
             *      at java.security.AccessController.doPrivileged(Native Method)
             *      at sun.rmi.transport.tcp.TCPTransport$ConnectionHandler.run(TCPTransport.java:687)
             *      at java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1149)
             *      at java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:624)
             *      at java.lang.Thread.run(Thread.java:748)
             */
            Utils.toogleOutput();
            ActivationGroupID groupID = ActivationGroup.getSystem().registerGroup(groupDesc);
            Utils.toogleOutput();

            ActivationDesc desc = new ActivationDesc(groupID, ActivationService.class.getName(), codebase, null);
            remoteObject1 = Activatable.register(desc);

            ActivationDesc desc2 = new ActivationDesc(groupID, ActivationService2.class.getName(), codebase, null);
            remoteObject2 = Activatable.register(desc2);

            remoteObject3 = new PlainServer();
            IPlainServer stub = (IPlainServer)UnicastRemoteObject.exportObject(remoteObject3, 0);

            Utils.bindToRegistry(remoteObject1, LocateRegistry.getRegistry(activationSystemPort), "activation-test");
            Utils.bindToRegistry(remoteObject2, LocateRegistry.getRegistry(activationSystemPort), "activation-test2");
            Utils.bindToRegistry(stub, LocateRegistry.getRegistry(activationSystemPort), "plain-server");

            Logger.println("");
            Logger.decreaseIndent();

            Logger.println("Server setup finished.");
            Logger.println("Waiting for incoming connections.");
            Logger.println("");

        } catch (Exception e) {
            Logger.eprintln("Unexpected RMI Error:");
            e.printStackTrace();
        }
    }
}
