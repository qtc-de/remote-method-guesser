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
import java.util.Properties;

import de.qtc.rmg.server.utils.Logger;
import de.qtc.rmg.server.utils.Utils;

@SuppressWarnings("unused")
public class ActivationServer
{
    private static int activationSystemPort = 1098;
    private static Remote remoteObject1 = null;

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

            ActivationDesc desc = new ActivationDesc(groupID, ActivationService.class.getName(), null, null);
            remoteObject1 = Activatable.register(desc);

            Utils.bindToRegistry(remoteObject1, LocateRegistry.getRegistry(activationSystemPort), "activation-test");

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
