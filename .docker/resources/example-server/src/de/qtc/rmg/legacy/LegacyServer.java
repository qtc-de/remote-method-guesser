package de.qtc.rmg.legacy;

import java.net.MalformedURLException;
import java.rmi.AccessException;
import java.rmi.AlreadyBoundException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;

import de.qtc.rmg.interfaces.IPlainServer;
import de.qtc.rmg.operations.PlainServer;

@SuppressWarnings("unused")
public class LegacyServer {

    private static int registryPort = 9010;
    private static Remote remoteObject1 = null;
    private static Remote remoteObject2 = null;
    private static Remote remoteObject3 = null;

    public static void init()
    {
        try {
            System.out.print("[+] \tCreating RMI-Registry on port " + registryPort + "... ");
            Registry registry = LocateRegistry.createRegistry(registryPort);
            System.out.println("done.");

            System.out.print("[+] \tCreating LegacyServiceImpl object... ");
            remoteObject1 = new LegacyServiceImpl();
            System.out.println("done.");

            System.out.print("[+] \t\tBindung LegacyServiceImpl as legacy-service... ");
            Naming.rebind("//127.0.0.1:" + registryPort + "/legacy-service", remoteObject1);
            System.out.println("done.");

            Object o = registry.lookup("legacy-service");
            String className = o.getClass().getName();
            System.out.println("[+] \t\tBoundname 'legacy-service' as class '" + className + "' is ready." );

            System.out.print("[+] \tCreating Plain Server object... ");
            remoteObject2 = new PlainServer();
            IPlainServer stub1 = (IPlainServer)UnicastRemoteObject.exportObject(remoteObject2, 0);
            System.out.println("done.");
            bindToRegistry(stub1, registry, "plain-server");

            System.out.print("[+] \tCreating another Plain Server object... ");
            remoteObject3 = new PlainServer();
            IPlainServer stub2 = (IPlainServer)UnicastRemoteObject.exportObject(remoteObject3, 0);
            System.out.println("done.");
            bindToRegistry(stub2, registry, "plain-server2");

            System.out.println("[+] Server setup finished.\n[+]");
            System.out.println("[+] Waiting for incoming connections.");

        } catch (RemoteException | MalformedURLException | AlreadyBoundException | NotBoundException e) {
            System.err.println("[-] Unexpected RMI Error:");
            e.printStackTrace();
        }
    }

    public static void bindToRegistry(Remote object, Registry registry, String boundName) throws AccessException, RemoteException, AlreadyBoundException, NotBoundException
    {
        System.out.print("[+] \t\tBinding Server as '" + boundName + "'... ");
        registry.bind(boundName, object);
        System.out.println("done.");

        Object o = registry.lookup(boundName);
        String className = o.getClass().getName();
        System.out.println("[+] \t\tBoundname '" + boundName + "' as class '" + className + "' is ready.");
    }
}
