package de.qtc.rmg.legacy;

import java.rmi.AccessException;
import java.rmi.Remote;
import java.rmi.Naming;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.net.MalformedURLException;

@SuppressWarnings("unused")
public class LegacyServer {

    private static int registryPort = 9010;
    private static Remote remoteObject = null;

    public static void init()
    {
        try {
            System.out.print("[+] \tCreating RMI-Registry on port " + registryPort + "... ");
            LocateRegistry.createRegistry(registryPort);
            System.out.println("done.");

            System.out.print("[+] \tCreating LegacyServiceImpl object... ");
            remoteObject = new LegacyServiceImpl();
            System.out.println("done.");

            System.out.print("[+] \tBindung LegacyServiceImpl as LegacyService... ");
            Naming.rebind("//127.0.0.1:" + registryPort + "/LegacyService", remoteObject);
            System.out.println("done.");

            System.out.println("[+] Server setup finished.\n[+]");
            System.out.println("[+] Waiting for incoming connections.");

        } catch (RemoteException | MalformedURLException e) {
            System.err.println("[-] Unexpected RMI Error:");
            e.printStackTrace();
        }
    }
}
