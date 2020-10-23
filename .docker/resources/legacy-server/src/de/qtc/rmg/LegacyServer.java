package de.qtc.rmg;

import java.rmi.AccessException;
import java.rmi.Remote;
import java.rmi.Naming;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.net.MalformedURLException;

public class LegacyServer {

    private static int registryPort = 1090;
    private static Remote remoteObject = null;

    public static void main(String[] argv)
    {
        try {
            System.out.print("[+] Creating RMI-Registry on port " + registryPort + "... ");
            LocateRegistry.createRegistry(registryPort);
            System.out.println("done.");

            System.out.print("[+] Creating LegacyServiceImpl object... ");
            remoteObject = new LegacyServiceImpl();
            System.out.println("done.");

            System.out.print("[+] Bindung LegacyServiceImpl as LegacyService... ");
            Naming.rebind("//127.0.0.1:" + registryPort + "/LegacyService", remoteObject);
            System.out.println("done.");

            System.out.println("[+] Server setup finished.");
            System.out.println("[+] Waiting for incoming connections.");

        } catch (RemoteException | MalformedURLException e) {
            System.err.println("[-] Unexpected RMI Error:");
            e.printStackTrace();
        }
    }
}
