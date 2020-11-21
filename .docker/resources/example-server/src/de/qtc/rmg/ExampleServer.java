package de.qtc.rmg.server;

import java.rmi.AccessException;
import java.rmi.AlreadyBoundException;
import java.rmi.NotBoundException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;

import javax.rmi.ssl.SslRMIClientSocketFactory;
import javax.rmi.ssl.SslRMIServerSocketFactory;

import de.qtc.rmg.server.interfaces.IPlainServer;
import de.qtc.rmg.server.interfaces.ISecureServer;
import de.qtc.rmg.server.interfaces.ISslServer;
import de.qtc.rmg.server.legacy.LegacyServer;
import de.qtc.rmg.server.operations.PlainServer;
import de.qtc.rmg.server.operations.SecureServer;
import de.qtc.rmg.server.operations.SslServer;

public class ExampleServer {

    private static int registryPort = 1090;
    private static Remote remoteObject1 = null;
    private static Remote remoteObject2 = null;
    private static Remote remoteObject3 = null;

    public static void main(String[] argv)
    {
        System.out.println("[+] Initializing Java RMI Server:");

        if (System.getSecurityManager() == null) {
            System.setSecurityManager(new SecurityManager());
        }

        try {
            SslRMIClientSocketFactory csf = new SslRMIClientSocketFactory();
            SslRMIServerSocketFactory ssf = new SslRMIServerSocketFactory();

            System.out.print("[+] \tCreating RMI-Registry on port " + registryPort + "... ");
            Registry registry = LocateRegistry.createRegistry(registryPort, csf, ssf);
            System.out.println("done.");

            System.out.print("[+] \tCreating Plain Server object... ");
            remoteObject1 = new PlainServer();
            IPlainServer stub = (IPlainServer)UnicastRemoteObject.exportObject(remoteObject1, 0);
            System.out.println("done.");
            bindToRegistry(stub, registry, "plain-server");

            System.out.print("[+] \tCreating SSL Server object... ");
            remoteObject2 = new SslServer();
            ISslServer stub2 = (ISslServer)UnicastRemoteObject.exportObject(remoteObject2, 0, csf, ssf);
            System.out.println("done.");
            bindToRegistry(stub2, registry, "ssl-server");

            System.out.print("[+] \tCreating Secure Server object... ");
            remoteObject3 = new SecureServer();
            ISecureServer stub3 = (ISecureServer)UnicastRemoteObject.exportObject(remoteObject3, 0);
            System.out.println("done.");
            bindToRegistry(stub3, registry, "secure-server");

            System.out.println("[+] \tServer setup finished.\n[+]");
            System.out.println("[+] Initializing legacy server.");

            LegacyServer.init();

        } catch (RemoteException | AlreadyBoundException | NotBoundException e) {
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
