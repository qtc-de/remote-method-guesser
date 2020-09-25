package de.qtc.rmg;

import java.rmi.AccessException;
import java.rmi.AlreadyBoundException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;

import javax.rmi.ssl.SslRMIClientSocketFactory;
import javax.rmi.ssl.SslRMIServerSocketFactory;

public class ExampleServer {

    private static int registryPort = 1090;
    private static Remote remoteObject1 = null;
    private static Remote remoteObject2 = null;
    private static Remote remoteObject3 = null;

    public static void main(String[] argv)
    {

        try {
            SslRMIClientSocketFactory csf = new SslRMIClientSocketFactory();
            SslRMIServerSocketFactory ssf = new SslRMIServerSocketFactory();

            System.out.print("[+] Creating RMI-Registry on port " + registryPort + "... ");
            Registry registry = LocateRegistry.createRegistry(registryPort, csf, ssf);
            System.out.println("done.");

            System.out.print("[+] Creating Plain Server object... ");
            remoteObject1 = new PlainServer();
            IPlainServer stub = (IPlainServer)UnicastRemoteObject.exportObject(remoteObject1, 0);
            System.out.println("done.");

            System.out.print("[+] Creating SSL Server object... ");
            remoteObject2 = new SslServer();
            ISslServer stub2 = (ISslServer)UnicastRemoteObject.exportObject(remoteObject2, 0, csf, ssf);
            System.out.println("done.");

            System.out.print("[+] Creating Secure Server object... ");
            remoteObject3 = new SecureServer();
            ISecureServer stub3 = (ISecureServer)UnicastRemoteObject.exportObject(remoteObject3, 0);
            System.out.println("done.");

            bindToRegistry(stub, registry, "plain-server");
            bindToRegistry(stub2, registry, "ssl-server");
            bindToRegistry(stub3, registry, "secure-server");

            System.out.print("[+] Server setup finished.");
            System.out.print("[+] Waiting for incoming connections.");

        } catch (RemoteException | AlreadyBoundException e) {
            System.err.println("[-] Unexpected RMI Error:");
            e.printStackTrace();
        }
    }

    public static void bindToRegistry(Remote object, Registry registry, String boundName) throws AccessException, RemoteException, AlreadyBoundException
    {
        System.out.print("[+] Binding Server as '" + boundName + "'... ");
        registry.bind(boundName, object);
        System.out.println("done.");
        System.err.println("[+] Boundname '" + boundName + "' is ready.");
    }
}
