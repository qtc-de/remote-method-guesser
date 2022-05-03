package de.qtc.rmg.server;

import java.rmi.AlreadyBoundException;
import java.rmi.NotBoundException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;

import javax.rmi.ssl.SslRMIClientSocketFactory;
import javax.rmi.ssl.SslRMIServerSocketFactory;

import de.qtc.rmg.server.activation.ActivationServer;
import de.qtc.rmg.server.interfaces.IPlainServer;
import de.qtc.rmg.server.interfaces.ISecureServer;
import de.qtc.rmg.server.interfaces.ISslServer;
import de.qtc.rmg.server.legacy.LegacyServer;
import de.qtc.rmg.server.operations.PlainServer;
import de.qtc.rmg.server.operations.SecureServer;
import de.qtc.rmg.server.operations.SslServer;
import de.qtc.rmg.server.utils.Logger;
import de.qtc.rmg.server.utils.Utils;

public class ExampleServer {

    private static int registryPort = 1090;
    private static Remote remoteObject1 = null;
    private static Remote remoteObject2 = null;
    private static Remote remoteObject3 = null;

    public static void main(String[] argv)
    {
        String disableColor = System.getProperty("de.qtc.rmg.server.disableColor");
        if (disableColor != null && disableColor.equalsIgnoreCase("true"))
            Logger.disableColor();

        Logger.println("Initializing Java RMI Server:");
        Logger.println("");
        Logger.increaseIndent();

        if (System.getSecurityManager() == null) {
            System.setSecurityManager(new SecurityManager());
        }

        try {
            SslRMIClientSocketFactory csf = new SslRMIClientSocketFactory();
            SslRMIServerSocketFactory ssf = new SslRMIServerSocketFactory();

            Logger.printMixedBlue("Creating", "RMI-Registry", "on port ");
            Logger.printlnPlainYellow(String.valueOf(registryPort));
            Registry registry = LocateRegistry.createRegistry(registryPort, csf, ssf);
            Logger.println("");

            Logger.printlnMixedBlue("Creating", "PlainServer", "object.");
            remoteObject1 = new PlainServer();
            IPlainServer stub = (IPlainServer)UnicastRemoteObject.exportObject(remoteObject1, 0);
            Utils.bindToRegistry(stub, registry, "plain-server");

            Logger.printlnMixedBlue("Creating", "SSLServer", "object.");
            remoteObject2 = new SslServer();
            ISslServer stub2 = (ISslServer)UnicastRemoteObject.exportObject(remoteObject2, 0, csf, ssf);
            Utils.bindToRegistry(stub2, registry, "ssl-server");

            Logger.printlnMixedBlue("Creating", "SecureServer", "object.");
            remoteObject3 = new SecureServer();
            ISecureServer stub3 = (ISecureServer)UnicastRemoteObject.exportObject(remoteObject3, 0);
            Utils.bindToRegistry(stub3, registry, "secure-server");

            Logger.decreaseIndent();
            Logger.println("");
            Logger.println("Server setup finished.");
            Logger.println("Initializing legacy server.");
            Logger.println("");

            LegacyServer.init();
            ActivationServer.init();

        } catch (RemoteException | AlreadyBoundException | NotBoundException e) {
            Logger.eprintln("Unexpected RMI Error:");
            e.printStackTrace();
        }
    }
}
