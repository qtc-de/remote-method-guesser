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
import de.qtc.rmg.server.factory.CustomSocketFactoryServer;
import de.qtc.rmg.server.interfaces.IPlainServer;
import de.qtc.rmg.server.interfaces.ISecureServer;
import de.qtc.rmg.server.interfaces.ISslServer;
import de.qtc.rmg.server.legacy.LegacyServer;
import de.qtc.rmg.server.operations.PlainServer;
import de.qtc.rmg.server.operations.SecureServer;
import de.qtc.rmg.server.operations.SslServer;
import de.qtc.rmg.server.utils.Logger;
import de.qtc.rmg.server.utils.Utils;

public class ExampleServer
{
    private static final int registryPort = 1090;
    private static final int activatorPort = 1098;
    private static final int plainRegistryPort = 9010;

    private static Remote remoteObjectOne;
    private static Remote remoteObjectTwo;
    private static Remote remoteObjectThree;

    private static final String boundNameOne = "plain-server";
    private static final String boundNameTwo = "ssl-server";
    private static final String boundNameThree = "secure-server";

    public static void main(String[] argv)
    {
        String disableColor = System.getProperty("de.qtc.rmg.server.disableColor");

        if (disableColor != null && disableColor.equalsIgnoreCase("true"))
        {
            Logger.disableColor();
        }

        Logger.println("Initializing Java RMI Server:");
        Logger.println("");
        Logger.increaseIndent();

        if (System.getSecurityManager() == null)
        {
            System.setSecurityManager(new SecurityManager());
        }

        try
        {
            SslRMIClientSocketFactory csf = new SslRMIClientSocketFactory();
            SslRMIServerSocketFactory ssf = new SslRMIServerSocketFactory();

            Logger.printMixedBlue("Creating", "RMI-Registry", "on port ");
            Logger.printlnPlainYellow(String.valueOf(registryPort));
            Registry registry = LocateRegistry.createRegistry(registryPort, csf, ssf);
            Logger.println("");

            Logger.printlnMixedBlue("Creating", "PlainServer", "object.");
            remoteObjectOne = new PlainServer();
            IPlainServer stub = (IPlainServer)UnicastRemoteObject.exportObject(remoteObjectOne, 0);
            Utils.bindToRegistry(stub, registry, boundNameOne);

            Logger.printlnMixedBlue("Creating", "SSLServer", "object.");
            remoteObjectTwo = new SslServer();
            ISslServer stub2 = (ISslServer)UnicastRemoteObject.exportObject(remoteObjectTwo, 0, csf, ssf);
            Utils.bindToRegistry(stub2, registry, boundNameTwo);

            Logger.printlnMixedBlue("Creating", "SecureServer", "object.");
            remoteObjectThree = new SecureServer();
            ISecureServer stub3 = (ISecureServer)UnicastRemoteObject.exportObject(remoteObjectThree, 0);
            Utils.bindToRegistry(stub3, registry, boundNameThree);

            Logger.decreaseIndent();
            Logger.println("");
            Logger.println("Server setup finished.");
            Logger.println("Initializing LegacyServer.");
            Logger.println("");

            LegacyServer.init(plainRegistryPort);

            Logger.println("LegacyServer setup finished.");
            Logger.println("Initializing ActivationServer.");
            Logger.println("");

            ActivationServer.init(activatorPort);

            Logger.println("ActivationServer setup finished.");
            Logger.println("Initializing CustomSocketFactoryServer.");
            Logger.println("");

            CustomSocketFactoryServer.startServer(plainRegistryPort);

            Logger.println("Setup finished.");
            Logger.println("Waiting for incoming connections.");
            Logger.println("");
        }

        catch (RemoteException | AlreadyBoundException | NotBoundException e)
        {
            Logger.eprintln("Unexpected RMI Error:");
            e.printStackTrace();
        }
    }
}
