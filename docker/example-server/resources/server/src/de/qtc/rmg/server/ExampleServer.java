package eu.tneitzel.rmg.server;

import java.rmi.AlreadyBoundException;
import java.rmi.NotBoundException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;

import javax.rmi.ssl.SslRMIClientSocketFactory;
import javax.rmi.ssl.SslRMIServerSocketFactory;

import eu.tneitzel.rmg.server.activation.ActivationServer;
import eu.tneitzel.rmg.server.factory.CustomSocketFactoryServer;
import eu.tneitzel.rmg.server.interfaces.IPlainServer;
import eu.tneitzel.rmg.server.interfaces.ISecureServer;
import eu.tneitzel.rmg.server.interfaces.ISslServer;
import eu.tneitzel.rmg.server.legacy.LegacyServer;
import eu.tneitzel.rmg.server.operations.PlainServer;
import eu.tneitzel.rmg.server.operations.SecureServer;
import eu.tneitzel.rmg.server.operations.SslServer;
import eu.tneitzel.rmg.server.utils.Logger;
import eu.tneitzel.rmg.server.utils.Utils;

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
        String disableColor = System.getProperty("eu.tneitzel.rmg.server.disableColor");

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
