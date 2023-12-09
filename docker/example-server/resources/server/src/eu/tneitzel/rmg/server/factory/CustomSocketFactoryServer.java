package eu.tneitzel.rmg.server.factory;

import java.rmi.AlreadyBoundException;
import java.rmi.NotBoundException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.RMISocketFactory;
import java.rmi.server.UnicastRemoteObject;

import eu.tneitzel.rmg.server.interfaces.IPlainServer;
import eu.tneitzel.rmg.server.operations.PlainServer;
import eu.tneitzel.rmg.server.utils.Logger;
import eu.tneitzel.rmg.server.utils.Utils;

public class CustomSocketFactoryServer
{
    private static Remote remoteObjectOne;;
    private static final String boundName = "custom-socks";

    public static void startServer(int registryPort)
    {
        Logger.increaseIndent();

        try
        {
            RMISocketFactory csf = new CustomSocketFactory();

            Logger.printMixedBlue("Locating", "RMI-Registry", "on port ");
            Logger.printlnPlainYellow(String.valueOf(registryPort));
            Registry registry = LocateRegistry.getRegistry(registryPort);
            Logger.println("");

            Logger.printlnMixedBlue("Creating", "PlainServer", "object.");
            remoteObjectOne = new PlainServer();
            IPlainServer stub = (IPlainServer)UnicastRemoteObject.exportObject(remoteObjectOne, 0, csf, null);
            Utils.bindToRegistry(stub, registry, boundName);

            Logger.println("Server setup finished.");
        }

        catch (RemoteException | AlreadyBoundException | NotBoundException e)
        {
            Logger.eprintln("Unexpected RMI Error:");
            e.printStackTrace();
        }

        Logger.println("");
        Logger.decreaseIndent();
    }
}
