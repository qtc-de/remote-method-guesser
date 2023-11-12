package de.qtc.rmg.server.legacy;

import java.net.MalformedURLException;
import java.rmi.AlreadyBoundException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;

import de.qtc.rmg.server.interfaces.IPlainServer;
import de.qtc.rmg.server.operations.PlainServer;
import de.qtc.rmg.server.utils.Logger;
import de.qtc.rmg.server.utils.Utils;

@SuppressWarnings("unused")
public class LegacyServer
{
    private static Remote remoteObjectOne;
    private static Remote remoteObjectTwo;
    private static Remote remoteObjectThree;
    private static Remote remoteObjectFour;

    private static final String boundNameOne = "legacy-service";
    private static final String boundNameTwo = "plain-server";
    private static final String boundNameThree = "plain-server2";

    public static void init(int registryPort)
    {
        Logger.increaseIndent();

        try
        {
            Logger.printMixedBlue("Creating", "RMI-Registry", "on port ");
            Logger.printlnPlainYellow(String.valueOf(registryPort));
            Registry registry = LocateRegistry.createRegistry(registryPort);
            Logger.println("");

            Logger.printlnMixedBlue("Creating", "LegacyServiceImpl", "object.");
            remoteObjectOne = new LegacyServiceImpl();

            Logger.increaseIndent();
            Logger.printMixedYellow("Binding", "LegacyServiceImpl");
            Logger.printlnPlainMixedBlue(" as", "legacy-service");
            Naming.rebind("//127.0.0.1:" + registryPort + "/legacy-service", remoteObjectOne);

            Object o = registry.lookup("legacy-service");
            String className = o.getClass().getName();
            Logger.printMixedYellow("Boundname", boundNameOne);
            Logger.printlnPlainMixedBlue(" with class", className, "is ready.");
            Logger.decreaseIndent();

            Logger.printlnMixedBlue("Creating", "PlainServer", "object.");
            remoteObjectTwo = new PlainServer();
            IPlainServer stub1 = (IPlainServer)UnicastRemoteObject.exportObject(remoteObjectTwo, 0);
            Utils.bindToRegistry(stub1, registry, boundNameTwo);

            Logger.printlnMixedBlue("Creating another", "PlainServer", "object.");
            remoteObjectThree = new PlainServer();
            IPlainServer stub2 = (IPlainServer)UnicastRemoteObject.exportObject(remoteObjectThree, 0);
            Utils.bindToRegistry(stub2, registry, boundNameThree);

            try
            {
                Logger.printlnMixedBlue("Creating", "ActivatorImp", "object.");
                Logger.increaseIndent();

                remoteObjectFour = Utils.getActivator(registryPort, null);
                Logger.printlnMixedYellowFirst("Activator", "is ready.");
            }

            catch (Exception e)
            {
                Logger.printlnYellow("Activator initialization failed.");
            }

            finally
            {
                Logger.decreaseIndent();
            }

            Logger.println("");
            Logger.decreaseIndent();
        }

        catch (RemoteException | MalformedURLException | AlreadyBoundException | NotBoundException e)
        {
            Logger.eprintln("Unexpected RMI Error:");
            e.printStackTrace();
        }
    }
}
