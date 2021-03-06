package de.qtc.rmg.server.legacy;

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

import de.qtc.rmg.server.interfaces.IPlainServer;
import de.qtc.rmg.server.operations.PlainServer;
import de.qtc.rmg.server.utils.Logger;
import de.qtc.rmg.server.utils.Utils;

@SuppressWarnings("unused")
public class LegacyServer {

    private static int registryPort = 9010;
    private static Remote remoteObject1 = null;
    private static Remote remoteObject2 = null;
    private static Remote remoteObject3 = null;
    private static Remote remoteObject4 = null;


    public static void init()
    {
        Logger.increaseIndent();

        try {
            Logger.printlnMixedYellow("Creating RMI-Registry on port", String.valueOf(registryPort));
            Registry registry = LocateRegistry.createRegistry(registryPort);
            Logger.println("");

            Logger.printlnMixedBlue("Creating", "LegacyServiceImpl", "object.");
            remoteObject1 = new LegacyServiceImpl();

            Logger.increaseIndent();
            Logger.printMixedYellow("Binding", "LegacyServiceImpl");
            Logger.printlnPlainMixedBlue(" as", "legacy-service");
            Naming.rebind("//127.0.0.1:" + registryPort + "/legacy-service", remoteObject1);

            Object o = registry.lookup("legacy-service");
            String className = o.getClass().getName();
            Logger.printMixedYellow("Boundname", "legacy-service");
            Logger.printlnPlainMixedBlue(" with class", className, "is ready.");
            Logger.decreaseIndent();

            Logger.printlnMixedBlue("Creating", "PlainServer", "object.");
            remoteObject2 = new PlainServer();
            IPlainServer stub1 = (IPlainServer)UnicastRemoteObject.exportObject(remoteObject2, 0);
            bindToRegistry(stub1, registry, "plain-server");

            Logger.printlnMixedBlue("Creating another", "PlainServer", "object.");
            remoteObject3 = new PlainServer();
            IPlainServer stub2 = (IPlainServer)UnicastRemoteObject.exportObject(remoteObject3, 0);
            bindToRegistry(stub2, registry, "plain-server2");

            try {
                Logger.printlnMixedBlue("Creating", "ActivatorImp", "object.");
                Logger.increaseIndent();

                remoteObject4 = Utils.getActivator(registryPort, null);
                Logger.printlnMixedYellowFirst("Activator", "is ready.");

            } catch( Exception e) {
                Logger.printlnYellow("Activator initialization failed.");

            } finally {
                Logger.decreaseIndent();
            }

            Logger.println("");
            Logger.decreaseIndent();

            Logger.println("Server setup finished.");
            Logger.println("Waiting for incoming connections.");
            Logger.println("");

        } catch (RemoteException | MalformedURLException | AlreadyBoundException | NotBoundException e) {
            Logger.eprintln("Unexpected RMI Error:");
            e.printStackTrace();
        }
    }

    public static void bindToRegistry(Remote object, Registry registry, String boundName) throws AccessException, RemoteException, AlreadyBoundException, NotBoundException
    {
        Logger.increaseIndent();
        Logger.printlnMixedYellow("Binding Object as", boundName);
        registry.bind(boundName, object);

        Object o = registry.lookup(boundName);
        String className = o.getClass().getInterfaces()[0].getSimpleName();
        Logger.printMixedYellow("Boundname", boundName);
        Logger.printlnPlainMixedBlue(" with interface", className, "is ready.");
        Logger.decreaseIndent();
    }
}
