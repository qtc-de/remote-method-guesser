package de.qtc.rmg.server.ssrf;

import java.rmi.AlreadyBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

import de.qtc.rmg.server.ssrf.http.SSRFServer;
import de.qtc.rmg.server.ssrf.rmi.FileManager;
import de.qtc.rmg.server.ssrf.rmi.IFileManager;
import de.qtc.rmg.server.ssrf.utils.Logger;

/**
 * The Starter class is responsible for creating an HTTP server that is vulnerable
 * to SSRF attacks and an RMI registry that contains a single bound FileManager object.
 * Together, this combination is already sufficient to practice some SSRF attacks on
 * Java RMI. Notice that non localhost access to the RMI ports is not prevented by default
 * and needs to be achieved manually (e.g. by using a firewall).
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class Starter {

    private final static int defaultPort = 8000;
    private final static int registryPort = 1090;

    private static IFileManager fileManager = null;

    /**
     * Starts the HttpServer, the RMI registry and a FileManager remote object.
     *
     * @param args Commandline arguments. None are expected.
     * @throws RemoteException
     * @throws AlreadyBoundException Should never occur
     */
    public static void main(String[] args) throws RemoteException, AlreadyBoundException
    {
        SSRFServer server = new SSRFServer(defaultPort);
        server.start();

        Logger.printlnMixedYellow("Creating RMI-Registry on port", String.valueOf(registryPort));
        Registry registry = LocateRegistry.createRegistry(registryPort);

        Logger.printlnMixedBlue("Creating", "FileManager", "object.");
        fileManager = new FileManager();
        registry.bind("FileManager", fileManager);
    }
}
