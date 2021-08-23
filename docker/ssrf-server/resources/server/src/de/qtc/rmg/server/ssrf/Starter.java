package de.qtc.rmg.server.ssrf;

import java.io.IOException;
import java.rmi.AlreadyBoundException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.RMISocketFactory;

import de.qtc.rmg.server.ssrf.http.SSRFServer;
import de.qtc.rmg.server.ssrf.rmi.FileManager;
import de.qtc.rmg.server.ssrf.rmi.IFileManager;
import de.qtc.rmg.server.ssrf.rmi.LocalhostJmxConnector;
import de.qtc.rmg.server.ssrf.rmi.LocalhostSocketFactory;
import de.qtc.rmg.server.ssrf.utils.Logger;

/**
 * The Starter class is responsible for creating an HTTP server that is vulnerable
 * to SSRF attacks and an RMI registry that contains two bound names: FileManager
 * and jmxrmi. Together, this combination is usable to practice some SSRF attacks on
 * Java RMI. To make the RMI ports inaccessible from remote, a custom socket factory
 * is used.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class Starter {

    private final static int defaultPort = 8000;
    private final static int registryPort = 1090;

    private static IFileManager fileManager = null;

    /**
     * Starts the HttpServer, the RMI registry and adds the FileManager and JMX remote objects.
     *
     * @param args command line arguments. None are expected.
     * @throws AlreadyBoundException Should never occur
     * @throws IOException
     */
    public static void main(String[] args) throws AlreadyBoundException, IOException
    {
        SSRFServer server = new SSRFServer(defaultPort);
        server.start();

        RMISocketFactory.setSocketFactory(new LocalhostSocketFactory());

        Logger.printlnMixedYellow("Creating RMI-Registry on port", String.valueOf(registryPort));
        Registry registry = LocateRegistry.createRegistry(registryPort);

        Logger.printlnMixedBlue("Creating", "FileManager", "object.");
        fileManager = new FileManager();
        registry.bind("FileManager", fileManager);

        LocalhostJmxConnector jmxConnector = new LocalhostJmxConnector(registryPort);
        jmxConnector.start();
    }
}
