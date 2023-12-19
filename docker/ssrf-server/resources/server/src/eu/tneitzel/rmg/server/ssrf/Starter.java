package eu.tneitzel.rmg.server.ssrf;

import java.io.IOException;
import java.rmi.AlreadyBoundException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.RMISocketFactory;

import eu.tneitzel.rmg.server.ssrf.http.SSRFServer;
import eu.tneitzel.rmg.server.ssrf.rmi.FileManager;
import eu.tneitzel.rmg.server.ssrf.rmi.IFileManager;
import eu.tneitzel.rmg.server.ssrf.rmi.LocalhostJmxConnector;
import eu.tneitzel.rmg.server.ssrf.rmi.LocalhostSocketFactory;
import eu.tneitzel.rmg.server.ssrf.utils.Logger;

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

    private final static int httpPort = 8000;
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
        System.setProperty("java.rmi.server.hostname", "localhost");
        System.setProperty("java.rmi.server.codebase", "http://localhost:8000/rmi-class-definitions.jar");

        Logger.printlnMixedBlue("Creating HTTP server on port", String.valueOf(httpPort));
        SSRFServer server = new SSRFServer(httpPort);
        server.start();

        RMISocketFactory.setSocketFactory(new LocalhostSocketFactory());

        Logger.printlnMixedYellow("Creating RMI-Registry on port", String.valueOf(registryPort));
        Registry registry = LocateRegistry.createRegistry(registryPort);

        Logger.printlnMixedBlue("Creating", "FileManager", "remote object.");
        fileManager = new FileManager();
        registry.bind("FileManager", fileManager);

        Logger.printlnMixedBlue("Creating", "JMX", "remote object.");
        LocalhostJmxConnector jmxConnector = new LocalhostJmxConnector(registryPort);
        jmxConnector.start();
    }
}
