package de.qtc.rmg.server.ssrf.http;

import java.io.IOException;
import java.net.InetSocketAddress;

import com.sun.net.httpserver.HttpServer;

import de.qtc.rmg.server.ssrf.utils.Logger;

/**
 * The SSRFServer class creates an HTTP server that is vulnerable to SSRF attacks.
 * For details, check the SSRFHandler class, that implements the actual SSRF vulnerability.
 * Additionally, a JarHandler is implemented that an be used to obtain classes from the servers
 * codebase.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
@SuppressWarnings("restriction")
public class SSRFServer {

    private HttpServer server;
    private InetSocketAddress address;

    /**
     * Create the HttpServer on the specified port and assign an SSRFHandler and JarHandler to it.
     *
     * @param bindPort Port number to bind the HttpServer to.
     */
    public SSRFServer(int bindPort)
    {
        this.address = new InetSocketAddress(bindPort);

        try {
            server = HttpServer.create(address, 0);
            server.createContext("/", new SSRFHandler());
            server.createContext("/rmi-class-definitions.jar", new JarHandler());

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Starts the HttpServer.
     */
    public void start()
    {
        Logger.printlnYellow("Starting HTTP server.");
        server.start();
    }
}
