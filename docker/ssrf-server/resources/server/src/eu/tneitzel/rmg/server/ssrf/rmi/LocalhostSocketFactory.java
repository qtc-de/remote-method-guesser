package eu.tneitzel.rmg.server.ssrf.rmi;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.rmi.server.RMISocketFactory;

/**
 * Custom implementation of an RMISocketFactory that binds to localhost only.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class LocalhostSocketFactory extends RMISocketFactory {

    /**
     * Just create a Socket object for the specified host and port combination and return it.
     */
    @Override
    public Socket createSocket(String host, int port) throws IOException
    {
        return new Socket(host, port);
    }

    /**
     * Creates a ServerSocket on the specified port that only listens on localhost.
     */
    @Override
    public ServerSocket createServerSocket(int port) throws IOException
    {
        ServerSocket sock = new ServerSocket();
        InetSocketAddress addr = new InetSocketAddress("127.0.0.1", port);

        sock.bind(addr);

        return sock;
    }
}
