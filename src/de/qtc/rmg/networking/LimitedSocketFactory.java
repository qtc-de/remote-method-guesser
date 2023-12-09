package eu.tneitzel.rmg.networking;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.UnknownHostException;
import java.rmi.server.RMISocketFactory;

import eu.tneitzel.rmg.io.Logger;
import eu.tneitzel.rmg.utils.RMGUtils;

/**
 * The LimitedSocketFactoryClass is used when creating a rogue JMX server. It is required
 * to bind the server only to the address that was specified by the user.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class LimitedSocketFactory extends RMISocketFactory {

    private InetAddress addr;

    /**
     * Creates a limited socket factory using the specified address.
     *
     * @param address Address to bind the socket factory to.
     */
    public LimitedSocketFactory(String address)
    {
        try {
            addr = InetAddress.getByName(address);

        } catch (UnknownHostException e) {
            Logger.eprintlnMixedYellow("Unable to resolve hostname", address);
            RMGUtils.exit();
        }
    }

    /**
     * Creates a client socket.
     */
    @Override
    public Socket createSocket(String host, int port) throws IOException
    {
        Socket sock = new Socket();

        SocketAddress sockAddr = new InetSocketAddress(host, port);
        sock.connect(sockAddr);

        return sock;
    }

    /**
     * Creates a server socket.
     */
    @Override
    public ServerSocket createServerSocket(int port) throws IOException
    {
        ServerSocket serverSocket = new ServerSocket(port, 0, addr);
        return serverSocket;
    }
}
