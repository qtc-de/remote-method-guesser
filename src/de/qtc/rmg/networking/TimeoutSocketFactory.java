package de.qtc.rmg.networking;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.rmi.server.RMISocketFactory;

/**
 * The TimeoutSocketFactory is a wrapper around the default RMISocketFactory
 * that allows to set timeouts for the created sockets. This is required because
 * RMI sockets have large default values for connect or read timeouts. During
 * remote-method-guesser's scan operation, this is not desired.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class TimeoutSocketFactory extends RMISocketFactory {

    private int connectTimeout;
    private int readTimeout;
    private RMISocketFactory fac;

    /**
     * Create a new factory using the specified read and connect timeout for TCP sockets.
     *
     * @param readTimeout timeout for read operations on the socket
     * @param connectTimeout timeout for the initial socket connect
     */
    public TimeoutSocketFactory(int readTimeout, int connectTimeout)
    {
        this.readTimeout = readTimeout;
        this.connectTimeout = connectTimeout;

        this.fac = RMISocketFactory.getDefaultSocketFactory();
    }

    /**
     * Never used by remote-method-guesser but required to implement the interface.
     * Just hand over to the default factory.
     */
    public ServerSocket createServerSocket(int port) throws IOException
    {
        return fac.createServerSocket(port);
    }

    /**
     * Creates a socket by using the default factory and sets the read timeout on it.
     * Then the socket is connected to the target using the specified connect timeout.
     */
    public Socket createSocket(String host, int port) throws IOException
    {
        Socket sock = new Socket();
        sock.setSoTimeout(readTimeout);

        SocketAddress sockAddr = new InetSocketAddress(host, port);
        sock.connect(sockAddr, connectTimeout);

        return sock;
    }
}
