package de.qtc.rmg.networking;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.rmi.server.RMISocketFactory;

/**
 * Factory class for creating SSRFSockets. This is required as SocketFactories
 * are the default way how Java RMI creates sockets during RMI communication. This socket
 * factory is used when the --ssrf option was specified.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class SSRFSocketFactory extends RMISocketFactory {

    @Override
    public Socket createSocket(String host, int port) throws IOException
    {
        return new SSRFSocket(host, port);
    }

    @Override
    public ServerSocket createServerSocket(int port) throws IOException
    {
        return null;
    }
}
