package de.qtc.rmg.networking;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.rmi.server.RMISocketFactory;

/**
 * Factory class for creating SSRFResponseSockets. This is required as SocketFactories
 * are the default way how Java RMI creates sockets during RMI communication. This socket
 * factory is used when the --ssrf-response option was specified.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class SSRFResponseSocketFactory extends RMISocketFactory {

    private byte[] content;

    public SSRFResponseSocketFactory(byte[] content)
    {
        this.content = content;
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException
    {
        return new SSRFResponseSocket(host, port, content);
    }

    @Override
    public ServerSocket createServerSocket(int port) throws IOException
    {
        return null;
    }
}
