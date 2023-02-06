package de.qtc.rmg.networking;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.rmi.server.RMISocketFactory;

/**
 * The DGCClientSocket factory is used when the --ssrf-response option was specified on the
 * command line. In this case, the user may supplies an SSRF response that contains a remote
 * object reference. These references create outbound DGC connections upon deserialization.
 * To prevent these outbound connections, we use a dummy socket factory. This factory returns
 * sockets that discard all incoming data and return an malformed DGC response when being read.
 *
 * Since no outgoing data is expected when using --ssrf-response, this socket factory is set
 * to the default RMI socket factory if the --ssrf-response option is used.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class DGCClientSocketFactory extends RMISocketFactory {

    @Override
    public Socket createSocket(String host, int port) throws IOException
    {
        return new DGCClientSocket(host, port);
    }

    @Override
    public ServerSocket createServerSocket(int port) throws IOException
    {
        return null;
    }
}
