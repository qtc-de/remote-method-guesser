package eu.tneitzel.rmg.networking;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

import javax.net.ssl.SSLSocketFactory;

/**
 * SSL implementation of the DGCClientSocketFactory. This is required when remote objects are configured
 * to use the SslRMIClientSocketFactory to create sockets. For more details, see the documentation of the
 * DGCCLientSocketFactory class.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class DGCClientSslSocketFactory extends SSLSocketFactory {

    /**
     * Instead of creating a real socket, return a DGCClientSocket that prevents outgoing connections.
     */
    @Override
    public Socket createSocket(String host, int port) throws IOException
    {
        return new DGCClientSocket(host, port);
    }

    @Override
    public String[] getDefaultCipherSuites()
    {
        return null;
    }

    @Override
    public String[] getSupportedCipherSuites()
    {
        return null;
    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException
    {
        return null;
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException, UnknownHostException
    {
        return null;
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException
    {
        return new DGCClientSocket(host.getHostAddress(), port);
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException
    {
        return null;
    }
}
