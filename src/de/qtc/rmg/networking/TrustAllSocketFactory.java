package eu.tneitzel.rmg.networking;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.rmi.server.RMIClientSocketFactory;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import eu.tneitzel.rmg.internal.ExceptionHandler;
import eu.tneitzel.rmg.io.Logger;
import eu.tneitzel.rmg.utils.RMGUtils;

/**
 * Wrapper around an SSLSocketFactory that trusts all certificates. This is used for TLS protected
 * RMI connections to prevent certificate errors. Furthermore, the class also allows to set custom
 * values for the underlying TCP sockets read and connect timeouts. This is required for the portscan
 * operation.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class TrustAllSocketFactory implements RMIClientSocketFactory {

    private SSLSocketFactory fax;
    private int readTimeout;
    private int connectTimeout;

    /**
     * Creates a new TrustAllSocketFactory by disabling certificate validation on an SSLContext and
     * using the resulting SSLSocketFactory. This constructor sets some default values for the read
     * and connect timeouts that are used by the socket.
     */
    public TrustAllSocketFactory()
    {
        this(30 * 1000, 30 * 1000);
    }


    /**
     * Same as the previous constructor, but allows user defined values for the timeouts. This can be handy when
     * e.g. connecting to plain text sockets that do not return anything when receiving an incoming SSL handshake.
     * The default behavior of an SSL socket is to hang forever in such a case.
     *
     * @param readTimeout timeout for read operations on the socket
     * @param connectTimeout timeout for the initial socket connect
     */
    public TrustAllSocketFactory(int readTimeout, int connectTimeout)
    {
        this.readTimeout = readTimeout;
        this.connectTimeout = connectTimeout;

        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[] { new DummyTrustManager() }, null);

            fax = ctx.getSocketFactory();

        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            Logger.eprintlnMixedBlue("Unable to create", "TrustAllSocketFactory", "for SSL connections.");
            ExceptionHandler.showStackTrace(e);
            RMGUtils.exit();
        }
    }

    /**
     * Uses the SSLSocketFactory to create a socket, sets the read timeout on it and connects
     * the socket to the target using the specified connect timeout.
     */
    @Override
    public Socket createSocket(String host, int port) throws IOException
    {
        Socket sock = fax.createSocket();
        sock.setSoTimeout(readTimeout);

        SocketAddress sockAddr = new InetSocketAddress(host, port);
        sock.connect(sockAddr, connectTimeout);

        return sock;
    }

    /**
     * Can be used to obtain the underlying SSLSocketFactory
     *
     * @return SSLSocketFactory of the TrustAll context
     */
    public SSLSocketFactory getSSLSocketFactory()
    {
        return this.fax;
    }
}
