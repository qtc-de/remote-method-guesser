package de.qtc.rmg.networking;

import java.io.IOException;
import java.net.Socket;
import java.rmi.server.RMIClientSocketFactory;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import de.qtc.rmg.internal.ExceptionHandler;
import de.qtc.rmg.io.Logger;
import de.qtc.rmg.utils.RMGUtils;

/**
 * Wrapper around an SSLSocketFactory that trusts all certificates.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class TrustAllSocketFactory implements RMIClientSocketFactory {

    private SSLSocketFactory fax;

    /**
     * Creates a new TrustAllSocketFactory by disabling certificate validation on an SSLContext and
     * using the resulting SSLSocketFactory.
     */
    public TrustAllSocketFactory()
    {
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
     * Just hands over to the createSocket method of the underlying SSLSocketFactory
     */
    @Override
    public Socket createSocket(String host, int port) throws IOException
    {
        return fax.createSocket(host, port);
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
