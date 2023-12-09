package eu.tneitzel.rmg.networking;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509TrustManager;

/**
 * A dummy implementation for a trust manager. Accepts all certificates.
 * Should never be used within of other applications where trust matters.
 * Not sure where this code was initially from. Probably copied from this
 * project gist: https://gist.github.com/matthewromano/4178946
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class DummyTrustManager implements X509TrustManager {

    public X509Certificate[] getAcceptedIssuers() {
        return null;
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
    }
}
