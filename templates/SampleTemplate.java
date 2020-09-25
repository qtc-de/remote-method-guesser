package de.qtc.rmg;

import java.io.IOException;
import java.net.Socket;
import java.net.ServerSocket;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.rmi.registry.Registry;
import java.rmi.registry.LocateRegistry;
import java.rmi.server.RMISocketFactory;
import java.rmi.server.RMIClientSocketFactory;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.HashMap;

import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.rmi.ssl.SslRMIClientSocketFactory;

/*
 * Compile this sample class with the following command:
 *      javac -d . <SAMPLECLASSNAME>.java
 */
public class <SAMPLECLASSNAME> extends SSLSocketFactory {

    private static int remotePort = <REMOTEPORT>;
    private static String remoteHost = "<REMOTEHOST>";

    public static void main(String[] argv) {

        /*
         * Setup the default RMISocketFactory. The LoopbackSocketFactory implementation
         * is a custom socketFactory, which is capable of redirecting connection attempts
         * back to the actual RMI server. This is sometimes required, when the RMI server
         * binds its RMI objects e.g. to localhost.
         */
        RMISocketFactory fac = RMISocketFactory.getDefaultSocketFactory();
        RMISocketFactory my = new LoopbackSocketFactory(remoteHost, fac, <FOLLOW>);
        
        try {
            RMISocketFactory.setSocketFactory(my);
        } catch (IOException e2) {
            System.err.println("Unable to set RMISocketFactory.");
            System.err.println("Host redirection will not work.");
        }

        /*
         * Setup the default ssl.SocketFactory. The DummyTrustManager is a trust manager
         * that skips certificate verification. The SSLSocketFactory needs to be a public
         * class. To make the code self contained, the current class is implementing this
         * interface and implements the same redirection funcationality as the
         * LoopbackSocketFactory.
         */
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[] { new DummyTrustManager() }, null);
            SSLContext.setDefault(ctx);

            <SAMPLECLASSNAME>.host = remoteHost;
            <SAMPLECLASSNAME>.fac = ctx.getSocketFactory();
            <SAMPLECLASSNAME>.followRedirect = <FOLLOW>;
            java.security.Security.setProperty("ssl.SocketFactory.provider", "de.qtc.rmg.<SAMPLECLASSNAME>");

        } catch (NoSuchAlgorithmException | KeyManagementException e1) {
            System.err.println("Unable to set TrustManager for SSL connections.");
            System.err.println("SSL connections to untrusted hosts might fail.");
        }

        /*
         * This part starts the actual RMI communication and invokes the method in question.
         * You may want to modify this section according to your requirements.
         */
        try {

            System.out.print("[+] Connecting to registry on " + remoteHost + ":" + remotePort + "... ");
            Registry registry = null;

            if( <SSL> ) {
                RMIClientSocketFactory csf = new SslRMIClientSocketFactory();
                registry = LocateRegistry.getRegistry(remoteHost, remotePort, csf);
            } else {
                registry = LocateRegistry.getRegistry(remoteHost, remotePort);
            }

            System.out.println("done!");

            System.out.println("[+] Starting lookup on <BOUNDNAME>... ");
            <CLASSNAME> stub = (<CLASSNAME>) registry.lookup("<BOUNDNAME>");

            System.out.print("[+] Invoking method <METHODNAME>... ");
            <RETURNTYPE> response = stub.<METHODNAME>(<ARGUMENTS>);
            System.out.println("done!");

            System.out.println("[+] The servers response is: " + response);

          } catch (Exception e) {
              System.err.println("failed!");
              System.err.println("[-] The following exception was thrown:" + e.getMessage());
              System.err.println("[-] Full stacktrace:");
              e.printStackTrace();
          }
    }

    /*
     * This is dirty, but ssl.SocketFactory.provider needs to be a public class.
     * In order to make the code self contained, this has to be added to the
     * main class.
     */
    public static String host = "";
    public static SSLSocketFactory fac = null;
    public static boolean printInfo = true;
    public static boolean followRedirect = false;

	@Override
    public Socket createSocket(String target, int port) throws IOException {
        if(!host.equals(target)) {
            printInfos("[+] RMI object tries to connect to different remote host: " + target);

            if( followRedirect ) {
                printInfos("[+]\tFollowing ssl connection to new target... ");
            } else {
                printInfos("[+]\tRedirecting the ssl connection back to " + host + "... ");
                target = host;
            }
            printInfos("[+]\tThis is done for all further requests. This message is not shown again. ");
            printInfo = false;
        }
        return fac.createSocket(target, port);
    }

	@Override
	public Socket createSocket(Socket arg0, String arg1, int arg2, boolean arg3) throws IOException {
		return fac.createSocket(arg0, arg1, arg2, arg3);
	}

	@Override
	public String[] getDefaultCipherSuites() {
		return fac.getDefaultCipherSuites();
	}

	@Override
	public String[] getSupportedCipherSuites() {
		return fac.getSupportedCipherSuites();
	}

	@Override
	public Socket createSocket(InetAddress arg0, int arg1) throws IOException {
		return fac.createSocket(arg0, arg1);
	}

	@Override
	public Socket createSocket(String arg0, int arg1, InetAddress arg2, int arg3) throws IOException, UnknownHostException {
		return fac.createSocket(arg0, arg1, arg2, arg3);
	}

	@Override
	public Socket createSocket(InetAddress arg0, int arg1, InetAddress arg2, int arg3) throws IOException {
		return fac.createSocket(arg0, arg1, arg2, arg3);
	}

    private void printInfos(String info) {
        if( printInfo )
            System.out.println(info);
    }
}


/*
 * Custom TrustManager that skips certificate validation.
 * Do not use it in cases where you want the certificates
 * to be validated.
 */
class DummyTrustManager implements X509TrustManager {

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


/*
 * Custom RMISocketFactory. Is capable of redirecting connection
 * attempts if required.
 */
class LoopbackSocketFactory extends RMISocketFactory {

    private String host;
    private RMISocketFactory fac;
    private boolean printInfo = true;
    private boolean followRedirect = false;

    public LoopbackSocketFactory(String host, RMISocketFactory fac, boolean followRedirect) {
        this.host = host;
        this.fac = fac;
        this.followRedirect= followRedirect;
    }

    public ServerSocket createServerSocket(int port) throws IOException {
        return fac.createServerSocket(port);
    }

    public Socket createSocket(String host, int port) throws IOException {
        if(!this.host.equals(host)) {
            printInfos("[+] RMI object tries to connect to different remote host: " + host);

            if( this.followRedirect ) {
                printInfos("[+]\tFollowing connection to new target... ");
            } else {
                printInfos("[+]\tRedirecting the connection back to " + this.host + "... ");
                host = this.host;
            }
            printInfos("[+]\tThis is done for all further requests. This message is not shown again. ");
            this.printInfo = false;
        }
        return fac.createSocket(host, port);
    }

    private void printInfos(String info) {
        if( this.printInfo )
            System.out.println(info);
    }
}
