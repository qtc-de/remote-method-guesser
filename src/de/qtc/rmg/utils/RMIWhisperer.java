package de.qtc.rmg.utils;

import java.io.IOException;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.RMIClientSocketFactory;
import java.rmi.server.RMISocketFactory;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.rmi.ssl.SslRMIClientSocketFactory;

import de.qtc.rmg.io.Logger;
import de.qtc.rmg.networking.DummyTrustManager;
import de.qtc.rmg.networking.LoopbackSocketFactory;
import de.qtc.rmg.networking.LoopbackSslSocketFactory;

public final class RMIWhisperer {

    public int port;
    public String host;
    private Registry rmiRegistry;

    public void connect(String host, int port, boolean ssl, boolean followRedirects) {

        this.host = host;
        this.port = port;

        RMISocketFactory fac = RMISocketFactory.getDefaultSocketFactory();
        RMISocketFactory my = new LoopbackSocketFactory(host, fac, followRedirects);
        try {
            RMISocketFactory.setSocketFactory(my);
        } catch (IOException e2) {
            System.err.println("[-] Unable to set RMISocketFactory.");
            System.err.println("[-] Host redirection will not work.");
        }

        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[] { new DummyTrustManager() }, null);
            SSLContext.setDefault(ctx);

            LoopbackSslSocketFactory.host = host;
            LoopbackSslSocketFactory.fac = ctx.getSocketFactory();
            LoopbackSslSocketFactory.followRedirect = followRedirects;
            java.security.Security.setProperty("ssl.SocketFactory.provider", "de.qtc.rmg.networking.LoopbackSslSocketFactory");

        } catch (NoSuchAlgorithmException | KeyManagementException e1) {
            System.err.println("[-] Unable to set TrustManager for SSL connections.");
            System.err.println("[-] SSL connections to untrusted hosts might fail.");
        }

        Logger.print("[+] Connecting to RMI registry... ");
        try {
            if( ssl ) {

                RMIClientSocketFactory csf = new SslRMIClientSocketFactory();
                this.rmiRegistry = LocateRegistry.getRegistry(host, port, csf);

            } else {
                this.rmiRegistry = LocateRegistry.getRegistry(host, port);
            }
            Logger.println("done.");

        } catch( RemoteException e ) {

            Logger.println("failed.");
            System.err.println("[-] Error: Could not connect to " + host + "on port " + port);
            System.err.println("[-] Exception Details: " + e.toString());
            System.exit(1);
        }
    }


    public String[] getBoundNames() {

        String[] boundNames = null;
        Logger.print("[+] Obtaining a list of bound names... ");

        try {

            boundNames = rmiRegistry.list();
            Logger.println("done.");
            Logger.println("[+] " + boundNames.length + " names are bound to the registry.");

        } catch( RemoteException e ) {

            Logger.println("failed.");
            System.err.println("[-] Error: Remote failure when listing bound names");
            System.err.println("[-] Exception Details: " + e.toString());
            System.exit(1);
        }
        return boundNames;
    }


    public ArrayList<HashMap<String, String>> getClassNames(String[] boundNames) {

        ArrayList<HashMap<String, String>> returnList = new ArrayList<HashMap<String, String>>();

        HashMap<String, String> knownClasses = new HashMap<String,String>();
        HashMap<String, String> unknownClasses = new HashMap<String,String>();

        Object object = null;

        for( String className : boundNames ) {

          try {

              object = rmiRegistry.lookup(className);
              knownClasses.put(className, object.getClass().getName());

          } catch( RemoteException e ) {

              String exception = e.toString();

              int start = exception.indexOf("java.lang.ClassNotFoundException: ") + 34;
              int end = exception.indexOf(" (no security manager: RMI class loader disabled)");

              String missingClass = exception.substring(start, end);
              unknownClasses.put(className, missingClass);

          } catch( NotBoundException e) {
              Logger.println("[-] Error: Failure while looking up '" + className + "'... ");
          }
        }

        returnList.add(knownClasses);
        returnList.add(unknownClasses);
        return returnList;
    }

    public Registry getRegistry() {
        return this.rmiRegistry;
    }
}
