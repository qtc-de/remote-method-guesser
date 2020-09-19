package de.qtc.rmg.networking;

import java.net.Socket;
import java.io.IOException;
import java.net.ServerSocket;
import java.rmi.server.RMISocketFactory;

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
            printInfos("[*]		RMI object tries to connect to different remote host: " + host, true);

            if( this.followRedirect ) {
                printInfos("[*]		Following connection to new target... ", false);
            } else {
                printInfos("[*]		Redirecting the connection back to " + this.host + "... ", false);
                host = this.host;
            }
            this.printInfo = false;
        }
        return fac.createSocket(host, port);
    }

    private void printInfos(String info, boolean newLine) {
        if( this.printInfo ) {
            if( newLine )
                System.out.println(info);
            else
                System.out.print(info);
        }
    }
}
