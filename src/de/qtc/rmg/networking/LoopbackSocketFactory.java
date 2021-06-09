package de.qtc.rmg.networking;

import java.net.Socket;
import java.io.IOException;
import java.net.ServerSocket;
import java.rmi.server.RMISocketFactory;

import de.qtc.rmg.io.Logger;

/**
 * Remote objects bound to an RMI registry are usually pointing to remote endpoints
 * on the same host. In order to protect from unauthorized access, some developers
 * suggest setting these references to localhost or 127.0.0.1 explicitly. This will
 * indeed cause hickups in most RMI clients, as they try to call to 127.0.0.1 after
 * fetching a remote object. However, when the TCP ports of the corresponding remote
 * objects are open, it is still possible to communicate with them.
 *
 * The LoopbackSocketFactory class extends the default RMISocketFactory and can be set
 * as a replacement. Within its constructor, it requires to specify a host that is the
 * actual target of the RMI communication (usually the registry host). All other RMI
 * connections are then expected to target the same host. This is implemented by overwriting
 * the createSocket function. If the specified host value does not match the expected value,
 * it is replaced by the expected value and the connection is therefore redirected.
 *
 * During a redirect, the class prints a warning to the user to inform about the
 * redirection. If redirection is a desired behavior, the user can use the --follow option
 * with rmg, which sets the followRedirect attribute to true. In these cases, a warning
 * is still printed, but the connection goes to the specified target.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class LoopbackSocketFactory extends RMISocketFactory {

    private String host;
    private RMISocketFactory fac;
    private boolean printInfo = true;
    private boolean followRedirect = false;

    /**
     * Creates a new LoopbackSocketFactory.
     *
     * @param host remote host that is expected to get all further RMI connections
     * @param fac original socket factory to create sockets from
     * @param followRedirect if true, connections are not redirected to the expected host
     */
    public LoopbackSocketFactory(String host, RMISocketFactory fac, boolean followRedirect)
    {
        this.host = host;
        this.fac = fac;
        this.followRedirect= followRedirect;
    }

    public ServerSocket createServerSocket(int port) throws IOException
    {
        return fac.createServerSocket(port);
    }

    /**
     * Overwrites the default implementation of createSocket. Checks whether host matches the expected
     * value and changes the value if required. After the host check was done, the default socket factory
     * is used to create the real socket.
     */
    public Socket createSocket(String host, int port) throws IOException
    {
        if(!this.host.equals(host)) {
            printInfos("RMI object tries to connect to different remote host: " + host + ".");

            if( this.followRedirect ) {
                printInfos("\tFollowing connection to new target... ");
            } else {
                printInfos("\tRedirecting the connection back to " + this.host + "... ");
                host = this.host;
            }
            printInfos("\tThis is done for all further requests. This message is not shown again. ");
            this.printInfo = false;
        }
        return fac.createSocket(host, port);
    }

    /**
     * Especially during method guessing, the number of warnings can go out of control. Therefore, redirection warnings
     * are only printed once. This helper function checks whether a warning was already printed and only prints
     * a new warning if this was not the case.
     *
     * @param info user information about redirects
     */
    private void printInfos(String info)
    {
        if( this.printInfo && Logger.verbose )
            Logger.eprintlnBlue(info);
    }
}
