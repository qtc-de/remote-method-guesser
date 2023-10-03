package de.qtc.rmg.networking;

import java.net.Socket;
import java.net.UnknownHostException;
import java.io.IOException;
import java.net.ServerSocket;
import java.rmi.server.RMISocketFactory;

import de.qtc.rmg.internal.ExceptionHandler;
import de.qtc.rmg.internal.RMGOption;
import de.qtc.rmg.io.Logger;

/**
 * Remote objects bound to an RMI registry are usually pointing to remote endpoints
 * on the same host. In order to protect from unauthorized access, some developers
 * suggest setting these references to localhost or 127.0.0.1 explicitly. This will
 * indeed cause hiccups in most RMI clients, as they try to call to 127.0.0.1 after
 * fetching a remote object. However, when the TCP ports of the corresponding remote
 * objects are open, it is still possible to communicate with them.
 *
 * The LoopbackSocketFactory class extends the default RMISocketFactory and can be set
 * as a replacement. The class uses remote-method-guessers global option access to obtain
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
public class LoopbackSocketFactory extends RMISocketFactory
{
    private transient RMISocketFactory fax;
    private transient boolean printInfo = true;

    @Override
    public ServerSocket createServerSocket(int port) throws IOException
    {
        return getFax().createServerSocket(port);
    }

    /**
     * Overwrites the default implementation of createSocket. Checks whether host matches the expected
     * value and changes the value if required. After the host check was done, the default socket factory
     * is used to create the real socket.
     */
    public Socket createSocket(String host, int port) throws IOException
    {
        Socket sock = null;

        if (!RMGOption.TARGET_HOST.getValue().equals(host))
        {
            if (printInfo && RMGOption.GLOBAL_VERBOSE.getBool())
            {
                Logger.printInfoBox();
                Logger.printlnMixedBlue("RMI object tries to connect to different remote host:", host);
            }

            if (RMGOption.CONN_FOLLOW.getBool())
            {
                if ( printInfo && RMGOption.GLOBAL_VERBOSE.getBool())
                {
                    Logger.println("Following redirect to new target...");
                }
            }

            else
            {
                host = RMGOption.TARGET_HOST.getValue();

                if (printInfo && RMGOption.GLOBAL_VERBOSE.getBool())
                {
                    Logger.printlnMixedBlue("Redirecting the connection back to", host);
                    Logger.printlnMixedYellow("You can use", "--follow", "to prevent this.");
                }
            }

            if (printInfo && RMGOption.GLOBAL_VERBOSE.getBool())
            {
                Logger.decreaseIndent();
            }

            this.printInfo = false;
        }

        try
        {
            sock = getFax().createSocket(host, port);
        }

        catch( UnknownHostException e )
        {
            ExceptionHandler.unknownHost(e, host, true);
        }

        return sock;
    }

    /**
     * Obtain the RMISocketFactory to create sockets from. This is always the default RMISocketFactory.
     */
    private RMISocketFactory getFax()
    {
        if (fax == null)
        {
            fax = RMISocketFactory.getDefaultSocketFactory();
        }

        return fax;
    }
}
