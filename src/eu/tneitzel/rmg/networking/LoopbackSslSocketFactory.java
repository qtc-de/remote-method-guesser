package eu.tneitzel.rmg.networking;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.rmi.server.RMIClientSocketFactory;

import javax.net.ssl.SSLSocketFactory;

import eu.tneitzel.rmg.internal.ExceptionHandler;
import eu.tneitzel.rmg.internal.RMGOption;
import eu.tneitzel.rmg.io.Logger;

/**
 * Remote objects bound to an RMI registry are usually pointing to remote endpoints
 * on the same host. In order to protect from unauthorized access, some developers
 * suggest setting these references to localhost or 127.0.0.1 explicitly. This will
 * indeed cause hiccups in most RMI clients, as they try to call to 127.0.0.1 after
 * fetching a remote object. However, when the TCP ports of the corresponding remote
 * objects are open, it is still possible to communicate with them.
 *
 * The LoopbackSslSocketFactory class extends the default SSLSocketFactory and can be set
 * as a replacement. The class uses remote-method-guessers global option access to obtain
 * the actual target of the RMI communication (usually the registry host). All other RMI
 * connections are then expected to target the same host. This is implemented by overwriting
 * the createSocket function. If the specified host value does not match the expected value,
 * it is replaced by the expected value and the connection is therefore redirected.
 *
 * During a redirect, the class prints a warning to the user to inform about the
 * redirection. If redirection is a desired behavior, the user can use the --follow option
 * with remote-method-guesser, which sets the followRedirect attribute to true. In these
 * cases, a warning is still printed, but the connection goes to the specified target.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class LoopbackSslSocketFactory extends SSLSocketFactory implements RMIClientSocketFactory
{
    /** SSLSocketFactory used for socket creation */
    public transient SSLSocketFactory fax;
    /** Whether to print redirection information */
    public transient boolean printInfo = true;

    /**
     * Overwrites the default implementation of createSocket. Checks whether host matches the expected
     * value and changes the value if required. After the host check was done, the default socket factory
     * is used to create the real socket.
     */
    @Override
    public Socket createSocket(String target, int port) throws IOException
    {
        Socket sock = null;

        if(!RMGOption.TARGET_HOST.getValue().equals(target)) {

            if (printInfo && RMGOption.GLOBAL_VERBOSE.getBool())
            {
                Logger.printInfoBox();
                Logger.printlnMixedBlue("RMI object tries to connect to different remote host:", target);
            }

            if (RMGOption.CONN_FOLLOW.getBool())
            {
                if (printInfo && RMGOption.GLOBAL_VERBOSE.getBool())
                {
                    Logger.println("Following SSL redirect to new target...");
                }
            }

            else
            {
                target = RMGOption.TARGET_HOST.getValue();

                if (printInfo && RMGOption.GLOBAL_VERBOSE.getBool())
                {
                    Logger.printlnMixedBlue("Redirecting the SSL connection back to", target);
                    Logger.printlnMixedYellow("You can use", "--follow", "to prevent this.");
                }
            }

            if (printInfo && RMGOption.GLOBAL_VERBOSE.getBool())
            {
                Logger.decreaseIndent();
            }

            printInfo = false;
        }

        try
        {
            sock = getFax().createSocket(target, port);
        }

        catch (UnknownHostException e)
        {
            ExceptionHandler.unknownHost(e, target, true);
        }

        return sock;
    }

    @Override
    public Socket createSocket(Socket arg0, String arg1, int arg2, boolean arg3) throws IOException
    {
        return getFax().createSocket(arg0, arg1, arg2, arg3);
    }

    @Override
    public String[] getDefaultCipherSuites()
    {
        return getFax().getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites()
    {
        return getFax().getSupportedCipherSuites();
    }

    @Override
    public Socket createSocket(InetAddress arg0, int arg1) throws IOException
    {
        return getFax().createSocket(arg0, arg1);
    }

    @Override
    public Socket createSocket(String arg0, int arg1, InetAddress arg2, int arg3) throws IOException, UnknownHostException
    {
        return getFax().createSocket(arg0, arg1, arg2, arg3);
    }

    @Override
    public Socket createSocket(InetAddress arg0, int arg1, InetAddress arg2, int arg3) throws IOException
    {
        return getFax().createSocket(arg0, arg1, arg2, arg3);
    }

    /**
     * Obtain the SSLSocketFactory to create sockets from. This is always the underlying SSLSocketFactory
     * from the TrustAllSocketFactory.
     */
    private SSLSocketFactory getFax()
    {
        if (fax == null)
        {
            fax = new TrustAllSocketFactory().getSSLSocketFactory();
        }

        return fax;
    }
}
