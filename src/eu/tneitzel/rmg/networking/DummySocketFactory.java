package eu.tneitzel.rmg.networking;

import java.io.IOException;
import java.io.Serializable;
import java.net.ServerSocket;
import java.net.Socket;
import java.rmi.server.RMISocketFactory;

import eu.tneitzel.rmg.internal.ExceptionHandler;

/**
 * During the creation of the An Trinh registry whitelist bypass gadget, the creation of a
 * UnicastRemoteObject is required. There are several different ways to achieve this. One of
 * them is to access the 'official' constructor via reflection. This approach is used by rmg,
 * but it has the downside that RMI tries to export the object within the constructor directly.
 * Therefore, when blindly using the constructor, a port will open on your machine.
 *
 * To avoid this, rmg uses a dummy socket factory with the constructed UnicastRemoteObject.
 * This dummy socket factory returns a dummy ServerSocket with an overwritten accept method.
 * Calls to accept just cause a sleep. In this time, rmg has already unexported the object,
 * which closes the socket.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class DummySocketFactory extends RMISocketFactory implements Serializable{

    private static final long serialVersionUID = 1L;

    public ServerSocket createServerSocket(int port) throws IOException {
        return new DummyServerSocket();
    }

    public Socket createSocket(String host, int port) throws IOException {
        return RMISocketFactory.getDefaultSocketFactory().createSocket(host, port);
    }
}

class DummyServerSocket extends ServerSocket {

    public DummyServerSocket() throws IOException
    {
    }

    public Socket accept() throws IOException
    {
        try {
            Thread.sleep(Long.MAX_VALUE);
        } catch (InterruptedException e) {
            ExceptionHandler.unexpectedException(e, "DummyServerSocket.accept", "call", false);
        }
        return null;
    }
}
