package de.qtc.rmg.networking;

import java.io.IOException;
import java.io.Serializable;
import java.net.ServerSocket;
import java.net.Socket;
import java.rmi.server.RMISocketFactory;

import de.qtc.rmg.io.Logger;
import de.qtc.rmg.utils.RMGUtils;

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
            Logger.eprintMixedYellow("Caught unexpected", "InterruptedException", "in");
            Logger.eprintlnBlue("DummyServerSocket.accept()");
            Logger.println("Please report this to improve rmg :)");
            RMGUtils.stackTrace(e);
        }
        return null;
    }
}
