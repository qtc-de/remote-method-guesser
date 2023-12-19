package eu.tneitzel.rmg.server.factory;

import java.io.IOException;
import java.io.Serializable;
import java.net.ServerSocket;
import java.net.Socket;
import java.rmi.server.RMISocketFactory;

public class CustomSocketFactory extends RMISocketFactory implements Serializable
{
    private static final long serialVersionUID = -1168901302380021730L;
    private final transient RMISocketFactory defaultFax;

    public CustomSocketFactory()
    {
        defaultFax = RMISocketFactory.getDefaultSocketFactory();
    }

    public ServerSocket createServerSocket(int arg0) throws IOException
    {
        return defaultFax.createServerSocket(arg0);
    }

    public Socket createSocket(String arg0, int arg1) throws IOException
    {
        return defaultFax.createSocket(arg0, arg1);
    }
}
