package de.qtc.rmg.networking;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.rmi.server.RMISocketFactory;

public class SSRFSocketFactory extends RMISocketFactory {

	@Override
	public Socket createSocket(String host, int port) throws IOException
    {
		return new SSRFSocket();
	}

	@Override
	public ServerSocket createServerSocket(int port) throws IOException
	{
		return null;
	}
}
