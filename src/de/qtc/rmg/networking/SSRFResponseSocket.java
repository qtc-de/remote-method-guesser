package de.qtc.rmg.networking;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

import de.qtc.rmg.io.DevNullOutputStream;

/**
 * Socket implementation that prevents outputs from being send anywhere and that simulates input
 * by using a byte array that is set when calling the constructor. This socket is used for the
 * ssrf-response option, where no real network interaction is desired and where the server response
 * is already present in form of a byte array.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class SSRFResponseSocket extends Socket {

    private byte[] content;

    private static int count = 0;

    public SSRFResponseSocket(byte[] response)
    {
        this.content = response;
    }

    public InputStream getInputStream() throws IOException
    {
        ByteArrayInputStream bis = new ByteArrayInputStream(content);
        return bis;
    }

    public OutputStream getOutputStream()
    {
        if( count != 0 )
            System.exit(0);

        SSRFResponseSocket.count += 1;
        return new DevNullOutputStream();
    }
}
