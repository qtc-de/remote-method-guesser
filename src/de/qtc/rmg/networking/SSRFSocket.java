package de.qtc.rmg.networking;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.rmi.server.UID;

import de.qtc.rmg.exceptions.SSRFException;
import sun.rmi.server.MarshalOutputStream;
import sun.rmi.transport.TransportConstants;

@SuppressWarnings("restriction")
public class SSRFSocket extends Socket {

    private static ByteArrayOutputStream bos;

    public InputStream getInputStream() throws IOException
    {
        UID uid = new UID();

        ByteArrayOutputStream ibos = new ByteArrayOutputStream();
        ibos.write(TransportConstants.ProtocolAck);

        DataOutputStream dos = new DataOutputStream(ibos);
        dos.writeUTF("localhost");
        dos.writeInt(4444);

        dos.writeByte(TransportConstants.Return);
        MarshalOutputStream mos = new MarshalOutputStream(ibos);

        mos.writeByte(TransportConstants.ExceptionalReturn);
        uid.write(mos);
        mos.writeObject(new SSRFException());

        return new ByteArrayInputStream(ibos.toByteArray());
    }

    public OutputStream getOutputStream()
    {
        if( bos == null )
            bos = new ByteArrayOutputStream();

        return bos;
    }

    public static byte[] getContent()
    {
        return bos.toByteArray();
    }
}
