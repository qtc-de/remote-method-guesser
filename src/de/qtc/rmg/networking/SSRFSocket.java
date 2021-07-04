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
import de.qtc.rmg.internal.RMGOption;
import de.qtc.rmg.io.Logger;
import de.qtc.rmg.utils.RMGUtils;
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

    public static void printContent(String host, int port)
    {
        byte[] content = bos.toByteArray();
        String hexContent = RMGUtils.bytesToHex(content);

        if( RMGOption.GOPHER.getBool()) {

            StringBuilder builder = new StringBuilder();
            builder.append("gopher://" + host + ":" + port +"/");

            for(int ctr = 0; ctr < hexContent.length(); ctr++) {

                if( (ctr % 2) == 0)
                    builder.append("%");

                builder.append(hexContent.charAt(ctr));
            }

            hexContent = builder.toString();
        }

        Logger.printlnMixedYellow("SSRF Payload:", hexContent);
        System.exit(0);
    }
}
