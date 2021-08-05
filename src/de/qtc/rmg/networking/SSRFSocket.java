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

/**
 * The SSRFSocket class is an alternative Socket implementation that sends all socket output
 * to a byte array and that uses another static byte array for simulating server input. This
 * kind of socket is used when the --ssrf option was specified. In this case, all RMI output
 * should be printed instead of being send to a server. Since no real server communication
 * occurs, server responses have to be simulated.
 *
 * When simulating server responses, the socket uses some static data that always ends in an
 * ExceptionalReturn (RMI transport code for an exception that was caused on the server side).
 * The corresponding exception is an SSRFException, that is defined within remote-method-guesser.
 * This mechanism is used to terminate the program after the output operation has finished.
 * As soon as the tool attempts to read the servers response, it will catch the exception, print
 * all data that was collected by the output stream, byte array buffer, and exit.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
@SuppressWarnings("restriction")
public class SSRFSocket extends Socket {

    private String host;
    private int port;

    private static ByteArrayOutputStream bos;

    public SSRFSocket(String host, int port)
    {
        this.host = host;
        this.port = port;
    }

    /**
     * Simulate an InputStream that is connected to an RMI server. Always returns
     * the same static data that ends in an ExceptionalReturn containing an
     * SSRFException.
     */
    public InputStream getInputStream() throws IOException
    {
        UID uid = new UID();

        ByteArrayOutputStream ibos = new ByteArrayOutputStream();
        ibos.write(TransportConstants.ProtocolAck);

        DataOutputStream dos = new DataOutputStream(ibos);
        dos.writeUTF(host);
        dos.writeInt(port);

        dos.writeByte(TransportConstants.Return);
        MarshalOutputStream mos = new MarshalOutputStream(ibos);

        mos.writeByte(TransportConstants.ExceptionalReturn);
        uid.write(mos);
        mos.writeObject(new SSRFException());

        return new ByteArrayInputStream(ibos.toByteArray());
    }

    /**
     * Simulate an OutputStream that is connected to an RMI server. Instead of sending
     * anything, collect all data in a byte array.
     */
    public OutputStream getOutputStream()
    {
        if( bos == null )
            bos = new ByteArrayOutputStream();

        return bos;
    }

    /**
     * This function is used to print the collected output stream data. It is intended to be
     * called when the SSRFException is caught, as this is an indicator that the output
     * operation has finished.
     *
     * @param host can be specified to set the host when gopher output is used
     * @param port can be specified to set the port when gopher output is used
     */
    public static void printContent(String host, int port)
    {
        byte[] content = bos.toByteArray();
        String hexContent = RMGUtils.bytesToHex(content);

        if( RMGOption.GOPHER.getBool()) {

            StringBuilder builder = new StringBuilder();
            builder.append("gopher://" + host + ":" + port +"/_");

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
