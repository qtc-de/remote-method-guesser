package eu.tneitzel.rmg.networking;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.rmi.server.UID;

import eu.tneitzel.rmg.exceptions.SSRFException;
import eu.tneitzel.rmg.internal.ExceptionHandler;
import eu.tneitzel.rmg.internal.RMGOption;
import eu.tneitzel.rmg.io.Logger;
import eu.tneitzel.rmg.io.SingleOpOutputStream;
import eu.tneitzel.rmg.utils.RMGUtils;
import sun.rmi.server.MarshalOutputStream;
import sun.rmi.transport.TransportConstants;

/**
 * The SSRFSocket class is an alternative Socket implementation that sends all socket output
 * to a byte array and that uses another static byte array for simulating server input. This
 * kind of socket is used when the --ssrf option was specified. In this case, all RMI output
 * should be printed instead of being sent to a server. Since no real server communication
 * occurs, server responses have to be simulated.
 *
 * When simulating server responses, the socket uses some static data that always ends in an
 * ExceptionalReturn (RMI transport code for an exception that was caused on the server side).
 * The corresponding exception is an SSRFException, that is defined within remote-method-guesser.
 * This mechanism is used to terminate the program after the output operation has finished.
 * As soon as the tool attempts to read the server's response, it will catch the exception, print
 * all data that was collected by the output stream, byte array buffer, and exit.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
@SuppressWarnings("restriction")
public class SSRFSocket extends Socket
{
    private String host;
    private int port;

    private static ByteArrayOutputStream bos;

    /**
     * Create a new SSRFSocket.
     *
     * @param host remote host
     * @param port remote port
     */
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
     * anything, collect all data in a byte array. If the SSRF_SINGLEOP option was used,
     * we choose an SingleOpOutputStream. This stream inspects data written to it and
     * modifies stream protocol messages to single operation protocol messages.
     */
    public OutputStream getOutputStream()
    {
        if( bos == null ) {

            if( RMGOption.SSRF_STREAM_PROTOCOL.getBool() )
                bos = new ByteArrayOutputStream();

            else
                bos = new SingleOpOutputStream();
        }

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

        if( RMGOption.SSRF_GOPHER.getBool()) {

            StringBuilder builder = new StringBuilder();
            builder.append("gopher");

            if( RMGOption.CONN_SSL.getBool() )
                builder.append("s");

            builder.append("://" + host + ":" + port +"/_");

            for(int ctr = 0; ctr < hexContent.length(); ctr++) {

                if( (ctr % 2) == 0)
                    builder.append("%");

                builder.append(hexContent.charAt(ctr));
            }

            hexContent = builder.toString();
        }

        if( RMGOption.SSRF_ENCODE.getBool() ) {

            try {
                hexContent = URLEncoder.encode(hexContent, StandardCharsets.UTF_8.toString());

            } catch (UnsupportedEncodingException e) {
                ExceptionHandler.internalError("SSRFSocket.printContent", "Invalid encoding selected.");
            }

        }

        if( RMGOption.SSRF_RAW.getBool() )
            System.out.println(hexContent);

        else
            Logger.printlnMixedYellow("SSRF Payload:", hexContent);

        System.exit(0);
    }
}
