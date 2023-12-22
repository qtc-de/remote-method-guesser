package eu.tneitzel.rmg.networking;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.rmi.server.UID;

import eu.tneitzel.rmg.io.DevNullOutputStream;
import sun.rmi.server.MarshalOutputStream;
import sun.rmi.transport.TransportConstants;

/**
 * The DGCClientSocket simulates a connection to the DGC server side component of a remote object.
 * All output that is written to the socket is dropped. When input is read from the socket, it
 * returns a static DGC response that contains an invalid class (an Integer that violates the DGC
 * deserialization filter). The standard behavior for the DGC is to give up on DGC calls when an
 * invalid class is encountered. An alternative is to return a long living Lease.
 *
 * Currently where is only one use case in remote-method-guesser for this class that should create
 * at maximum one DGC connection per remote endpoint. The implementation in this class is not suitable
 * for connection reuse. If connections are reused, the DGC will encounter errors, since the static
 * response always contains a full RMI handshake. In the current state this should never occur and even
 * if it occurs, it shouldn't impact the user experience as DGC exceptions are handled hidden from the
 * user. If reuse of connections is required in future, you may want to add a more sophisticated connection
 * handling in this class, which checks whether a connection is newly created or being reused.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
@SuppressWarnings("restriction")
public class DGCClientSocket extends Socket {

    private UID uid;
    private int port;
    private String host;

    /**
     * Create a new DGCClientSocket.
     *
     * @param host remote host
     * @param port remote port
     */
    public DGCClientSocket(String host, int port)
    {
        this.host = host;
        this.port = port;

        this.uid = new UID();
    }

    /**
     * Simulates an InputStream that is connected to the DGC component of an RMI server.
     * Always returns the same static response, which is the result of a DGC.dirty call.
     * Instead of returning a Lease, we return an Integer, which triggers the deserialization
     * filter of the DGC component and prevents remote references from being registered on
     * the runtime.
     */
    public InputStream getInputStream() throws IOException
    {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(TransportConstants.ProtocolAck);

        DataOutputStream dos = new DataOutputStream(bos);
        dos.writeUTF(host);
        dos.writeInt(port);

        dos.writeByte(TransportConstants.Return);
        MarshalOutputStream mos = new MarshalOutputStream(bos);

        mos.writeByte(TransportConstants.NormalReturn);
        uid.write(mos);
        mos.writeObject(0);

        return new ByteArrayInputStream(bos.toByteArray());
    }

    /**
     * Simulate an OutputStream that is connected to the DGC component of an RMI server.
     * Instead of sending data, the output stream drops anything that is put into it.
     */
    public OutputStream getOutputStream()
    {
        return new DevNullOutputStream();
    }
}
