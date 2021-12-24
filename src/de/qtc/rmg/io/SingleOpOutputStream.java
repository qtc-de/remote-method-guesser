package de.qtc.rmg.io;

import java.io.ByteArrayOutputStream;

import de.qtc.rmg.internal.ExceptionHandler;

/**
 * The SingleOpOutputStream class is used during SSRF operations. When the SSRF option is used,
 * remote-method-guesser collects output data into an byte array instead of sending it to a remote
 * server. The corresponding RMI calls always use the stream protocol, which is not ideal for SSRF
 * attacks. The SingleOpOutputStream abuses the fact that Java RMI calls the flush method on the
 * stream directly before and after the handshake that is performed within the stream protocol.
 * This allows to cleanly cutoff the handshake and to switch the contents of the resulting byte
 * array to the single operation protocol.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class SingleOpOutputStream extends ByteArrayOutputStream {

    private int flushCount;

    public SingleOpOutputStream() {
        super();
        flushCount = 0;
    }

    /**
     * Java RMI calls the flush method before and after the handshake. During the first call, only the
     * RMI magic, the protocol version and the protocol type are contained in the stream. After the
     * second call, the client host and client port are contained. Afterwards, the handshake has completed
     * and the RMI communication starts.
     */
    public synchronized void write(byte[] b, int off, int len)
    {
        switch( flushCount++ ) {

            case 0:

                if( b[len - 1] != 0x4b )
                    ExceptionHandler.internalError("SingleOpOutputStream.write", "invalid protocol type");

                b[len - 1] = 0x4c;
                break;

            case 1:

                return;

            case 2:

                if( b[0] != 0x50 )
                    ExceptionHandler.internalError("SingleOpOutputStream.write", "invalid operation type");

                break;
        }

        super.write(b, off, len);
    }
}
