package eu.tneitzel.rmg.io;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Dummy implementation of an OutputStream. This one is used during the ssrf-response action to prevent
 * remote-method-guesser from sending RMI messages to anywhere.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class DevNullOutputStream extends OutputStream {

    @Override
    public void write(int b) throws IOException
    {
    }
}
