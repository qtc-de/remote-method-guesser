package eu.tneitzel.rmg.io;

import java.io.DataOutput;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;

import eu.tneitzel.rmg.internal.ExceptionHandler;

/**
 * Wrapper class for an ObjectOutputStream. Allows to perform raw byte operations on the underlying
 * output stream.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class RawObjectOutputStream {

    private DataOutput bout;
    private OutputStream outStream;

    /**
     * Wraps an ObjectOutputStream into an RawObjectOutputStream. The underlying OutputStream object is made
     * accessible via reflection. This underlying OutputStream can then be used to perform raw byte operations.
     *
     * @param out OutputStream to wrap around
     */
    public RawObjectOutputStream(ObjectOutputStream out)
    {
        try {
            Field boutField = ObjectOutputStream.class.getDeclaredField("bout");
            boutField.setAccessible(true);
            bout = (DataOutput)boutField.get(out);

            Field outputStreamField = null;
            Class<?>[] classes = ObjectOutputStream.class.getDeclaredClasses();
            for(Class<?> c : classes) {
                if(c.getCanonicalName().endsWith("BlockDataOutputStream")) {
                    outputStreamField = c.getDeclaredField("out");
                    outputStreamField.setAccessible(true);
                }
            }

            outStream = (OutputStream)outputStreamField.get(bout);

        } catch (Exception e) {
            ExceptionHandler.unexpectedException(e, "creation", "of MaliciousOutputStream", true);
        }
    }

    /**
     * Write raw byte to the underlying output stream.
     *
     * @param content byte to write
     * @throws IOException internal error
     */
    public void writeRaw(byte content) throws IOException
    {
        outStream.write(content);
    }
}
