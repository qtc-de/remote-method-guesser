package de.qtc.rmg.io;

import java.io.DataInput;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.lang.reflect.Field;

import de.qtc.rmg.internal.ExceptionHandler;

/**
 * Wrapper class for an ObjectInputStream. Allows to perform raw byte operations on the underlying
 * input stream.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class RawObjectInputStream {

    private DataInput bin;
    private InputStream inStream;

    /**
     * Wraps an ObjectInputStream into an RawObjectInputStream. The underlying InputStream object is made
     * accessible via reflection. This underlying InputStream can then be used to perform raw byte operations.
     *
     * @param in ObjectInputStream to wrap around
     */
    public RawObjectInputStream(ObjectInputStream in)
    {
        try {
            Field binField = ObjectInputStream.class.getDeclaredField("bin");
            binField.setAccessible(true);
            bin = (DataInput)binField.get(in);

            Field inputStreamField = null;
            Class<?>[] classes = ObjectInputStream.class.getDeclaredClasses();
            for(Class<?> c : classes) {
                if(c.getCanonicalName().endsWith("BlockDataInputStream")) {
                    inputStreamField = c.getDeclaredField("in");
                    inputStreamField.setAccessible(true);
                }
            }

            inStream = (InputStream)inputStreamField.get(bin);

        } catch (Exception e) {
            ExceptionHandler.unexpectedException(e, "creation", "of MaliciousOutputStream", true);
        }
    }

    /**
     * Skip the next n bytes of input on the stream.
     *
     * @param n amount of bytes to skip
     * @throws IOException
     */
    public void skip(int n) throws IOException
    {
        inStream.skip(n);
    }
}
