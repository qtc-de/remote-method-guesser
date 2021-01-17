package de.qtc.rmg.io;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;

import de.qtc.rmg.internal.ExceptionHandler;
import de.qtc.rmg.utils.DefinitelyNonExistingClass;
import de.qtc.rmg.utils.RMGUtils;
import sun.rmi.server.MarshalOutputStream;

/**
 * MaliciousOutputStream can be used as a wrapper around a MarshalOutputStream or other subclasses
 * of it. Its main purpose is to overwrite the 'writeLocation' method in a convenient way and to allow
 * arbitrary objects to be passed as the location of an object. Within the remote-method-guesser project,
 * this can be used to enumerate how the String type is unmarshalled by the remote server. If the String
 * type is unmarshalled via 'readObject', the 'resolveClass' method will be called which tries to deserialize
 * the 'location' via another 'readObject'. If 'readString' is used to unmarshall the String type, the location
 * is just ignored. During a RMI lookup call.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
@SuppressWarnings("restriction")
public class MaliciousOutputStream extends MarshalOutputStream {

    private Object location;
    private ObjectOutputStream inner;

    private static Object defaultLocation = null;

    /**
     * Wraps a MarshalOutputStream into an extending class to overwrite its writeLocation method.
     * Wrapping already existing instances of ObjectOutputStream (or subclasses) is not trivial,
     * as the outer wrapper class usually causes a malformed OutputStream due to stream headers or
     * invalid block boundaries. In this implementation, it was tried to prevent this by cloning
     * the underlying BlockDataOutputStream.
     *
     * @param out  inner OutputStream. Needs to be declared as OutputStream because of inheritance.
     *                However, actually requires a MarshalOutputStream.
     * @throws IOException if the constructor of a super class throws this exception.
     */
    public MaliciousOutputStream(OutputStream out) throws IOException
    {
        super(out);

        if( !MarshalOutputStream.class.isAssignableFrom(out.getClass()) ) {
            Logger.eprintlnMixedYellow("Internal error:", "de.qtc.rmg.io.MaliciousOutputStream", "requires MaliciousOutputStream.");
            RMGUtils.exit();
        }

        try {
            Field bout = ObjectOutputStream.class.getDeclaredField("bout");
            bout.setAccessible(true);

            inner = (ObjectOutputStream)out;
            bout.set(this, bout.get(inner));

        } catch (Exception e) {
            Logger.eprintMixedYellow("Caught unexpected", e.getClass().getName(), "during creation of");
            Logger.printlnPlainBlue("MaliciousOutputStream.");
            Logger.eprintln("Please report this to improve rmg :)");
            ExceptionHandler.stackTrace(e);
            RMGUtils.exit();
        }

        if( defaultLocation != null )
            location = defaultLocation;
        else
            location = new DefinitelyNonExistingClass();
    }

    /**
     * Overwrites the default writeStreamHeader function from ObjectOutputStream.
     * This is required when wrapping an ObjectOutputStream into another one, as
     * otherwise the stream headers cause a malformed stream.
     */
    protected void writeStreamHeader() throws IOException
    {
    }


    /**
     * Overwrites the writeLocation method of MarshalOutputStream. Allows
     * to pass arbitrary objects as the 'location' of an object. This needs to
     * be done directly on the inner stream, as otherwise the method would be
     * called recursively (only twice, as the second call generates a reference,
     * but this would already break the stream).
     */
    protected void writeLocation(String realLocation) throws IOException
    {
        inner.writeObject(location);
    }

    public static void setDefaultLocation(Object payload)
    {
        defaultLocation = payload;
    }

    public static void resetDefaultLocation()
    {
        defaultLocation = null;
    }
}
