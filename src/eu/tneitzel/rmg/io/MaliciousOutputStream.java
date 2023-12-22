package eu.tneitzel.rmg.io;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;

import eu.tneitzel.rmg.internal.ExceptionHandler;
import eu.tneitzel.rmg.utils.DefinitelyNonExistingClass;
import eu.tneitzel.rmg.utils.RMGUtils;
import sun.rmi.server.MarshalOutputStream;

/**
 * MaliciousOutputStream can be used as a wrapper around a MarshalOutputStream or other subclasses
 * of it. Its main purpose is to overwrite the 'writeLocation' method in a convenient way and to allow
 * arbitrary objects to be passed as the location of an object. Within the remote-method-guesser project,
 * this can be used to enumerate how the String type is unmarshalled by the remote server. If the String
 * type is unmarshalled via 'readObject', the 'resolveClass' method will be called which tries to deserialize
 * the 'location' via another 'readObject'. If 'readString' is used to unmarshal the String type, the location
 * is just ignored during a RMI lookup call.
 *
 * Technically speaking, the above mentioned unmarshal behavior could also be enumerated easier (which is also
 * done in current versions) by just specifying a malformed URL an catching the corresponding exception. However,
 * passing arbitrary objects has initially been an idea to bypass the new marshalling of the String type. For this
 * purpose, this class was used. Although bypassing String marshalling does not work (cause resolve class is never
 * called as explained above), this class is kept as it may be useful for other ideas on the subject.
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
     * @param out inner OutputStream. Needs to be declared as OutputStream because of inheritance.
     *                However, actually requires a MarshalOutputStream.
     * @throws IOException if the constructor of a super class throws this exception.
     */
    public MaliciousOutputStream(OutputStream out) throws IOException
    {
        super(out);

        if( !MarshalOutputStream.class.isAssignableFrom(out.getClass()) ) {
            Logger.eprintlnMixedYellow("Internal error:", "eu.tneitzel.rmg.io.MaliciousOutputStream", "requires MaliciousOutputStream.");
            RMGUtils.exit();
        }

        try {
            Field bout = ObjectOutputStream.class.getDeclaredField("bout");
            bout.setAccessible(true);

            inner = (ObjectOutputStream)out;
            bout.set(this, bout.get(inner));

        } catch (Exception e) {
            ExceptionHandler.unexpectedException(e, "creation", "of MaliciousOutputStream", true);
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
     * to pass arbitrary objects as the 'location' of an object. Depending on
     * the specified type, This needs to be done directly on the inner stream.
     * I'm not 100% sure, but I guess the problem is that for non primitive and
     * non String objects, the method would be called twice which causes a malformed
     * stream.
     *
     * Notice that the method needs to accept only String types as arguments because
     * of inheritance. However, only the 'location' attribute is used for the stream,
     * while 'realLocation' is completely ignored.
     *
     * @param realLocation is completely ignored
     */
    protected void writeLocation(String realLocation) throws IOException
    {
        if(location.getClass().isPrimitive() || location instanceof String)
            writeObject(location);
        else
            inner.writeObject(location);
    }

    /**
     * Set the location object to provide within the stream.
     *
     * @param payload object to use as location.
     */
    public static void setDefaultLocation(Object payload)
    {
        defaultLocation = payload;
    }

    /**
     * Return the class name of the currently configured location object.
     *
     * @return classname of the currently configured location.
     */
    public static String getDefaultLocation()
    {
        if(defaultLocation instanceof String)
            return (String)defaultLocation;
        else
            return defaultLocation.getClass().getName();
    }

    /**
     * Reset the default location to null.
     */
    public static void resetDefaultLocation()
    {
        defaultLocation = null;
    }
}
