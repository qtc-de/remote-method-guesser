package eu.tneitzel.rmg.plugin;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

import javassist.CtClass;

/**
 * The IRmiMarshalProvider interface allows users to customize marshaling of RMI objects.
 * The default marshaling implemented by DefaultProvider follows the RMI specification and
 * should be fine for most use cases. Only implement this interface if you need something
 * to be marshaled in an unusual way.
 *
 * This interface is implemented by rmg's DefaultProvider class by default.
 *
 * @author Tobias Neitzel (@qtc_de)
 */

public interface IRmiMarshalProvider
{
    /**
     * Marshals the input Object according to the specified type and writes it to the
     * ObjectOutput
     *
     * @param type  the type the object needs to be marshaled to
     * @param value  the object that needs to be marshaled
     * @param out  the ObjectOutput the object should be marshaled to
     */
    void marshalValue(Class<?> type, Object value, ObjectOutput out) throws IOException;
    
    /**
     * Unmarshals a value from ObjectInput. This method is called when processing the
     * return value of an RMI call.
     *
     * @param type  the expected type to unmarshal from ObjectInput
     * @param in  the ObjectInbut to unmarshal the object from
     * @return the unmarshaled object
     */
    Object unmarshalValue(CtClass type, ObjectInput in) throws IOException, ClassNotFoundException;
}
