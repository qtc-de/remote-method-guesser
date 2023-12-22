package eu.tneitzel.rmg.internal;

import java.util.Iterator;

/**
 * Internally, Java RMI always uses an array of objects as argument for method calls.
 * During the marshalling, reflective access to the corresponding remote method is used
 * to determine the correct marshalling type. Primitive types are marshalled by their
 * corresponding write function (e.g. writeInt for the int type), whereas non primitive
 * types are usually marshalled with writeObject (except of String, that uses writeString).
 *
 * Within rmg, we do not use the high level RMI API and implemented low level RMI calls manually
 * (well, we still use RMI library functions and only implemented the actual dispatching manually).
 * This allows to call remote methods in different ways that it is usually done. E.g. it is no longer
 * required that the corresponding Method object actually exists and methods can be called directly
 * by specifying their hash value.
 *
 * However, the correct marshalling of call arguments is still required and if the corresponding
 * remote method does not exist within the current scope, it is required to pass the desired argument
 * types in a different way. For this purpose, we use the MethodArguments class, that stores
 * method arguments together with their desired marshalling type.
 *
 * When creating a MethodArguments object, you currently need to pass the expected capacity for the
 * argument array. This was a design decision, to allow storing method arguments within the most
 * simple data structure. Previously, we used LinkedHashMap to store arguments, which caused troubles
 * as deserialization gadgets triggered when putting them into the map.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
@SuppressWarnings("rawtypes")
public class MethodArguments implements Iterable<Pair<Object,Class>>, Iterator<Pair<Object,Class>>
{
    private int size = 0;
    private int capacity = 0;
    private int currentIndex = 0;

    private Pair<Object,Class>[] methodArguments;

    /**
     * @param capacity
     */
    @SuppressWarnings("unchecked")
    public MethodArguments(int capacity)
    {
        this.capacity = capacity;
        this.methodArguments = new Pair[capacity];
    }

    /**
     * @param argumentObject
     * @param argumentClass
     */
    @SuppressWarnings("unchecked")
    public MethodArguments(Object argumentObject, Class argumentClass)
    {
        this.capacity = 1;
        this.methodArguments = new Pair[capacity];

        methodArguments[size++] = new Pair<Object, Class>(argumentObject, argumentClass);
    }

    @Override
    public Iterator<Pair<Object,Class>> iterator()
    {
        return this;
    }

    @Override
    public boolean hasNext()
    {
        return currentIndex < size;
    }

    @Override
    public Pair<Object,Class> next()
    {
        return methodArguments[currentIndex++];
    }

    /**
     * @param argumentObject
     * @param argumentClass
     */
    public void add(Object argumentObject, Class argumentClass)
    {
        if (size < capacity)
        {
            methodArguments[size++] = new Pair<Object, Class>(argumentObject, argumentClass);
        }
    }
}
