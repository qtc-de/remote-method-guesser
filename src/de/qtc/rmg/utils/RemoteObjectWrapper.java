package de.qtc.rmg.utils;

import java.lang.reflect.Proxy;
import java.rmi.Remote;
import java.rmi.server.RemoteObjectInvocationHandler;
import java.rmi.server.RemoteRef;
import java.util.ArrayList;
import java.util.List;

import de.qtc.rmg.endpoints.KnownEndpoint;
import de.qtc.rmg.endpoints.KnownEndpointHolder;
import de.qtc.rmg.internal.ExceptionHandler;
import sun.rmi.server.UnicastRef;

/**
 * The RemoteObjectWrapper class represents a wrapper around the ordinary RMI remote object related classes.
 * It stores the basic information that is required to use the remote object as usual, but adds additional
 * fields that allow to obtain meta information more easily.
 *
 * From remote-method-guesser v4.3.0 on, the class gets extended by the UnicastWrapper and ActivatbaleWrapper
 * classes. As the names suggest, UnicastWrapper is used to wrap remote objects that contain a UnicastRef,
 * whereas ActivatableWrapper is used for wrapping ActivatabaseRef types.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
@SuppressWarnings("restriction")
public class RemoteObjectWrapper
{
    public String className;
    public String boundName;
    public Remote remoteObject;
    public KnownEndpoint knownEndpoint;

    public List<RemoteObjectWrapper> duplicates;

    /**
     * This constructor is only used for special purposes during the enum action. The resulting
     * RemoteObjectWrapper is not fully functional and should not be used for other purposes than
     * displaying the bound name.
     *
     * @param boundName as used in the RMI registry
     */
    public RemoteObjectWrapper(String boundName)
    {
        this.boundName = boundName;
    }

    /**
     * Partially initializes a wrapper. This constructor goes already a little bit deeper than the
     * previous one by also assigning the remote object, checking for the implementing class and
     * whether it is a duplicate. However, this constructor should still only be used by subclasses
     * that add the missing fields.
     *
     * @param boundName bound name as used in the RMI registry
     * @param remoteObject the corresponding remote object
     */
    public RemoteObjectWrapper(String boundName, Remote remoteObject)
    {
        this.boundName = boundName;
        this.remoteObject = remoteObject;

        this.className = RMGUtils.getClassName(remoteObject);
        this.duplicates = new ArrayList<RemoteObjectWrapper>();
        this.knownEndpoint = KnownEndpointHolder.getHolder().lookup(className);
    }

    /**
     * Create a RemoteObjectWrapper for the specified Remote. See the extended
     * version of the function below for more information.
     *
     * @param remote remote to create the wrapper for
     * @return RemoteObjectWrapper for the specified remote
     * @throws Reflection related exceptions
     */
    public static RemoteObjectWrapper getInstance(Remote remote) throws IllegalArgumentException, IllegalAccessException, NoSuchFieldException, SecurityException
    {
        return RemoteObjectWrapper.getInstance(remote, null);
    }

    /**
     * Create a RemoteObjectWrapper for the specified Remote. This function uses reflection
     * to inspect the reference type of the specified Remote. If it is a UnicastRef, a UnicastWrapper
     * is returned. Otherwise, an ActivatbaleWrapper is returned.
     *
     * @param remote remote to create the wrapper for
     * @param boundName bound name as specified in the RMI registry
     * @return RemoteObjectWrapper - Either a UnicastWrapper or a ActivatbaleWrapper depending on the Remote
     * @throws Reflection related exceptions
     */
    public static RemoteObjectWrapper getInstance(Remote remote, String boundName) throws IllegalArgumentException, IllegalAccessException, NoSuchFieldException, SecurityException
    {
        RemoteObjectWrapper wrapper = null;
        RemoteRef ref = RMGUtils.extractRef(remote);

        if (ref instanceof UnicastRef)
            wrapper = new UnicastWrapper(remote, boundName, (UnicastRef)ref);

        else if (ref.getClass().getName().contains("ActivatableRef"))
            wrapper = new ActivatableWrapper(remote, boundName, ref);

        else
            ExceptionHandler.internalError("RemoteObjectWrapper.getInstance", "Unexpected reference type");

        return wrapper;
    }
    /**
     * Create a new RemoteObjectWrapper from a RemoteRef. This function creates a Proxy that implements
     * the specified interface and uses a RemoteObjectInvocationHandler to forward method invocations to
     * the specified RemoteRef.
     *
     * @param remoteRef RemoteRef to the targeted RemoteObject
     * @param intf Interface that is implemented by the RemoteObject
     * @throws many Exceptions...
     */
    public static RemoteObjectWrapper fromRef(RemoteRef remoteRef, Class<?> intf) throws IllegalArgumentException, IllegalAccessException, NoSuchFieldException, SecurityException
    {
        if( !Remote.class.isAssignableFrom(intf) )
            ExceptionHandler.internalError("RemoteObjectWrapper.fromRef", "Specified interface is not valid");

        RemoteObjectInvocationHandler remoteObjectInvocationHandler = new RemoteObjectInvocationHandler(remoteRef);
        Remote remoteObject = (Remote)Proxy.newProxyInstance(intf.getClassLoader(), new Class[] { intf }, remoteObjectInvocationHandler);

        return RemoteObjectWrapper.getInstance(remoteObject);
    }

    /**
     * Checks whether the Wrapper has any duplicates (other remote objects that implement the same
     * remote interface).
     *
     * @return true if duplicates are present
     */
    public boolean hasDuplicates()
    {
        if( this.duplicates.size() == 0 )
            return false;

        return true;
    }

    /**
     * Add a duplicate to the RemoteObjectWrapper. This should be a wrapper that implements the same
     * remote interface as the original wrapper.
     *
     * @param o duplicate RemoteObjectWrapper that implements the same remote interface
     */
    public void addDuplicate(RemoteObjectWrapper o)
    {
        this.duplicates.add(o);
    }

    /**
     * Iterates over the list of registered duplicates and returns the associated bound names as an array.
     *
     * @return array of String that contains duplicate bound names
     */
    public String[] getDuplicateBoundNames()
    {
        List<String> duplicateNames = new ArrayList<String>();

        for(RemoteObjectWrapper o : this.duplicates)
            duplicateNames.add(o.boundName);

        return duplicateNames.toArray(new String[0]);
    }

    /**
     * Searches a supplied list of RemoteObjectWrapper objects for the Wrapper that is associated to the
     * specified bound name.
     *
     * @param boundName associated bound name to look for
     * @param list RemoteObjectWrapper objects to search in
     * @return RemoteObjectWrapper that matches the specified bound name or null
     */
    public static RemoteObjectWrapper getByName(String boundName, RemoteObjectWrapper[] list)
    {
        for(RemoteObjectWrapper o : list)
        {
            if( o != null && o.boundName.equals(boundName) )
                return o;
        }

        return null;
    }

    /**
     * Takes a list of RemoteObjectWrappers and looks for duplicates within it. The return value
     * is a list of unique RemoteObjectWrappers that have the corresponding duplicates assigned.
     *
     * @param list RemoteObjectWrappers to search for duplicates
     * @return Unique RemoteObjectWrappers with duplicates assigned
     */
    public static RemoteObjectWrapper[] handleDuplicates(RemoteObjectWrapper[] list)
    {
        List<RemoteObjectWrapper> unique = new ArrayList<RemoteObjectWrapper>();

        outer: for(RemoteObjectWrapper current : list) {

            for(RemoteObjectWrapper other : unique) {

                if(other.className.equals(current.className)) {
                    other.addDuplicate(current);
                    continue outer;
                }
            }

            unique.add(current);
        }

        return unique.toArray(new RemoteObjectWrapper[0]);
    }

    /**
     * Takes a list of RemoteObjectWrappers and checks whether one of them contains duplicates.
     *
     * @param list RemoteObjectWrappers to check for duplicates
     * @return true if at least one RemoteObjectWrapper contains a duplicate
     */
    public static boolean hasDuplicates(RemoteObjectWrapper[] list)
    {
        for(RemoteObjectWrapper o : list) {

            if( o.hasDuplicates() )
                return true;
        }

        return false;
    }

    /**
     * Creates an array of RemoteObjectWrapper from an array of bound names. The resulting RemoteObjectWrappers
     * are dummy objects that just contain the associated bound name. This should only be used during rmg's enum
     * action to display bound names using the Formatter class.
     *
     * @param boundNames Array of String to create the RemoteObjectWrapper from
     * @return Array of RemoteObjectWrapper associated to the specified bound names
     */
    public static RemoteObjectWrapper[] fromBoundNames(String[] boundNames)
    {
        RemoteObjectWrapper[] returnValue = new RemoteObjectWrapper[boundNames.length];

        for(int ctr = 0; ctr < boundNames.length; ctr++)
            returnValue[ctr] = new RemoteObjectWrapper(boundNames[ctr]);

        return returnValue;
    }

    /**
     * Check whether the endpoint is a known endpoint.
     *
     * @return True of the endpoint is known.
     */
    public boolean isKnown()
    {
        if( knownEndpoint == null )
            return false;

        return true;
    }

    /**
     * Transform an array of RemoteObjectWrapper into an array of UnicastWrapper. If an
     * element is already a UnicastWrapper, it is simply returned. ActivatableWrappers, on
     * the other hand, are activated to create a UnicastWrapper.
     *
     * @param wrappers RemoteObjectWrapper array
     * @return Array of associated UnicastWrappers
     */
    public static UnicastWrapper[] getUnicastWrappers(RemoteObjectWrapper[] wrappers)
    {
        UnicastWrapper[] unicastWrappers = new UnicastWrapper[wrappers.length];

        for (int ctr = 0; ctr < wrappers.length; ctr++)
        {
            if (wrappers[ctr] instanceof UnicastWrapper)
            {
                unicastWrappers[ctr] = (UnicastWrapper) wrappers[ctr];
            }

            else
            {
                try {
                    unicastWrappers[ctr] = ((ActivatableWrapper)wrappers[ctr]).activate();
                } catch (IllegalArgumentException | IllegalAccessException | NoSuchFieldException | SecurityException e) {
                    ExceptionHandler.unexpectedException(e, "activate", "call", true);
                }
            }
        }

        return unicastWrappers;
    }
}
