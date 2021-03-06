package de.qtc.rmg.operations;

import java.lang.reflect.Method;

import de.qtc.rmg.internal.ExceptionHandler;

/**
 * The Operation enum class contains one item for each possible rmg action. An enum item consists out of
 * the corresponding method name, the expected positional parameters and the helpstring that should be
 * displayed for the method. This allows to keep all this information structured in one place without having
 * to maintain it elsewhere. During the construction, the constructor of the Operation class looks up the specified
 * method within the Dispatcher class and saves a reference to it. Methods are then invoked by using the
 * Operation.invoke function.
 *
 * To create a new rmg action, a new enum item has to be created and the corresponding method has to be added to
 * the Dispatcher class.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public enum Operation {
    ACT("dispatchActivator", "<gadget> <command>", "Performs Activator based deserialization attacks"),
    BIND("dispatchBind", "[gadget] <command>", "Binds an object to the registry thats points to listener"),
    CALL("dispatchCall", "<arguments>", "Regulary calls a method with the specified arguments"),
    CODEBASE("dispatchCodebase", "<classname> <url>", "Perform remote class loading attacks"),
    DGC("dispatchDGC", "<gadget> <command>", "Perform DGC based deserialization attacks"),
    ENUM("dispatchEnum", "", "Enumerate bound names, classes, SecurityManger and JEP290"),
    GUESS("dispatchGuess", "", "Guess methods on bound names"),
    LISTEN("dispatchListen", "<gadget> <command>", "Open ysoserials JRMP listener"),
    METHOD("dispatchMethod", "<gadget> <command>", "Perform method based deserialization attacks"),
    REBIND("dispatchRebind", "[gadget] <command>", "Rebinds boundname as object that points to listener"),
    REG("dispatchRegistry", "<gadget> <command>", "Perform registry based deserialization attacks"),
    UNBIND("dispatchUnbind", "", "Removes the specified bound name from the registry");

    private Method method;
    private String arguments;
    private String description;

    /**
     * Creates a new Operation item. The first argument (methodName) is used for a reflective method
     * accesses within the Dispatcher class. The corresponding method is saved within the corresponding
     * enum item.
     *
     * @param methodName name of the method that belongs to the operation
     * @param arguments expected positional arguments
     * @param description description of the method to show in the help menu
     */
    Operation(String methodName, String arguments, String description)
    {
        try {
            this.method = Dispatcher.class.getDeclaredMethod(methodName, new Class<?>[] {});
        } catch(Exception e) {
            ExceptionHandler.internalException(e, "Operation constructor", true);
        }

        this.arguments = arguments;
        this.description = description;
    }

    public Method getMethod()
    {
        return this.method;
    }

    public String getDescription()
    {
        return this.description;
    }

    public String getArgs()
    {
        return this.arguments;
    }

    /**
     * Invokes the method that was saved within the Operation.
     *
     * @param dispatcherObject object to invoke the method on
     */
    public void invoke(Dispatcher dispatcherObject)
    {
        try {
            this.method.invoke(dispatcherObject);
        } catch(Exception e) {
            ExceptionHandler.internalException(e, "Operation invoke", true);
        }
    }

    /**
     * Iterates over the Operation enumeration and returns the operation that equals the specified
     * operation name.
     *
     * @param name desired Operation to return
     * @return requested Operation object or null if not found
     */
    public static Operation getByName(String name)
    {
        Operation returnItem = null;

        for(Operation item : Operation.values()) {
            if(item.toString().equalsIgnoreCase(name)) {
                returnItem = item;
                break;
            }
        }

        return returnItem;
    }
}
