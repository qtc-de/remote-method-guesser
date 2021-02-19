package de.qtc.rmg.operations;

import java.lang.reflect.Method;

import de.qtc.rmg.internal.ExceptionHandler;

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

    public void invoke(Dispatcher dispatcherObject)
    {
        try {
            this.method.invoke(dispatcherObject);
        } catch(Exception e) {
            ExceptionHandler.internalException(e, "Operation invoke", true);
        }
    }

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
