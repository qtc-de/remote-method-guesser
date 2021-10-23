package de.qtc.rmg.internal;

import java.rmi.server.ObjID;

import de.qtc.rmg.io.Logger;
import de.qtc.rmg.utils.RMGUtils;

/**
 * During the different RMI operations you have always a roughly same set of exceptions
 * that can occur. To have a unified error handling and to avoid too much duplicate code,
 * the most common exceptions are handled by this class.
 *
 * The overall exception handling could be improved even more by defining exception handlers
 * that automatically handle the exceptions that could be thrown by a specific type of attack
 * (e.g. codebase, deserialize, ...). This may be implemented in future and will remove much
 * more duplicate code.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class ExceptionHandler {

    private static boolean alwaysShowExceptions = false;

    private static void sslOption()
    {
        if(RMGOption.SSL.getBool())
            Logger.eprintlnMixedBlue("You probably used", "--ssl", "on a plaintext connection?");
        else
            Logger.eprintlnMixedYellow("You can retry the operation using the", "--ssl", "option.");
    }

    public static void internalError(String functionName, String message)
    {
        Logger.eprintlnMixedYellow("Internal error within the", functionName, "function.");
        Logger.eprintln(message);
        RMGUtils.exit();
    }

    public static void internalException(Exception e, String functionName, boolean exit)
    {
        Logger.eprintMixedYellow("Internal error. Caught unexpected", e.getClass().getName(), "within the ");
        Logger.printlnPlainMixedBlue(functionName, "function.");
        stackTrace(e);

        if(exit)
            RMGUtils.exit();
    }

    public static void unexpectedException(Exception e, String during1, String during2, boolean exit)
    {
        Logger.eprintMixedYellow("Caught unexpected", e.getClass().getName(), "during ");
        Logger.printlnPlainMixedBlueFirst(during1, during2 + ".");
        Logger.eprintln("Please report this to improve rmg :)");
        stackTrace(e);

        if(exit)
            RMGUtils.exit();
    }

    public static void alreadyBoundException(Exception e, String boundName)
    {
        Logger.eprintlnMixedYellow("Bind operation", "was accepted", "by the server.");
        Logger.eprintlnMixedBlue("But the boundname", boundName, "is already bound.");
        Logger.eprintlnMixedYellow("Use the", "rebind", "action instead.");
        showStackTrace(e);
    }

    public static void nonLocalhost(Exception e, String callName, boolean bypass)
    {
        Logger.eprintlnMixedYellow("Registry", "rejected " + callName + " call", "because it was not send from localhost.");

        if(!bypass)
            Logger.eprintlnMixedBlue("You can attempt to bypass this restriction using the", "--localhost-bypass", "option.");
        else
            Logger.eprintlnMixedBlue("Localhost bypass was used but", "failed.");

        showStackTrace(e);
    }

    public static void jep290(Exception e)
    {
        Logger.eprintlnMixedYellow("RMI registry", "rejected", "deserialization of the supplied gadget.");
        Logger.eprintlnMixedBlue("The specified gadget", "did not", "pass the deserialization filter.");
        showStackTrace(e);
    }

    public static void deserializeClassNotFound(Exception e)
    {
        Logger.eprintlnMixedYellow("Server", "accepted", "deserialization of the supplied gadget, but");
        Logger.eprintlnMixedBlue("during the deserialization, a", "ClassNotFoundException", "was encountered.");
        Logger.eprintMixedYellow("The supplied gadget may have", "worked anyway", "or it is ");
        Logger.printlnPlainMixedBlueFirst("not available", "on the servers classpath.", "");
        showStackTrace(e);
    }

    public static void deserializeClassNotFoundRandom(Exception e, String during1, String during2, String className)
    {
        Logger.printlnMixedYellow("Caught", "ClassNotFoundException", "during " + during1 + " " + during2 + ".");
        Logger.printlnMixedBlue("Server attempted to deserialize dummy class", className + ".");
        Logger.printlnMixedYellow("Deserialization attack", "probably worked :)");
        showStackTrace(e);
    }

    public static void deserlializeClassCast(Exception e, boolean wasString)
    {
        Logger.printlnMixedYellow("Caught", "ClassCastException", "during deserialization attack.");

        if(wasString)
            Logger.printlnMixedBlue("The server uses either", "readString()", "to unmarshal String parameters, or");

        Logger.printlnMixedYellowFirst("Deserialization attack", "was probably successful :)");
        showStackTrace(e);
    }

    public static void codebaseClassNotFound(Exception e, String className)
    {
        Logger.eprintlnMixedYellow("Caught", "ClassNotFoundException", "during codebase attack.");
        Logger.eprintlnMixedBlue("The payload class could", "not be loaded", "from the specified endpoint.");
        Logger.eprintMixedYellow("The endpoint is probably configured with", "useCodeBaseOnly=true");
        Logger.printlnPlainYellow(" (not vulnerable)");
        Logger.eprintlnMixedBlue("or the file", className + ".class", "was not found on the specified endpoint.");
        showStackTrace(e);
    }

    public static void codebaseSecurityManager(Exception e)
    {
        Logger.eprintlnMixedYellow("The class loader of the specified target is", "disabled.");
        Logger.eprintlnMixedBlue("Codebase attacks are", "not", "possible.");
        showStackTrace(e);
    }

    public static void codebaseClassNotFoundRandom(Exception e, String className, String payloadName)
    {
        Logger.printlnMixedBlue("Remote class loader attempted to load dummy class", className);
        Logger.printlnMixedYellow("Codebase attack", "probably worked :)");

        Logger.lineBreak();
        Logger.printlnMixedYellow("If where was no callback, the server did not load the attack class", payloadName + ".class.");
        Logger.println("The class is probably known by the server or it was already loaded before.");
        Logger.printlnMixedBlue("In this case, you should try a", "different classname.");
        showStackTrace(e);
    }

    public static void codebaseClassCast(Exception e, boolean wasString)
    {
        Logger.printlnMixedYellow("Caught", "ClassCastException", "during codebase attack.");

        if(wasString)
            Logger.printlnMixedBlue("The server uses either", "readString()", "to unmarshal String parameters, or");

        Logger.printlnMixedYellowFirst("Codebase attack", "most likely", "worked :)");
        showStackTrace(e);
    }

    public static void codebaseClassFormat(Exception e)
    {
        Logger.printlnMixedYellow("Caught", "ClassFormatError", "during codebase attack.");
        Logger.eprintlnMixedBlue("The loaded file", "is not", "a valid Java class.");

        showStackTrace(e);
    }

    public static void connectionRefused(Exception e, String during1, String during2)
    {
        Logger.eprintlnMixedYellow("Caught unexpected", "ConnectException", "during " + during1 + " " + during2 + ".");
        Logger.eprintMixedBlue("Target", "refused", "the connection.");
        Logger.printlnPlainMixedBlue(" The specified port is probably", "closed.");
        showStackTrace(e);
        RMGUtils.exit();
    }

    public static void noRouteToHost(Exception e, String during1, String during2)
    {
        Logger.eprintlnMixedYellow("Caught unexpected", "NoRouteToHostException", "during " + during1 + " " + during2 + ".");
        Logger.eprintln("Have you entered the correct target?");
        showStackTrace(e);
        RMGUtils.exit();
    }

    public static void noJRMPServer(Exception e, String during1, String during2)
    {
        Logger.eprintlnMixedYellow("Caught unexpected", "ConnectIOException", "during " + during1 + " " + during2 + ".");
        Logger.eprintMixedBlue("Remote endpoint is either", "no RMI endpoint", "or uses an");
        Logger.printlnPlainBlue(" SSL socket.");

        ExceptionHandler.sslOption();

        showStackTrace(e);
        RMGUtils.exit();
    }

    public static void sslError(Exception e, String during1, String during2)
    {
        Logger.eprintlnMixedYellow("Caught unexpected", "SSLException", "during " + during1 + " " + during2 + ".");
        ExceptionHandler.sslOption();

        showStackTrace(e);
        RMGUtils.exit();
    }

    public static void invalidClass(Exception e, String endpoint)
    {
        invalidClass(e, endpoint, true);
    }

    public static void invalidClass(Exception e, String endpoint, boolean trace)
    {
        Logger.eprintlnMixedYellow(endpoint, "rejected", "deserialization of one of the transmitted classes.");
        Logger.eprintlnMixedBlue("The supplied gadget", "did not", "pass the deserialization filter.");

        if( trace )
            showStackTrace(e);
    }

    public static void invalidClassBind(Exception e, String operation, String className)
    {
        Logger.eprintln(operation + " operation failed!");
        Logger.eprintMixedYellow("RMI registry", "rejected", "deserialization of class ");
        Logger.printlnPlainBlue(className);
        Logger.eprintlnMixedBlue("  --> The server uses a", "custom deserialization filter", "for the RMI registry.");
        Logger.eprintlnMixedYellow("This is common for", "JMX", "based registry services.");
        showStackTrace(e);

        RMGUtils.exit();
    }

    public static void invalidClassEnum(Exception e, String callName)
    {
        Logger.printlnMixedYellow("- Caught", "InvalidClassException", "during " + callName + " call.");
        Logger.printMixedBlue("  --> The server uses a", "custom deserialization filter", "for the RMI registry");
        Logger.printlnPlainBlue(" (JMX?)");
        Logger.statusUndecided("Configuration");
        showStackTrace(e);
    }

    public static void unsupportedOperationException(Exception e, String callName)
    {
        Logger.eprintlnMixedYellow("Caught", "UnsupportedOperationException", "during " + callName + " call.");
        Logger.eprintlnMixedBlue("The server probably uses a", "custom deserialization filter.");
        Logger.eprintlnMixedBlue("This behavior is known e.g. by the", "NotSoSerial", "project.");
        showStackTrace(e);

        RMGUtils.exit();
    }

    public static void unsupportedOperationExceptionEnum(Exception e, String callName)
    {
        Logger.eprintlnMixedYellow("- Caught", "UnsupportedOperationException", "during " + callName + " call.");
        Logger.eprintlnMixedBlue("  --> The server probably uses a", "custom deserialization filter (NotSoSerial?)");
        Logger.statusUndecided("Configuration");
        showStackTrace(e);
    }

    public static void accessControl(Exception e, String during1, String during2)
    {
        Logger.eprintlnMixedYellow("Caught unexpected", "AccessControlException", "during " + during1 + " " + during2 + ".");
        Logger.eprintlnMixedBlue("The servers", "SecurityManager", "may refused the operation.");
        showStackTrace(e);
    }

    public static void singleEntryRegistry(Exception e, String during1)
    {
        Logger.eprintlnMixedYellow("- Caught", "AccessException", "during " + during1 + "call.");
        Logger.eprintlnMixedBlue("  --> The servers seems to use a", "SingleEntryRegistry", "(probably JMX based).");
        Logger.statusUndecided("Vulnerability");
        showStackTrace(e);
    }

    public static void noSuchObjectException(Exception e, String object, boolean exit)
    {
        Logger.eprintlnMixedYellow("Caught", "NoSuchObjectException", "during RMI call.");
        Logger.eprintlnMixedBlue("There seems to be no", object, "object avaibale on the specified endpoint.");
        showStackTrace(e);

        if(exit)
            RMGUtils.exit();
    }

    public static void noSuchObjectException(Exception e, ObjID objID, boolean exit)
    {
        Logger.eprintlnMixedYellow("Caught", "NoSuchObjectException", "during RMI call.");

        if(objID != null)
            Logger.eprintlnMixedBlue("ObjID", objID.toString(), "is not available on this endpoint.");

        else
            Logger.eprintlnMixedBlue("The targeted object", "is not", "available on this endpoint.");

        showStackTrace(e);

        if(exit)
            RMGUtils.exit();
    }

    public static void noSuchObjectExceptionRegistryEnum()
    {
        Logger.printlnBlue("RMI Registry Enumeration");
        Logger.lineBreak();
        Logger.increaseIndent();
        Logger.printlnMixedYellow("- Specified endpoint", "is not", "an RMI registry");
        Logger.println("  Skipping registry related checks.");
        Logger.decreaseIndent();
    }

    public static void eofException(Exception e, String during1, String during2)
    {
        Logger.eprintlnMixedYellow("Caught unexpected", "EOFException", "during " + during1 + " " + during2 + ".");
        Logger.eprintlnMixedBlue("One possible reason is a missmatch in the", "TLS", "settings.");

        ExceptionHandler.sslOption();

        showStackTrace(e);
        RMGUtils.exit();
    }

    public static void invalidListenerFormat(boolean gadget)
    {
        if(gadget)
            Logger.eprintlnMixedBlue("Selected gadget expects a", "listener", "as command input.");

        Logger.eprintlnMixedYellow("Listener must be specified in", "host:port", "format.");
        RMGUtils.exit();
    }

    public static void invalidSignature(String signature)
    {
        Logger.eprintlnMixedYellow("Encountered invalid function signature:", signature);
        Logger.eprintln("Correct the format and try again :)");
        RMGUtils.exit();
    }

    public static void unknownDeserializationException(Exception e)
    {
        Throwable cause = getCause(e);

        Logger.printlnMixedYellow("Caught", cause.getClass().getName(), "during deserialization attack.");
        Logger.printlnMixedBlue("This could be caused by your gadget an the attack", "probably worked anyway.");
        Logger.printlnMixedYellow("If it did not work, you can retry with", "--stack-trace", "to see the details.");
        showStackTrace(e);
    }

    public static void unsupportedClassVersion(Exception e, String during1, String during2)
    {
        Logger.eprintlnMixedYellow("Caught", e.getClass().getName(), "during " + during1 + " " + during2 + ".");
        Logger.eprintlnMixedBlue("You probably used an", "incompatible compiler version", "for class generation.");
        Logger.eprintln("Exception Message: " + e.getMessage());
        showStackTrace(e);
    }

    public static void illegalArgument(Exception e)
    {
        Logger.printlnMixedYellow("Caught", "IllegalArgumentException", "during deserialization attack.");
        Logger.printlnMixedYellowFirst("Deserialization attack", "was probably successful :)");
        showStackTrace(e);
    }

    public static void illegalArgumentCodebase(Exception e)
    {
        Logger.printlnMixedYellow("Caught", "IllegalArgumentException", "during codebase attack.");
        Logger.printlnMixedYellowFirst("Codebase attack", "was probably successful :)");
        showStackTrace(e);
    }

    public static void cannotCompile(Exception e, String during1, String during2, boolean exit)
    {
        Logger.eprintlnMixedYellow("Caught", "CannotCompileException", "during " + during1 + " " + during2 + ".");
        showStackTrace(e);

        if(exit)
            RMGUtils.exit();
    }

    public static void unknownHost(Exception e, String host, boolean exit)
    {
        Logger.eprintlnMixedYellow("Caugth", "UnknownHostException", "during connection setup.");
        Logger.eprintlnMixedBlue("The IP address of the endpoint", host, "could not be resolved.");
        showStackTrace(e);

        if(exit)
            RMGUtils.exit();
    }

    public static void networkUnreachable(Exception e, String during1, String during2)
    {
        Logger.eprintlnMixedYellow("Caugth", "SocketException", "during " + during1 + " " + during2 + ".");
        Logger.eprintlnMixedBlue("The specified target is", "not reachable", "with your current network configuration.");
        showStackTrace(e);
        RMGUtils.exit();
    }

    public static void bindException(Exception e)
    {
        Throwable bindException = ExceptionHandler.getThrowable("BindException", e);

        Logger.lineBreak();
        Logger.printlnMixedYellow("Caught", "BindException", "while starting the listener.");
        Logger.printlnMixedBlue("Exception message:", bindException.getMessage());

        showStackTrace(e);
        RMGUtils.exit();
    }

    public static void ysoNotPresent(String location)
    {
        Logger.eprintlnMixedYellow("Unable to find ysoserial library in path", location);
        Logger.eprintlnMixedYellow("Check your configuration file or specify it on the command line using the", "--yso", "parameter");
        RMGUtils.exit();
    }

    public static void missingSignature()
    {
        Logger.eprintlnMixedYellow("The", "--signature", "option is required for the requested operation.");
        Logger.eprintlnMixedBlue("Specify a valid signature like", "--signature \"void login(String password)\"");
        RMGUtils.exit();
    }

    public static void missingTarget(String action)
    {
        Logger.eprintMixedYellow("Either", "--bound-name", "or ");
        Logger.printPlainMixedYellowFirst("--objid", "must be specified for the ");
        Logger.printlnPlainMixedBlueFirst(action, "action.");
        RMGUtils.exit();
    }

    public static void invalidObjectId(String objID)
    {
        Logger.eprintlnMixedYellow("The specified ObjID", objID, "is invalid.");
        Logger.eprintlnMixedBlue("Use plain numbers to target default components:", "Registry: 0, Activator: 1, DGC: 2");
        Logger.eprintlnMixedBlue("Or the full ObjID string for other remote objects:", "[unique:time:count, objNum]");
        RMGUtils.exit();
    }

    public static void unrecognizedMethodHash(Exception e, String action, String signature)
    {
        Logger.printlnMixedYellow("Caught", "UnmarshalException (unrecognized method hash)", "during " + action + " action.");
        Logger.printlnMixedBlue("The specified method signature", signature, "is not supported by the remote object.");
        showStackTrace(e);
        RMGUtils.exit();
    }

    public static void localhostBypassNoException()
    {
        Logger.printlnMixedYellow("- Server", "did not", "raise any exception during unbind operation.");
        Logger.printlnMixedBlue("  This can occur for custom RMI implementations like e.g.", "apache-karaf.");
        Logger.statusNonDefault();
    }

    public static void lookupClassNotFoundException(Exception e, String name)
    {
        name = name.replace(" (no security manager: RMI class loader disabled)", "");

        Logger.eprintlnMixedYellow("Caught unexpected", "ClassNotFoundException", "during lookup action.");
        Logger.eprintlnMixedBlue("The class", name, "could not be resolved within your class path.");
        Logger.eprintlnMixedBlue("This usually means that the RemoteObject is using a custom", "RMIClientSocketFactory or InvocationHandler.");

        showStackTrace(e);
        RMGUtils.exit();
    }

    public static void notBoundException(Exception e, String boundName)
    {
        Logger.eprintMixedYellow("Caught", "NotBoundException", "on bound name ");
        Logger.printlnPlainBlue(boundName + ".");
        Logger.eprintln("The specified bound name is not bound to the registry.");
        showStackTrace(e);
        RMGUtils.exit();
    }

    public static void timeoutException(Exception e, String during1, String during2)
    {
        Logger.eprintlnMixedYellow("Caught", "SocketTimeoutException", "during " + during1 + " " + during2 + ".");
        Logger.eprintlnMixedBlue("The specified port is probably", "not an RMI service.");
        ExceptionHandler.showStackTrace(e);
        RMGUtils.exit();
    }

    public static void connectionReset(Exception e, String during1, String during2)
    {
        Logger.eprintlnMixedYellow("Caught", "Connection Reset", "during " + during1 + " " + during2 + ".");
        Logger.eprintMixedBlue("The specified port is probably", "not an RMI service ");
        Logger.printlnPlainMixedBlue("or you used a wrong", "TLS", "setting.");

        ExceptionHandler.sslOption();
        ExceptionHandler.showStackTrace(e);
        RMGUtils.exit();
    }

    public static void connectException(Exception e, String callName)
    {
        Throwable t = ExceptionHandler.getCause(e);

        if( t instanceof java.net.ConnectException && t.getMessage().contains("Connection refused")) {
            ExceptionHandler.connectionRefused(e, callName, "call");

        } else {
            ExceptionHandler.unexpectedException(e, callName, "call", true);
        }
    }

    public static void connectIOException(Exception e, String callName)
    {
        Throwable t = ExceptionHandler.getCause(e);

        if( t instanceof java.io.EOFException ) {
            ExceptionHandler.eofException(e, callName, "call");

        } else if( t instanceof java.net.SocketTimeoutException) {
            ExceptionHandler.timeoutException(e, callName, "call");

        } else if( t instanceof java.net.NoRouteToHostException) {
            ExceptionHandler.noRouteToHost(e, callName, "call");

        } else if( t instanceof java.rmi.ConnectIOException && t.getMessage().contains("non-JRMP server")) {
            ExceptionHandler.noJRMPServer(e, callName, "call");

        } else if( t instanceof javax.net.ssl.SSLException && t.getMessage().contains("Unsupported or unrecognized SSL message")) {
            ExceptionHandler.sslError(e, callName, "call");

        } else if( t instanceof java.net.SocketException && t.getMessage().contains("Network is unreachable")) {
            ExceptionHandler.networkUnreachable(e, callName, "call");

        } else if( t instanceof java.net.SocketException && t.getMessage().contains("Connection reset")) {
            ExceptionHandler.connectionReset(e, callName, "call");

        } else {
            ExceptionHandler.unexpectedException(e, callName, "call", true);
        }
    }

    /**
     * Walks down a stacktrace and searches for a specific exception name.
     * If it finds the corresponding name, the corresponding Throwable is returned.
     *
     * @param name Exception name to look for.
     * @param e stack trace to search in.
     * @return identified Throwable.
     */
    public static Throwable getThrowable(String name, Throwable e)
    {
        if( e.getClass().getSimpleName().equals(name) )
            return e;

        Throwable exception = e;
        Throwable cause = e.getCause();

        while((exception != cause) && (cause != null)) {

            if( cause.getClass().getSimpleName().equals(name))
                return cause;

            exception = cause;
            cause = exception.getCause();
        }

        return null;
    }

    /**
     * Sets the value of the alwaysShowExceptions option.
     *
     * @param b show stack traces?
     */
    public static void showStackTrace(boolean b)
    {
        alwaysShowExceptions = b;
    }

    /**
     * By using the --stack-trace option, uses can always display stack traces if they
     * want to. This is handled by this function. It checks whether --stack-trace was used
     * (in this case alwaysShowExceptions is true) and prints the stacktrace if desired.
     * This function should be used in most of the error handling code of rmg.
     *
     * @param e Exception that was caught.
     */
    public static void showStackTrace(Exception e)
    {
        if(alwaysShowExceptions) {
            Logger.eprintln("");
            stackTrace(e);
        }
    }

    /**
     * Helper function that prints a stacktrace with a prefixed Logger item.
     *
     * @param e Exception that was caught.
     */
    public static void stackTrace(Exception e)
    {
        Logger.eprintln("StackTrace:");
        e.printStackTrace();
    }

    /**
     * Taken from https://stackoverflow.com/questions/17747175/how-can-i-loop-through-exception-getcause-to-find-root-cause-with-detail-messa
     * Returns the actual cause of an exception.
     *
     * @param e Exception that should be handeled.
     * @return cause of the Exception.
     */
    public static Throwable getCause(Throwable e)
    {
        Throwable cause = null;
        Throwable result = e;

        while(null != (cause = result.getCause()) && (result != cause) ) {
            result = cause;
        }

        return result;
    }
}
