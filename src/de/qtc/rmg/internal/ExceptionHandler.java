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

    private static void sslOption()
    {
        if(RMGOption.CONN_SSL.getBool())
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

    public static void unknownCodebaseException(Throwable e, boolean exit)
    {
        Logger.eprintlnMixedYellow("Caught unexpected", e.getClass().getName(), "during codebase attack.");
        Logger.eprintlnMixedBlue("This Exception was probably thrown by the", "ReadObject method", "of the uploaded class.");
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
        Logger.printlnMixedBlue("Server attempted to deserialize canary class", className + ".");
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
        Logger.printlnMixedBlue("Remote class loader attempted to load canary class", className);
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
        Logger.eprintlnPlainBlue(" SSL socket.");

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

    public static void invalidHostFormat(String format)
    {
        Logger.eprintlnMixedYellow("The specified host format", format, "is invalid.");
        Logger.eprintlnMixedBlue("Host must be specified in", "host:port", "format.");
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
        Logger.eprintlnMixedYellow("Caught", "UnsupportedClassVersionError", "during " + during1 + " " + during2 + ".");
        Logger.eprintlnMixedBlue("You probably used an", "incompatible compiler version", "for class generation.");
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

    public static void wrongArgumentCount(int expected, int is)
    {
        Logger.eprintlnMixedYellow("The specified method signature expects", String.valueOf(expected), "arguments,");
        Logger.eprintlnMixedBlue("but", String.valueOf(is), "arguments have been specified.");
        RMGUtils.exit();
    }

    public static void unrecognizedMethodHash(Exception e, String action, String signature)
    {
        Logger.eprintlnMixedYellow("Caught", "UnmarshalException (unrecognized method hash)", "during " + action + " action.");
        Logger.eprintlnMixedBlue("The specified method signature", signature, "is not supported by the remote object.");
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
        Logger.eprintlnPlainMixedBlue("or you used a wrong", "TLS", "setting.");

        ExceptionHandler.sslOption();
        ExceptionHandler.showStackTrace(e);
        RMGUtils.exit();
    }

    public static void genericCall(Exception e)
    {
        Logger.printlnMixedYellow("Caught", e.getClass().getName(), "during generic call action.");
        Logger.printlnMixedBlue("The call was", "probably successful,", "but caused an exception on the server side.");
        ExceptionHandler.stackTrace(e);
    }

    public static void connectException(Exception e, String callName)
    {
        Throwable t = ExceptionHandler.getCause(e);

        if( t instanceof java.net.ConnectException ) {

            String message = t.getMessage();

            if( message.contains("Connection refused") )
                ExceptionHandler.connectionRefused(e, callName, "call");

            if( message.contains("Network is unreachable") )
                ExceptionHandler.networkUnreachable(e, callName, "call");

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
     * By using the --stack-trace option, uses can always display stack traces if they
     * want to. This is handled by this function. It checks whether --stack-trace was used
     * and prints the stacktrace if desired. This function should be used in most of the error
     * handling code of remote-method-guesser.
     *
     * @param e Exception that was caught.
     */
    public static <T extends Throwable> void showStackTrace(T e)
    {
        if( RMGOption.GLOBAL_STACK_TRACE.getBool() ) {
            Logger.eprintln("");
            stackTrace(e);
        }
    }

    /**
     * Helper function that prints a stacktrace with a prefixed Logger item.
     *
     * @param e Exception that was caught.
     */
    public static <T extends Throwable> void stackTrace(T e)
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

    /**
     * Handle an Exception that is thrown during codebase attacks. The exception reasons are similar for most RMI components
     * and it makes sense to use a unified function here.
     *
     * @param exception Exception that was raised during the codebase attack
     * @param className ClassName that was used during the codebase attack
     * @param component RMIComponent that was targeted
     * @param method Server-side methodName that was used for the attack
     */
    public static void handleCodebaseException(Exception exception, String className, RMIComponent component, String method)
    {
        ExceptionHandler.handleCodebaseException(exception, className, component, method, null);
    }

    /**
     * Handle an Exception that is thrown during codebase attacks. The exception reasons are similar for most RMI components
     * and it makes sense to use a unified function here. This method uses an additional randomClassName parameter. This can
     * be used to indicate that a canary was used during the attack.
     *
     * @param exception Exception that was raised during the codebase attack
     * @param className ClassName that was used during the codebase attack
     * @param component RMIComponent that was targeted
     * @param method Server-side methodName that was used for the attack
     * @param randomClassName Class name of the canary that was used during the attack
     */
    public static void handleCodebaseException(Exception exception, String className, RMIComponent component, String method, String randomClassName)
    {
        try {
            throw exception;

        } catch( java.rmi.ServerException e ) {

            Throwable cause = ExceptionHandler.getCause(e);

            if( cause instanceof java.io.InvalidClassException ) {

                if( component != RMIComponent.REGISTRY )
                    ExceptionHandler.invalidClass(e, component.name);

                else {
                    ExceptionHandler.invalidClass(e, component.name, false);
                    Logger.eprintlnMixedBlue("Make sure your payload class", "implements Remote.");
                    ExceptionHandler.showStackTrace(e);
                }

            } else if( cause instanceof java.lang.UnsupportedOperationException ) {
                ExceptionHandler.unsupportedOperationException(e, method);

            } else if( cause instanceof java.lang.ClassFormatError ) {

                if( cause.getClass() == java.lang.UnsupportedClassVersionError.class )
                    ExceptionHandler.unsupportedClassVersion(e, "codebase", "attack");

                else
                    ExceptionHandler.codebaseClassFormat(e);

            } else if( cause instanceof java.lang.ClassNotFoundException ) {

                String exceptionMessage = e.getMessage();

                if( exceptionMessage.contains("RMI class loader disabled") ) {
                    ExceptionHandler.codebaseSecurityManager(e);
                }

                else if( exceptionMessage.contains(className) ) {
                    ExceptionHandler.codebaseClassNotFound(e, className);
                }

                else if( randomClassName != null && exceptionMessage.contains(randomClassName) ) {
                    ExceptionHandler.codebaseClassNotFoundRandom(e, randomClassName, className);

                } else {
                    ExceptionHandler.unexpectedException(e, method, "call", false);
                }

            } else if( cause instanceof java.lang.ClassCastException ) {

                if ( RMGUtils.createdByReadString(cause.getMessage()) )
                    ExceptionHandler.codebaseClassCast(e, true);

                else
                    ExceptionHandler.codebaseClassCast(e, false);

            } else if( cause instanceof java.security.AccessControlException) {
                ExceptionHandler.accessControl(e, method, "call");

            } else {

                Throwable unmarshalException = ExceptionHandler.getThrowable("UnmarshalException", e);

                if( unmarshalException != null)
                    ExceptionHandler.unknownCodebaseException(unmarshalException.getCause(), false);

                else
                    ExceptionHandler.unexpectedException(e, method, "call", false);
            }

        } catch( java.rmi.ServerError e ) {

            Throwable cause = ExceptionHandler.getCause(e);

            if( cause instanceof java.lang.ClassFormatError) {

                if( cause.getClass() == java.lang.UnsupportedClassVersionError.class )
                    ExceptionHandler.unsupportedClassVersion(e, "codebase", "attack");

                else
                    ExceptionHandler.codebaseClassFormat(e);

            } else {
                ExceptionHandler.unexpectedException(e, method, "call", false);
            }

        } catch( java.lang.IllegalArgumentException e ) {
            ExceptionHandler.illegalArgumentCodebase(e);

        } catch( java.lang.ClassCastException e ) {

            if ( RMGUtils.createdByReadString(e.getMessage()) )
                ExceptionHandler.codebaseClassCast(e, true);

            else
                ExceptionHandler.codebaseClassCast(e, false);

        } catch( java.security.AccessControlException e ) {
            ExceptionHandler.accessControl(e, method, "call");

        } catch( java.rmi.NoSuchObjectException e ) {
            ExceptionHandler.noSuchObjectException(e, component.name, false);

        } catch( Exception e ) {
            ExceptionHandler.unexpectedException(e, method, "call", false);
        }
    }

    /**
     * Handle an Exception that is thrown during gadget call attacks. The exception reasons are similar for most RMI
     * components and it makes sense to use a unified function here.
     *
     * @param exception Exception that was raised during the gadget call attack
     * @param component RMIComponent that was targeted
     * @param method Server-side methodName that was used for the attack
     */
    public static void handleGadgetCallException(Exception exception, RMIComponent component, String method)
    {
        ExceptionHandler.handleGadgetCallException(exception, component, method, null);
    }

    /**
     * Handle an Exception that is thrown during gadget call attacks. The exception reasons are similar for most RMI
     * components and it makes sense to use a unified function here. This method uses an additional randomClassName
     * parameter. This can be used to indicate that a canary was used during the attack.
     *
     * @param exception Exception that was raised during the gadget call attack
     * @param component RMIComponent that was targeted
     * @param method Server-side methodName that was used for the attack
     * @param randomClassName Class name of the canary that was used during the attack
     */
    public static void handleGadgetCallException(Exception exception, RMIComponent component, String method, String randomClassName)
    {
        try {
            throw exception;

        } catch( java.rmi.ServerException | java.rmi.ServerError e ) {

            Throwable cause = ExceptionHandler.getCause(e);

            if( cause instanceof java.io.InvalidClassException ) {
                ExceptionHandler.invalidClass(e, component.name);

            } else if( cause instanceof java.security.AccessControlException ) {
                ExceptionHandler.accessControl(e, "deserialization", "attack");

            } else if( cause instanceof java.lang.UnsupportedOperationException ) {
                ExceptionHandler.unsupportedOperationException(e, method);

            } else if( cause instanceof java.lang.ClassNotFoundException ) {

                if( randomClassName != null && e.getMessage().contains(randomClassName) ) {
                    ExceptionHandler.deserializeClassNotFoundRandom(e, "deserialization", "attack", randomClassName);

                } else {
                    ExceptionHandler.deserializeClassNotFound(e);
                }

            } else if( cause instanceof java.lang.ClassCastException ) {

                if ( RMGUtils.createdByReadString(cause.getMessage()) )
                    ExceptionHandler.deserlializeClassCast(e, true);

                else
                    ExceptionHandler.deserlializeClassCast(e, false);

            } else {
                ExceptionHandler.unknownDeserializationException(e);
            }

        } catch( java.lang.ClassCastException e ) {

            if ( RMGUtils.createdByReadString(e.getMessage()) )
                ExceptionHandler.deserlializeClassCast(e, true);

            else
                ExceptionHandler.deserlializeClassCast(e, false);

        } catch( java.lang.IllegalArgumentException e ) {
            ExceptionHandler.illegalArgument(e);

        } catch( java.rmi.NoSuchObjectException e ) {
            ExceptionHandler.noSuchObjectException(e, component.name, false);

        } catch( java.rmi.UnmarshalException e ) {

            Throwable t = ExceptionHandler.getCause(e);

            if( t instanceof java.lang.ClassNotFoundException ) {
                Logger.eprintlnMixedYellow("Caught local", "ClassNotFoundException", "during deserialization attack.");
                Logger.eprintlnMixedBlue("This usually occurs when the", "gadget caused an exception", "on the server side.");
                Logger.eprintlnMixedYellow("You probably entered entered an", "invalid command", "for the gadget.");
                ExceptionHandler.showStackTrace(e);

            } else {
                ExceptionHandler.unexpectedException(e, "deserialization", "attack", false);
            }

        } catch( java.security.AccessControlException e ) {
            ExceptionHandler.accessControl(e, "deserialization", "attack");

        } catch( Exception e ) {
            ExceptionHandler.unexpectedException(e, method, "call", false);
        }
    }
}
