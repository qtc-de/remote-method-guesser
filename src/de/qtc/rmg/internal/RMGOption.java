package de.qtc.rmg.internal;

import java.util.EnumSet;
import java.util.Properties;

import de.qtc.rmg.io.Logger;
import de.qtc.rmg.operations.Operation;
import de.qtc.rmg.utils.RMGUtils;
import net.sourceforge.argparse4j.impl.Arguments;
import net.sourceforge.argparse4j.inf.Argument;
import net.sourceforge.argparse4j.inf.ArgumentAction;
import net.sourceforge.argparse4j.inf.ArgumentGroup;
import net.sourceforge.argparse4j.inf.ArgumentParser;
import net.sourceforge.argparse4j.inf.Namespace;

/**
 * The RMGOption enum is an additional helper class to manage command line parameters. remote-method-guesser uses argparse4j
 * to parse command line arguments. After command line arguments were parsed, each of them is stored within one of the enum
 * items contained within the RMGOption class. This allows other parts of the program to access arguments via static references.
 * This is usually not best practice, as it makes the program behavior dependent on a global state, which is usually not what
 * you want. On the other hand, it has some advantages, as certain problems become easy solvable. As remote-method-guesser
 * is not a library, we go with the non best practice approach and enjoy the benefits of having global argument access.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public enum RMGOption {

    // Global arguments
    GLOBAL_CONFIG("--config", "path to a configuration file", Arguments.store(), RMGOptionGroup.GENERAL, "path"),
    GLOBAL_VERBOSE("--verbose", "enable verbose output", Arguments.storeTrue(), RMGOptionGroup.GENERAL),
    GLOBAL_PLUGIN("--plugin", "file system path to a rmg plugin", Arguments.store(), RMGOptionGroup.GENERAL, "path"),
    GLOBAL_NO_COLOR("--no-color", "disable colored output", Arguments.storeTrue(), RMGOptionGroup.GENERAL),
    GLOBAL_STACK_TRACE("--stack-trace", "display stack traces for caught exceptions", Arguments.storeTrue(), RMGOptionGroup.GENERAL),

    TARGET_HOST("host", "target host", Arguments.store(), RMGOptionGroup.NONE, "host"),
    TARGET_PORT("port", "target port", Arguments.store(), RMGOptionGroup.NONE, "port"),
    TARGET_COMPONENT("--component", "target RMI component", Arguments.store(), RMGOptionGroup.TARGET, "component"),
    TARGET_BOUND_NAME("--bound-name", "target bound name within an RMI registry", Arguments.store(), RMGOptionGroup.TARGET, "name"),
    TARGET_OBJID("--objid", "target ObjID", Arguments.store(), RMGOptionGroup.TARGET, "objid"),
    TARGET_SIGNATURE("--signature", "target method signature", Arguments.store(), RMGOptionGroup.TARGET, "signature"),

    CONN_FOLLOW("--follow", "follow redirects to different servers", Arguments.storeTrue(), RMGOptionGroup.CONNECTION),
    CONN_SSL("--ssl", "use SSL for connections", Arguments.storeTrue(), RMGOptionGroup.CONNECTION),
    SCAN_TIMEOUT_READ("--timeout-read", "scan timeout for read operation", Arguments.store(), RMGOptionGroup.CONNECTION, "sec"),
    SCAN_TIMEOUT_CONNECT("--timeout-connect", "scan timeout for connect operation", Arguments.store(), RMGOptionGroup.CONNECTION, "sec"),

    SSRF_GOPHER("--gopher", "print SSRF content as gopher payload", Arguments.storeTrue(), RMGOptionGroup.SSRF),
    SSRF("--ssrf", "print SSRF payload instead of contacting a server", Arguments.storeTrue(), RMGOptionGroup.SSRF),
    SSRFRESPONSE("--ssrf-response", "evaluate ssrf response from the server", Arguments.store(), RMGOptionGroup.SSRF, "hex"),
    SSRF_ENCODE("--encode", "double URL encode the SSRF payload", Arguments.storeTrue(), RMGOptionGroup.SSRF),
    SSRF_RAW("--raw", "print payload without color and without additional text", Arguments.storeTrue(), RMGOptionGroup.SSRF),
    SSRF_STREAM_PROTOCOL("--stream-protocol", "use the stream protocol instead of single operation", Arguments.storeTrue(), RMGOptionGroup.SSRF),

    BIND_OBJID("--bind-objid", "ObjID of the bound object.", Arguments.store(), RMGOptionGroup.ACTION, "objid"),
    BIND_ADDRESS("bind-host", "host specifications the bound remote object should point to", Arguments.store(), RMGOptionGroup.ACTION, "host:port"),
    BIND_BOUND_NAME("bound-name", "Bound name to use for (un)bind action", Arguments.store(), RMGOptionGroup.ACTION, "name"),
    BIND_BYPASS("--localhost-bypass", "attempt localhost bypass (CVE-2019-2684)", Arguments.storeTrue(), RMGOptionGroup.ACTION),
    BIND_GADGET_NAME("--gadget-name", "attempt to bind the specified gadget instead of JMXServer", Arguments.store(), RMGOptionGroup.ACTION, "gadget"),
    BIND_GADGET_CMD("--gadget-cmd", "command for a custom gadget", Arguments.store(), RMGOptionGroup.ACTION, "cmd"),

    CODEBASS_CLASS("classname", "classname to load during codebase attack", Arguments.store(), RMGOptionGroup.ACTION, "classname"),
    CODEBASE_URL("url", "codebase URL to load the payload from", Arguments.store(), RMGOptionGroup.ACTION, "url"),

    LISTEN_IP("ip", "IP address to start the listener on", Arguments.store(), RMGOptionGroup.ACTION, "ip"),
    LISTEN_PORT("port", "port number to start the listener on", Arguments.store(), RMGOptionGroup.ACTION, "port"),

    ROGUEJMX_OBJID("--objid", "objid to use for the JMX listener", Arguments.store(), RMGOptionGroup.ACTION, "objid"),
    ROGUEJMX_FORWARD_HOST("--forward-host", "host to forward incoming JMX connections to", Arguments.store(), RMGOptionGroup.ACTION, "host"),
    ROGUEJMX_FORWARD_PORT("--forward-port", "port to forward incoming JMX connections to", Arguments.store(), RMGOptionGroup.ACTION, "port"),
    ROGUEJMX_FORWARD_BOUND_NAME("--forward-bound-name", "bound name to forward incoming JMX connections to", Arguments.store(), RMGOptionGroup.ACTION, "name"),
    ROGUEJMX_FORWARD_OBJID("--forward-objid", "objid to forward incoming JMX connections to", Arguments.store(), RMGOptionGroup.ACTION, "objid"),

    GUESS_WORDLIST_FILE("--wordlist-file", "wordlist file to use for method guessing", Arguments.store(), RMGOptionGroup.ACTION, "path"),
    GUESS_WORDLIST_FOLDER("--wordlist-folder", "location of the wordlist folder", Arguments.store(), RMGOptionGroup.ACTION, "path"),
    GUESS_CREATE_SAMPLES("--create-samples", "create sample classes for identified methods", Arguments.storeTrue(), RMGOptionGroup.ACTION),
    GUESS_SAMPLE_FOLDER("--sample-folder", "folder used for sample generation", Arguments.store(), RMGOptionGroup.ACTION, "path"),
    GUESS_TEMPLATE_FOLDER("--template-folder", "location of the template folder", Arguments.store(), RMGOptionGroup.ACTION, "path"),
    GUESS_TRUSTED("--trusted", "disable bound name filtering", Arguments.storeTrue(), RMGOptionGroup.ACTION),
    GUESS_FORCE_GUESSING("--force-guessing", "force guessing on known remote objects", Arguments.storeTrue(), RMGOptionGroup.ACTION),
    GUESS_DUPLICATES("--guess-duplicates", "guess duplicate remote classes", Arguments.storeTrue(), RMGOptionGroup.ACTION),
    GUESS_UPDATE("--update", "update wordlist file with method hashes", Arguments.storeTrue(), RMGOptionGroup.ACTION),
    GUESS_ZERO_ARG("--zero-arg", "allow guessing on void functions (dangerous)", Arguments.storeTrue(), RMGOptionGroup.ACTION),

    GADGET_NAME("gadget", "gadget name to use for the deserialization attack", Arguments.store(), RMGOptionGroup.ACTION, "gadget"),
    GADGET_CMD("cmd", "command to pass for the specified gadget", Arguments.store(), RMGOptionGroup.ACTION, "cmd"),

    ENUM_BYPASS("--localhost-bypass", "attempt localhost bypass during enum", Arguments.storeTrue(), RMGOptionGroup.ACTION),
    ENUM_ACTION("--scan-action", "scan actions to perform during the enumeration", Arguments.store(), RMGOptionGroup.ACTION, "action"),

    SCAN_HOST("host", "host to perform the scan on", Arguments.store(), RMGOptionGroup.ACTION, "host"),
    SCAN_PORTS("--ports", "port specifications to perform the portscan on", Arguments.store(), RMGOptionGroup.ACTION, "port"),

    CALL_ARGUMENTS("arguments", "argument string to use for the call", Arguments.store(), RMGOptionGroup.ACTION, "args"),
    OBJID_OBJID("objid", "ObjID string to parse", Arguments.store(), RMGOptionGroup.ACTION, "objid"),
    KNOWN_CLASS("classname", "classname to check within the database", Arguments.store(), RMGOptionGroup.ACTION, "classname"),

    ARGUMENT_POS("--position", "payload argument position", Arguments.store(), RMGOptionGroup.ACTION, "pos"),
    NO_CANARY("--no-canary", "do not use a canary during RMI attacks", Arguments.storeTrue(), RMGOptionGroup.ACTION),
    NO_PROGRESS("--no-progress", "disable progress bars", Arguments.storeTrue(), RMGOptionGroup.ACTION),
    THREADS("--threads", "maximum number of threads (default: 5)", Arguments.store(), RMGOptionGroup.ACTION, "threads"),
    YSO("--yso", "location of ysoserial.jar for deserialization attacks", Arguments.store(), RMGOptionGroup.ACTION, "yso-path"),
    DGC_METHOD("--dgc-method", "method to use for dgc operations", Arguments.store(), RMGOptionGroup.ACTION, "method"),
    REG_METHOD("--registry-method", "method to use for registry operations", Arguments.store(), RMGOptionGroup.ACTION, "method");


    public final String name;
    public final String description;
    public final String metavar;
    public final ArgumentAction argumentAction;
    public RMGOptionGroup optionGroup = null;

    public Object value = null;

    private final static EnumSet<RMGOption> intOptions = EnumSet.of(RMGOption.THREADS, RMGOption.ARGUMENT_POS, RMGOption.SCAN_TIMEOUT_CONNECT,
            RMGOption.SCAN_TIMEOUT_READ, RMGOption.LISTEN_PORT, RMGOption.TARGET_PORT, RMGOption.ROGUEJMX_FORWARD_PORT);
    private final static EnumSet<RMGOption> booleanOptions = EnumSet.of(RMGOption.GLOBAL_VERBOSE, RMGOption.GLOBAL_NO_COLOR, RMGOption.GLOBAL_STACK_TRACE,
            RMGOption.CONN_FOLLOW, RMGOption.CONN_SSL, RMGOption.SSRF_GOPHER, RMGOption.SSRF, RMGOption.BIND_BYPASS, RMGOption.GUESS_CREATE_SAMPLES,
            RMGOption.GUESS_TRUSTED, RMGOption.GUESS_FORCE_GUESSING, RMGOption.GUESS_DUPLICATES, RMGOption.GUESS_UPDATE, RMGOption.GUESS_ZERO_ARG,
            RMGOption.ENUM_BYPASS, RMGOption.NO_CANARY, RMGOption.NO_PROGRESS, RMGOption.SSRF_ENCODE, RMGOption.SSRF_RAW);

    /**
     * Initializes an enum field with the corresponding Option name, the Option description the argument action,
     * which decides whether the option is boolean or expects a value and an RMGOptionGroup, that is used to
     * group options within command line help.
     *
     * @param name Name of the option. As used on the command line
     * @param description Description that is shown within the help menu
     * @param argumentAction argparse4j ArgumentAction for this option
     * @param optionGroup Logical group to display the argument in when printing the help menu
     */
    RMGOption(String name, String description, ArgumentAction argumentAction, RMGOptionGroup optionGroup)
    {
        this(name, description, argumentAction, optionGroup, null);
    }

    /**
     * Initializes an enum field with the corresponding Option name, the Option description the argument action,
     * which decides whether the option is boolean or expects a value, an RMGOptionGroup, that is used to
     * group options within command line help and the name metavar of the option value, if required.
     *
     * @param name Name of the option. As used on the command line
     * @param description Description that is shown within the help menu
     * @param argumentAction argparse4j ArgumentAction for this option
     * @param optionGroup Logical group to display the argument in when printing the help menu
     * @param metavar Meta name for the expected option value
     */
    RMGOption(String name, String description, ArgumentAction argumentAction, RMGOptionGroup optionGroup, String metavar)
    {
        this.name = name;
        this.description = description;
        this.argumentAction = argumentAction;

        this.metavar = metavar;
        this.optionGroup = optionGroup;
    }

    /**
     * Returns true if the value is null.
     *
     * @return true or false
     */
    public boolean isNull()
    {
        if( this.value == null)
            return true;

        return false;
    }

    /**
     * Returns true if a value is set.
     *
     * @return true or false
     */
    public boolean notNull()
    {
        if( this.value == null)
            return false;

        return true;
    }

    /**
     * Returns the option value as boolean.
     *
     * @return option value as boolean
     */
    public boolean getBool()
    {
        if( this.value == null)
            return false;

        return (boolean)this.value;
    }

    /**
     * Returns the value stored within the option.
     *
     * @return value stored within the option
     */
    @SuppressWarnings("unchecked")
    public <T> T getValue()
    {
        try {
            return (T)value;

        } catch( ClassCastException e ) {
            ExceptionHandler.internalError("RMGOption.getValue", "ClassCastException was caught.");
        }

        return null;
    }

    /**
     * Sets the option to the specified value.
     *
     * @param value Object value to set for this option
     */
    public void setValue(Object value)
    {
        this.value = value;
    }

    /**
     * Sets the option to the specified value. If the value is null, use the specified default.
     *
     * @param value Object value to set for this option
     * @param def Default value to set for this option
     */
    public void setValue(Object value, Object def)
    {
        if( value != null )
            this.value = value;

        else
            this.value = def;
    }

    /**
     * Attempts to set an option value obtained from an argparse4j Namespace object.
     * If the corresponding option was not specified, use the default value.
     *
     * @param value
     */
    public void setValue(Namespace args, Object def)
    {
        this.value = args.get(this.name.replaceFirst("--", "").replace("-", "_"));
        this.setValue(value, def);
    }


    /**
     * Prepare the RMGOption enum by using an argparse4j Namespace object and the global
     * remote-method-guesser configuration. This function initializes all options within
     * the enum and uses either the value that was specified on the command line or the
     * value obtained from the configuration file.
     *
     * @param args argparse4j Namespace for the current command line
     * @param config Global remote-method-guesser configuration
     */
    public static void prepareOptions(Namespace args, Properties config)
    {
        for(RMGOption option : RMGOption.values() ) {

            Object defaultValue = config.getProperty(option.name().toLowerCase());

            try {

                if( defaultValue != null && !((String) defaultValue).isEmpty() ) {

                    if( intOptions.contains(option) )
                        defaultValue = Integer.valueOf((String) defaultValue);

                    else if( booleanOptions.contains(option) )
                        defaultValue = Boolean.valueOf((String) defaultValue);

                } else if( defaultValue != null && ((String) defaultValue).isEmpty() ) {
                    defaultValue = null;
                }

            } catch( Exception e ) {
                Logger.eprintlnMixedYellow("RMGOption", option.name, "obtained an invalid argument.");
                ExceptionHandler.stackTrace(e);
                RMGUtils.exit();
            }

            option.setValue(args, defaultValue);
        }
    }

    /**
     * Adds options from the RMGOption enum to an argument parser. The options that are added depend
     * on the currently selected action, which is expected as one of the arguments. Arguments that
     * belong to an RMGOptionGroup are added to the corresponding group and the group is added to the
     * parser.
     *
     * @param operation remote-method-guesser operation specified on the command line
     * @param argParser argparse4j ArgumentParser object for the current command line
     */
    public static void addOptions(Operation operation, ArgumentParser argParser)
    {
        Argument arg;
        RMGOptionGroup group;
        ArgumentGroup arggroup;

        for( RMGOption option : RMGOption.values() ) {

            if( !operation.containsOption(option) )
                continue;

            group = option.optionGroup;

            if( group == RMGOptionGroup.NONE || group == RMGOptionGroup.ACTION )
                arg = argParser.addArgument(option.name).help(option.description).action(option.argumentAction);

            else {
                arggroup = group.addArgumentGroup(argParser, operation);
                arg = arggroup.addArgument(option.name).help(option.description).action(option.argumentAction);
            }

            addModifiers(option, arg);
        }
    }

    /**
     * Certain option only allow a specific set of arguments, have metavariables, expect multiple variables or
     * are expected to be of an specific type. This function adds these requirements to the options. It is not
     * very elegant to assign these attributes in a static function, but only a few arguments require such
     * attributes and initializing them in the enum constructor would make the whole class less readable.
     *
     * @param option RMGOption that is checked for special attribute requirements
     * @param arg Argument to apply special attributes to
     */
    public static void addModifiers(RMGOption option, Argument arg)
    {
        if( option.metavar != null )
            arg.metavar(option.metavar);

        if( option == RMGOption.TARGET_COMPONENT ) {
            arg.choices("act", "dgc", "reg");

        } else if( option == RMGOption.ENUM_ACTION ) {
            arg.choices("activator", "codebase", "filter-bypass", "jep290",
                        "list", "localhost-bypass", "security-manager", "string-marshalling");
            arg.nargs("+");

        } else if( option == RMGOption.SCAN_PORTS ) {
            arg.nargs("+");

        } else if( option == RMGOption.REG_METHOD ) {
            arg.choices("lookup", "unbind", "rebind", "bind");

        } else if( option == RMGOption.DGC_METHOD ) {
            arg.choices("clean", "dirty");

        } else if( intOptions.contains(option) )
            arg.type(Integer.class);
    }

    /**
     * The require function allows other parts of the source code to require an option value.
     * If the corresponding option was not set, an error message is printed and the current execution
     * ends. This should be called first by functions that require an specific argument.
     *
     * @param option RMGOption that is required
     * @return the currently set option value
     */
    @SuppressWarnings("unchecked")
    public static <T> T require(RMGOption option)
    {
        if( option.notNull() ) {

            try {
                return (T)option.value;

            } catch( ClassCastException e ) {
                ExceptionHandler.internalError("RMGOption.require", "Caught class cast exception.");
            }
        }

        Logger.eprintlnMixedYellow("Error: The specified aciton requires the", option.name, "option.");
        RMGUtils.exit();

        return null;
    }

    /**
     * Allows other parts of the source code to check whether one of the requested RMGOptions was
     * specified on the command line. If none of the requested RMGOptions was found, print an error
     * and exit. This should be called first by functions that require one of a set of RMGOptions.
     *
     * @param options RMGOptions to check for
     * @return the value of the first option that was found.
     */
    public static Object requireOneOf(RMGOption... options)
    {
        StringBuilder helpString = new StringBuilder();

        for( RMGOption option : options ) {

            if( option.notNull() )
                return option.value;

            helpString.append(option.name);
            helpString.append(", ");
        }

         helpString.setLength(helpString.length() - 2);

        Logger.eprintlnMixedYellow("Error: The specified aciton requires one of the", helpString.toString(), "options.");
        RMGUtils.exit();

        return null;
    }

    /**
     * Allows other parts of the source code to check whether all of the requested RMGOptions were
     * specified on the command line. If not all of the requested RMGOptions was found, print an error
     * and exit. This should be called first by functions that require one of a set of RMGOptions.
     *
     * @param options RMGOptions to check for
     */
    public static void requireAllOf(RMGOption... options)
    {
        for( RMGOption option : options ) {

            if( !option.notNull() ) {
                Logger.eprintlnMixedYellow("Error: The specified aciton requires the", option.name, "option.");
                RMGUtils.exit();
            }
        }
    }

    /**
     * Helper function that calls requireOneOf with target related options. This is used by functions that require
     * a target that could either be an RMI component, a bound name or an ObjID.
     */
    public static void requireTarget()
    {
        RMGOption.requireOneOf(RMGOption.TARGET_COMPONENT, RMGOption.TARGET_OBJID, RMGOption.TARGET_BOUND_NAME);
    }
}
