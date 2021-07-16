package de.qtc.rmg.internal;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.ParseException;

/**
 * The RMGOption enum contains all possible rmg optional values and flags. It is the preferred way to obtain
 * option values. Obtaining positional arguments or options with error handling (e.g. obtaining reg-method with
 * filtering of invalid methods) should be done via the ArgumentParser class.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public enum RMGOption {

    ARGUMENT_POS("argument-position", "select argument position for deserialization attacks", true),
    BOUND_NAME("bound-name", "guess only on the specified bound name", true),
    CONFIG("config", "path to a configuration file", true),
    CREATE_SAMPLES("create-samples", "create sample classes for identified methods", false),
    DGC_METHOD("dgc-method", "method to use during dgc operations (clean|dirty)", true),
    FOLLOW("follow", "follow redirects to different servers", false),
    FORCE_GUESSING("force-guessing", "force guessing on known remote objects", false),
    GOPHER("gopher", "print SSRF content as gopher payload", false),
    GUESS_DUPLICATES("guess-duplicates", "guess duplicate remote classes", false),
    HELP("help", "display help message", false),
    LOCALHOST_BYPASS("localhost-bypass", "attempt localhost bypass for registry operations (CVE-2019-2684)", false),
    NO_COLOR("no-color", "disable colored output", false),
    OBJID("objid", "use an ObjID instead of bound names", true),
    PLUGIN("plugin", "file system path to a rmg plugin", true),
    REG_METHOD("reg-method", "method to use during registry operations (bind|lookup|unbind|rebind)", true),
    SAMPLE_FOLDER("sample-folder", "folder used for sample generation", true),
    SIGNATURE("signature", "function signature or one of (dgc|reg|act)", true),
    SSL("ssl", "use SSL for the rmi-registry connection", false),
    SSRF("ssrf", "print SSRF payload instead of contacting a server", false),
    SSRFResponse("ssrf-response", "evaluate ssrf response from the server", true),
    STACK_TRACE("stack-trace", "display stack traces for caught exceptions", false),
    TEMPLATE_FOLDER("template-folder", "location of the template folder", true),
    THREADS("threads", "maximum number of threads (default: 5)", true),
    TRUSTED("trusted", "disable bound name filtering", false),
    UPDATE("update", "update wordlist file with method hashes", false),
    VERBOSE("verbose", "enable verbose output", false),
    WORDLIST_FILE("wordlist-file", "wordlist file to use for method guessing", true),
    WORDLIST_FOLDER("wordlist-folder", "location of the wordlist folder", true),
    YSO("yso", "location of ysoserial.jar for deserialization attacks", true),
    ZERO_ARG("zero-arg", "allow guessing on void functions (dangerous)", false),
    TARGET("bound-name or --objid", "Combined option for bound-name and objid. Only used during parameter validation.", false);

    public String name;
    public String description;
    public boolean requiresValue;

    public Object value = null;

    /**
     * Initializes an enum field with the corresponding Option name, the Option description and a boolean
     * that determines whether the option requires an argument.
     *
     * @param name Name of the option. E.g. --help -> help
     * @param description Description that is shown within the help menu
     * @param requiresValue Boolean that determines whether the option requires a value
     */
    RMGOption(String name, String description, boolean requiresValue)
    {
        this.name = name;
        this.description = description;
        this.requiresValue = requiresValue;
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
     * @return option value
     */
    public boolean getBool()
    {
        if( this.value == null)
            return false;

        return (boolean)this.value;
    }

    /**
     * Returns the option value as String.
     *
     * @return option value
     */
    public String getString()
    {
        return (String)this.value;
    }

    /**
     * Returns the option value as int.
     *
     * @return option value
     */
    public int getInt()
    {
        return (int)this.value;
    }

    /**
     * Sets the option to the specified value.
     *
     * @param value
     */
    public void setValue(Object value)
    {
        this.value = value;
    }

    /**
     * Checks the specified CommandLine for the current option name and parses
     * the corresponding value from it.
     *
     * @param cmdLine CommandLine specified by the user.
     */
    public void setValue(CommandLine cmdLine)
    {
        this.value = cmdLine.getOptionValue(this.name);
    }

    /**
     * Checks the specified CommandLine for the current option name and parses
     * the corresponding value from it.
     *
     * @param cmdLine CommandLine specified by the user.
     * @param def default value used if option is not present
     */
    public void setValue(CommandLine cmdLine, String def)
    {
        this.value = cmdLine.getOptionValue(this.name, def);
    }

    /**
     * Checks the specified CommandLine for the current option name and sets the
     * value to true if it was specified.
     *
     * @param cmdLine CommandLine specified by the user.
     */
    public void setBoolean(CommandLine cmdLine)
    {
        this.value = cmdLine.hasOption(this.name);
    }

    /**
     * Checks the specified CommandLine for the current option name and parses
     * the corresponding value from it. The value is then attempted to be parsed
     * as an integer.
     *
     * @param cmdLine CommandLine specified by the user.
     * @param def default value used if option is not present
     * @throws ParseException
     */
    public void setInt(CommandLine cmdLine, Object def) throws ParseException
    {
        value = cmdLine.getParsedOptionValue(this.name);

        if(value instanceof Number)
            value = ((Number)value).intValue();

        if( value == null )
            value = def;
    }

    /**
     * Look up an option value by name. Normally, option values should be obtained directly,
     * e.g. by using RMGOptions.BOUND_NAME.value. However, sometimes you need access to a value
     * by string. This function can be used for this purpose (e.g. RMGOption.getValueByName("bound-name"))
     *
     * @param name
     * @return
     */
    public static Object getValueByName(String name)
    {
        Object returnItem = null;

        for(RMGOption item : RMGOption.values()) {
            if(item.name.equalsIgnoreCase(name)) {
                returnItem = item.value;
                break;
            }
        }

        return returnItem;
    }
}
