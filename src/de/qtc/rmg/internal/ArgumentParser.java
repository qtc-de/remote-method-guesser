package de.qtc.rmg.internal;

import java.util.HashMap;
import java.util.List;
import java.util.Properties;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import de.qtc.rmg.io.Logger;
import de.qtc.rmg.plugin.PluginSystem;
import de.qtc.rmg.utils.RMGUtils;
import de.qtc.rmg.utils.Security;
import de.qtc.rmg.utils.YsoIntegration;

/**
 * This is a helper class that handles all the argument parsing related stuff
 * during an execution of rmg. In future we may move to an module based
 * argument parser, as the amount of options and actions has become quite
 * high. However, for now the current parsing should be sufficient.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class ArgumentParser {

    private String action = null;

    private Options options;
    private String helpString;
    private HelpFormatter formatter;
    private CommandLineParser parser;
    private CommandLine cmdLine;
    private List<String> argList;
    private Properties config;
    private HashMap<String,Object> parameters;

    private static String rmg_version = "rmg v3.2.0";
    private static String defaultConfiguration = "/config.properties";

    /**
     * Creates the actual parser object and initializes it with some default
     * options.
     */
    public ArgumentParser(String[] argv)
    {
        this.parser = new DefaultParser();
        this.options = getParserOptions();
        this.helpString = getHelpString();
        this.formatter = new HelpFormatter();
        this.formatter.setWidth(130);
        this.formatter.setDescPadding(6);

        this.parse(argv);
    }

    private Object parseOption(String name, Object defaultValue)
    {
        Object returnValue = null;

        try {
            returnValue = cmdLine.getParsedOptionValue(name);

            if(returnValue instanceof Number)
                returnValue = ((Number)returnValue).intValue();

        } catch(ParseException e) {
            Logger.printlnPlainMixedYellow("Error: Invalid parameter type for argument", name);
            System.out.println("");
            this.printHelp();
            System.exit(1);
        }

        if( returnValue == null )
            return defaultValue;
        else
            return returnValue;
    }

    private void preapreParameters()
    {
        parameters = new HashMap<String,Object>();

        parameters.put("argument-position", this.parseOption("argument-position", -1));
        parameters.put("threads", this.parseOption("threads", Integer.valueOf(config.getProperty("threads"))));
        parameters.put("sample-folder", cmdLine.getOptionValue("sample-folder", config.getProperty("sample-folder")));
        parameters.put("wordlist-file", cmdLine.getOptionValue("wordlist-file", config.getProperty("wordlist-file")));
        parameters.put("template-folder", cmdLine.getOptionValue("template-folder", config.getProperty("template-folder")));
        parameters.put("wordlist-folder", cmdLine.getOptionValue("wordlist-folder", config.getProperty("wordlist-folder")));
        parameters.put("signature", cmdLine.getOptionValue("signature", ""));
        parameters.put("bound-name", cmdLine.getOptionValue("bound-name", null));
        parameters.put("objid", this.parseOption("objid", -1));
        parameters.put("reg-method", cmdLine.getOptionValue("reg-method", "lookup"));
        parameters.put("dgc-method", cmdLine.getOptionValue("dgc-method", "clean"));

        parameters.put("ssl", cmdLine.hasOption("ssl"));
        parameters.put("follow", cmdLine.hasOption("follow"));
        parameters.put("update", cmdLine.hasOption("update"));
        parameters.put("create-samples", cmdLine.hasOption("create-samples"));
        parameters.put("zero-arg", cmdLine.hasOption("zero-arg"));
        parameters.put("localhost-bypass", cmdLine.hasOption("localhost-bypass"));
    }

    /**
     * This function constructs all required parser options. rmg uses long options
     * only and does not define short versions for any option.
     *
     * @return parser options.
     */
    private Options getParserOptions()
    {
        Options options = new Options();

        Option position = new Option(null, "argument-position", true, "select argument position for deserialization attacks");
        position.setArgName("int");
        position.setRequired(false);
        position.setType(Number.class);
        options.addOption(position);

        Option name = new Option(null, "bound-name", true, "guess only on the specified bound name");
        name.setArgName("name");
        name.setRequired(false);
        options.addOption(name);

        Option configOption = new Option(null, "config", true, "path to a configuration file");
        configOption.setArgName("file");
        configOption.setRequired(false);
        options.addOption(configOption);

        Option samples = new Option(null, "create-samples", false, "create sample classes for identified methods");
        samples.setRequired(false);
        options.addOption(samples);

        Option dgcMethod = new Option(null, "dgc-method", true, "method to use during dgc operations (clean|dirty)");
        dgcMethod.setArgName("method");
        dgcMethod.setRequired(false);
        options.addOption(dgcMethod);

        Option follow = new Option(null, "follow", false, "follow redirects to different servers");
        follow.setRequired(false);
        options.addOption(follow);

        Option forceLegacy = new Option(null, "force-legacy", false, "treat all classes as legacy stubs");
        forceLegacy.setRequired(false);
        options.addOption(forceLegacy);

        Option help = new Option(null, "help", false, "display help message");
        help.setRequired(false);
        options.addOption(help);

        Option local = new Option(null, "localhost-bypass", false, "attempt localhost bypass for registry operations (CVE-2019-2684)");
        local.setRequired(false);
        options.addOption(local);

        Option noColor = new Option(null, "no-color", false, "disable colored output");
        noColor.setRequired(false);
        options.addOption(noColor);

        Option noLegacy = new Option(null, "no-legacy", false, "disable automatic legacy stub detection");
        noLegacy.setRequired(false);
        options.addOption(noLegacy);

        Option objID = new Option(null, "objid", true, "use an ObjID instead of bound names");
        objID.setRequired(false);
        objID.setArgName("objID");
        objID.setType(Number.class);
        options.addOption(objID);

        Option plugin = new Option(null, "plugin", true, "file system path to a rmg plugin");
        plugin.setArgName("path");
        plugin.setRequired(false);
        options.addOption(plugin);

        Option regMethod = new Option(null, "reg-method", true, "method to use during registry operations (bind|lookup|unbind|rebind)");
        regMethod.setArgName("method");
        regMethod.setRequired(false);
        options.addOption(regMethod);

        Option outputs = new Option(null, "sample-folder", true, "folder used for sample generation");
        outputs.setArgName("folder");
        outputs.setRequired(false);
        options.addOption(outputs);

        Option signature = new Option(null, "signature", true, "function signature or one of (dgc|reg|act)");
        signature.setArgName("method");
        signature.setRequired(false);
        options.addOption(signature);

        Option ssl = new Option(null, "ssl", false, "use SSL for the rmi-registry connection");
        ssl.setRequired(false);
        options.addOption(ssl);

        Option stackTrace = new Option(null, "stack-trace", false, "display stack traces for caught exceptions");
        stackTrace.setRequired(false);
        options.addOption(stackTrace);

        Option templates = new Option(null, "template-folder", true, "location of the template folder");
        templates.setArgName("folder");
        templates.setRequired(false);
        options.addOption(templates);

        Option threads = new Option(null, "threads", true, "maximum number of threads (default: 5)");
        threads.setArgName("int");
        threads.setRequired(false);
        threads.setType(Number.class);
        options.addOption(threads);

        Option trusted = new Option(null, "trusted", false, "disable bound name filtering");
        trusted.setRequired(false);
        options.addOption(trusted);

        Option update = new Option(null, "update", false, "update wordlist file with method hashes");
        update.setRequired(false);
        options.addOption(update);

        Option wordlist = new Option(null, "wordlist-file", true, "wordlist file to use for method guessing");
        wordlist.setArgName("file");
        wordlist.setRequired(false);
        options.addOption(wordlist);

        Option wordlistFolder = new Option(null, "wordlist-folder", true, "location of the wordlist folder");
        wordlistFolder.setArgName("folder");
        wordlistFolder.setRequired(false);
        options.addOption(wordlistFolder);

        Option yso = new Option(null, "yso", true, "location of ysoserial.jar for deserialization attacks");
        yso.setArgName("file");
        yso.setRequired(false);
        options.addOption(yso);

        Option zeroArg = new Option(null, "zero-arg", false, "allow guessing on void functions (dangerous)");
        zeroArg.setRequired(false);
        options.addOption(zeroArg);

        return options;
    }

    /**
     * Returns the help string that is used by rmg.
     *
     * @return help string.
     */
    private String getHelpString()
    {
        String helpString = "rmg [options] <ip> <port> <action>\n\n"
                +rmg_version
                +" - Identify common misconfigurations on Java RMI endpoints.\n\n"
                +"Positional Arguments:\n"
                +"    ip                              IP address of the target\n"
                +"    port                            Port of the RMI registry\n"
                +"    action                          One of the possible actions listed below\n\n"
                +"Possible Actions:\n"
                +"    call <arguments>                Regulary calls a method with the specified arguments\n"
                +"    act <gadget> <command>          Performs Activator based deserialization attacks\n"
                +"    bind [gadget] <command>         Binds an object to the registry thats points to listener\n"
                +"    codebase <classname> <url>      Perform remote class loading attacks\n"
                +"    dgc <gadget> <command>          Perform DGC based deserialization attacks\n"
                +"    enum                            Enumerate bound names, classes, SecurityManger and JEP290\n"
                +"    guess                           Guess methods on bound names\n"
                +"    listen <gadget> <command>       Open ysoserials JRMP listener\n"
                +"    method <gadget> <command>       Perform method based deserialization attacks\n"
                +"    rebind [gadget] <command>       Rebinds boundname as object that points to listener\n"
                +"    reg <gadget> <command>          Perform registry based deserialization attacks\n"
                +"    unbind                          Removes the specified bound name from the registry\n\n"
                +"Optional Arguments:";

        return helpString;
    }

    /**
     * Parses the specified command line arguments and handles some shortcuts.
     * The --help option and --trusted are already caught at this level and
     * do not need to be processed later on.
     *
     * @param argv arguments specified on the command line
     * @return
     */
    public void parse(String[] argv)
    {
        try {
            cmdLine = parser.parse(this.options, argv);
        } catch (ParseException e) {
            System.err.println("Error: " + e.getMessage() + "\n");
            printHelp();
            System.exit(1);
        }

        this.config = new Properties();
        RMGUtils.loadConfig(defaultConfiguration, config, false);
        RMGUtils.loadConfig(cmdLine.getOptionValue("config", null), config, true);

        if( cmdLine.hasOption("help") ) {
            printHelp();
            System.exit(0);
        }

        if( cmdLine.hasOption("trusted") )
            Security.trusted();

        if( cmdLine.hasOption("no-color") )
            Logger.disableColor();

        PluginSystem.init(cmdLine.getOptionValue("plugin", null));
        ExceptionHandler.showStackTrace(cmdLine.hasOption("stack-trace"));
        YsoIntegration.setYsoPath(cmdLine.getOptionValue("yso", config.getProperty("ysoserial-path")));

        preapreParameters();
    }

    /**
     * Prints the help menu of rmg.
     */
    public void printHelp()
    {
        formatter.printHelp(helpString, options);
    }

    public Object get(String name)
    {
        return parameters.get(name);
    }

    /**
     * Takes a number that represents the position of a positional argument and
     * returns the corresponding argument as String. Currently, no error handling
     * is implemented. The checkArgumentCount should therefore be called first.
     *
     * @param position number of the requested positional argument
     * @return String value of the requested positional argument
     */
    public String getPositionalString(int position)
    {
        if( this.argList != null ) {
            return this.argList.get(position);
        } else {
            this.argList = cmdLine.getArgList();
            return this.argList.get(position);
        }
    }

    /**
     * Takes a number that represents the position of a positional argument and
     * returns the corresponding argument as Integer. Currently, no error handling
     * is implemented. The checkArgumentCount should therefore be called first.
     *
     * @param position number of the requested positional argument
     * @return Integer value of the requested positional argument
     */
    public int getPositionalInt(int position)
    {
        try {
            if( this.argList != null ) {
                return Integer.valueOf(this.argList.get(position));
            } else {
                this.argList = cmdLine.getArgList();
                return Integer.valueOf(this.argList.get(position));
            }
        } catch( Exception e ) {
            System.err.println("Error: Unable to parse " + this.argList.get(position) + " as integer.");
            printHelp();
            System.exit(1);
        }
        return 0;
    }

    /**
     * Returns the number of specified positional arguments.
     *
     * @return number of positional arguments.
     */
    public int getArgumentCount()
    {
        if( this.argList != null ) {
            return this.argList.size();
        } else {
            this.argList = cmdLine.getArgList();
            return this.argList.size();
        }
    }

    /**
     * Checks whether the specified amount of positional arguments is sufficiently high.
     * If the number of actual positional arguments is lower than the specified counter,
     * the program exists with an error.
     *
     * @param expectedCount minimum number of arguments
     */
    public void checkArgumentCount(int expectedCount)
    {
         List<String> remainingArgs = cmdLine.getArgList();
         if( remainingArgs.size() < expectedCount ) {
             System.err.println("Error: insufficient number of arguments.\n");
             printHelp();
             System.exit(1);
         }
    }

    /**
     * rmg allows uses to specify whether RMI calls should be made by using the legacy
     * Stub-Skeleton approach. Internally, these modes are represented by an integer:
     *
     *         2    ->    Never use legacy Stub-Skeleton approach
     *         1    ->    Always use legacy Stub-Skeleton approach
     *         0    ->    Automatically decide whether using Stub-Skeleton approach
     *
     * This function returns the corresponding integer depending on the specified arguments.
     *
     * @return legacy mode.
     */
    public int getLegacyMode()
    {
        if( this.cmdLine.hasOption("--no-legacy") )
            return 2;

        else if( this.cmdLine.hasOption("--force-legacy") )
            return 1;

        else
            return 0;
    }

    /**
     * Simply returns the specified action on the command line. If no action was specified, returns
     * 'enum' as the default action.
     */
    public String getAction()
    {
        if(this.action != null)
            return this.action;

        else if( this.getArgumentCount() < 3 ) {
            this.action = "enum";

        } else {
            this.action = this.getPositionalString(2);
        }

        return action;
    }

    /**
     * During registry related rmg operations, users can select the registry method
     * that is used for the different RMI calls. This function validates whether
     * the registry method is actually available. An invalid method specification
     * causes an error and closes the program.
     *
     * @param regMethod requested by the user.
     * @return regMethod if valid.
     */
    public String validateRegMethod()
    {
        String regMethod = (String)this.get("reg-method");

        if(!regMethod.matches("lookup|bind|unbind|rebind")) {
            Logger.printlnPlainMixedYellow("Unsupported registry method:", regMethod);
            printHelp();
            System.exit(1);
        }

        return regMethod;
    }

    /**
     * During DGC related rmg operations, users can select the DGC method
     * that is used for the different RMI calls. This function validates whether
     * the DGC method is actually available. An invalid method specification
     * causes an error and closes the program.
     *
     * @param dgcMethod requested by the user.
     * @return dgcMethod if valid.
     */
    public String validateDgcMethod()
    {
        String dgcMethod = (String)this.get("dgc-method");

        if(!dgcMethod.matches("clean|dirty")) {
            Logger.printlnPlainMixedYellow("Unsupported DGC method:", dgcMethod);
            printHelp();
            System.exit(1);
        }

        return dgcMethod;
    }

    /**
     *
     * Determines whether the specified function signature is one of reg, dgc or act.
     * These do not require the creation of a MethodCandidate and are therefore handeled
     * in a special way.
     *
     * @param functionSignature the function signature specified on the command line
     * @return true if the specified function signature is valid (not reg, dgc, act or empty)
     */
    public boolean containsMethodSignature()
    {
        String signature = (String)this.get("signature");

        boolean result = !signature.equals("");
        result = result && !signature.matches("reg|dgc|act");

        return result;
    }

    public String getHost()
    {
        return this.getPositionalString(0);
    }

    public int getPort()
    {
        return this.getPositionalInt(1);
    }

    public Object getGadget()
    {
        String gadget = this.getPositionalString(3);
        String command = null;

        if(this.getArgumentCount() > 4)
            command = this.getPositionalString(4);

        return PluginSystem.getPayloadObject(this.getAction(), gadget, command);
    }

    public Object[] getCallArguments()
    {
        String argumentString = this.getPositionalString(3);
        return PluginSystem.getArgumentArray(argumentString);
    }

    public String requireBoundName()
    {
        String boundName = (String)this.get("bound-name");

        if(boundName == null) {
            Logger.eprintlnMixedYellow("The", "--bound-name", "argument is required for this action");
            RMGUtils.exit();
        }

        return boundName;
    }
}
