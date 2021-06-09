package de.qtc.rmg.internal;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Properties;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import de.qtc.rmg.annotations.Parameters;
import de.qtc.rmg.io.Logger;
import de.qtc.rmg.operations.Operation;
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
 * To implement more complicated parsing logic, it is recommended to look at the
 * de.qtc.rmg.annotations.Parameters class.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class ArgumentParser {

    private Operation action = null;

    private Options options;
    private String helpString;
    private HelpFormatter formatter;
    private CommandLineParser parser;
    private CommandLine cmdLine;
    private List<String> argList;
    private Properties config;

    private  String defaultConfiguration = "/config.properties";

    /**
     * Creates the actual parser object and initializes it with some default options
     * and parses the current command line. Parsed parameters are stored within the
     * parameters HashMap.
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

    /**
     * Parses the specified command line arguments and handles some shortcuts.
     * E.g. the --help and --trusted options are already caught at this level and
     * set the corresponding global variables in other classes.
     *
     * @param argv arguments specified on the command line
     */
    private void parse(String[] argv)
    {
        try {
            cmdLine = parser.parse(this.options, argv);
        } catch (ParseException e) {
            System.err.println("Error: " + e.getMessage() + "\n");
            printHelpAndExit(1);
        }

        this.config = new Properties();
        loadConfig(cmdLine.getOptionValue(RMGOption.CONFIG.name, null));

        if( cmdLine.hasOption(RMGOption.HELP.name) ) {
            printHelpAndExit(0);
        }

        if( cmdLine.hasOption(RMGOption.TRUSTED.name) )
            Security.trusted();

        if( cmdLine.hasOption(RMGOption.NO_COLOR.name) )
            Logger.disableColor();

        if( cmdLine.hasOption(RMGOption.VERBOSE.name) )
            Logger.verbose = true;

        PluginSystem.init(cmdLine.getOptionValue("plugin", null));
        ExceptionHandler.showStackTrace(cmdLine.hasOption("stack-trace"));
        YsoIntegration.setYsoPath(cmdLine.getOptionValue("yso", config.getProperty("ysoserial-path")));

        preapreParameters();
    }

    /**
     * Loads the remote-method-guesser configuration file from the specified destination. The default configuration
     * is always loaded. If the filename parameter is not null, an additional user specified config is loaded, that
     * may overwrites some configurations.
     *
     * @param filename file system path to load the configuration file from
     */
    private void loadConfig(String filename)
    {
        try {
            InputStream configStream = null;

            configStream = ArgumentParser.class.getResourceAsStream(defaultConfiguration);
            config.load(configStream);
            configStream.close();

            if( filename != null ) {
                configStream = new FileInputStream(filename);
                config.load(configStream);
                configStream.close();
            }

        } catch( IOException e ) {
            ExceptionHandler.unexpectedException(e, "loading", ".properties file", true);
        }
    }


    /**
     * Command line parameters are stored within the RMGOption enum. This function parses the values
     * from the command line and sets the corresponding enum values.
     */
    private void preapreParameters()
    {
        RMGOption.SAMPLE_FOLDER.setValue(cmdLine, config.getProperty("sample-folder"));
        RMGOption.WORDLIST_FILE.setValue(cmdLine, config.getProperty("wordlist-file"));
        RMGOption.TEMPLATE_FOLDER.setValue(cmdLine, config.getProperty("template-folder"));
        RMGOption.WORDLIST_FOLDER.setValue(cmdLine, config.getProperty("wordlist-folder"));
        RMGOption.SIGNATURE.setValue(cmdLine);
        RMGOption.BOUND_NAME.setValue(cmdLine);
        RMGOption.REG_METHOD.setValue(cmdLine, "lookup");
        RMGOption.DGC_METHOD.setValue(cmdLine, "clean");

        RMGOption.SSL.setBoolean(cmdLine);
        RMGOption.FOLLOW.setBoolean(cmdLine);
        RMGOption.UPDATE.setBoolean(cmdLine);
        RMGOption.CREATE_SAMPLES.setBoolean(cmdLine);
        RMGOption.ZERO_ARG.setBoolean(cmdLine);
        RMGOption.LOCALHOST_BYPASS.setBoolean(cmdLine);
        RMGOption.FORCE_GUESSING.setBoolean(cmdLine);

        try {
            RMGOption.OBJID.setInt(cmdLine, null);
            RMGOption.ARGUMENT_POS.setInt(cmdLine, -1);
            RMGOption.THREADS.setInt(cmdLine, Integer.valueOf(config.getProperty("threads")));

        } catch(ParseException e) {
            Logger.printlnPlainMixedYellow("Error: Invalid parameter type for argument", "OBJID | ARGUMENT_POS | THREADS");
            System.out.println("");
            printHelpAndExit(1);
        }

        if( RMGOption.OBJID.value != null )
            RMGOption.TARGET.setValue(RMGOption.OBJID.value);
        else if( RMGOption.BOUND_NAME.value != null )
            RMGOption.TARGET.setValue(RMGOption.BOUND_NAME.value);
    }

    /**
     * Returns the number of specified positional arguments.
     *
     * @return number of positional arguments.
     */
    private int getArgumentCount()
    {
        if( this.argList != null ) {
            return this.argList.size();
        } else {
            this.argList = cmdLine.getArgList();
            return this.argList.size();
        }
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

        Option position = new Option(null, RMGOption.ARGUMENT_POS.name, RMGOption.ARGUMENT_POS.requiresValue, RMGOption.ARGUMENT_POS.description);
        position.setArgName("int");
        position.setRequired(false);
        position.setType(Number.class);
        options.addOption(position);

        Option name = new Option(null, RMGOption.BOUND_NAME.name, RMGOption.BOUND_NAME.requiresValue, RMGOption.BOUND_NAME.description);
        name.setArgName("name");
        name.setRequired(false);
        options.addOption(name);

        Option configOption = new Option(null, RMGOption.CONFIG.name, RMGOption.CONFIG.requiresValue, RMGOption.CONFIG.description);
        configOption.setArgName("file");
        configOption.setRequired(false);
        options.addOption(configOption);

        Option samples = new Option(null, RMGOption.CREATE_SAMPLES.name, RMGOption.CREATE_SAMPLES.requiresValue, RMGOption.CREATE_SAMPLES.description);
        samples.setRequired(false);
        options.addOption(samples);

        Option dgcMethod = new Option(null, RMGOption.DGC_METHOD.name, RMGOption.DGC_METHOD.requiresValue, RMGOption.DGC_METHOD.description);
        dgcMethod.setArgName("method");
        dgcMethod.setRequired(false);
        options.addOption(dgcMethod);

        Option follow = new Option(null, RMGOption.FOLLOW.name, RMGOption.FOLLOW.requiresValue, RMGOption.FOLLOW.description);
        follow.setRequired(false);
        options.addOption(follow);

        Option forceGuessing = new Option(null, RMGOption.FORCE_GUESSING.name, RMGOption.FORCE_GUESSING.requiresValue, RMGOption.FORCE_GUESSING.description);
        forceGuessing.setRequired(false);
        options.addOption(forceGuessing);

        Option forceLegacy = new Option(null, RMGOption.FORCE_LEGACY.name, RMGOption.FORCE_LEGACY.requiresValue, RMGOption.FORCE_LEGACY.description);
        forceLegacy.setRequired(false);
        options.addOption(forceLegacy);

        Option help = new Option(null, RMGOption.HELP.name, RMGOption.HELP.requiresValue, RMGOption.HELP.description);
        help.setRequired(false);
        options.addOption(help);

        Option local = new Option(null, RMGOption.LOCALHOST_BYPASS.name, RMGOption.LOCALHOST_BYPASS.requiresValue, RMGOption.LOCALHOST_BYPASS.description);
        local.setRequired(false);
        options.addOption(local);

        Option noColor = new Option(null, RMGOption.NO_COLOR.name, RMGOption.NO_COLOR.requiresValue, RMGOption.NO_COLOR.description);
        noColor.setRequired(false);
        options.addOption(noColor);

        Option noLegacy = new Option(null, RMGOption.NO_LEGACY.name, RMGOption.NO_LEGACY.requiresValue, RMGOption.NO_LEGACY.description);
        noLegacy.setRequired(false);
        options.addOption(noLegacy);

        Option objID = new Option(null, RMGOption.OBJID.name, RMGOption.OBJID.requiresValue, RMGOption.OBJID.description);
        objID.setRequired(false);
        objID.setArgName("objID");
        objID.setType(Number.class);
        options.addOption(objID);

        Option plugin = new Option(null, RMGOption.PLUGIN.name, RMGOption.PLUGIN.requiresValue, RMGOption.PLUGIN.description);
        plugin.setArgName("path");
        plugin.setRequired(false);
        options.addOption(plugin);

        Option regMethod = new Option(null, RMGOption.REG_METHOD.name, RMGOption.REG_METHOD.requiresValue, RMGOption.REG_METHOD.description);
        regMethod.setArgName("method");
        regMethod.setRequired(false);
        options.addOption(regMethod);

        Option outputs = new Option(null, RMGOption.SAMPLE_FOLDER.name, RMGOption.SAMPLE_FOLDER.requiresValue, RMGOption.SAMPLE_FOLDER.description);
        outputs.setArgName("folder");
        outputs.setRequired(false);
        options.addOption(outputs);

        Option signature = new Option(null, RMGOption.SIGNATURE.name, RMGOption.SIGNATURE.requiresValue, RMGOption.SIGNATURE.description);
        signature.setArgName("method");
        signature.setRequired(false);
        options.addOption(signature);

        Option ssl = new Option(null, RMGOption.SSL.name, RMGOption.SSL.requiresValue, RMGOption.SSL.description);
        ssl.setRequired(false);
        options.addOption(ssl);

        Option stackTrace = new Option(null, RMGOption.STACK_TRACE.name, RMGOption.STACK_TRACE.requiresValue, RMGOption.STACK_TRACE.description);
        stackTrace.setRequired(false);
        options.addOption(stackTrace);

        Option templates = new Option(null, RMGOption.TEMPLATE_FOLDER.name, RMGOption.TEMPLATE_FOLDER.requiresValue, RMGOption.TEMPLATE_FOLDER.description);
        templates.setArgName("folder");
        templates.setRequired(false);
        options.addOption(templates);

        Option threads = new Option(null, RMGOption.THREADS.name, RMGOption.THREADS.requiresValue, RMGOption.THREADS.description);
        threads.setArgName("int");
        threads.setRequired(false);
        threads.setType(Number.class);
        options.addOption(threads);

        Option trusted = new Option(null, RMGOption.TRUSTED.name, RMGOption.TRUSTED.requiresValue, RMGOption.TRUSTED.description);
        trusted.setRequired(false);
        options.addOption(trusted);

        Option update = new Option(null, RMGOption.UPDATE.name, RMGOption.UPDATE.requiresValue, RMGOption.UPDATE.description);
        update.setRequired(false);
        options.addOption(update);

        Option verbose = new Option(null, RMGOption.VERBOSE.name, RMGOption.VERBOSE.requiresValue, RMGOption.VERBOSE.description);
        verbose.setRequired(false);
        options.addOption(verbose);

        Option wordlist = new Option(null, RMGOption.WORDLIST_FILE.name, RMGOption.WORDLIST_FILE.requiresValue, RMGOption.WORDLIST_FILE.description);
        wordlist.setArgName("file");
        wordlist.setRequired(false);
        options.addOption(wordlist);

        Option wordlistFolder = new Option(null, RMGOption.WORDLIST_FOLDER.name, RMGOption.WORDLIST_FOLDER.requiresValue, RMGOption.WORDLIST_FOLDER.description);
        wordlistFolder.setArgName("folder");
        wordlistFolder.setRequired(false);
        options.addOption(wordlistFolder);

        Option yso = new Option(null, RMGOption.YSO.name, RMGOption.YSO.requiresValue, RMGOption.YSO.description);
        yso.setArgName("file");
        yso.setRequired(false);
        options.addOption(yso);

        Option zeroArg = new Option(null, RMGOption.ZERO_ARG.name, RMGOption.ZERO_ARG.requiresValue, RMGOption.ZERO_ARG.description);
        zeroArg.setRequired(false);
        options.addOption(zeroArg);

        return options;
    }

    /**
     * The validateOperation function is used to validate that all required parameters were specified for an operation.
     * Each operation has one assigned method, that can be annotated with the Parameters annotation. If this annotation
     * is present, this function checks the 'count' and 'requires' attribute and makes sure that the corresponding values
     * have been specified on the command line. Read the de.qtc.rmg.annotations.Parameters class for more details.
     *
     * @param operation Operation to validate
     */
    private void validateOperation(Operation operation)
    {
        Method m = operation.getMethod();
        Parameters paramRequirements = (Parameters)m.getAnnotation(Parameters.class);

        if(paramRequirements == null)
            return;

        this.checkArgumentCount(paramRequirements.count());

        for(RMGOption requiredOption: paramRequirements.requires()) {

            if(requiredOption.value == null) {

                Logger.eprint("Error: The ");
                Logger.printPlainYellow("--" + requiredOption.name);
                Logger.printlnPlainMixedBlue(" option is required for the", operation.toString().toLowerCase(), "operation.");
                RMGUtils.exit();
            }
        }
    }

    /**
     * Returns the help string that is used by rmg. The version information is read from the pom.xml, which makes
     * it easier to keep it in sync. Possible operation names are taken from the Operation enumeration.
     *
     * @return help string.
     */
    private String getHelpString()
    {
        String helpString = "rmg [options] <ip> <port> <action>\n\n"
                +"rmg v" + ArgumentParser.class.getPackage().getImplementationVersion()
                +" - Identify common misconfigurations on Java RMI endpoints.\n\n"
                +"Positional Arguments:\n"
                +"    ip                              IP address of the target\n"
                +"    port                            Port of the RMI registry\n"
                +"    action                          One of the possible actions listed below\n\n"
                +"Possible Actions:\n";

        for(Operation op : Operation.values()) {
            helpString += "    "
                    + Logger.padRight(op.toString().toLowerCase() + " " + op.getArgs(), 32)
                    + op.getDescription() + "\n";
        }

        helpString += "\nOptional Arguments:";
        return helpString;
    }

    /**
     * Utility function to show the program help and exit it right away.
     *
     * @param code return code of the program
     */
    private void printHelpAndExit(int code)
    {
        formatter.printHelp(helpString, options);
        System.exit(code);
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
            printHelpAndExit(1);
        }
        return 0;
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
             printHelpAndExit(1);
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
        if( this.cmdLine.hasOption(RMGOption.NO_LEGACY.name) )
            return 2;

        else if( this.cmdLine.hasOption(RMGOption.FORCE_LEGACY.name) )
            return 1;

        else
            return 0;
    }

    /**
     * This function is used to check the requested operation name on the command line and returns the corresponding
     * Operation object. If no operation was specified, the Operation.ENUM is used. Operations are always validated
     * before they are returned. The validation checks if all required parameters for the corresponding operation were
     * specified.
     *
     * @return Operation requested by the client
     */
    public Operation getAction()
    {
        if(this.action != null)
            return this.action;

        else if( this.getArgumentCount() < 3 ) {
            this.action = Operation.ENUM;

        } else {
            this.action = Operation.getByName(this.getPositionalString(2));
        }

        if(this.action == null) {
            Logger.eprintlnMixedYellow("Error: Specified operation", this.getPositionalString(2), "is not supported.");
            printHelpAndExit(1);
        }

        validateOperation(action);
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
    public String getRegMethod()
    {
        String regMethod = RMGOption.REG_METHOD.getString();

        if(!regMethod.matches("lookup|bind|unbind|rebind")) {
            Logger.printlnPlainMixedYellow("Unsupported registry method:", regMethod);
            printHelpAndExit(1);
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
    public String getDgcMethod()
    {
        String dgcMethod = RMGOption.DGC_METHOD.getString();

        if(!dgcMethod.matches("clean|dirty")) {
            Logger.printlnPlainMixedYellow("Unsupported DGC method:", dgcMethod);
            printHelpAndExit(1);
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
        String signature = RMGOption.SIGNATURE.getString();

        if(signature == null)
            return false;

        return !signature.matches("reg|dgc|act");
    }

    /**
     * Utility function that returns the hostname specified on the command line.
     *
     * @return user specified hostname (target)
     */
    public String getHost()
    {
        return this.getPositionalString(0);
    }

    /**
     * Utility function that returns the port specified on the command line.
     *
     * @return user specified port (target)
     */
    public int getPort()
    {
        return this.getPositionalInt(1);
    }

    /**
     * Parses the user specified gadget arguments to request a corresponding gadget from the PayloadProvider.
     * The corresponding gadget object is returned.
     *
     * @return gadget object build from the user specified arguments
     */
    public Object getGadget()
    {
        String gadget = this.getPositionalString(3);
        String command = null;

        if(this.getArgumentCount() > 4)
            command = this.getPositionalString(4);

        return PluginSystem.getPayloadObject(this.getAction(), gadget, command);
    }

    /**
     * Parses the user specified argument string during a call action. Passes the string to the corresponding
     * ArgumentProvider and returns the result argument array.
     *
     * @return Object array resulting from the specified argument string
     */
    public Object[] getCallArguments()
    {
        String argumentString = this.getPositionalString(3);
        return PluginSystem.getArgumentArray(argumentString);
    }
}
