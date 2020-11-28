package de.qtc.rmg.internal;

import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import de.qtc.rmg.utils.Security;

public class ArgumentParser {

    private Options options;
    private String helpString;
    private HelpFormatter formatter;
    private CommandLineParser parser;
    private CommandLine cmdLine;
    private List<String> argList;

    public ArgumentParser()
    {
        this.parser = new DefaultParser();
        this.options = getParserOptions();
        this.helpString = getHelpString();
        this.formatter = new HelpFormatter();
        this.formatter.setWidth(130);
    }

    public CommandLine parse(String[] argv)
    {
        CommandLine cmd = null;
        try {
            cmd = parser.parse(this.options, argv);
        } catch (ParseException e) {
            System.err.println("Error: " + e.getMessage() + "\n");
            printHelp();
            System.exit(1);
        }

        if( cmd.hasOption("help") ) {
            printHelp();
            System.exit(0);
        }

        if( cmd.hasOption("trusted") )
            Security.trusted();

        this.cmdLine = cmd;
        return cmd;
    }

    public void printHelp()
    {
        formatter.printHelp(helpString, options);
    }

    public void checkArgumentCount(int expectedCount)
    {
         List<String> remainingArgs = cmdLine.getArgList();
         if( remainingArgs.size() < expectedCount ) {
             System.err.println("Error: insufficient number of arguments.\n");
             printHelp();
             System.exit(1);
         }
    }

    private Options getParserOptions()
    {
        Options options = new Options();

        Option position = new Option(null, "argument-position", true, "select argument position for deserialization attacks");
        position.setArgName("int");
        position.setRequired(false);
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

        Option follow = new Option(null, "follow", false, "follow redirects to different servers");
        follow.setRequired(false);
        options.addOption(follow);

        Option forceLegacy = new Option(null, "force-legacy", false, "treat all classes as legacy stubs");
        forceLegacy.setRequired(false);
        options.addOption(forceLegacy);

        Option help = new Option(null, "help", false, "display help message");
        help.setRequired(false);
        options.addOption(help);

        Option jsonOutput = new Option(null, "json", false, "output in json format");
        jsonOutput.setRequired(false);
        options.addOption(jsonOutput);

        Option noColor = new Option(null, "no-color", false, "disable colored output");
        noColor.setRequired(false);
        options.addOption(noColor);

        Option noLegacy = new Option(null, "no-legacy", false, "disable automatic legacy stub detection");
        noLegacy.setRequired(false);
        options.addOption(noLegacy);

        Option outputs = new Option(null, "sample-folder", true, "folder used for sample generation");
        outputs.setArgName("folder");
        outputs.setRequired(false);
        options.addOption(outputs);

        Option signature = new Option(null, "signature", true, "function signature for guessing or attacking");
        signature.setArgName("method");
        signature.setRequired(false);
        options.addOption(signature);

        Option ssl = new Option(null, "ssl", false, "use SSL for the rmi-registry connection");
        ssl.setRequired(false);
        options.addOption(ssl);

        Option templates = new Option(null, "template-folder", true, "location of the template folder");
        templates.setArgName("folder");
        templates.setRequired(false);
        options.addOption(templates);

        Option threads = new Option(null, "threads", true, "maximum number of threads (default: 5)");
        threads.setArgName("int");
        threads.setRequired(false);
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

    private String getHelpString()
    {
        String helpString = "rmg [options] <ip> <port> <action>\n"
                +"Identify common misconfigurations on Java RMI endpoints.\n\n"
                +"Positional Arguments:\n"
                +"    ip:                          IP address of the target\n"
                +"    port:                        Port of the RMI registry\n"
                +"    action:                      One of the possible actions listed below\n\n"
                +"Possible Actions:\n"
                +"    attack <gadget> <command>    Perform deserialization attacks\n"
                +"    codebase <url> <classname>   Perform remote class loading attacks\n"
                +"    enum                         Enumerate bound names and classes\n"
                +"    guess                        Guess methods on bound names\n\n"
                +"Optional Arguments:";

        return helpString;
    }

    public String getPositionalString(int position)
    {
        if( this.argList != null ) {
            return this.argList.get(position);
        } else {
            this.argList = cmdLine.getArgList();
            return this.argList.get(position);
        }
    }

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

    public int getArgumentCount()
    {
        if( this.argList != null ) {
            return this.argList.size();
        } else {
            this.argList = cmdLine.getArgList();
            return this.argList.size();
        }
    }

    public int getLegacyMode()
    {
        if( this.cmdLine.hasOption("--no-legacy") )
            return 2;

        else if( this.cmdLine.hasOption("--force-legacy") )
            return 1;

        else
            return 0;
    }
}
