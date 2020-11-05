package de.qtc.rmg;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;

import org.apache.commons.cli.CommandLine;

import de.qtc.rmg.exceptions.UnexpectedCharacterException;
import de.qtc.rmg.internal.ArgumentParser;
import de.qtc.rmg.internal.MethodCandidate;
import de.qtc.rmg.io.Formatter;
import de.qtc.rmg.io.Logger;
import de.qtc.rmg.io.WordlistHandler;
import de.qtc.rmg.operations.MethodAttacker;
import de.qtc.rmg.operations.MethodGuesser;
import de.qtc.rmg.utils.RMGUtils;
import de.qtc.rmg.utils.RMIWhisperer;
import de.qtc.rmg.utils.SampleWriter;
import javassist.CannotCompileException;
import javassist.NotFoundException;

public class Starter {

    private static String defaultConfiguration = "/config.properties";

    public static void main(String[] argv) {

        ArgumentParser parser = new ArgumentParser();
        CommandLine commandLine = parser.parse(argv);

        parser.checkArgumentCount(2);
        String action = "enum";
        String host = parser.getPositionalString(0);
        int port = parser.getPositionalInt(1);

        if( parser.getArgumentCount() >= 3 ) {
            action = parser.getPositionalString(2);

            if( action == "attack" ) {
                parser.checkArgumentCount(5);
            }
        }

        Properties config = new Properties();
        Starter.loadConfig(defaultConfiguration, config, false);

        String additionalConfig = commandLine.getOptionValue("config", null);
        if( additionalConfig != null )
            Starter.loadConfig(additionalConfig, config, true);

        int argumentPos = Integer.valueOf(commandLine.getOptionValue("argument-position", "0"));
        int threadCount = Integer.valueOf(commandLine.getOptionValue("threads", config.getProperty("threads")));
        String sampleFolder = commandLine.getOptionValue("sample-folder", config.getProperty("sample-folder"));
        String wordlistFile = commandLine.getOptionValue("wordlist-file", config.getProperty("wordlist-file"));
        String templateFolder = commandLine.getOptionValue("template-folder", config.getProperty("template-folder"));
        String wordlistFolder = commandLine.getOptionValue("wordlist-folder", config.getProperty("wordlist-folder"));
        String ysoserialPath = commandLine.getOptionValue("yso", config.getProperty("ysoserial"));
        String functionSignature = commandLine.getOptionValue("signature", null);
        String boundName = commandLine.getOptionValue("bound-name", null);

        Logger.verbose = !commandLine.hasOption("json");
        boolean sslValue = commandLine.hasOption("ssl");
        boolean followRedirect = commandLine.hasOption("follow");
        boolean updateWordlists = commandLine.hasOption("update");
        boolean createSamples = commandLine.hasOption("create-samples");
        boolean zeroArg = commandLine.hasOption("zero-arg");

        if( commandLine.hasOption("no-color") ) {
            Logger.disableColor();
        }

        Formatter format = new Formatter(commandLine.hasOption("json"));
        RMIWhisperer rmi = new RMIWhisperer();

        RMGUtils.init();
        rmi.connect(host, port, sslValue, followRedirect);
        String[] boundNames = rmi.getBoundNames();
        ArrayList<HashMap<String,String>> boundClasses = rmi.getClassNames(boundNames);

        MethodCandidate candidate = null;
        if( functionSignature != null ) {

            try {
                candidate = new MethodCandidate(functionSignature);

            } catch (CannotCompileException | NotFoundException e) {
                Logger.eprintln("Supplied method signature seems to be invalid.");
                Logger.eprintlnMixedYellow("The following exception was caught:", e.getMessage());
                Logger.eprintln("Cannot continue from here.");
                System.exit(1);
            }
        }

        switch( action ) {

            case "guess":
                if( !containsUnknown(boundClasses.get(1)) )
                    break;

                List<MethodCandidate> candidates = new ArrayList<MethodCandidate>();
                if( candidate != null ) {

                    candidates.add(candidate);

                } else {

                    try {
                        WordlistHandler wlHandler = new WordlistHandler(wordlistFile, wordlistFolder, updateWordlists);
                        candidates = wlHandler.getWordlistMethods();
                    } catch( IOException e ) {
                        Logger.eprintlnMixedYellow("Caught exception while reading wordlist file(s):", e.getMessage());
                        Logger.eprintln("Cannot continue from here.");
                        System.exit(1);
                    }
                }

                MethodGuesser guesser = new MethodGuesser(rmi, boundClasses.get(1), candidates);
                HashMap<String,ArrayList<MethodCandidate>> results = guesser.guessMethods(boundName, threadCount, createSamples, zeroArg);

                format.listGuessedMethods(results);
                if( !createSamples )
                    break;

                Logger.println("");
                Logger.println("Starting creation of sample files");
                Logger.increaseIndent();

                try {
                    String className;
                    SampleWriter writer;
                    writer = new SampleWriter(templateFolder, sampleFolder, sslValue, followRedirect);

                    for(String name : results.keySet()) {

                        Logger.printlnMixedYellow("Creating samples for bound name", name);
                        Logger.increaseIndent();

                        className = boundClasses.get(1).get(name);
                        writer.createInterfaceSample(name, className, (List<MethodCandidate>)results.get(name));
                        writer.createSamples(name, className, (List<MethodCandidate>)results.get(name), rmi);

                        Logger.decreaseIndent();
                    }

                } catch (IOException | CannotCompileException | NotFoundException e) {
                    Logger.eprintlnMixedYellow("Caught unexpected", e.getClass().getName(), "during sample creation.");
                    Logger.eprintln("StackTrace:");
                    e.printStackTrace();
                    RMGUtils.exit();

                } catch (UnexpectedCharacterException e) {
                    Logger.eprintlnMixedYellow("Caught", "UnexpectedCharacterException", "during sample creation.");
                    Logger.eprintln("This is caused by special characters within bound- or classes names.");
                    Logger.eprintlnMixedYellow("You can enforce sample cration with the", "--trusted", "switch.");
                    RMGUtils.exit();
                }

                Logger.decreaseIndent();
                break;

            case "attack":

                String gadget = parser.getPositionalString(3);
                String command = parser.getPositionalString(4);

                HashMap<String,String> classes = boundClasses.get(0);
                classes.putAll(boundClasses.get(1));

                Object payload = RMGUtils.getPayloadObject(ysoserialPath, gadget, command);
                MethodAttacker attacker = new MethodAttacker(rmi, classes, candidate);
                attacker.attack(payload, boundName, argumentPos);

                break;

            default:
                Logger.printlnMixedYellow("Unknown action:", action, ".");
                Logger.printlnMixedBlue("Performing default action:", "enum");

            case "enum":
                format.listBoundNames(boundNames, boundClasses);
        }
    }

    private static boolean containsUnknown(HashMap<String,String> unknownClasses)
    {
        if( unknownClasses.size() <= 0 ) {
            Logger.eprintln("No unknown classes identified.");
            Logger.eprintln("Guessing methods not necessary.");
            return false;
        }

        return true;
    }

    private static void loadConfig(String filename, Properties prop, boolean extern) {

        InputStream configStream = null;
        try {
            if( extern ) {
                configStream = new FileInputStream(filename);
            } else {
                configStream = Starter.class.getResourceAsStream(filename);
            }

        prop.load(configStream);
        configStream.close();

        } catch( IOException e ) {
            Logger.eprintln("Unable to load properties file '" + filename + "'");
            System.exit(1);
        }
    }
}
