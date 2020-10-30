package de.qtc.rmg;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;

import org.apache.commons.cli.CommandLine;

import de.qtc.rmg.internal.ArgumentParser;
import de.qtc.rmg.internal.MethodCandidate;
import de.qtc.rmg.io.Formatter;
import de.qtc.rmg.io.Logger;
import de.qtc.rmg.io.WordlistHandler;
import de.qtc.rmg.utils.RMGUtils;
import de.qtc.rmg.utils.RMIWhisperer;

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
        }

        Properties config = new Properties();
        Starter.loadConfig(defaultConfiguration, config, false);

        String additionalConfig = commandLine.getOptionValue("config", null);
        if( additionalConfig != null )
            Starter.loadConfig(additionalConfig, config, true);

        int threadCount = Integer.valueOf(commandLine.getOptionValue("threads", config.getProperty("threads")));
        String sampleFolder = commandLine.getOptionValue("sample-folder", config.getProperty("sample-folder"));
        String wordlistFile = commandLine.getOptionValue("wordlist-file", config.getProperty("wordlist-file"));
        String templateFolder = commandLine.getOptionValue("template-folder", config.getProperty("template-folder"));
        String wordlistFolder = commandLine.getOptionValue("wordlist-folder", config.getProperty("wordlist-folder"));
        String boundName = commandLine.getOptionValue("bound-name", null);

        Logger.verbose = !commandLine.hasOption("quite") && !commandLine.hasOption("json");
        boolean sslValue = commandLine.hasOption("ssl");
        boolean followRedirect = commandLine.hasOption("follow");
        boolean updateWordlists = commandLine.hasOption("update");
        boolean createSamples = commandLine.hasOption("create-samples");

        Formatter format = new Formatter(commandLine.hasOption("json"));
        RMIWhisperer rmi = new RMIWhisperer();

        RMGUtils.init();
        rmi.connect(host, port, sslValue, followRedirect);
        String[] boundNames = rmi.getBoundNames();
        ArrayList<HashMap<String,String>> boundClasses = rmi.getClassNames(boundNames);

        switch( action ) {

            case "guess":
                if( !containsUnknown(boundClasses.get(1)) )
                    break;

                WordlistHandler wlHandler = new WordlistHandler(wordlistFile, wordlistFolder, updateWordlists);
                List<MethodCandidate> candidates = null;

                try {
                    candidates = wlHandler.getWordlistMethods();
                } catch( IOException e ) {
                    Logger.eprintlnMixedYellow("Caught exception while reading wordlist file(s):", e.getMessage());
                    Logger.eprintln("Cannot continue from here.");
                    System.exit(1);
                }

                MethodGuesser guesser = new MethodGuesser(rmi, boundClasses.get(1), candidates);
                HashMap<String,ArrayList<MethodCandidate>> results = guesser.guessMethods(boundName, threadCount, createSamples);

                format.listGuessedMethods(results);
                break;

            case "attack":

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
