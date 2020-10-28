package de.qtc.rmg;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;

import org.apache.commons.cli.CommandLine;

import de.qtc.rmg.io.Formatter;
import de.qtc.rmg.io.Logger;
import de.qtc.rmg.utils.ArgumentParser;
import de.qtc.rmg.utils.RMGUtils;
import de.qtc.rmg.utils.RMIWhisperer;
import de.qtc.rmg.utils.Security;

public class Starter {

    private static String defaultConfiguration = "/config.properties";

    public static void main(String[] argv) {

        ArgumentParser parser = new ArgumentParser();
        CommandLine commandLine = parser.parse(argv);;

        Properties config = new Properties();
        Starter.loadConfig(defaultConfiguration, config, false);

        String additionalConfig = commandLine.getOptionValue("config", null);
        if( additionalConfig != null )
            Starter.loadConfig(additionalConfig, config, true);

        int threadCount = Integer.valueOf(commandLine.getOptionValue("threads", config.getProperty("threads")));
        String templateFolder = commandLine.getOptionValue("template-folder", config.getProperty("templateFolder"));
        String boundName = commandLine.getOptionValue("bound-name", null);
        Security.trusted = commandLine.hasOption("trusted");

        List<String> remainingArgs = commandLine.getArgList();
        if( remainingArgs.size() != 2 ) {
            System.err.println("Error: insufficient number of arguments.\n");
            parser.printHelp();
            System.exit(1);
        }

        String host = remainingArgs.get(0);
        int port = 1090;

        try {
            port = Integer.valueOf(remainingArgs.get(1));
        } catch( Exception e ) {
            System.err.println("Error: Specified port is not an integer.\n");
            parser.printHelp();
            System.exit(1);
        }

        Logger.verbose = !commandLine.hasOption("quite") && !commandLine.hasOption("json");
        Formatter format = new Formatter(commandLine.hasOption("json"));
        RMIWhisperer rmi = new RMIWhisperer();

        boolean sslValue = commandLine.hasOption("ssl");
        boolean followRedirect = commandLine.hasOption("follow");
        rmi.connect(host, port, sslValue, followRedirect);

        String[] boundNames = rmi.getBoundNames();
        ArrayList<HashMap<String,String>> boundClasses = null;

        if( commandLine.hasOption("classes") || commandLine.hasOption("guess") ) {
            boundClasses = rmi.getClassNames(boundNames);
        }

        if( !commandLine.hasOption("guess") ) {
            format.listBoundNames(boundNames, boundClasses);
            System.exit(0);
        }

        if( boundClasses.get(1).size() <= 0 ) {
            format.listBoundNames(boundNames, boundClasses);
            Logger.eprintln("No unknown classes identified.");
            Logger.eprintln("Guessing methods not necessary.");
            System.exit(0);
        }

        RMGUtils.init(templateFolder);
        MethodGuesser guesser = null;

        try {
            guesser = new MethodGuesser(rmi, boundClasses.get(1));
        } catch (NoSuchFieldException | SecurityException e) {
            Logger.eprintlnYellow("Unable to create MethodGuesser object.");
            Logger.eprintln("StackTrace:");
            e.printStackTrace();
            System.exit(1);
        }

        boolean createSamples = commandLine.hasOption("create-samples");
        HashMap<String,ArrayList<Method>> results = guesser.guessMethods(boundName, threadCount, createSamples);

        format.listGuessedMethods(results);
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
