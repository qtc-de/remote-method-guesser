package de.qtc.rmg;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.util.ArrayList;
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
import org.apache.commons.io.FileUtils;

public class Starter {

    private static String defaultConfiguration = "/config.properties";

	public static void main(String[] argv) {
		
		Options options = new Options();
		
        Option name = new Option(null, "boundName", true, "guess only on this bound name");
        name.setRequired(false);
        options.addOption(name);

		Option build = new Option(null, "buildFolder", true, "location of the build folder");
		build.setRequired(false);
		options.addOption(build);
        
		Option classes = new Option(null, "classes", false, "show also class names");
		classes.setRequired(false);
		options.addOption(classes);
		
        Option configOption = new Option(null, "config", true, "path to a configuration file");
        configOption.setRequired(false);
        options.addOption(configOption);
		
		Option guess = new Option(null, "guess", false, "guess valid methods on classes");
		guess.setRequired(false);
		options.addOption(guess);

		Option jsonOutput = new Option(null, "json", false, "output in json format");
		jsonOutput.setRequired(false);
		options.addOption(jsonOutput);
		
		Option javac = new Option(null, "javacPath", true, "location of the javac executable");
		javac.setRequired(false);
		options.addOption(javac);
		
		Option jar = new Option(null, "jarPath", true, "location of the jar executable");
		jar.setRequired(false);
		options.addOption(jar);

		Option outputs = new Option(null, "outputFolder", true, "location of the source folder");
		outputs.setRequired(false);
		options.addOption(outputs);
		
		Option sources = new Option(null, "sourceFolder", true, "location of the source folder");
		sources.setRequired(false);
		options.addOption(sources);
		
        Option threads = new Option(null, "threads", true, "maximum number of threads");
        threads.setRequired(false);
        options.addOption(threads);
		
		Option templates = new Option(null, "templateFolder", true, "location of the template folder");
		templates.setRequired(false);
		options.addOption(templates);
		
		Option showClasses = new Option(null, "quite", false, "less verbose output format");
		showClasses.setRequired(false);
		options.addOption(showClasses);

		
		
		CommandLineParser parser = new DefaultParser();
		HelpFormatter formatter = new HelpFormatter();
		CommandLine commandLine = null;

		String helpString = "rmg.jar [options] [clean | <ip> <port>]\n";
		helpString += "Tries to identify juicy methods on unknown RMI interfaces.\n\n";
		helpString += "Positional arguments:\n";
		helpString += "    clean                    Removes all temporary directories.\n";
		helpString += "    ip                       IP address of the target host\n";
		helpString += "    port                     Port number of the RMI registry\n\n";
		helpString += "Optional arguments:\n";
				
		try {
			commandLine = parser.parse(options, argv);
		} catch (ParseException e) {
			formatter.printHelp(helpString, options);
			System.exit(1);
		}

		 /* The default configuration values are loaded from the default configuration file inside the .jar */
        Properties config = new Properties();
        Starter.loadConfig(defaultConfiguration, config, false);

        /* If an additional configuration file is specified on the command line, we overwrite specified properties */
        String additionalConfig = commandLine.getOptionValue("config", null);
        if( additionalConfig != null )
        	Starter.loadConfig(additionalConfig, config, true);
        
		String templateFolder = commandLine.getOptionValue("templateFolder", config.getProperty("templateFolder"));
		String outputFolder = commandLine.getOptionValue("outputFolder", config.getProperty("outputFolder"));
		String sourceFolder = commandLine.getOptionValue("sourceFolder", config.getProperty("sourceFolder"));
		String buildFolder = commandLine.getOptionValue("buildFolder", config.getProperty("buildFolder"));
		String javacPath = commandLine.getOptionValue("javacPath", config.getProperty("javacPath"));
		String jarPath = commandLine.getOptionValue("jarPath", config.getProperty("jarPath"));
		String boundName = commandLine.getOptionValue("boundName", null);
		int threadCount = Integer.valueOf(commandLine.getOptionValue("threads", config.getProperty("threads")));
		File[] tmpDirectories = new File[] { new File(sourceFolder), new File(buildFolder), new File(outputFolder) };
		
		List<String> remainingArgs = commandLine.getArgList();
		
		if( remainingArgs.size() == 1 && remainingArgs.get(0).equals("clean") ) {
			for(File dir : tmpDirectories) {
				try {
					FileUtils.deleteDirectory(dir);
				} catch (IOException e) {
					Logger.println("[-] Error during cleanup.");
				}
			}
			System.exit(0);
		}
		
		
		if( remainingArgs.size() != 2 ) {
            formatter.printHelp(helpString, options);
            System.exit(1);
		}

		String host = remainingArgs.get(0);
		int port = 1099;
		
		try {
			port = Integer.valueOf(remainingArgs.get(1));
		} catch( Exception e ) {
			formatter.printHelp(helpString, options);
			System.exit(1);
		}
		
		Logger.verbose = ! commandLine.hasOption("quite") && ! commandLine.hasOption("json");
		Formatter format = new Formatter(commandLine.hasOption("json"));
		RMIWhisperer rmi = new RMIWhisperer();
		
		rmi.connect(host, port);
		
		String[] boundNames = rmi.getBoundNames();
		ArrayList<HashMap<String,String>> boundClasses = null;
		
		if( commandLine.hasOption("classes") || commandLine.hasOption("guess") ) {
			boundClasses = rmi.getClassNames(boundNames);
		}
		
		if( !commandLine.hasOption("guess") ) {
			format.listBoundNames(boundNames, boundClasses);
			System.exit(0);
		} 
		
		/* If execution reaches this point, we need the template folder */
		File templatesFolder = new File(templateFolder);
		if( !templatesFolder.exists() ) {
			System.err.println("[-] Error: Template folder '" + templateFolder + "' does not exist");
			System.err.println("[-] RMG attacks require an existing template folder.");
			System.exit(1);
		}
	        
        for(File dir : tmpDirectories) {
        	 if( !dir.exists() ) {
        		 Logger.print("[+] Creating required folder '" + dir.getName() + "'... ");
        		 dir.mkdir();
                 Logger.println("done.");
        	 }
		}
		
		ClassWriter classWriter = new ClassWriter(templateFolder, sourceFolder);
		JavaUtils javaUtils = new JavaUtils(javacPath, jarPath, buildFolder, outputFolder);
		MethodGuesser guesser = new MethodGuesser(rmi, boundClasses.get(1), classWriter, javaUtils);
		
		HashMap<String,ArrayList<Method>> results = guesser.guessMethods(boundName, threadCount);
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
            System.out.println("[-] Unable to load properties file '" + filename + "'");
            System.exit(1);
        }
    }
}
