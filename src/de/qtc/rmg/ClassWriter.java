package de.qtc.rmg;

import java.io.File;
import java.io.PrintWriter;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class ClassWriter {

    public String templateFolder;
    public String sourceFolder;
    private String template;
	private String exploitClassName;


    public ClassWriter(String templateFolder, String sourceFolder) {
        this.templateFolder = templateFolder;
        this.sourceFolder = sourceFolder;
    }
    
    
    public File[] getTemplateFiles() {
    	
        File templateDir = new File(this.templateFolder);
        File[] containedFiles = templateDir.listFiles();
        
        List<File> templateFiles = new ArrayList<File>();
        for( File file : containedFiles ) {
          if( file.getName().matches("[a-zA-Z0-9]+Template.java") && ! file.getName().equals("ExploitTemplate.java") ) {
            templateFiles.add(file);
          }
        }
        
        return templateFiles.toArray(new File[templateFiles.size()]);
    }
    
    
    public void loadTemplate(String templateName) {

        String path = this.templateFolder + "/" + templateName;
        File exploitTemplate = new File(path);

        if( ! exploitTemplate.exists() ) {
            System.err.println("[-]\t\tError: '" + templateName + "' seems not to be contained in '" + this.templateFolder + "'");
            System.err.println("[-] Stopping execution.");
            System.exit(1);
        }

        Logger.print("[+]\t\tReading template file: '" + path +  "'... ");
        try {

            this.template = new String(Files.readAllBytes(Paths.get(path)));
            Logger.println("done");

        } catch( Exception e ) {

        	Logger.println("failed");
            System.err.println("[-]\t\tError: unable to read template file");
            System.exit(1);

        }
        

    }  

    public String writeClass(String fullClassName) {

    	String[] components = splitNames(fullClassName);
    	String packageName = components[0];
    	String className = components[1];
    	
        this.template = this.template.replace("<PACKAGENAME>", packageName);
        this.template = this.template.replace("<CLASSNAME>", className);

        String destination = this.sourceFolder + "/" + className + ".java";
        Logger.print("[+]\t\tWriting class '" + destination + "' to disk... ");

        try {

            PrintWriter writer = new PrintWriter(destination, "UTF-8");
            writer.print(this.template);
            writer.close();
            Logger.println("done.");

        } catch( Exception e ) {

        	Logger.println("failed.");
            System.err.println("[-] Error: Cannot open '" + destination + "'");
            System.exit(1);

        }
        
        return destination;

    }


    public void prepareExploit(String packageName, String className, String boundName, Method method, String exploitClassName, String remoteHost, int remotePort) {
        
    	this.loadTemplate("ExploitTemplate.java");
        this.exploitClassName = exploitClassName; 
        String port = String.valueOf(remotePort);

        int numberOfArguments = method.getParameterCount();
        StringBuilder argumentString = new StringBuilder();
        
        Class<?>[] typeOfArguments = method.getParameterTypes();

        for(int ctr = 1; ctr <= numberOfArguments; ctr++) {
        	if( typeOfArguments[ctr-1].isArray() ) {
        		argumentString.append("convertToArray(argv[" + ctr + "])" + ((ctr == numberOfArguments) ? "" : ","));
        	} else {
        		argumentString.append("argv[" + ctr + "]" + ((ctr == numberOfArguments) ? "" : ",")); 
        	}
        }

        Logger.print("[+]\t\tPreparing exploit... ");

        this.template = this.template.replace(  "<PACKAGE>",      packageName + "." + className);
        this.template = this.template.replace(  "<CLASSNAME>",    exploitClassName);
        this.template = this.template.replace(  "<METHODSIG>",    method.toString());
        this.template = this.template.replace(  "<REMOTEHOST>",   remoteHost);
        this.template = this.template.replace(  "<REMOTEPORT>",   port);
        this.template = this.template.replace(  "<BOUNDNAME>",    boundName);
        this.template = this.template.replace(  "<CLASS>",        className);
        this.template = this.template.replace(  "<METHODNAME>",   method.getName());
        this.template = this.template.replace(  "<RETURNTYPE>",   method.getReturnType().getName());
        this.template = this.template.replace(  "<ARGCOUNT>",     Integer.toString(numberOfArguments));
        this.template = this.template.replace(  "<ARGUMENTS>",    argumentString.toString());

        Logger.println("done.");

    }

    
    public String writeExploit() {

        String destination = this.sourceFolder + "/" + this.exploitClassName + ".java";
        Logger.print("[+]\t\tWriting exploit '" + destination + "' to disk... ");

        try {

            PrintWriter writer = new PrintWriter(destination, "UTF-8");
            writer.print(template);
            writer.close();
            Logger.println("done.");

        } catch( Exception e ) {

        	Logger.println("failed.");
            System.err.println("[-] Error: Cannot open '" + destination + "'");
            System.exit(1);

        }
        
        return destination;

    }
    
    
    public static String[] splitNames(String fullName) {
    	String className = fullName.substring(fullName.lastIndexOf(".") + 1, fullName.length());
    	String packageName = fullName.substring(0, fullName.lastIndexOf("."));
    	return new String[] { packageName, className };
    }

}
