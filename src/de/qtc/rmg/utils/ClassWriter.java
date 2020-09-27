package de.qtc.rmg.utils;

import java.io.File;
import java.io.PrintWriter;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import de.qtc.rmg.io.Logger;

public class ClassWriter {

    public String templateFolder;
    public String sourceFolder;
    public String sampleFolder;

    private String ssl;
    private String template;
    private String templateIntf;
    private String sampleClassName;
    private String followRedirects;

    public ClassWriter(String templateFolder, String sourceFolder, String sampleFolder) {
        this.sourceFolder = sourceFolder;
        this.templateFolder = templateFolder;
        this.sampleFolder = sampleFolder;
        this.ssl = "false";
        this.followRedirects = "false";
    }

    public ClassWriter(String templateFolder, String sourceFolder, String sampleFolder, boolean ssl, boolean followRedirects) {
        this.sourceFolder = sourceFolder;
        this.templateFolder = templateFolder;
        this.sampleFolder = sampleFolder;
        this.ssl = ssl ? "true" : "false";
        this.followRedirects = followRedirects ? "true" : "false";
    }

    public File[] getTemplateFiles() {

        File templateDir = new File(this.templateFolder);
        File[] containedFiles = templateDir.listFiles();

        List<File> templateFiles = new ArrayList<File>();
        for( File file : containedFiles ) {
            if( file.getName().matches("[a-zA-Z0-9]+Template.java") && !file.getName().equals("SampleTemplate.java") ) {
                templateFiles.add(file);
            }
        }

        return templateFiles.toArray(new File[templateFiles.size()]);
    }

    public void loadTemplate(String templateName) {
        loadTemplate(templateName, true);
    }

    public void loadTemplate(String templateName, boolean populateIntf) {

        String path = this.templateFolder + "/" + templateName;
        File sampleTemplate = new File(path);

        if( !sampleTemplate.exists() ) {
            Logger.eprintln("Error: '" + templateName + "' seems not to be contained in '" + this.templateFolder + "'.");
            Logger.eprintln("Stopping execution.");
            System.exit(1);
        }

        Logger.print("Reading template file: '" + path +  "'... ");
        try {

            this.template = new String(Files.readAllBytes(Paths.get(path)));

            if(populateIntf) {
                int interfaceIndex = this.template.indexOf("public interface");
                if( interfaceIndex < 0 ) {
                    Logger.eprintln("Error: '" + templateName + "' seems not to be a valid template file");
                    System.exit(1);
                }
                this.templateIntf = this.template.substring(interfaceIndex + 7);
            }
            Logger.printlnPlain("done");

        } catch( Exception e ) {
            Logger.printlnPlain("failed");
            Logger.eprintln("Error: unable to read template file.");
            Logger.eprint("The following exception was thrown: ");
            Logger.eprintln_ye(e.getMessage());
            System.exit(1);
        }
    }


    public String writeClass(String fullClassName) throws UnexpectedCharacterException{

        Security.checkPackageName(fullClassName);

        String[] components = splitNames(fullClassName);
        String packageName = components[0];
        String className = components[1];

        this.template = this.template.replace("<PACKAGENAME>", packageName);
        this.template = this.template.replace("<CLASSNAME>", className);

        String destination = this.sourceFolder + "/" + className + ".java";
        Logger.print("Writing class '" + destination + "' to disk... ");

        try {
            PrintWriter writer = new PrintWriter(destination, "UTF-8");
            writer.print(this.template);
            writer.close();
            Logger.printlnPlain("done.");

        } catch( Exception e ) {
            Logger.printlnPlain("failed.");
            Logger.eprintln("Error: Cannot open '" + destination + "'.");
            Logger.eprint("The following exception was thrown: ");
            Logger.eprintln_ye(e.getMessage());
            System.exit(1);
        }

        return destination;
    }


    public void prepareSample(String className, String boundName, Method method, String sampleClassName, String remoteHost, int remotePort) throws UnexpectedCharacterException{

        Security.checkBoundName(boundName);
        Security.checkAlphaNumeric(className);
        Security.checkAlphaNumeric(sampleClassName);

        this.loadTemplate("SampleTemplate.java", false);
        this.template += "\n" + this.templateIntf;

        this.sampleClassName = sampleClassName;
        String port = String.valueOf(remotePort);

        int numberOfArguments = method.getParameterCount();
        StringBuilder argumentString = new StringBuilder();
        Class<?>[] typeOfArguments = method.getParameterTypes();

        String argument = "";
        String placeholder = "<ARGUMENTTYPE> <ARGUMENT> = TODO;";

        for(int ctr = 0; ctr < numberOfArguments; ctr++) {
            argument = "argument" + ctr;
            this.template = this.template.replace(placeholder, placeholder + "\n            " + placeholder);
            this.template = this.template.replaceFirst("<ARGUMENTTYPE>", typeOfArguments[ctr].getName());
            this.template = this.template.replaceFirst("<ARGUMENT>", argument);
            argument += (ctr == numberOfArguments - 1) ? "" : ", ";
            argumentString.append(argument);
        }

        this.template = this.template.replace("\n            " + placeholder, "");
        Logger.print("Preparing sample... ");

        this.template = this.template.replace(  "<SAMPLECLASSNAME>",    sampleClassName);
        this.template = this.template.replace(  "<SSL>",          this.ssl);
        this.template = this.template.replace(  "<FOLLOW>",       this.followRedirects);
        this.template = this.template.replace(  "<REMOTEHOST>",   remoteHost);
        this.template = this.template.replace(  "<REMOTEPORT>",   port);
        this.template = this.template.replace(  "<BOUNDNAME>",    boundName);
        this.template = this.template.replace(  "<CLASSNAME>",    className);
        this.template = this.template.replace(  "<METHODNAME>",   method.getName());
        this.template = this.template.replace(  "<ARGUMENTS>",    argumentString.toString());

        String returnType = method.getReturnType().getName();

        if( returnType.equals("void") ) {
            this.template = this.template.replace("<RETURNTYPE> response = ", "");
            this.template = this.template.replace("System.out.println(\"[+] The servers response is: \" + response);", "");
        } else {
            this.template = this.template.replace("<RETURNTYPE>", returnType);
        }

        Logger.printlnPlain("done.");
    }


    public String writeSample() {

        String sampleDir = this.sampleFolder + "/" + this.sampleClassName;
        new File(sampleDir).mkdirs();

        String destination = sampleDir + "/" + this.sampleClassName + ".java";
        Logger.print("Writing sample '" + destination + "' to disk... ");

        try {
            PrintWriter writer = new PrintWriter(destination, "UTF-8");
            writer.print(template);
            writer.close();
            Logger.printlnPlain("done.");

        } catch( Exception e ) {
            Logger.printlnPlain("failed.");
            Logger.eprintln("Error: Cannot open '" + destination + "'.");
            Logger.eprint("The following exception was thrown: ");
            Logger.eprintln_ye(e.getMessage());
            System.exit(1);
        }

        return destination;
    }


    public static String[] splitNames(String fullName) {
        int index = fullName.lastIndexOf(".");
        String className = fullName.substring(index + 1, fullName.length());
        String packageName = fullName.substring(0, index);
        return new String[] { packageName, className };
    }
}
