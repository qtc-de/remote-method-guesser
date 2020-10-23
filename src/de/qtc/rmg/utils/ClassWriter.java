package de.qtc.rmg.utils;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.io.FileUtils;

import de.qtc.rmg.io.Logger;

public class ClassWriter {

    public String templateFolder;
    public String sourceFolder;
    public String sampleFolder;
    public String buildFolder;

    private String ssl;
    private String template;
    private String className;
    private String packageName;
    private String templateIntf;
    private String sampleClassName;
    private String followRedirects;

    public ClassWriter(String templateFolder, String sourceFolder, String sampleFolder, String buildFolder)
    {
        this.ssl = "false";
        this.followRedirects = "false";
        this.buildFolder = buildFolder;
        this.sourceFolder = sourceFolder;
        this.sampleFolder = sampleFolder;
        this.templateFolder = templateFolder;
    }

    public ClassWriter(String templateFolder, String sourceFolder, String sampleFolder, String buildFolder, boolean ssl, boolean followRedirects)
    {
        this.buildFolder = buildFolder;
        this.sampleFolder = sampleFolder;
        this.sourceFolder = sourceFolder;
        this.templateFolder = templateFolder;
        this.ssl = ssl ? "true" : "false";
        this.followRedirects = followRedirects ? "true" : "false";
    }

    public File[] getTemplateFiles()
    {
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

    public void loadTemplate(String templateName)
    {
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
            Logger.printlnPlain("done");

        } catch( Exception e ) {
            Logger.printlnPlain("failed");
            Logger.eprintln("Error: unable to read template file.");
            Logger.eprint("The following exception was thrown: ");
            Logger.eprintln_ye(e.getMessage());
            System.exit(1);
        }
    }


    public String writeClass(String fullClassName) throws UnexpectedCharacterException
    {
        Security.checkPackageName(fullClassName);

        String[] components = splitNames(fullClassName);
        String packageName = components[0];
        String className = components[1];

        this.template = this.template.replace("<PACKAGENAME>", packageName);
        this.template = this.template.replace("<CLASSNAME>", className);
        this.templateIntf = this.template;

        String destination = this.sourceFolder + "/" + className + ".java";
        Logger.print("Writing class '" + destination + "' to disk... ");
        writeFile(destination, this.template);

        return destination;
    }

    public void prepareSample(String packageName, String className, String boundName, Method method, String sampleClassName, String remoteHost, int remotePort) throws UnexpectedCharacterException
    {
        Security.checkBoundName(boundName);
        Security.checkClassName(className);
        Security.checkPackageName(packageName);
        Security.checkClassName(sampleClassName);

        this.loadTemplate("SampleTemplate.java");

        this.className = className;
        this.packageName = packageName;
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

        Logger.print("Preparing sample... ");

        this.template = this.template.replace("\n            " + placeholder, "");
        this.template = this.template.replace(  "<PACKAGE>",      packageName + "." + className);
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

    public void writeSample()
    {
        File sampleDir = new File(this.sampleFolder + File.separator + this.sampleClassName);
        sampleDir.mkdirs();

        try {
            String samplePath = sampleDir.getCanonicalPath();

            String destination = samplePath + File.separator + this.sampleClassName + ".java";
            Logger.print("Writing sample '" + destination + "' to disk... ");
            writeFile(destination, this.template);

            destination = samplePath + File.separator + this.className + ".java";
            Logger.print("Writing sample interface '" + destination + "' to disk... ");
            writeFile(destination, this.templateIntf);

            String packagePath = this.packageName.replace(".", File.separator);
            File interfaceFile = new File(this.buildFolder + File.separator + packagePath + File.separator + this.className + ".class");

            if( !interfaceFile.exists() ) {
                Logger.printlnPlain("failed.");
                Logger.eprint("Unable to find compiled interface at: ");
                Logger.eprintln_ye(interfaceFile.getCanonicalPath());
                return;
            }

            sampleDir = new File(samplePath + File.separator + packagePath);
            sampleDir.mkdirs();
            FileUtils.copyFileToDirectory(interfaceFile, sampleDir);

        } catch( IOException e ) {
            Logger.printlnPlain("failed.");
            Logger.eprint("The following exception was thrown: ");
            Logger.eprintln_ye(e.getMessage());
            System.exit(1);
        }
    }

    public static String[] splitNames(String fullName)
    {
        int index = fullName.lastIndexOf(".");
        String className = fullName.substring(index + 1, fullName.length());
        String packageName = fullName.substring(0, index);
        return new String[] { packageName, className };
    }

    private static void writeFile(String destination, String content)
    {
        try {
            PrintWriter writer = new PrintWriter(destination, "UTF-8");
            writer.print(content);
            writer.close();
            Logger.printlnPlain("done.");

        } catch( Exception e ) {
            Logger.printlnPlain("failed.");
            Logger.eprintln("Error: Cannot open '" + destination + "'.");
            Logger.eprint("The following exception was thrown: ");
            Logger.eprintln_ye(e.getMessage());
            System.exit(1);
        }

    }
}
