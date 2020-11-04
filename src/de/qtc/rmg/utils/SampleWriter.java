package de.qtc.rmg.utils;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;

import de.qtc.rmg.exceptions.UnexpectedCharacterException;
import de.qtc.rmg.internal.MethodCandidate;
import de.qtc.rmg.io.Logger;
import javassist.CannotCompileException;
import javassist.CtClass;
import javassist.NotFoundException;

public class SampleWriter {

    private String ssl;
    private String followRedirects;

    private File sampleFolder;
    private File templateFolder;

    public SampleWriter(String templateFolder, String sampleFolder, boolean ssl, boolean followRedirects) throws IOException
    {
        this.ssl = ssl ? "true" : "false";
        this.followRedirects = followRedirects ? "true" : "false";

        this.sampleFolder = new File(sampleFolder);
        this.templateFolder = new File(templateFolder);

        if( !this.templateFolder.exists() ) {
            Logger.eprintlnMixedYellow("Template folder", this.templateFolder.getCanonicalPath(), "does not exist.");
            RMGUtils.exit();
        }

        if( !this.sampleFolder.exists() ) {
            Logger.printlnMixedBlue("Sample folder", this.sampleFolder.getCanonicalPath(), "does not exist.");
            Logger.println("Creating sample folder.");
            this.sampleFolder.mkdirs();
        }
    }

    public String loadTemplate(String templateName) throws IOException
    {
        File templateFile = new File(this.templateFolder, templateName);
        String canonicalPath = templateFile.getCanonicalPath();

        if( !templateFile.exists() ) {
            Logger.eprintlnMixedYellow("Template file", canonicalPath, "was not found in the template folder.");
            RMGUtils.exit();
        }

        Logger.printlnMixedBlue("Reading template file:", canonicalPath, "...");
        return new String(Files.readAllBytes(templateFile.toPath()));
    }

    public void writeSample(String sampleName, String sampleContent) throws UnexpectedCharacterException, IOException
    {
        Security.checkAlphaNumeric(sampleName);
        sampleName = sampleName + ".java";
        File destination = new File(this.templateFolder, sampleName);

        Logger.printlnMixedBlue("Writing sample file", destination.getCanonicalPath(), ".");

        PrintWriter writer = new PrintWriter(destination, "UTF-8");
        writer.print(sampleContent);
        writer.close();
    }

    public void createSample(String className, String boundName, MethodCandidate method, String remoteHost, int remotePort) throws UnexpectedCharacterException, NotFoundException, IOException, CannotCompileException
    {
        Logger.printlnMixedBlue("Preparing sample for", boundName + ":" + className, ".");

        Security.checkBoundName(boundName);
        Security.checkPackageName(className);
        Security.checkAlphaNumeric(className);

        String template = loadTemplate("SampleTemplate.java");
        String port = String.valueOf(remotePort);

        method = new MethodCandidate(method.getSignature());
        CtClass[] types = method.getMethod().getParameterTypes();
        int numberOfArguments = types.length;

        String argument = "";
        StringBuilder argumentString = new StringBuilder();
        String placeholder = "<ARGUMENTTYPE> <ARGUMENT> = TODO;";

        for(int ctr = 0; ctr < numberOfArguments; ctr++) {
            argument = "argument" + ctr;
            template = template.replace(placeholder, placeholder + "\n            " + placeholder);
            template = template.replaceFirst("<ARGUMENTTYPE>", types[ctr].getName());
            template = template.replaceFirst("<ARGUMENT>", argument);
            argument += (ctr == numberOfArguments - 1) ? "" : ", ";
            argumentString.append(argument);
        }

        String pureClassName = getClassName(className);
        String sampleClassName = pureClassName + "_Sample";

        template = template.replace("\n            " + placeholder, "");
        template = template.replace(  "<PACKAGE>",                  className);
        template = template.replace(  "<SAMPLECLASSNAME>",            sampleClassName);
        template = template.replace(  "<SSL>",                      this.ssl);
        template = template.replace(  "<FOLLOW>",                   this.followRedirects);
        template = template.replace(  "<REMOTEHOST>",               remoteHost);
        template = template.replace(  "<REMOTEPORT>",               port);
        template = template.replace(  "<BOUNDNAME>",                boundName);
        template = template.replace(  "<CLASSNAME>",                pureClassName);
        template = template.replace(  "<METHODNAME>",               method.getMethod().getName());
        template = template.replace(  "<ARGUMENTS>",                argumentString.toString());

        String returnType = method.getMethod().getReturnType().getName();

        if( returnType.equals("void") ) {
            template = template.replace("<RETURNTYPE> response = ", "");
            template = template.replace("System.out.println(\"[+] The servers response is: \" + response);", "");
        } else {
            template = template.replace("<RETURNTYPE>", returnType);
        }

        writeSample(sampleClassName, template);
    }

    private static String getClassName(String fullName)
    {
        int index = fullName.lastIndexOf(".");
        String className = fullName.substring(index + 1, fullName.length());
        return className;
    }

}
