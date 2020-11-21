package de.qtc.rmg.utils;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

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
            Logger.println("");
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

        return new String(Files.readAllBytes(templateFile.toPath()));
    }

    public void writeSample(String sampleFolder, String sampleName, String sampleContent) throws UnexpectedCharacterException, IOException
    {
        writeSample(sampleFolder, sampleName, sampleContent, null);
    }

    public void writeSample(String sampleFolder, String sampleName, String sampleContent, String subfolder) throws UnexpectedCharacterException, IOException
    {
        Security.checkAlphaNumeric(sampleName);
        Security.checkAlphaNumeric(sampleFolder);

        File destinationFolder = new File(this.sampleFolder, sampleFolder);
        if( subfolder != null ) {
            destinationFolder = new File(destinationFolder, subfolder);
        }
        destinationFolder.mkdirs();

        sampleName = sampleName + ".java";
        File sampleFile = new File(destinationFolder, sampleName);

        Logger.printlnMixedBlue("Writing sample file", sampleFile.getCanonicalPath());

        PrintWriter writer = new PrintWriter(sampleFile, "UTF-8");
        writer.print(sampleContent);
        writer.close();
    }

    public void createSamples(String boundName, String className, List<MethodCandidate> methods, RMIWhisperer rmi) throws UnexpectedCharacterException, NotFoundException, IOException, CannotCompileException
    {
        for(MethodCandidate method : methods) {
            createSample(className, boundName, method, rmi.host, rmi.port);
        }
    }

    public void createSample(String className, String boundName, MethodCandidate method, String remoteHost, int remotePort) throws UnexpectedCharacterException, NotFoundException, IOException, CannotCompileException
    {
        Security.checkBoundName(boundName);
        Security.checkPackageName(className);

        String template = loadTemplate("SampleTemplate.java");
        String port = String.valueOf(remotePort);

        CtClass[] types = method.getParameterTypes();
        int numberOfArguments = types.length;

        String typeName;
        String importPlaceholder = "import <IMPORT>;";
        List<String> typeList = new ArrayList<String>();

        for(CtClass type : types) {

            typeName = type.getName();
            if( typeName.contains(".") && !typeName.startsWith("java.lang") && !typeList.contains(typeName)) {
                typeList.add(typeName);
                template = template.replace(importPlaceholder, importPlaceholder + "\n" + importPlaceholder);
                template = template.replaceFirst("<IMPORT>", typeName);
            }
        }

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
        String sampleClassName = method.getName();

        template = template.replace(importPlaceholder, "");
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

        writeSample(boundName, sampleClassName, template, sampleClassName);
    }

    public void createInterfaceSample(String boundName, String className, List<MethodCandidate> methods) throws UnexpectedCharacterException, IOException, CannotCompileException, NotFoundException
    {
        Security.checkPackageName(className);
        String template = loadTemplate("InterfaceTemplate.java");

        String typeName;
        List<String> types = new ArrayList<String>();

        String importPlaceholder = "import <IMPORT>;";
        String methodPlaceholder = "    <METHOD> throws RemoteException;";

        for(MethodCandidate method : methods) {
            template = template.replaceFirst(methodPlaceholder, methodPlaceholder + "\n" + methodPlaceholder);
            template = template.replaceFirst("<METHOD>", method.getSignature());

            for(CtClass type : method.getParameterTypes()) {

                typeName = type.getName();
                if( typeName.contains(".") && !typeName.startsWith("java.lang") && !types.contains(typeName)) {
                    types.add(typeName);
                    template = template.replace(importPlaceholder, importPlaceholder + "\n" + importPlaceholder);
                    template = template.replaceFirst("<IMPORT>", typeName);
                }
            }
        }

        template = template.replace(importPlaceholder, "");
        template = template.replace(methodPlaceholder, "");

        String packageName = getPackageName(className);
        className = getClassName(className);

        template = template.replace("<PACKAGENAME>", packageName);
        template = template.replace("<CLASSNAME>", className);
        template = template.replace("<METHOD>", className);

        writeSample(boundName, className, template);
    }

    private static String getClassName(String fullName)
    {
        int index = fullName.lastIndexOf(".");
        String className = fullName.substring(index + 1, fullName.length());
        return className;
    }

    private static String getPackageName(String fullName)
    {
        int index = fullName.lastIndexOf(".");
        String packageName = fullName.substring(0, index);
        return packageName;
    }

}
