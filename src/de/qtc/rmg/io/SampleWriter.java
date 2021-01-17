package de.qtc.rmg.io;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

import de.qtc.rmg.exceptions.UnexpectedCharacterException;
import de.qtc.rmg.internal.MethodCandidate;
import de.qtc.rmg.networking.RMIWhisperer;
import de.qtc.rmg.utils.RMGUtils;
import de.qtc.rmg.utils.Security;
import javassist.CannotCompileException;
import javassist.CtClass;
import javassist.CtMethod;
import javassist.CtPrimitiveType;
import javassist.NotFoundException;

public class SampleWriter {

    private int legacyMode;

    private String ssl;
    private String followRedirects;

    private File sampleFolder;
    private File templateFolder;

    private static String importPlaceholder = "import <IMPORT>;";
    private static String methodPlaceholder = "    <METHOD> throws RemoteException;";
    private static String argumentPlaceholder = "            <ARGUMENTTYPE> <ARGUMENT> = TODO;";

    public SampleWriter(String templateFolder, String sampleFolder, boolean ssl, boolean followRedirects, int legacyMode) throws IOException
    {
        this.legacyMode = legacyMode;

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
        boolean isLegacy = RMGUtils.isLegacy(className, legacyMode, false);
        if(isLegacy)
            className += "_Interface";

        Security.checkBoundName(boundName);
        Security.checkPackageName(className);

        String template = loadTemplate("SampleTemplate.java");
        String port = String.valueOf(remotePort);

        CtClass returnType = method.getMethod().getReturnType();
        CtClass[] types = method.getParameterTypes();
        int numberOfArguments = types.length;

        List<String> typeList = new ArrayList<String>();
        template = addImport(template, returnType.getName(), typeList);

        String argument = "";
        StringBuilder argumentString = new StringBuilder();

        for(int ctr = 0; ctr < numberOfArguments; ctr++) {
            template = addImport(template, types[ctr].getName(), typeList);
            argument = "argument" + ctr;

            template = duplicate(template, argumentPlaceholder);
            template = template.replaceFirst("<ARGUMENTTYPE>", types[ctr].getName());
            template = template.replaceFirst("<ARGUMENT>", argument);

            argument += (ctr == numberOfArguments - 1) ? "" : ", ";
            argumentString.append(argument);
        }

        template = remove(template, importPlaceholder);
        template = remove(template, argumentPlaceholder);
        String pureClassName = getClassName(className);
        String sampleClassName = method.getName();

        template = template.replace("<PACKAGE>", className);
        template = template.replace("<SAMPLECLASSNAME>", sampleClassName);
        template = template.replace("<SSL>", this.ssl);
        template = template.replace("<FOLLOW>", this.followRedirects);
        template = template.replace("<REMOTEHOST>", remoteHost);
        template = template.replace("<REMOTEPORT>", port);
        template = template.replace("<BOUNDNAME>", boundName);
        template = template.replace("<CLASSNAME>", pureClassName);
        template = template.replace("<METHODNAME>", method.getMethod().getName());
        template = template.replace("<ARGUMENTS>", argumentString.toString());

        if( returnType.getName().equals("void") ) {
            template = remove(template, "<RETURNTYPE> response = ");
            template = remove(template, "System.out.println(\"[+] The servers response is: \" + response);");
        } else {
            template = template.replace("<RETURNTYPE>", returnType.getName());
        }

        writeSample(boundName, sampleClassName, template, sampleClassName);
    }

    public void createInterface(String boundName, String className, List<MethodCandidate> methods) throws UnexpectedCharacterException, IOException, CannotCompileException, NotFoundException
    {
        boolean isLegacy = RMGUtils.isLegacy(className, legacyMode, false);

        if(isLegacy) {
            createInterfaceSample(boundName, className + "_Interface", methods);
            createLegacyStub(boundName, className, methods);
        } else {
            createInterfaceSample(boundName, className, methods);
        }
    }

    public void createInterfaceSample(String boundName, String className, List<MethodCandidate> methods) throws UnexpectedCharacterException, IOException, CannotCompileException, NotFoundException
    {
        Security.checkPackageName(className);
        String template = loadTemplate("InterfaceTemplate.java");

        for(MethodCandidate method : methods) {
            template = duplicate(template, methodPlaceholder);
            template = template.replaceFirst("<METHOD>", method.getSignature());

            List<String> types = new ArrayList<String>();
            CtClass returnType = method.getMethod().getReturnType();
            template = addImport(template, returnType.getName(), types);

            for(CtClass type : method.getParameterTypes()) {
                template = addImport(template, type.getName(), types);
            }
        }

        template = remove(template, importPlaceholder);
        template = remove(template, methodPlaceholder);

        String packageName = getPackageName(className);
        className = getClassName(className);

        template = template.replace("<PACKAGENAME>", packageName);
        template = template.replace("<CLASSNAME>", className);

        writeSample(boundName, className, template);
    }

    public void createLegacyStub(String boundName, String className, List<MethodCandidate> methods) throws UnexpectedCharacterException, IOException, CannotCompileException, NotFoundException
    {
        Security.checkPackageName(className);
        String stubTemplate = loadTemplate("LegacyTemplate.java");
        String methodTemplate = loadTemplate("LegacyMethodTemplate.java");

        int count = 0;
        String argName;
        String castPlaceholder = "            return (<CAST>)object;";
        String methodPlaceholder = "    <METHOD>";
        String methodVarPlaceholder = "    <METHOD_VAR>";
        String methodLookupPlaceholder = "            <METHOD_LOOKUP>";
        List<String> types = new ArrayList<String>();

        for(MethodCandidate method : methods) {

            CtMethod current = method.getMethod();
            CtClass returnType = current.getReturnType();
            CtClass[] parameterTypes = current.getParameterTypes();

            String currentTemplate = methodTemplate;
            stubTemplate = duplicate(stubTemplate, methodPlaceholder);
            stubTemplate = duplicate(stubTemplate, methodVarPlaceholder);
            stubTemplate = duplicate(stubTemplate, methodLookupPlaceholder);

            if( returnType != CtPrimitiveType.voidType) {
                stubTemplate = addImport(stubTemplate, returnType.getName(), types);
                currentTemplate = currentTemplate.replaceFirst("<CAST>", RMGUtils.getCast(returnType));
            } else {
                currentTemplate = remove(currentTemplate, castPlaceholder);
            }

            int ctr = 0;
            StringBuilder arguments = new StringBuilder();
            StringBuilder argumentArray = new StringBuilder();
            StringBuilder methodLookup = new StringBuilder();
            methodLookup.append("intf.getMethod(\"" + method.getName() + "\", ");

            for(CtClass type : parameterTypes) {

                stubTemplate = addImport(stubTemplate, type.getName(), types);
                argName = "arg_" + ctr;

                arguments.append(type.getName() + " " + argName + ", ");
                argumentArray.append(RMGUtils.getSampleArgument(type, argName) + ", ");
                methodLookup.append(RMGUtils.getTypeString(type) + ", ");

                ctr += 1;
            }

            methodLookup.setLength(methodLookup.length() - 2);
            methodLookup.append(");");

            String methodVariable = "method_" + count;
            stubTemplate = stubTemplate.replaceFirst("<METHOD_VAR>", "private static Method " + methodVariable + ";");
            stubTemplate = stubTemplate.replaceFirst("<METHOD_LOOKUP>", methodVariable + " = " + methodLookup);

            currentTemplate = currentTemplate.replaceFirst("<METHODNAME>", method.getName());
            currentTemplate = currentTemplate.replaceFirst("<ARGUMENTS>", arguments.substring(0, arguments.length() - 2));
            currentTemplate = currentTemplate.replaceFirst("<ARGUMENT_ARRAY>", argumentArray.substring(0, argumentArray.length() - 2));
            currentTemplate = currentTemplate.replaceFirst("<HASH>", Long.toString(method.getHash()));
            currentTemplate = currentTemplate.replaceFirst("<RETURN>", returnType.getName());
            currentTemplate = currentTemplate.replaceFirst("<METHOD>", methodVariable);
            stubTemplate = stubTemplate.replaceFirst(methodPlaceholder, currentTemplate);

            count += 1;
        }

        stubTemplate = remove(stubTemplate, importPlaceholder);
        stubTemplate = remove(stubTemplate, methodPlaceholder);
        stubTemplate = remove(stubTemplate, methodLookupPlaceholder);
        stubTemplate = remove(stubTemplate, methodVarPlaceholder);

        String packageName = getPackageName(className);
        String pureClassName = getClassName(className);

        stubTemplate = stubTemplate.replace("<PACKAGE>", packageName);
        stubTemplate = stubTemplate.replace("<INTERFACE_IMPORT>", className + "_Interface");
        stubTemplate = stubTemplate.replace("<CLASSNAME>", pureClassName);
        stubTemplate = stubTemplate.replace("<INTERFACE>", pureClassName + "_Interface");
        stubTemplate = stubTemplate.replace("<METHOD>", className);

        writeSample(boundName, pureClassName, stubTemplate);
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

    private static String duplicate(String template, String match)
    {
        return template.replace(match, match + "\n" + match);
    }

    private static String remove(String template, String match)
    {
        return template.replace(match, "");
    }

    private static String addImport(String template, String typeName, List<String> types)
    {
        if( typeName.contains(".") && !typeName.startsWith("java.lang") && !types.contains(typeName)) {
            types.add(typeName);
            template = duplicate(template, importPlaceholder);
            template = template.replaceFirst("<IMPORT>", typeName);
        }

        return template;
    }
}
