package de.qtc.rmg.io;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.io.IOUtils;

import de.qtc.rmg.exceptions.UnexpectedCharacterException;
import de.qtc.rmg.internal.MethodCandidate;
import de.qtc.rmg.networking.RMIEndpoint;
import de.qtc.rmg.utils.RMGUtils;
import de.qtc.rmg.utils.Security;
import javassist.CannotCompileException;
import javassist.CtClass;
import javassist.CtMethod;
import javassist.CtPrimitiveType;
import javassist.NotFoundException;

/**
 * The SampleWriter class handles the dynamic creation of RMI code. It uses samples defined within the template folder
 * of the project and replaces some place holders that are defined within them. The result should be compilable Java
 * code that can be used to perform RMI operations.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class SampleWriter {

    private String ssl;
    private String followRedirects;

    private File sampleFolder;
    private String templateFolder;

    private static String importPlaceholder = "import <IMPORT>;";
    private static String methodPlaceholder = "    <METHOD> throws RemoteException;";
    private static String argumentPlaceholder = "            <ARGUMENTTYPE> <ARGUMENT> = TODO;";

    /**
     * Creates a SmapleWriter object. During the creation, a samples folder may be generated if not
     * already present. If the specified template folder is null or empty, rmg defaults to use it's
     * internal template folder that is packed into the JAR file.
     *
     * @param templateFolder folder where template files are stored
     * @param sampleFolder folder where created samples should be created
     * @param ssl whether the targeted RMI endpoint uses ssl on the registry
     * @param followRedirects whether redirects of remote objects should be followed
     * @throws IOException may be thrown when one of the required folders is not present
     */
    public SampleWriter(String templateFolder, String sampleFolder, boolean ssl, boolean followRedirects) throws IOException
    {
        this.ssl = ssl ? "true" : "false";
        this.followRedirects = followRedirects ? "true" : "false";

        this.templateFolder = templateFolder;
        this.sampleFolder = new File(sampleFolder);

        if( !this.sampleFolder.exists() ) {
            Logger.printlnMixedBlue("Sample folder", this.sampleFolder.getCanonicalPath(), "does not exist.");
            Logger.println("Creating sample folder.");
            Logger.lineBreak();
            this.sampleFolder.mkdirs();
        }
    }

    /**
     * Reads a template from the template folder and returns the corresponding content. Depending
     * on the contents of this.templateFolder, an external template folder or the internal from the
     * JAR file is used.
     *
     * @param templateName name of the template file
     * @return template content
     * @throws IOException is thrown when an IO operation fails.
     */
    public String loadTemplate(String templateName) throws IOException
    {
        if(this.templateFolder != null && this.templateFolder.isEmpty())
            return loadTemplateStream(templateName);

        else
            return loadTemplateFile(templateName);
    }

    /**
     * Reads a template file form the internal template folder and returns it's contents. As the
     * internal template folder is contained within the JAR file, getResourceAsStream is used to
     * load the template.
     *
     * @param templateName name of the template file
     * @return template content
     * @throws IOException is thrown when an IO operation fails.
     */
    public String loadTemplateStream(String templateName) throws IOException
    {
        InputStream stream = this.getClass().getResourceAsStream("/resources/templates/" + templateName);
        byte[] content = IOUtils.toByteArray(stream);
        stream.close();
        return new String(content);
    }

    /**
     * Reads a template from the template folder and returns the corresponding content. This function is
     * called when external template folders are used.
     *
     * @param templateName name of the template file
     * @return template content
     * @throws IOException is thrown when an IO operation fails.
     */
    public String loadTemplateFile(String templateName) throws IOException
    {
        File templateFile = new File(this.templateFolder, templateName);
        String canonicalPath = templateFile.getCanonicalPath();

        if( !templateFile.exists() ) {
            Logger.eprintlnMixedYellow("Template file", canonicalPath, "does not exist.");
            RMGUtils.exit();
        }

        return new String(Files.readAllBytes(templateFile.toPath()));
    }

    /**
     * Wrapper around writeSamples with additional subfolder argument.
     */
    public void writeSample(String sampleFolder, String sampleName, String sampleContent) throws UnexpectedCharacterException, IOException
    {
        writeSample(sampleFolder, sampleName, sampleContent, null);
    }

    /**
     * Writes a sample file into the sample folder. Performs basic security checks on the filenames.
     *
     * @param sampleFolder sub folder within the sample folder to write the files in.
     * @param sampleName name of the sample file
     * @param sampleContent content of the sample file
     * @param subfolder sub folder within the sub folder of the sample folder
     * @throws UnexpectedCharacterException is thrown if the filenames are violating the security settings
     * @throws IOException is thrown if an IO operation fails
     */
    public void writeSample(String sampleFolder, String sampleName, String sampleContent, String subfolder) throws UnexpectedCharacterException, IOException
    {
        Security.checkAlphaNumeric(sampleName);
        Security.checkAlphaNumeric(sampleFolder);

        if(subfolder != null)
            Security.checkAlphaNumeric(subfolder);

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

    /**
     * Creates samples for a bound name and the corresponding available remote methods.
     *
     * @param boundName bound name to create the sample for
     * @param className underlying class name of the corresponding bound name (usually an interface)
     * @param methods available remote methods represented by MethodCandidates
     * @param rmi RMIEndpoint to the currently targeted RMI endpoint
     * @throws UnexpectedCharacterException is thrown if class or bound names violate the security policies
     * @throws NotFoundException should not occur
     * @throws IOException if an IO operation fails
     * @throws CannotCompileException should not occur
     */
    public void createSamples(String boundName, String className, boolean unknownClass, List<MethodCandidate> methods, RMIEndpoint rmi) throws UnexpectedCharacterException, NotFoundException, IOException, CannotCompileException
    {
        for(MethodCandidate method : methods) {
            createSample(className, unknownClass, boundName, method, rmi.host, rmi.port);
        }
    }

    /**
     * Creates a sample to invoke the specified MethodCandidate on the specified remoteHost. Creating the sample
     * is basically an ugly find an replace over the template files.
     *
     * @param className class name of the remote interface or the RMI stub (if legacy is used)
     * @param boundName bound name where the corresponding class name is available
     * @param method MethodCandidate to create the sample for
     * @param remoteHost currently targeted RMI host
     * @param remotePort currently targeted RMI registry port
     * @throws UnexpectedCharacterException is thrown if bound names or class names violate security policies
     * @throws NotFoundException should not occur
     * @throws IOException if an IO operation fails
     * @throws CannotCompileException should not occur
     */
    public void createSample(String className, boolean unknownClass, String boundName, MethodCandidate method, String remoteHost, int remotePort) throws UnexpectedCharacterException, NotFoundException, IOException, CannotCompileException
    {
        if(className.endsWith("_Stub") && unknownClass)
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

    /**
     * Creates an interface file for the remote method call. In the case of currently used RMI techniques (proxy invocation)
     * an interface file is sufficient. For legacy RMI we also need to create the Java code for the corresponding stub object.
     *
     * @param boundName targeted bound name
     * @param className class name of the remote interface or stub
     * @param methods MethodCandidates that should be part of the interface
     * @throws UnexpectedCharacterException is thrown if bound names or class names violate security policies
     * @throws IOException if an IO operation fails
     * @throws CannotCompileException should never occur
     * @throws NotFoundException should never occur
     */
    public void createInterface(String boundName, String className, List<MethodCandidate> methods) throws UnexpectedCharacterException, IOException, CannotCompileException, NotFoundException
    {
        if(className.endsWith("_Stub")) {
            createInterfaceSample(boundName, className + "_Interface", methods);
            createLegacyStub(boundName, className, methods);
        } else {
            createInterfaceSample(boundName, className, methods);
        }
    }

    /**
     * Create Java code for an remote interface. This interface extends Remote and contains all specified MethodCandidates.
     *
     * @param boundName targeted bound name (only used for the file name)
     * @param className class name of the remote interface
     * @param methods MethodCandidates that should be included
     * @throws UnexpectedCharacterException is thrown if bound or class names violate the security policies
     * @throws IOException if an IO operation fails
     * @throws CannotCompileException should never occur
     * @throws NotFoundException should never occur
     */
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

    /**
     * Creates Java code for a legacy Stub object. These code samples are a little bit harder to create,
     * as each remote method needs to be hardcoded into the corresponding stub object. Theoretically, you
     * could also create this stub code using rmic, but rmic is no longer shipped with current Java releases.
     * When facing a legacy RMI server and only having e.g. Java11 installed, this method can be handy to
     * create the corresponding stub code.
     *
     * @param boundName currently targeted bound name
     * @param className class name of the remote stub
     * @param methods MethodCandidates that should be included
     * @throws UnexpectedCharacterException is thrown when bound or class names violate the security policies
     * @throws IOException if an IO operation fails
     * @throws CannotCompileException should never occur
     * @throws NotFoundException should never occur
     */
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

            if( ctr != 0 ) {
                arguments.setLength(arguments.length() - 2);
                argumentArray.setLength(argumentArray.length() - 2);
            }

            methodLookup.setLength(methodLookup.length() - 2);
            methodLookup.append(");");

            String methodVariable = "method_" + count;
            stubTemplate = stubTemplate.replaceFirst("<METHOD_VAR>", "private static Method " + methodVariable + ";");
            stubTemplate = stubTemplate.replaceFirst("<METHOD_LOOKUP>", methodVariable + " = " + methodLookup);

            currentTemplate = currentTemplate.replaceFirst("<METHODNAME>", method.getName());
            currentTemplate = currentTemplate.replaceFirst("<ARGUMENTS>", arguments.toString());
            currentTemplate = currentTemplate.replaceFirst("<ARGUMENT_ARRAY>", argumentArray.toString());
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

    /**
     * Takes a full qualified class name and returns only the actual class name.
     *
     * @param fullName full qualified class name
     * @return simple class name
     */
    private static String getClassName(String fullName)
    {
        int index = fullName.lastIndexOf(".");
        String className = fullName.substring(index + 1, fullName.length());
        return className;
    }

    /**
     * Takes a full qualified class name and returns only the package name.
     *
     * @param fullName full qualified class name
     * @return package name
     */
    private static String getPackageName(String fullName)
    {
        int index = fullName.lastIndexOf(".");
        String packageName = fullName.substring(0, index);
        return packageName;
    }

    /**
     * Takes a String representing a template and a expression that should be matched.
     * Duplicates the expression within the corresponding template (if found).
     *
     * @param template content of a template file
     * @param match expression to look for
     * @return modified template
     */
    private static String duplicate(String template, String match)
    {
        return template.replace(match, match + "\n" + match);
    }

    /**
     * Removes an expression from the specified template content.
     *
     * @param template content of a template file
     * @param match expression to look for
     * @return modified template
     */
    private static String remove(String template, String match)
    {
        return template.replace(match, "");
    }

    /**
     * Takes the content of a template, a type name and a list of type names. Checks whether
     * type is contained in type list. If not, duplicates the import statement of the template
     * and transforms one of the duplicated statements in an import for the corresponding type.
     * Finally, adds the type to the type list.
     *
     * @param template content of a template file
     * @param typeName name of the type to import
     * @param types names of already important types
     * @return modified template
     */
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
