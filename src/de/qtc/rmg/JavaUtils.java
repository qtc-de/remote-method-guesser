package de.qtc.rmg;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.List;

public class JavaUtils {

    private String javacPath;
    private String jarPath;
    public String buildFolder;
    public String outputFolder;

    public JavaUtils(String javacPath, String jarPath, String buildFolder, String outputFolder) {
        this.javacPath = javacPath;
        this.jarPath = jarPath;
        this.buildFolder = buildFolder;
        this.outputFolder = outputFolder;
    }


    public void compile(String filename) throws FileNotFoundException, UnexpectedCharacterException {
        this.compile(filename, this.buildFolder);
    }


    public void compile(String filename, String destinationFolder) throws FileNotFoundException, UnexpectedCharacterException {

        Logger.print("[+]\t\tCompiling file " + filename + "... ");

        File tmpFile = new File(filename);
        File tmpFolder = new File(destinationFolder);

        if( !tmpFile.exists() ) {
            throw new FileNotFoundException("Required resource '" + tmpFile.getAbsolutePath() + "' does not exist.");
        }

        if( !tmpFolder.exists() ) {
            throw new FileNotFoundException("Required resource '" + tmpFolder.getAbsolutePath() + "' does not exist.");
        }

        Security.checkShellInjection(filename);
        Security.checkShellInjection(destinationFolder);

        try {
            String[] command = new String[] { this.javacPath, "-cp", destinationFolder, "-d", destinationFolder, filename };
            Process compiler = Runtime.getRuntime().exec(command);
            compiler.waitFor();

            if( compiler.exitValue() != 0 ) {
                BufferedReader stdErr = new BufferedReader(new InputStreamReader(compiler.getErrorStream()));
                StringBuilder error = new StringBuilder("");
                String line = "";
                while ((line = stdErr.readLine()) != null) {
                      error.append(line);
                }
                throw new Exception(error.toString());
             }

            Logger.println("done.");

        } catch( Exception e ) {

            Logger.println("failed.");
            System.err.println("[-] Error: During compile phase");
            System.err.println("[-] Javac error stream: " + e.getMessage());
            System.exit(1);
        }
    }


    public void packJar(String mainClass, String jarName) throws UnexpectedCharacterException {
        Security.checkJarFile(jarName);
        Security.checkPackageName(mainClass);
        this.packJar(this.buildFolder, this.outputFolder + "/" + jarName, mainClass);
    }


    public void packJar(String inFolder, String outputFile, String mainClass) throws UnexpectedCharacterException {

        String manifestPath = inFolder + "/MANIFEST.MF";
        Logger.print("[+]\t\tCreating manifest for '" + outputFile + "... ");

        try {

            Security.checkPackageName(mainClass);
            PrintWriter writer = new PrintWriter(manifestPath, "UTF-8");
            String manifest = "Manifest-Version: 1.0\nMain-Class: de.qtc.rmg." + mainClass + "\n";
            writer.print(manifest);
            writer.close();
            Logger.println("done.");

        } catch( IOException e ) {

            Logger.println("failed.");
            System.err.println("[-] Error: Cannot create '" + manifestPath);
            System.exit(1);
        }

        Security.checkShellInjection(inFolder);
        Security.checkShellInjection(outputFile);

        try {
            Logger.print("[+]\t\tCreating " + outputFile + "... ");
            String[] command = new String[] { this.jarPath, "-cvfm", outputFile, manifestPath, "-C", inFolder, "." };
            Process packer = Runtime.getRuntime().exec(command.toString());
            packer.waitFor();

            if( packer.exitValue() != 0 ) {

                BufferedReader stdErr = new BufferedReader(new InputStreamReader(packer.getErrorStream()));
                StringBuilder error = new StringBuilder("");
                String line = "";
                while ((line = stdErr.readLine()) != null) {
                  error.append(line);
                }
                throw new Exception(error.toString());
        }

            Logger.println("done.");

        } catch( Exception e ) {

            Logger.println("failed.");
            System.err.println("[-] Error: During package phase");
            System.err.println("[-] jar error stream: " + e.getMessage());
            System.exit(1);
        }
    }
}
