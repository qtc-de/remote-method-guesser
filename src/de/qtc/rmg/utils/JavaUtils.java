package de.qtc.rmg.utils;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;

import de.qtc.rmg.io.Logger;

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

        Logger.print("Compiling file " + filename + "... ");

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

            Logger.printlnPlain("done.");

        } catch( Exception e ) {

            Logger.printlnPlain("failed.");
            Logger.eprintln("Error: During compile phase");
            Logger.eprint("Javac error stream: ");
            Logger.eprintlnPlain_ye(e.getMessage());
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
        Logger.print("Creating manifest for '" + outputFile + "... ");

        try {

            Security.checkPackageName(mainClass);
            PrintWriter writer = new PrintWriter(manifestPath, "UTF-8");
            String manifest = "Manifest-Version: 1.0\nMain-Class: de.qtc.rmg." + mainClass + "\n";
            writer.print(manifest);
            writer.close();
            Logger.printlnPlain("done.");

        } catch( IOException e ) {

            Logger.printlnPlain("failed.");
            Logger.eprintln("Error: Could not create file '" + manifestPath +"'.");
            System.exit(1);
        }

        Security.checkShellInjection(inFolder);
        Security.checkShellInjection(outputFile);

        try {
            Logger.print("Creating " + outputFile + "... ");
            String[] command = new String[] { this.jarPath, "-cvfm", outputFile, manifestPath, "-C", inFolder, "." };
            Process packer = Runtime.getRuntime().exec(command);
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

            Logger.printlnPlain("done.");

        } catch( Exception e ) {

            Logger.printlnPlain("failed.");
            Logger.eprintln("Error: During package phase");
            Logger.eprint("jar error stream: ");
            Logger.eprintlnPlain_ye(e.getMessage());
            System.exit(1);
        }
    }
}
