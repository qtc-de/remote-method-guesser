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
    public String buildFolder;
    public String outputFolder;

    public JavaUtils(String javacPath, String buildFolder, String outputFolder) {
        this.javacPath = javacPath;
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
}
