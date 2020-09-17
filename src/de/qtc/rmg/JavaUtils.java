package de.qtc.rmg;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;

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


    public void compile(String filename) {
        this.compile(filename, this.buildFolder);
    }


    public void compile(String filename, String destinationFolder) {

        Logger.print("[+]\t\tCompiling file " + filename + "... ");

        try {
            StringBuilder command = new StringBuilder(this.javacPath);
            command.append(" -cp " + destinationFolder);
            command.append(" -d " + destinationFolder);
            command.append(" " + filename);

            Process compiler = Runtime.getRuntime().exec(command.toString());
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

    public void packJar(String mainClass, String jarName) {
        this.packJar(this.buildFolder, this.outputFolder + "/" + jarName, mainClass);
    }


    public void packJar(String inFolder, String outputFile, String mainClass) {

        String manifestPath = inFolder + "/MANIFEST.MF";

        Logger.print("[+]\t\tCreating manifest for '" + outputFile + "... ");

        try {

            PrintWriter writer = new PrintWriter(manifestPath, "UTF-8");
            String manifest = "Manifest-Version: 1.0\nMain-Class: de.qtc.rmg." + mainClass + "\n";
            writer.print(manifest);
            writer.close();
            Logger.println("done.");

        } catch( Exception e ) {

            Logger.println("failed.");
            System.err.println("[-] Error: Cannot create '" + manifestPath);
            System.exit(1);

        }

        try {

            Logger.print("[+]\t\tCreating " + outputFile + "... ");
            StringBuilder command = new StringBuilder(this.jarPath);
            command.append(" -cvfm " + outputFile);
            command.append(" " + manifestPath);
            command.append(" -C " + inFolder);
            command.append(" .");

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


    public void clean() {

        try {

            Logger.print("[+] Removing '" + this.buildFolder + "' folder... ");
            Process cleanup = Runtime.getRuntime().exec("rm -r " + this.buildFolder);
            cleanup.waitFor();
            Logger.println("done.");

        } catch( Exception e ) {

            Logger.println("failed.");
            System.err.println("[-] Error during cleanup.");

        }

    }
}
