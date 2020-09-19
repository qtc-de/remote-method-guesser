package de.qtc.rmg;
        
import java.rmi.registry.Registry;
import java.rmi.registry.LocateRegistry;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.rmi.server.UnicastRemoteObject;
        
public class SslServer implements ISslServer {

    public String notRelevant() {
        /* A dummy method just to test the implementation */
        System.out.println("[+] \tSSL Server: Processing call for notRelevant()...");
        return "Some irrelevant text...";
    }


    public int execute(String command) {
        /* Dangerous method which executes a system command */
        System.out.println("[+] \tSSL Server: Processing call for 'int execute(String command)'...");
        
        try {
            Process p = java.lang.Runtime.getRuntime().exec(command);
            p.waitFor();
            return p.exitValue();
        }
        catch( Exception e) {}
        return -1;
    }


    public String system(String[] args) {
        /* Dangerous method which executes a system command */
        System.out.println("[+] \tSSL Server: Processing call for 'String system(String[] args)'...");

        StringBuilder result = new StringBuilder();
        try {
            Process p = java.lang.Runtime.getRuntime().exec(args);
            p.waitFor();

            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line = reader.readLine();

            while (line != null) {    
                System.out.println(line);
                result.append(line);
                line = reader.readLine();
            }

            reader = new BufferedReader(new InputStreamReader(p.getErrorStream()));
            line = reader.readLine();

            while (line != null) {    
                System.out.println("[+] \t\t" + line);
                result.append(line);
                line = reader.readLine();
            }
        }
        catch( Exception e) {}

        return result.toString();
    }
}
