package de.qtc.rmg;
        
import java.rmi.registry.Registry;
import java.rmi.registry.LocateRegistry;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.rmi.server.UnicastRemoteObject;
        
public class PlainServer implements IPlainServer {

    public String notRelevant() {
        /* A dummy method just to test the implementation */
        System.out.println("[+] \tPlain Server: Processing call for notRelevant()...");
        return "Some irrelevant text...";
    }

    public String execute(String command) {
        /* Dangerous method which executes a system command */
        System.out.println("[+] \tPlain Server: Processing call for 'String execute(String command)'...");

        StringBuilder result = new StringBuilder();
        try {
            Process p = java.lang.Runtime.getRuntime().exec(command);
            p.waitFor();

            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line = reader.readLine();

            while (line != null) {    
                System.out.println("[+] \t\t" + line);
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


    public String system(String command, String[] args) {
        /* Dangerous method which executes a system command */
        System.out.println("[+] \tPlain Server: Processing call for 'String system(String command, String[] args)'...");

        StringBuilder result = new StringBuilder();
         
        String[] commandArray = new String[args.length + 1];
        commandArray[0] = command;
        System.arraycopy(args, 0, commandArray, 1, args.length);

        try {
            Process p = java.lang.Runtime.getRuntime().exec(commandArray);
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
