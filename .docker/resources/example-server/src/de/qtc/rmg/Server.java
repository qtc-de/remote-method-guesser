package de.qtc.rmg.testserver;
        
import java.rmi.registry.Registry;
import java.rmi.registry.LocateRegistry;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.rmi.server.UnicastRemoteObject;
        

/*
 * This class implements the Java RMI IServer interface which contains some 
 * vulnerable methods. The exposed RMI Interface by the Server class
 * can be engaged using rmidumper to verify that everything works like
 * expected.
*/
public class Server implements IServer {

    private static String registryName = "SuperCoolServer";
        
    public Server() {}

    public String notRelevant() {
        /* A dummy method just to test the implementation */
        System.out.println("[+] \tProcessing call for notRelevant()...");
        return "Some irrelevant text...";
    }


    public String execute(String command) {
        /* Dangerous method which executes a system command */
        System.out.println("[+] \tProcessing call for 'String execute(String command)'...");

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
        System.out.println("[+] \tProcessing call for 'String system(String command, String[] args)'...");

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
        

    public static void main(String args[]) {
        /* Bind Server to the RMI Registry */
        try {
            System.out.print("[+] Creating Server object... ");
            Server obj = new Server();
            IServer stub = (IServer)UnicastRemoteObject.exportObject(obj, 0);
            System.out.println("done.");
            
            System.out.print("[+] Binding Server as '" + registryName + "'... ");
            Registry registry = LocateRegistry.getRegistry();
            registry.bind(registryName, stub);
            System.out.println("done.");
            
            System.err.println("[+] Server ready");
             
        } catch (Exception e) {
            System.err.println("failed.");
            System.err.println("[-] Server exception: " + e.toString());
        }
    }
}
