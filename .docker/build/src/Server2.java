package de.qtc.rmg.testserver;
        
import java.rmi.registry.Registry;
import java.rmi.registry.LocateRegistry;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.rmi.server.UnicastRemoteObject;
        

/*
 * This class implements the Java RMI IServer2 interface which contains some 
 * vulnerable methods. The exposed RMI Interface by the Server class
 * can be engaged using rmidumper to verify that everything works like
 * expected.
*/
public class Server2 implements IServer2 {

    private static String registryName = "AnotherSuperCoolServer";
        
    public Server2() {}

    public String notRelevant() {
        /* A dummy method just to test the implementation */
        System.out.println("[+] \tProcessing call for notRelevant()...");
        return "Some irrelevant text...";
    }


    public int execute(String command) {
        /* Dangerous method which executes a system command */
        System.out.println("[+] \tProcessing call for 'int execute(String command)'...");

        StringBuilder result = new StringBuilder();
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
        System.out.println("[+] \tProcessing call for 'String system(String[] args)'...");

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
        

    public static void main(String args[]) {
        /* Bind Server to the RMI Registry */
        try {
            System.out.print("[+] Creating Server object... ");
            Server2 obj = new Server2();
            IServer2 stub = (IServer2)UnicastRemoteObject.exportObject(obj, 0);
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
