package de.qtc.rmg;

import java.util.List;
import java.util.Arrays;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

import <PACKAGE>;

public class <CLASSNAME> {

    private static int remotePort = <REMOTEPORT>;
    private static String remoteHost = "<REMOTEHOST>";
    private static String arraySeperator = "<SEP>";

    public static void main(String[] argv) {

        List<String> list = Arrays.asList(argv);

        // If the command line switch '-x' is missing, or a help switch was used, we display a help message for the user and end execution.
        if( ! list.contains("-x") || list.contains("-h") || list.contains("--help") ) {

            System.out.println("[+] To run the sample, use the '-x' switch and specify the required arguments.");
            System.out.println("[+] If you need to specify a String array (String[]) as argument, use '" + arraySeperator + "' as array seperator.");
            System.out.println("[+] The method signature is: <METHODSIG>");
            System.exit(1);

        // If the command line switch '-x' was specified, the total number of arguments should match <ARGCOUNT> + 1. Otherwise, execution ends here.
        } else if( argv.length != <ARGCOUNT> + 1 ) {

          System.err.println("[-] Wrong number of arguments!");
          System.err.println("[-] Make sure that you have specified all arguments of the following method signature.");
          System.out.println("[+] Method Signature: <METHODSIG>");
          System.exit(1);

        }


        try {

          System.out.print("[+] Connecting to registry on " + remoteHost + ":" + remotePort + "... ");
          Registry registry = LocateRegistry.getRegistry(remoteHost, remotePort);
          System.out.println("done!");

          System.out.print("[+] Starting lookup on <BOUNDNAME>... ");
          <CLASS> stub = (<CLASS>) registry.lookup("<BOUNDNAME>");
          System.out.println("done!");

          System.out.print("[+] Invoking method <METHODNAME>... ");
          <RETURNTYPE> response = stub.<METHODNAME>(<ARGUMENTS>);
          System.out.println("done!");

          System.out.println("[+] The servers response is: " + response);

        } catch (Exception e) {
            System.err.println("failed!");
            System.err.println("[-] The following exception was thrown:" + e.toString());
        }

    }

    private static String[] convertToArray(String input) {
        return input.split(arraySeperator);
    }
}
