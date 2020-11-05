package de.qtc.rmg.operations;

import java.io.IOException;

import de.qtc.rmg.Utils;
import de.qtc.rmg.interfaces.IPlainServer;

public class PlainServer implements IPlainServer {

    public String notRelevant()
    {
        System.out.println("[+]\t[Plain Server]: Processing call for notRelevant()...");
        return "Some irrelevant text...";
    }

    public String execute(String command)
    {
        System.out.println("[+]\t[Plain Server]: Processing call for 'String execute(String command)'...");
        String result = "";

        try {
            Process p = java.lang.Runtime.getRuntime().exec(command);
            p.waitFor();
            result = Utils.readFromProcess(p);
        } catch( IOException | InterruptedException e) {
            result = "Exception: " + e.getMessage();
        }

        return result;
    }

    public String system(String command, String[] args)
    {
        System.out.println("[+]\t[Plain Server]: Processing call for 'String system(String command, String[] args)'...");
        String result = "";

        String[] commandArray = new String[args.length + 1];
        commandArray[0] = command;
        System.arraycopy(args, 0, commandArray, 1, args.length);

        try {
            Process p = java.lang.Runtime.getRuntime().exec(commandArray);
            p.waitFor();
            result = Utils.readFromProcess(p);
        } catch( IOException | InterruptedException e) {
            result = "Exception: " + e.getMessage();
        }

        return result;
    }
}
