package eu.tneitzel.rmg.server.operations;

import java.io.IOException;

import eu.tneitzel.rmg.server.interfaces.IPlainServer;
import eu.tneitzel.rmg.server.utils.Logger;
import eu.tneitzel.rmg.server.utils.Utils;

public class PlainServer implements IPlainServer {

    public String notRelevant()
    {
        Logger.printlnMixedBlueYellow("[PlainServer]:", "Processing call for", "String notRelevant()");
        return "Hello world :)";
    }

    public String execute(String command)
    {
        Logger.printlnMixedBlueYellow("[PlainServer]:", "Processing call for", "String execute(String command)");
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
        Logger.printlnMixedBlueYellow("[PlainServer]:", "Processing call for", "String system(String command, String[] args)");
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

    public String upload(int size, int id, byte[] content)
    {
        Logger.printlnMixedBlueYellow("[PlainServer]:", "Processing call for", "String upload(int size, int id, byte[] content)");
        return "Upload of size " + size + " was saved as user_uploads_" + id + ".";
    }

    public int math(int num1, int num2)
    {
        Logger.printlnMixedBlueYellow("[PlainServer]:", "Processing call for", "int math(int num1, int num2)");
        return num1 / num2;
    }
}
