package de.qtc.rmg.server.operations;

import java.io.IOException;

import de.qtc.rmg.server.interfaces.ISslServer;
import de.qtc.rmg.server.utils.Logger;
import de.qtc.rmg.server.utils.Utils;

public class SslServer implements ISslServer {

    public String notRelevant()
    {
        Logger.printlnMixedBlueYellow("[SslServer]:", "Processing call for", "String notRelevant()");
        return "Hello World :)";
    }

    public int execute(String command)
    {
        Logger.printlnMixedBlueYellow("[SslServer]:", "Processing call for", "int execute(String command)");

        try {
            Process p = java.lang.Runtime.getRuntime().exec(command);
            p.waitFor();
            return p.exitValue();
        }
        catch( Exception e) {}
        return -1;
    }

    public String system(String[] args)
    {
        Logger.printlnMixedBlueYellow("[SslServer]:", "Processing call for", "String system(String[] args)");
        String result = "";

        try {
            Process p = java.lang.Runtime.getRuntime().exec(args);
            p.waitFor();

            result = Utils.readFromProcess(p);
        } catch( IOException | InterruptedException e) {
            result = "Exception: " + e.getMessage();
        }

        return result;
    }

    public void releaseRecord(int recordID, String tableName, Integer remoteHashCode)
    {
        Logger.printlnMixedBlueYellow("[SslServer]:", "Processing call for", "void releaseRecord(int recordID, String tableName, Integer remoteHashCode)");
        return;
    }
}
