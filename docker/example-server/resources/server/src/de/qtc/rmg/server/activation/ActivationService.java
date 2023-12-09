package eu.tneitzel.rmg.server.activation;

import java.io.IOException;
import java.rmi.MarshalledObject;
import java.rmi.RemoteException;
import java.rmi.activation.Activatable;
import java.rmi.activation.ActivationID;

import eu.tneitzel.rmg.server.utils.Logger;
import eu.tneitzel.rmg.server.utils.Utils;

public class ActivationService extends Activatable implements IActivationService
{
    private static final long serialVersionUID = 3047196196290730685L;

    @SuppressWarnings("rawtypes")
    public ActivationService(ActivationID id, MarshalledObject data) throws RemoteException
    {
        super(id, 0);
    }

    public String execute(String command)
    {
        Logger.printlnMixedBlueYellow("[ActivationServer]:", "Processing call for", "String execute(String command)");
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
        Logger.printlnMixedBlueYellow("[ActivationServer]:", "Processing call for", "String system(String command, String[] args)");
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
