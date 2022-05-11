package de.qtc.rmg.server.activation;

import java.rmi.MarshalledObject;
import java.rmi.RemoteException;
import java.rmi.activation.Activatable;
import java.rmi.activation.ActivationID;
import java.util.ArrayList;
import java.util.HashMap;

import javax.rmi.ssl.SslRMIClientSocketFactory;
import javax.rmi.ssl.SslRMIServerSocketFactory;

import de.qtc.rmg.server.utils.Logger;

public class ActivationService2 extends Activatable implements IActivationService2
{
    private static final long serialVersionUID = 4047196196290730685L;

    @SuppressWarnings("rawtypes")
    public ActivationService2(ActivationID id, MarshalledObject data) throws RemoteException
    {
        super(id, 0, new SslRMIClientSocketFactory(), new SslRMIServerSocketFactory());
    }

    @SuppressWarnings("unused")
    private ArrayList<String> preferences = null;

    public String login(HashMap<String, String> credentials) throws RemoteException
    {
        Logger.printlnMixedBlueYellow("[SecureServer]:", "Processing call for", "String login(HashMap<String, String> credentials)");
        String username = credentials.get("username");
        String password = credentials.get("password");
        if(username != null && password != null && username.equals("admin") && password.equals("admin")) {
            return "Session-ID-123";
        }
        return null;
    }

    @SuppressWarnings("unused")
    public void logMessage(int logLevel, Object message) throws RemoteException
    {
        Logger.printlnMixedBlueYellow("[SecureServer]:", "Processing call for", "void logMessage(int logLevel, Object message)");

        String logMessage = "";
        if( logLevel == 1 )
            logMessage = "Info: " +(String)message;
        if( logLevel == 2 )
            logMessage = "Error: " +(String)message;

        //tdb.appendToLog(logMessage);
    }

    public void updatePreferences(ArrayList<String> preferences) throws RemoteException
    {
        Logger.printlnMixedBlueYellow("[SecureServer]:", "Processing call for", "void updatePreferences(ArrayList<String> preferences)");
        this.preferences = preferences;
    }
}