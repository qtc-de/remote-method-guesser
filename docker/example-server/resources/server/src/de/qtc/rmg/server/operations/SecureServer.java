package de.qtc.rmg.server.operations;

import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.HashMap;

import de.qtc.rmg.server.interfaces.ISecureServer;
import de.qtc.rmg.server.utils.Logger;

public class SecureServer implements ISecureServer {

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
