package de.qtc.rmg;

import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.HashMap;

public class SecureServer implements ISecureServer {

    @SuppressWarnings("unused")
    private ArrayList<String> preferences = null;

    public String login(HashMap<String, String> credentials) throws RemoteException
    {
        System.out.println("[+]\t[Secure Server]: Processing call for 'String login(HashMap<String, String> arg)'...");
        String username = credentials.get("username");
        String password = credentials.get("password");
        if(username != null && password != null && username.equals("admin") && password.equals("admin")) {
            return "Session-ID-123";
        }
        return null;
    }

    public void logMessage(int logLevel, Object message) throws RemoteException
    {
        System.out.println("[+]\t[Secure Server]: Processing call for 'void logMessage(int arg, Object arg)'...");
        if( logLevel == 1 )
            System.out.println((String)message);
        if( logLevel == 2 )
            System.err.println((String)message);
        else
            System.err.println("Unknown logLevel: " + logLevel);
    }

    public void updatePreferences(ArrayList<String> preferences) throws RemoteException
    {
        System.out.println("[+]\t[Secure Server]: Processing call for 'void updatePreferences(ArrayList<String> arg)'...");
        this.preferences = preferences;
    }
}
