package de.qtc.rmg.server.interfaces;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.HashMap;

public interface ISecureServer extends Remote
{
    String login(HashMap<String, String> credentials) throws RemoteException;
    void logMessage(int logLevel, Object message) throws RemoteException;
    void updatePreferences(ArrayList<String> preferences) throws RemoteException;
}
