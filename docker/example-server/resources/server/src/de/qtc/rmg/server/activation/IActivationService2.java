package de.qtc.rmg.server.activation;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.HashMap;

public interface IActivationService2 extends Remote
{
    String login(HashMap<String, String> credentials) throws RemoteException;
    void logMessage(int logLevel, Object message) throws RemoteException;
    void updatePreferences(ArrayList<String> preferences) throws RemoteException;
}
