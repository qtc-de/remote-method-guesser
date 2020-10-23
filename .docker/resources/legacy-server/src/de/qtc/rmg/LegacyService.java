package de.qtc.rmg;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.util.HashMap;

public interface LegacyService extends Remote
{
    public String getMotd() throws RemoteException;
    String login(HashMap<String, String> credentials) throws RemoteException;
}
