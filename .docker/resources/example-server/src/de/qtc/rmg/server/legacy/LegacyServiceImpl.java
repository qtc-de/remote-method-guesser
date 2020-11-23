package de.qtc.rmg.server.legacy;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.util.HashMap;

import de.qtc.rmg.server.utils.Logger;

@SuppressWarnings("serial")
public class LegacyServiceImpl extends UnicastRemoteObject implements LegacyService
{
    public LegacyServiceImpl() throws RemoteException
    {
    }

    public String getMotd() throws RemoteException
    {
        Logger.printlnMixedBlueYellow("[LegacyServiceImpl]:", "Processing call for", "getMotd()");
        return "Legacy Java RMI is real :O";
    }

    public String login(HashMap<String, String> credentials) throws RemoteException
    {
        Logger.printlnMixedBlueYellow("[LegacyServiceImpl]:", "Processing call for", "String login(HashMap<String, String> credentials)");
        String username = credentials.get("username");
        String password = credentials.get("password");
        if(username != null && password != null && username.equals("admin") && password.equals("admin")) {
            return "Session-ID-123";
        }
        return null;
    }

    public void logMessage(int type, String msg) throws RemoteException
    {
        Logger.printlnMixedBlueYellow("[LegacyServiceImpl]:", "Processing call for", "void logMessage(int type, String msg)");
    }

    public void logMessage(int type, StringContainer msg) throws RemoteException
    {
        Logger.printlnMixedBlueYellow("[LegacyServiceImpl]:", "Processing call for", "void logMessage(int type, StringContainer msg)");
    }

    public int math(int num1, int num2) throws RemoteException
    {
        Logger.printlnMixedBlueYellow("[LegacyServiceImpl]:", "Processing call for", "void math(int num1, int num2)");
        return num1 + num2;
    }

    public void releaseRecord(int recordID, String tableName, Integer remoteHashCode)
    {
        Logger.printlnMixedBlueYellow("[LegacyServiceImpl]:", "Processing call for", "void releaseRecord(int recordID, String tableName, Integer remoteHashCode)");
        return;
    }
}
