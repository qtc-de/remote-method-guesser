package de.qtc.rmg;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.util.HashMap;

public class LegacyServiceImpl extends UnicastRemoteObject implements LegacyService
{
    public LegacyServiceImpl() throws RemoteException
    {
    }

    public String getMotd() throws RemoteException
    {
        System.out.println("[+]\t[LegacyServiceImpl]: Got call for 'getMotd()'...");
        return "Legacy Java RMI is real :O";
    }

    public String login(HashMap<String, String> credentials) throws RemoteException
    {
        System.out.println("[+]\t[LegacyServiceImpl]: Processing call for 'String login(HashMap<String, String> arg)'...");
        String username = credentials.get("username");
        String password = credentials.get("password");
        if(username != null && password != null && username.equals("admin") && password.equals("admin")) {
            return "Session-ID-123";
        }
        return null;
    }
}
