package de.qtc.rmg.server.legacy;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.util.HashMap;

@SuppressWarnings("serial")
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

    public void logMessage(int type, String msg) throws RemoteException
    {
        System.out.println("[+]\t[LegacyServiceImpl]: Processing call for 'void logMessage(int type, String msg)'...");
    }

    public void logMessage(int type, StringContainer msg) throws RemoteException
    {
        System.out.println("[+]\t[LegacyServiceImpl]: Processing call for 'void logMessage(int type, StringContainer msg)'...");
    }
}
