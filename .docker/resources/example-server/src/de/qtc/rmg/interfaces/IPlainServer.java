package de.qtc.rmg.interfaces;

import java.rmi.Remote;
import java.rmi.RemoteException;

public interface IPlainServer extends Remote
{
    String notRelevant() throws RemoteException;
    String execute(String cmd) throws RemoteException;
    String system(String cmd, String[] args) throws RemoteException;
}
