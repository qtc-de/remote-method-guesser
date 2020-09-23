package de.qtc.rmg;

import java.rmi.Remote;
import java.rmi.RemoteException;

public interface ISslServer extends Remote
{
    String notRelevant() throws RemoteException;
    int execute(String cmd) throws RemoteException;
    String system(String[] args) throws RemoteException;
}
