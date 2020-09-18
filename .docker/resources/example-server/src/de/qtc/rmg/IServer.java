package de.qtc.rmg.testserver;

import java.rmi.Remote;
import java.rmi.RemoteException;

/* Interface for an RMI Server which implements some vulnerable classes */
public interface IServer extends Remote {
    String notRelevant() throws RemoteException;
    String execute(String cmd) throws RemoteException;
    String system(String cmd, String[] args) throws RemoteException;
}
