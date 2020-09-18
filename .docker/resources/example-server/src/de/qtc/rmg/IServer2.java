package de.qtc.rmg.testserver;

import java.rmi.Remote;
import java.rmi.RemoteException;

/* Interface for an RMI Server which implements some vulnerable classes */
public interface IServer2 extends Remote {
    String notRelevant() throws RemoteException;
    int execute(String cmd) throws RemoteException;
    String system(String[] args) throws RemoteException;
}
