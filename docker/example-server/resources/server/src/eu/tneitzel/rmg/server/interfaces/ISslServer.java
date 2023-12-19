package eu.tneitzel.rmg.server.interfaces;

import java.rmi.Remote;
import java.rmi.RemoteException;

public interface ISslServer extends Remote
{
    String notRelevant() throws RemoteException;
    int execute(String cmd) throws RemoteException;
    String system(String[] args) throws RemoteException;
    void releaseRecord(int recordID, String tableName, Integer remoteHashCode) throws RemoteException;
}
