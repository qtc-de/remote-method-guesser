package eu.tneitzel.rmg.server.interfaces;

import java.rmi.Remote;
import java.rmi.RemoteException;

public interface IPlainServer extends Remote
{
    String notRelevant() throws RemoteException;
    String execute(String cmd) throws RemoteException;
    String system(String cmd, String[] args) throws RemoteException;
    String upload(int size, int id, byte[] content) throws RemoteException;
    int math(int num1, int num2) throws RemoteException;
}
