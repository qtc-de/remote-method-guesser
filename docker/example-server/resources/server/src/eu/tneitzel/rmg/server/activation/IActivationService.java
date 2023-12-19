package eu.tneitzel.rmg.server.activation;

import java.rmi.Remote;
import java.rmi.RemoteException;

public interface IActivationService extends Remote
{
    String execute(String cmd) throws RemoteException;
    String system(String cmd, String[] args) throws RemoteException;
}
