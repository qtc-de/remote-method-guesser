package de.qtc.rmg.server.ssrf.rmi;

import java.io.File;
import java.io.IOException;
import java.rmi.Remote;
import java.rmi.RemoteException;

/**
 * The IFileManager interface is intended to be implemented by remote objects
 * that want to give access to the servers underlying filesystem.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public interface IFileManager extends Remote
{
    File[] list(String dir) throws RemoteException;
    byte[] read(String file) throws RemoteException, IOException;
    String write(String file, byte[] content) throws RemoteException, IOException;
    String copy(String src, String dest) throws RemoteException, IOException, InterruptedException;
}
