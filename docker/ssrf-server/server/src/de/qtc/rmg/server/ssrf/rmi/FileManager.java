package de.qtc.rmg.server.ssrf.rmi;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

/**
 * The FileManager class can be used to create remote objects that provide access
 * to the servers underlying file system. In this server it can be used to practice
 * some RMI attacks. You should not use it for real use cases.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class FileManager extends UnicastRemoteObject implements IFileManager {

    private static final long serialVersionUID = -4152572890647308345L;

    /**
     * Calls the constructor of UnicastRemoteObject to export the object automatically
     * on instantiation.
     *
     * @throws RemoteException
     */
    public FileManager() throws RemoteException {
        super();
    }

    /**
     * Lists all files within the specified directory and returns the result as an array
     * of File.
     *
     * @param dir Absolute path of the directory to list
     * @return directory contents as array of File
     */
    @Override
    public File[] list(String dir) throws RemoteException
    {
        File[] directories = new File(dir).listFiles();
        return directories;
    }

    /**
     * Reads the specified file and returns the content as an array of byte.
     *
     * @param file Absolute path of the file to obtain the contents from
     * @return file content as array of byte
     */
    @Override
    public byte[] read(String file) throws RemoteException, IOException
    {
        File f = new File(file);
        return Files.readAllBytes(f.toPath());
    }

    /**
     * Writes the specified content to the specified location.
     *
     * @param file Absolute path of the file to write
     * @param content that is written to the file
     * @return error or success message
     */
    @Override
    public String write(String file, byte[] content) throws RemoteException, IOException, InterruptedException
    {
        Path f = Paths.get(file);
        Files.write(f, content);

        return "File " + file + " was successfully written.";
    }
}
