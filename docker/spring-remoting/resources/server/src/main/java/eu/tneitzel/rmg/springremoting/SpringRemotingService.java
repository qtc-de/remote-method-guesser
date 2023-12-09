package eu.tneitzel.rmg.springremoting;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.remoting.rmi.RmiServiceExporter;

@SuppressWarnings("deprecation")
public class SpringRemotingService implements ServerOperations
{
	Logger logger = LoggerFactory.getLogger(SpringRemotingService.class);
	
	SpringRemotingService springRemotingService()
	{
		return new SpringRemotingService();
	}

	@Bean
	RmiServiceExporter exporter(SpringRemotingService impl)
	{
		Class<ServerOperations> serverInterface = ServerOperations.class;
		RmiServiceExporter exporter = new RmiServiceExporter();
		
		exporter.setServiceInterface(serverInterface);
		exporter.setService(impl);
		exporter.setServiceName("spring-remoting");
		exporter.setRegistryPort(1099);
		
		return exporter;
	}
	
	public String notRelevant()
	{
    	logger.info("Processing call for: notRelevant()");
		return "Hello World :D";
	}

    public String execute(String command)
    {
    	logger.info("Processing call for: String execute(String command)");
        String result = "";

        try
        {
            Process p = java.lang.Runtime.getRuntime().exec(command);
            p.waitFor();
            result = readFromProcess(p);
        }
        
        catch (IOException | InterruptedException e)
        {
            result = "Exception: " + e.getMessage();
        }

        return result;
    }

    public String system(String command, String[] args)
    {
    	logger.info("Processing call for: String system(String command, String[] args)");
        String result = "";

        String[] commandArray = new String[args.length + 1];
        commandArray[0] = command;
        System.arraycopy(args, 0, commandArray, 1, args.length);

        try
        {
            Process p = java.lang.Runtime.getRuntime().exec(commandArray);
            p.waitFor();
            result = readFromProcess(p);
        }
        
        catch (IOException | InterruptedException e)
        {
            result = "Exception: " + e.getMessage();
        }

        return result;
    }

    public String upload(int size, int id, byte[] content)
    {
    	logger.info("Processing call for: String upload(int size, int id, byte[] content)");
        return "Upload of size " + size + " was saved as user_uploads_" + id + ".";
    }

    public int math(int num1, int num2)
    {
    	logger.info("Processing call for: int math(int num1, int num2)");
        return num1 / num2;
    }
    
    private static String readFromProcess(Process p) throws IOException
    {
        StringBuilder result = new StringBuilder();

        BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String line = reader.readLine();

        while (line != null)
        {
            result.append(line);
            line = reader.readLine();
        }

        reader = new BufferedReader(new InputStreamReader(p.getErrorStream()));
        line = reader.readLine();

        while (line != null)
        {
            result.append(line);
            line = reader.readLine();
        }

        return result.toString();
    }
}
