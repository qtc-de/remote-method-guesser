package eu.tneitzel.rmg.springremoting;

public interface ServerOperations
{
    String notRelevant();
    String execute(String cmd);
    String system(String cmd, String[] args);
    String upload(int size, int id, byte[] content);
    int math(int num1, int num2);
}
