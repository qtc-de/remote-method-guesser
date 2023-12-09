package eu.tneitzel.rmg.endpoints;

import java.util.List;

import eu.tneitzel.rmg.io.Logger;

/**
 * The KnownEndpoint class represents a well known RMI endpoint. By the term 'well known' we mean
 * that the class that implements the remote object was encountered before and meta information does
 * exist for it within the remote-method-guesser repository. Users can then use the 'known' action
 * to get additional information on the endpoint, like implemented remote methods or known vulnerabilities.
 *
 * KnownEndpoints are stored within a YAML file in the remote-method-guesser repository. The objects
 * are directly constructed from this file and the KnownEndpoint class needs to implement corresponding
 * getters and setters.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class KnownEndpoint
{
    private String name;
    private String description;

    private List<String> className;
    private List<String> remoteMethods;
    private List<String> references;

    private List<Vulnerability> vulnerabilities;

    public void setName(String name)
    {
        this.name = name;
    }

    public void setClassName(List<String> className)
    {
        this.className = className;
    }

    public void setDescription(String description)
    {
        this.description = description;
    }

    public void setRemoteMethods(List<String> remoteMethods)
    {
        this.remoteMethods = remoteMethods;
    }

    public void setReferences(List<String> references)
    {
        this.references = references;
    }

    public void setVulnerabilities(List<Vulnerability> vulnerabilities)
    {
        this.vulnerabilities = vulnerabilities;
    }

    public String getName()
    {
        return name;
    }

    public List<String> getClassName()
    {
        return className;
    }

    public String getDescription()
    {
        return description;
    }

    public List<String> getRemoteMethods()
    {
        return remoteMethods;
    }

    public List<String> getReferences()
    {
        return references;
    }

    public List<Vulnerability> getVulnerabilities()
    {
        return vulnerabilities;
    }

    /**
     * This function is called during the 'enum' action of remote-method-guesser to print
     * meta information for a KnownEndpoint in a formatted way.
     */
    public void printEnum()
    {
        String format = String.format("(known class: %s)", name);

        if( vulnerabilities.size() == 0 )
        {
            Logger.printlnPlainGreen(format);
        }

        else
        {
            Logger.printlnPlainYellow(format);
        }
    }
}
