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

    /**
     * Set the name of the endpoint.
     *
     * @param name of the endpoint
     */
    public void setName(String name)
    {
        this.name = name;
    }

    /**
     * Set the class name of the endpoint.
     *
     * @param className of the endpoint.
     */
    public void setClassName(List<String> className)
    {
        this.className = className;
    }

    /**
     * Set the description of the endpoint.
     *
     * @param description of the endpoint.
     */
    public void setDescription(String description)
    {
        this.description = description;
    }

    /**
     * Set the remote methods for the endpoint.
     *
     * @param remoteMethods list of remote methods
     */
    public void setRemoteMethods(List<String> remoteMethods)
    {
        this.remoteMethods = remoteMethods;
    }

    /**
     * Set the references for the endpoint.
     *
     * @param references list of references
     */
    public void setReferences(List<String> references)
    {
        this.references = references;
    }

    /**
     * Set the vulnerabilities for the endpoint.
     *
     * @param vulnerabilities list of vulnerabilities.
     */
    public void setVulnerabilities(List<Vulnerability> vulnerabilities)
    {
        this.vulnerabilities = vulnerabilities;
    }

    /**
     * @return name
     */
    public String getName()
    {
        return name;
    }

    /**
     * @return class name
     */
    public List<String> getClassName()
    {
        return className;
    }

    /**
     * @return description
     */
    public String getDescription()
    {
        return description;
    }

    /**
     * @return list of methods
     */
    public List<String> getRemoteMethods()
    {
        return remoteMethods;
    }

    /**
     * @return list of references
     */
    public List<String> getReferences()
    {
        return references;
    }

    /**
     * @return list of vulnerabilities
     */
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
