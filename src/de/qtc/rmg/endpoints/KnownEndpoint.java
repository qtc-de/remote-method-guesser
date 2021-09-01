package de.qtc.rmg.endpoints;

import java.util.List;

import de.qtc.rmg.io.Logger;

public class KnownEndpoint {

    private String name;
    private String className;
    private String description;

    private List<String> remoteMethods;
    private List<String> references;

    private List<Vulnerability> vulnerabilities;

    public void setName(String name)
    {
        this.name = name;
    }

    public void setClassName(String className)
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

    public String getClassName()
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

    public void printEnum()
    {
        String format = String.format("(known class: %s)", name);

        if( vulnerabilities.size() == 0 )
            Logger.printlnPlainGreen(format);

        else
            Logger.printlnPlainYellow(format);
    }
}