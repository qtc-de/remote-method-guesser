package de.qtc.rmg.endpoints;

import java.io.InputStream;
import java.util.List;

import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

public class KnownEndpointHolder {

    private List<KnownEndpoint> knownEndpoints = null;
    private static KnownEndpointHolder instance = null;

    private static final String resource = "/resources/known-endpoints/known-endpoints.yml";

    public List<KnownEndpoint> getKnownEndpoints()
    {
        return knownEndpoints;
    }

    public void setKnownEndpoints(List<KnownEndpoint> knownEndpoints)
    {
        this.knownEndpoints = knownEndpoints;
    }

    public KnownEndpoint lookup(String className)
    {
        if( knownEndpoints == null )
            return null;

        for( KnownEndpoint endpoint : knownEndpoints )

            if( endpoint.getClassName().equals(className) )
                return endpoint;

        return null;
    }

    public boolean isKnown(String className)
    {
        if( lookup(className) == null )
            return false;

        return true;
    }

    public static KnownEndpointHolder getHolder()
    {
        if( instance == null ) {
            Yaml yaml = new Yaml(new Constructor(KnownEndpointHolder.class));

            InputStream stream = KnownEndpoint.class.getResourceAsStream(resource);
            instance = yaml.load(stream);
        }

        return instance;
    }
}