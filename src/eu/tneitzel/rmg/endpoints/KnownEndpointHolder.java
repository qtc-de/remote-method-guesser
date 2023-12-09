package eu.tneitzel.rmg.endpoints;

import java.io.InputStream;
import java.util.List;

import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

/**
 * The KnownEndpointHolder is a helper class to work with KnownEndpoints. It is responsible
 * to create the list of KnownEndpoints from the known-endpoints.yml file that is contained
 * within the remote-method-guesser .jar file. Furthermore, it can be used to perform certain
 * operations on the list, like checking whether a KnownEndpoint exists in the list or returning
 * a KnownEndpoint by name.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class KnownEndpointHolder
{
    private List<KnownEndpoint> knownEndpoints = null;
    private static KnownEndpointHolder instance = null;

    private static final String resource = "/resources/known-endpoints/known-endpoints.yml";

    /**
     * Returns a List of KnownEndpoint that was created from the known-endpoints.yml file.
     * Can be null if KnownEndpointHolder was not created via getHolder().
     *
     * @return List of KnownEndpoint
     */
    public List<KnownEndpoint> getKnownEndpoints()
    {
        return knownEndpoints;
    }

    /**
     * Sets the List of KnownEndpoint for a KnownEndpointHolder instance.
     *
     * @param knownEndpoints List of KnownEndpoints to set within the holder
     */
    public void setKnownEndpoints(List<KnownEndpoint> knownEndpoints)
    {
        this.knownEndpoints = knownEndpoints;
    }

    /**
     * Can be used to lookup a class name within the List of KnownEndpoints. The first endpoint
     * that contains the corresponding class name within its className list is returned. If no
     * endpoint is matching, return null.
     *
     * @param className KnownEndpoint className to look for
     * @return KnownEndpoint that contains the requested class name or null
     */
    public KnownEndpoint lookup(String className)
    {
        if (knownEndpoints == null)
        {
            return null;
        }

        for (KnownEndpoint endpoint : knownEndpoints)
        {
            if (endpoint.getClassName().contains(className))
            {
                return endpoint;
            }
        }

        return null;
    }

    /**
     * Check whether the specified class name exists within the List of KnownEndpoint. If this is
     * the case, returns true. False otherwise.
     *
     * @param className KnownEndpoint className to look for
     * @return true if the className is contained, false otherwise
     */
    public boolean isKnown(String className)
    {
        if (lookup(className) == null)
        {
            return false;
        }

        return true;
    }

    /**
     * The getHolder function returns an instance of KnownEndpointHolder. This function should always
     * be used when such an Object is required, as it makes sure that the List of KnownEndpoint is
     * initialized.
     *
     * The creation of a new KnownEndpointHolder should only occur once when using this function. If
     * a KnownEndpointHolder was created previously, the already existing instance is returned instead
     * of a new one.
     *
     * @return KnownEndpointHolder with initialized List of KnownEndpoint
     */
    public static KnownEndpointHolder getHolder()
    {
        if (instance == null)
        {
            Yaml yaml = new Yaml(new Constructor(KnownEndpointHolder.class));

            InputStream stream = KnownEndpoint.class.getResourceAsStream(resource);
            instance = yaml.load(stream);
        }

        return instance;
    }
}
