package eu.tneitzel.rmg.server.ssrf.rmi;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.util.HashMap;
import java.util.Map;

import javax.management.MBeanServer;
import javax.management.remote.JMXConnectorServer;
import javax.management.remote.JMXConnectorServerFactory;
import javax.management.remote.JMXServiceURL;
import javax.management.remote.rmi.RMIConnectorServer;

/**
 * Since it is surprisingly difficult to make JMX only listen on localhost, we need to start the JMXConnectorServer
 * manually and supply our desired configuration. This class is responsible for doing so.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class LocalhostJmxConnector {

    private JMXConnectorServer server;

    /**
     * Creates a JMXConnectorServer that is configured to listen on localhost only. The constructor expects the
     * port number of an RMI registry on the local system where the jmxrmi bound name can be setup. This bind operation
     * does not trigger during instantiation, but at the start of the server.
     *
     * @param port Port of an RMI Registry server on the local system
     * @throws IOException
     */
    public LocalhostJmxConnector(int port) throws IOException
    {
         Map<String, Object> env = new HashMap<>();
         env.put(RMIConnectorServer.RMI_SERVER_SOCKET_FACTORY_ATTRIBUTE, new LocalhostSocketFactory());

         MBeanServer mbeanServer = ManagementFactory.getPlatformMBeanServer();
         JMXServiceURL url = new JMXServiceURL("service:jmx:rmi:///jndi/rmi://127.0.0.1:" + port + "/jmxrmi");

         server = JMXConnectorServerFactory.newJMXConnectorServer(url, env, mbeanServer);
    }

    /**
     * Starts the JMX service. This binds the jmxrmi bound name to the RMI registry and exports the corresponding
     * remote object.
     *
     * @throws IOException
     */
    public void start() throws IOException
    {
        server.start();
    }
}
