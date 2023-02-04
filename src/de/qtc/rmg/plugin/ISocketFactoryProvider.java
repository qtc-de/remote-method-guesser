package de.qtc.rmg.plugin;

import java.rmi.server.RMIClientSocketFactory;
import java.rmi.server.RMISocketFactory;

/**
 * The ISocketFactoryProvider interface can be used to overwrite SocketFactory implementations that are used during
 * RMI communication. This is usually not required, but when the RMI server uses a customized SocketFactory for RMI
 * communications, you may want to use it.
 *
 * The getClientSocketFactory function can be used to overwrite the RMIClientSocketFactory that is used for direct
 * connections (e.g. connecting to the RMI registry or an RMI endpoint directly).
 *
 * The getDefaultSocketFactory function can be used to overwrite the RMISocketFactory that is used on RMI operations
 * that are invoked on remote objects obtained from an RMI registry.
 *
 * The getDefaultSSLSocketFactory function can be used to overwrite the RMISocketFactory that is used on RMI operations
 * that are invoked on remote objects obtained from an RMI registry, that use the default SSLSocketFactory implementation.
 *
 * When an RMI server implements a custom RMISocketFactory on the RMI registry and for its remote objects, you usually
 * need to do the following:
 *
 *         1. Add an compiled version of the server's RMISocketFactory class to your class path
 *         2. Use the PluginSystem and the getClientSocketFactory function to make it the SocketFactory used for direct calls
 *
 * This should already be sufficient. If only remote objects use the custom RMISocketFactory, but the RMI registry is not,
 * you only need the first step. The PluginSystem is not even required in this case.
 *
 * The getDefaultSocketFactory and getDefaultSSLSocketFactory functions are only required to modify the connection behavior
 * on default RMI connections. remote-method-guesser for example uses these functions to prevent the automatic redirection
 * that is applied by RMI when the RMI server location was set to "localhost".
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public interface ISocketFactoryProvider {

    public RMIClientSocketFactory getClientSocketFactory(String host, int port);

    public RMISocketFactory getDefaultSocketFactory(String host, int port);

    public String getDefaultSSLSocketFactory(String host, int port);
}
