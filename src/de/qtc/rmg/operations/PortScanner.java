package de.qtc.rmg.operations;

import java.rmi.server.ObjID;
import java.rmi.server.RMIClientSocketFactory;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.TimeUnit;

import de.qtc.rmg.internal.ExceptionHandler;
import de.qtc.rmg.internal.MethodArguments;
import de.qtc.rmg.internal.RMGOption;
import de.qtc.rmg.io.Logger;
import de.qtc.rmg.networking.RMIEndpoint;
import de.qtc.rmg.networking.TimeoutSocketFactory;
import de.qtc.rmg.networking.TrustAllSocketFactory;


/**
 * The PortScanner class implements a simple RMI service scan that can be used to
 * identify RMI endpoints on a target. By default, it takes a list of ports from the
 * remote-method-guesser configuration file and attempts to perform an RMI call on
 * them. Calls are first dispatched without TLS, but for each port that is open and
 * that does not behave like an RMI port for plain text connections, a second attempt
 * with TLS is made.
 *
 * The PortScanner class is not meant to be used as a replacement for tools like nmap.
 * It is e.g. less reliable, as it does not implement retries and may misses some open
 * ports. However, it can still be useful in certain situations. A common scenario is,
 * that you encounter a product that is often deployed together with RMI services like
 * e.g. JBoss. Or that you already encountered a non registry RMI port and just want
 * to know where the registry is located. In these cases, a quick port scan that only
 * targets common RMI ports using RMI service probes might be a good choice.
 *
 * Concerning TLS protected ports, the PortScanner class might even be more reliable
 * than nmap regarding the service detection. In the past, we encountered several TLS
 * protected RMI ports where nmap was unable to detect the service correctly.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class PortScanner {

    private int hits;
    private String host;
    private int[] rmiPorts;

    private final ObjID OReg = new ObjID(0);
    private final ObjID OAct = new ObjID(1);
    private final ObjID ODgc = new ObjID(2);

    private ForkJoinPool pool;
    private MethodArguments scanArgs;
    private TrustAllSocketFactory sslFactory;
    private RMIClientSocketFactory sockFactory;

    private static int readTimeout = 5;
    private static int connectTimeout = 5;

    /**
     * The PortScanner class obtains the target host as a String and the ports to scan
     * as an array of int.
     *
     * @param host target for the port scan
     * @param rmiPorts ports to scan
     */
    public PortScanner(String host, int[] rmiPorts)
    {
        this.hits = 0;
        this.host = host;
        this.rmiPorts = rmiPorts;

        scanArgs = new MethodArguments(0);
        sslFactory = new TrustAllSocketFactory(readTimeout, connectTimeout);
        sockFactory = new TimeoutSocketFactory(readTimeout, connectTimeout);
    }

    /**
     * Performs the port scan. For each port to scan a PortScanWorker is created and is
     * executed within a ThreadPool. The function may performs two runs per port. In the
     * first run, a plain text connection is attempted. Closed ports are ignored, but for
     * open ports that do not behave like RMI ports on a plain text connection, a second
     * attempt using TLS is made.
     *
     * The function uses a ForkJoinPool as ExecutorService, as the TLS scans are dispatched
     * by the non TLS worker threads.
     *
     * @return number of identified open ports as int
     */
    public int portScan()
    {
        pool = new ForkJoinPool(RMGOption.THREADS.getInt());

        for( int port : rmiPorts ) {
            Runnable r = new PortScanWorker(port, false);
            pool.execute(r);
        }

        pool.awaitQuiescence(Long.MAX_VALUE, TimeUnit.NANOSECONDS);
        pool.shutdown();

        return hits;
    }

    /**
     * Set the socket timeout values. By default, RMI connections have long connect
     * and read timeouts, which makes the defaults difficult to use for portscans.
     *
     * @param read timeout for read operations on the sockets
     * @param connect timeout for the initial socket connect
     */
    public static void setSocketTimeouts(String read, String connect)
    {
        readTimeout = Integer.valueOf(read);
        connectTimeout = Integer.valueOf(connect);
    }

    /**
     * The PortScanWorker performs the actual connection attempt to a port. It is also
     * responsible for printing a status message for each identified RMI port.
     *
     * @author Tobias Neitzel (@qtc_de)
     */
    private class  PortScanWorker implements Runnable {

        private int port;
        private boolean ssl;
        private RMIEndpoint endpoint;

        private boolean dgc = false;
        private boolean registry = false;
        private boolean activator = false;


        /**
         * A PortScanWorkers obtains the candidate port it should scan and a boolean
         * that indicates whether the connection needs to be made using TLS.
         *
         * @param port port to scan
         * @param ssl whether to use TLS
         */
        public PortScanWorker(int port, boolean ssl)
        {
            this.ssl = ssl;
            this.port = port;

            if(ssl)
                this.endpoint = new RMIEndpoint(host, port, sslFactory);

            else
                this.endpoint = new RMIEndpoint(host, port, sockFactory);
        }

        /**
         * Perform the scan. This is done by performing an unmanagedCall on the endpoint object.
         * The call targets the RMI registry (ObjID = 0) and uses the operation number 22, which does
         * not exist within the registry.
         *
         * An RMI service that does not implement an RMI registry will return an NoSuchObjectException.
         * In this case, we perform additional scans for the DGC and the Activator remote objects. On
         * the other hand, an RMI port that implements an RMI registry will answer with an
         * ArrayIndexOutOfBoundException (due to the non existing operation number). In this case we mark
         * the port as registry port and perform additional scans for the DGC and Activator remote objects.
         */
        public void run()
        {
            try {
                endpoint.unmanagedCall(OReg, 22, 0L, scanArgs, false, null, null);

            } catch( java.rmi.NoSuchObjectException e ) {

                scanDgc();
                scanAct();
                printResult();

            } catch( java.lang.ArrayIndexOutOfBoundsException e ) {

                this.registry = true;
                scanDgc();
                scanAct();
                printResult();

            } catch( java.rmi.ConnectException e ) {

                Throwable t = ExceptionHandler.getCause(e);
                if( t instanceof java.net.ConnectException && t.getMessage().contains("Connection refused")) {
                    return;

                } else {

                    if( !ssl )
                        pool.execute(new PortScanWorker(port, true));
                }

            } catch (Exception e) {

                if( !ssl )
                    pool.execute(new PortScanWorker(port, true));
            }
        }

        /**
         * Performs an unmanaged call on the DGC remote object. If a DGC remote object is present,
         * this should always lead to an ArrayIndexOutOfBoundsException, as the operation number 22
         * is not available on DGC endpoints. If no DGC remote object is present, a NoSuchObjectException
         * is expected.
         *
         * Other exceptions should not occur since this functions is only called when the remote endpoint
         * was already identified as RMI endpoint.
         */
        private void scanDgc()
        {
            try {
                endpoint.unmanagedCall(ODgc, 22, 0L, scanArgs, false, null, null);

            } catch( java.rmi.NoSuchObjectException e ) {
                return;

            } catch ( java.lang.ArrayIndexOutOfBoundsException e ) {
                this.dgc = true;

            } catch (Exception e) {
                ExceptionHandler.unexpectedException(e, "portscan", "operation", false);
            }
        }

        /**
         * Performs an unmanaged call on the Activator remote object. If an Activator remote object is
         * present, this should always lead to an UnmarshalException, as the send method hash does not
         * exist on Activator endpoints. If no Activator remote object is present, a NoSuchObjectException
         * is expected.
         *
         * Other exceptions should not occur since this functions is only called when the remote endpoint
         * was already identified as RMI endpoint.
         */
        private void scanAct()
        {
            try {
                endpoint.unmanagedCall(OAct, -1, 0L, scanArgs, false, null, null);

            } catch( java.rmi.NoSuchObjectException e ) {
                return;

            } catch ( java.rmi.ServerException e ) {

                Throwable cause = ExceptionHandler.getCause(e);

                if( cause instanceof java.rmi.UnmarshalException && e.getMessage().contains("unrecognized method hash") )
                    this.activator = true;

                else
                    ExceptionHandler.unexpectedException(e, "portscan", "operation", false);

            } catch (Exception e) {
                ExceptionHandler.unexpectedException(e, "portscan", "operation", false);
            }
        }

        /**
         * Print the result of the portscan. Creates a new line for each identified port and
         * lists the corresponding port number and the identified RMI services.
         */
        private void printResult()
        {
            hits += 1;
            StringBuilder sb = new StringBuilder();

            if( registry | activator | dgc ) {

                sb.append("(");

                if( registry )
                    sb.append("Registry, ");

                if( activator )
                    sb.append("Activator, ");

                if( dgc )
                    sb.append("DGC, ");

                sb.setLength(sb.length() - 2);
                sb.append(")");

            } else {
                sb.append("(No known ObjID)");
            }

            String prefix = Logger.blue("[HIT] ");
            String suffix = Logger.blue(sb.toString());

            Logger.printlnMixedYellow(prefix + "Found RMI service(s) on", host + ":" + String.valueOf(port), suffix);
        }
    }
}
