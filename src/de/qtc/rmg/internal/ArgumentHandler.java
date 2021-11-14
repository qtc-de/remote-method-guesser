package de.qtc.rmg.internal;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

import de.qtc.rmg.io.Logger;
import de.qtc.rmg.operations.Operation;
import de.qtc.rmg.operations.PortScanner;
import de.qtc.rmg.operations.ScanAction;
import de.qtc.rmg.plugin.PluginSystem;
import de.qtc.rmg.utils.RMGUtils;
import net.sourceforge.argparse4j.ArgumentParsers;
import net.sourceforge.argparse4j.inf.ArgumentParser;
import net.sourceforge.argparse4j.inf.ArgumentParserException;
import net.sourceforge.argparse4j.inf.Namespace;
import net.sourceforge.argparse4j.inf.Subparsers;

/**
 * The ArgumentHandler class is a wrapper around an argparse4j ArgumentParser. It adds some
 * additional functionality that is useful for other parts of the program. Especially, it
 * initializes the RMGOption enum, which is used for global argument access.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class ArgumentHandler {

    private Namespace args;
    private ArgumentParser parser;
    private Properties config;

    private String regMethod = null;
    private String dgcMethod = null;
    private Operation action = null;
    private RMIComponent component = null;

    private  String defaultConfiguration = "/config.properties";

    /**
     * Creates the ArgumentParser used for remote-method-guesser and adds the desired arguments
     * and ArgumentGroups. Also starts the initialization of the RMGOption enum.
     *
     * @param argv Argument array as specified on the command line.
     */
    public ArgumentHandler(String[] argv)
    {
        parser = ArgumentParsers.newFor("remote-method-guesser").build();
        parser.description("rmg v" + ArgumentHandler.class.getPackage().getImplementationVersion() + " - a Java RMI Vulnerability Scanner");

        Subparsers subparsers = parser.addSubparsers().help(" ").metavar("action").dest("action");
        Operation.addSubparsers(subparsers);

        try {
            args = parser.parseArgs(argv);

        } catch (ArgumentParserException e) {
            parser.handleError(e);
            System.exit(1);
        }

        initialize();
    }

    /**
     * Loads the remote-method-guesser configuration file from the specified destination. The default configuration
     * is always loaded. If the filename parameter is not null, an additional user specified config is loaded, that
     * may overwrites some configurations.
     *
     * @param filename file system path to load the configuration file from
     */
    private Properties loadConfig(String filename)
    {
        Properties config = new Properties();

        try {
            InputStream configStream = null;

            configStream = ArgumentParser.class.getResourceAsStream(defaultConfiguration);
            config.load(configStream);
            configStream.close();

            if( filename != null ) {
                configStream = new FileInputStream(filename);
                config.load(configStream);
                configStream.close();
            }

        } catch( IOException e ) {
            ExceptionHandler.unexpectedException(e, "loading", ".properties file", true);
        }

        return config;
    }


    /**
     * Initializes the RMGOption enum and sets some static variables depending on the specified options.
     */
    private void initialize()
    {
        config = loadConfig(args.get(RMGOption.GLOBAL_CONFIG.name));
        RMGOption.prepareOptions(args, config);

        if( RMGOption.GLOBAL_NO_COLOR.getBool() )
            Logger.disableColor();

        PluginSystem.init(RMGOption.GLOBAL_PLUGIN.getValue());
    }

    /**
     * Returns the user specified remote-method-guesser action.
     *
     * @return Operation requested by the client
     */
    public Operation getAction()
    {
        this.action = Operation.getByName(args.getString("action"));

        if( action == null )
            ExceptionHandler.internalError("ArgumentHandler.getAction", "Invalid action was specified");

        return action;
    }

    /**
     * During registry related rmg operations, users can select the registry method
     * that is used for the different RMI calls. This is done by using the --signature
     * option. In contrast to custom remote objects, the method signature is not really
     * parsed. It is only checked for specific keywords and the corresponding registry
     * methods signature is chosen automatically.
     *
     * @return method to use for registry operations - if valid.
     */
    public String getRegMethod()
    {
        if( regMethod != null )
            return regMethod;

        String signature = RMGOption.REG_METHOD.getValue();
        String[] supported =  new String[]{"lookup", "unbind", "rebind", "bind"};

        if( signature == null ) {
            regMethod = "lookup";
            return regMethod;
        }

        for(String methodName : supported ) {

            if( signature.contains(methodName) ) {
                regMethod = methodName;
                return methodName;
            }
        }

        Logger.eprintlnMixedYellow("Unsupported registry method:", signature);
        Logger.eprintlnMixedBlue("Support values are", String.join(", ", supported));
        RMGUtils.exit();

        return null;
    }

    /**
     * During DGC related rmg operations, users can select the DGC method
     * that is used for the different RMI calls. This is done by using the --signature
     * option. In contrast to custom remote objects, the method signature is not really
     * parsed. It is only checked for specific keywords and the corresponding DGC
     * methods signature is chosen automatically.
     *
     * @return method to use for DGC operations - if valid.
     */
    public String getDgcMethod()
    {
        if( dgcMethod != null )
            return dgcMethod;

        String signature = RMGOption.DGC_METHOD.getValue();

        if( signature == null ) {
            dgcMethod = "clean";
            return dgcMethod;
        }

        for(String methodName : new String[]{"clean", "dirty"} ) {

            if( signature.contains(methodName) ) {
                dgcMethod = methodName;
                return methodName;
            }
        }

        Logger.eprintlnMixedYellow("Unsupported DGC method:", signature);
        Logger.eprintMixedBlue("Support values are", "clean", "and ");
        Logger.printlnPlainBlue("dirty");
        RMGUtils.exit();

        return null;
    }

    /**
     * Parse the user specified --component value. This function verifies that the value
     * matches one of the supported values: act, dgc or reg.
     *
     * @return user specified component value - if valid.
     */
    public RMIComponent getComponent()
    {
        if( component != null )
            return component;

        RMIComponent targetComponent = RMIComponent.getByShortName(RMGOption.TARGET_COMPONENT.getValue());

        if( targetComponent == null )
            return null;

        switch( targetComponent ) {

            case REGISTRY:
            case DGC:
            case ACTIVATOR:
                break;

            default:
                Logger.eprintlnMixedYellow("Unsupported RMI component:", RMGOption.TARGET_COMPONENT.getValue());
                Logger.eprintMixedBlue("Supported values are", RMIComponent.ACTIVATOR.shortName + ", " + RMIComponent.DGC.shortName, "and ");
                Logger.printlnPlainBlue(RMIComponent.REGISTRY.shortName);
                RMGUtils.exit();
        }

        component = targetComponent;

        return targetComponent;
    }

    /**
     * Parses the user specified gadget arguments to request a corresponding gadget from the PayloadProvider.
     * The corresponding gadget object is returned.
     *
     * @return gadget object build from the user specified arguments
     */
    public Object getGadget()
    {
        String gadget = null;
        String command = null;

        if( this.getAction() == Operation.BIND || this.getAction() == Operation.REBIND ) {
            gadget = "jmx";
            command = RMGOption.require(RMGOption.BIND_ADDRESS);

        } else {
            gadget = (String) RMGOption.require(RMGOption.GADGET_NAME);
            command = RMGOption.require(RMGOption.GADGET_CMD);
        }

        return PluginSystem.getPayloadObject(this.getAction(), gadget, command);
    }

    /**
     * Parses the user specified argument string during a call action. Passes the string to the corresponding
     * ArgumentProvider and returns the result argument array.
     *
     * @return Object array resulting from the specified argument string
     */
    public Object[] getCallArguments()
    {
        String argumentString = (String) RMGOption.require(RMGOption.CALL_ARGUMENTS);
        return PluginSystem.getArgumentArray(argumentString);
    }

    /**
     * Is used when the enum action was specified. The enum action allows users to limit enumeration to certain
     * scan actions. This function parses the user supplied arguments and checks which scan actions were requested.
     * The corresponding actions are returned as EnumSet.
     *
     * @return EnumSet of ScanAction which were requested by the user.
     */
    public EnumSet<ScanAction> getScanActions()
    {
        String[] scanActions = (String[]) RMGOption.ENUM_ACTION.value;

        if( scanActions == null )
            return EnumSet.allOf(ScanAction.class);

        return ScanAction.parseScanActions(Arrays.asList(scanActions));
    }

    /**
     * Is used to parse the port specification for the scan operation. For the scan operation, the
     * second port argument can be a range (e.g. 10-1000), a list (e.g. 1090-1099,9000,9010) a single
     * port (e.g. 1090) or the keyword "-" (scans all rmi ports configured in the config file). This
     * function parses the user specified value and returns the corresponding int array that needs to
     * be scanned.
     *
     * @return array of int which contains all ports that should be scanned
     */
    public int[] getRmiPots()
    {
        Set<Integer> rmiPorts = new HashSet<Integer>();

        String defaultPorts = config.getProperty("rmi_ports");
        String[] portStrings = (String[]) RMGOption.SCAN_PORTS.value;

        for(String portString : portStrings) {

            if( portString.equals("-") )
                addPorts(defaultPorts, rmiPorts);

            else
                addPorts(portString, rmiPorts);
        }

        return rmiPorts.stream().mapToInt(i->i).toArray();
    }

    /**
     * Helper function that handles port lists.
     *
     * @param portString user specified port string
     * @param portList Set of Integer where parsed ports are added
     */
    public void addPorts(String portString, Set<Integer> portList)
    {
        String[] ports = portString.split(",");

        for(String port: ports) {
            addRange(port, portList);
        }
    }

    /**
     * Helper function that handles port ranges.
     *
     * @param portString user specified port string
     * @param portList Set of Integer where parsed ports are added
     */
    public void addRange(String portRange, Set<Integer> portList)
    {
        try {

            if(!portRange.contains("-")) {
                portList.add(Integer.valueOf(portRange));
                return;
            }

            String[] split = portRange.split("-");
            int start = Integer.valueOf(split[0]);
            int end = Integer.valueOf(split[1]);

            for(int ctr = start; ctr <= end; ctr++)
                portList.add(ctr);

        } catch( java.lang.NumberFormatException | java.lang.ArrayIndexOutOfBoundsException e ) {
            Logger.eprintlnMixedYellow("Caught unexpected", e.getClass().getSimpleName(), "while parsing RMI ports.");
            Logger.eprintlnMixedBlue("The specified value", portRange, "is invalid.");
            RMGUtils.exit();
        }
    }

    /**
     * Is called when the scan action was requested. Sets custom timeout values for RMI socket
     * operations, as the default values are not well suited for portscanning.
     *
     * This function needs to be called early before the corresponding RMI classes are loaded.
     */
    public void setSocketTimeout()
    {
        String scanTimeoutRead = RMGOption.SCAN_TIMEOUT_READ.getValue();
        String scanTimeoutConnect = RMGOption.SCAN_TIMEOUT_CONNECT.getValue();

        System.setProperty("sun.rmi.transport.connectionTimeout", scanTimeoutConnect);
        System.setProperty("sun.rmi.transport.tcp.handshakeTimeout", scanTimeoutRead);
        System.setProperty("sun.rmi.transport.tcp.responseTimeout", scanTimeoutRead);

        PortScanner.setSocketTimeouts(scanTimeoutRead, scanTimeoutConnect);
    }
}
