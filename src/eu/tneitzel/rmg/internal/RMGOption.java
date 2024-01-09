package eu.tneitzel.rmg.internal;

import eu.tneitzel.argparse4j.global.IOption;
import eu.tneitzel.argparse4j.global.IOptionGroup;
import eu.tneitzel.argparse4j.global.exceptions.RequirementException;
import eu.tneitzel.argparse4j.global.modifiers.Choices;
import eu.tneitzel.argparse4j.global.modifiers.IArgumentModifier;
import eu.tneitzel.argparse4j.global.modifiers.MetaVar;
import eu.tneitzel.argparse4j.global.modifiers.NArgs;
import eu.tneitzel.argparse4j.global.modifiers.Type;
import eu.tneitzel.argparse4j.impl.Arguments;
import eu.tneitzel.argparse4j.inf.ArgumentAction;

/**
 * The RMGOption enum is an additional helper class to manage command line parameters. remote-method-guesser uses argparse4j
 * to parse command line arguments. After command line arguments were parsed, each of them is stored within one of the enum
 * items contained within the RMGOption class. This allows other parts of the program to access arguments via static references.
 * This is usually not best practice, as it makes the program behavior dependent on a global state, which is usually not what
 * you want. On the other hand, it has some advantages, as certain problems become easy solvable. As remote-method-guesser
 * is not a library, we go with the non best practice approach and enjoy the benefits of having global argument access.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public enum RMGOption implements IOption
{
    /** path to a configuration file */
    GLOBAL_CONFIG("--config",
            "path to a configuration file",
            Arguments.store(),
            RMGOptionGroup.GENERAL,
            new IArgumentModifier[] {
                new MetaVar("path")
            }),

    /** enable verbose output */
    GLOBAL_VERBOSE("--verbose",
            "enable verbose output",
            Arguments.storeTrue(),
            RMGOptionGroup.GENERAL),

    /** file system path to a rmg plugin */
    GLOBAL_PLUGIN("--plugin",
            "file system path to a rmg plugin",
            Arguments.store(),
            RMGOptionGroup.GENERAL,
            new IArgumentModifier[] {
                new MetaVar("path")
            }),

    /** disable colored output */
    GLOBAL_NO_COLOR("--no-color",
            "disable colored output",
            Arguments.storeTrue(),
            RMGOptionGroup.GENERAL),

    /** display stack traces for caught exceptions */
    GLOBAL_STACK_TRACE("--stack-trace",
            "display stack traces for caught exceptions",
            Arguments.storeTrue(),
            RMGOptionGroup.GENERAL),

    /** target host */
    TARGET_HOST("host",
            "target host",
            Arguments.store(),
            RMGOptionGroup.NONE,
            new IArgumentModifier[] {
                    new MetaVar("host")
                }),

    /** target port */
    TARGET_PORT("port",
            "target port",
            Arguments.store(),
            RMGOptionGroup.NONE,
            new IArgumentModifier[] {
                    new MetaVar("port"),
                    new Type(Integer.class)
                }),

    /** target RMI component */
    TARGET_COMPONENT("--component",
            "target RMI component",
            Arguments.store(),
            RMGOptionGroup.TARGET,
            new IArgumentModifier[] {
                    new MetaVar("component"),
                    new Choices("act", "dgc", "reg")
                }),

    /** target bound name within an RMI registry */
    TARGET_BOUND_NAME("--bound-name",
            "target bound name within an RMI registry",
            Arguments.store(),
            RMGOptionGroup.TARGET,
            new IArgumentModifier[] {
                    new MetaVar("name")
                }),

    /** target ObjID */
    TARGET_OBJID("--objid",
            "target ObjID",
            Arguments.store(),
            RMGOptionGroup.TARGET,
            new IArgumentModifier[] {
                    new MetaVar("objid")
                }),

    /** target method signature */
    TARGET_SIGNATURE("--signature",
            "target method signature",
            Arguments.store(),
            RMGOptionGroup.TARGET,
            new IArgumentModifier[] {
                    new MetaVar("signature")
                }),

    /** follow redirects to different servers */
    CONN_FOLLOW("--follow",
            "follow redirects to different servers",
            Arguments.storeTrue(),
            RMGOptionGroup.CONNECTION),

    /** use SSL for connections */
    CONN_SSL("--ssl",
            "use SSL for connections",
            Arguments.storeTrue(),
            RMGOptionGroup.CONNECTION),

    /** scan timeout for read operation */
    SCAN_TIMEOUT_READ("--timeout-read",
            "scan timeout for read operation",
            Arguments.store(),
            RMGOptionGroup.CONNECTION,
            new IArgumentModifier[] {
                    new MetaVar("sec"),
                    new Type(Integer.class)
                }),

    /** scan timeout for connect operation */
    SCAN_TIMEOUT_CONNECT("--timeout-connect",
            "scan timeout for connect operation",
            Arguments.store(),
            RMGOptionGroup.CONNECTION,
            new IArgumentModifier[] {
                    new MetaVar("sec"),
                    new Type(Integer.class)
                }),

    /** print SSRF content as gopher payload */
    SSRF_GOPHER("--gopher",
            "print SSRF content as gopher payload",
            Arguments.storeTrue(),
            RMGOptionGroup.SSRF),

    /** print SSRF payload instead of contacting a server */
    SSRF("--ssrf",
            "print SSRF payload instead of contacting a server",
            Arguments.storeTrue(),
            RMGOptionGroup.SSRF),

    /** evaluate SSRF response from the server */
    SSRFRESPONSE("--ssrf-response",
            "evaluate SSRF response from the server",
            Arguments.store(),
            RMGOptionGroup.SSRF,
            new IArgumentModifier[] {
                    new MetaVar("hex")
                }),

    /** double URL encode the SSRF payload */
    SSRF_ENCODE("--encode",
            "double URL encode the SSRF payload",
            Arguments.storeTrue(),
            RMGOptionGroup.SSRF),

    /** print payload without color and without additional text */
    SSRF_RAW("--raw",
            "print payload without color and without additional text",
            Arguments.storeTrue(),
            RMGOptionGroup.SSRF),

    /** use the stream protocol instead of single operation */
    SSRF_STREAM_PROTOCOL("--stream-protocol",
            "use the stream protocol instead of single operation",
            Arguments.storeTrue(),
            RMGOptionGroup.SSRF),

    /** ObjID of the bound object. */
    BIND_OBJID("--bind-objid",
            "ObjID of the bound object.",
            Arguments.store(),
            RMGOptionGroup.ACTION,
            new IArgumentModifier[] {
                    new MetaVar("objid")
                }),

    /** host specifications the bound remote object should point to */
    BIND_ADDRESS("bind-host",
                 "host specifications the bound remote object should point to",
                 Arguments.store(),
                 RMGOptionGroup.NONE,
                    new IArgumentModifier[] {
                            new MetaVar("host:port"),
                        }),

    /** Bound name to use for (un)bind action */
    BIND_BOUND_NAME("bound-name",
            "Bound name to use for (un)bind action",
            Arguments.store(),
            RMGOptionGroup.NONE,
            new IArgumentModifier[] {
                    new MetaVar("name"),
                }),

    /** attempt localhost bypass (CVE-2019-2684) */
    BIND_BYPASS("--localhost-bypass",
            "attempt localhost bypass (CVE-2019-2684)",
            Arguments.storeTrue(),
            RMGOptionGroup.ACTION),

    /** attempt to bind the specified gadget instead of JMXServer */
    BIND_GADGET_NAME("--gadget-name",
                     "attempt to bind the specified gadget instead of JMXServer",
                     Arguments.store(),
                     RMGOptionGroup.ACTION,
                        new IArgumentModifier[] {
                                new MetaVar("gadget"),
                            }),

    /** command for a custom gadget */
    BIND_GADGET_CMD("--gadget-cmd",
                    "command for a custom gadget",
                    Arguments.store(),
                    RMGOptionGroup.ACTION,
                    new IArgumentModifier[] {
                            new MetaVar("cmd"),
                        }),

    /** classname to load during codebase attack */
    CODEBASE_CLASS("classname",
            "classname to load during codebase attack",
            Arguments.store(),
            RMGOptionGroup.NONE,
            new IArgumentModifier[] {
                    new MetaVar("name"),
                }),

    /** codebase URL to load the payload from */
    CODEBASE_URL("url",
            "codebase URL to load the payload from",
            Arguments.store(),
            RMGOptionGroup.NONE,
            new IArgumentModifier[] {
                    new MetaVar("url"),
                }),

    /** IP address to start the listener on */
    LISTEN_IP("ip",
            "IP address to start the listener on",
            Arguments.store(),
            RMGOptionGroup.NONE,
            new IArgumentModifier[] {
                    new MetaVar("IP"),
                }),

    /** port number to start the listener on */
    LISTEN_PORT("port",
            "port number to start the listener on",
            Arguments.store(),
            RMGOptionGroup.NONE,
            new IArgumentModifier[] {
                    new MetaVar("port"),
                    new Type(Integer.class)
                }),

    /** ObjID to use for the JMX listener */
    ROGUEJMX_OBJID("--objid",
            "ObjID to use for the JMX listener",
            Arguments.store(),
            RMGOptionGroup.ACTION,
            new IArgumentModifier[] {
                    new MetaVar("objid")
                }),

    /** host to forward incoming JMX connections to */
    ROGUEJMX_FORWARD_HOST("--forward-host",
            "host to forward incoming JMX connections to",
            Arguments.store(),
            RMGOptionGroup.ACTION,
            new IArgumentModifier[] {
                    new MetaVar("host"),
                }),
    /** port to forward incoming JMX connections to */
    ROGUEJMX_FORWARD_PORT("--forward-port",
            "port to forward incoming JMX connections to",
            Arguments.store(),
            RMGOptionGroup.ACTION,
            new IArgumentModifier[] {
                    new MetaVar("port"),
                    new Type(Integer.class)
                }),

    /** bound name to forward incoming JMX connections to */
    ROGUEJMX_FORWARD_BOUND_NAME("--forward-bound-name",
            "bound name to forward incoming JMX connections to",
            Arguments.store(),
            RMGOptionGroup.ACTION,
            new IArgumentModifier[] {
                    new MetaVar("name")
                }),

    /** ObjID to forward incoming JMX connections to */
    ROGUEJMX_FORWARD_OBJID("--forward-objid",
            "ObjID to forward incoming JMX connections to",
            Arguments.store(),
            RMGOptionGroup.ACTION,
            new IArgumentModifier[] {
                    new MetaVar("objid"),
                }),

    /** wordlist file to use for method guessing */
    GUESS_WORDLIST_FILE("--wordlist-file",
            "wordlist file to use for method guessing",
            Arguments.store(),
            RMGOptionGroup.ACTION,
            new IArgumentModifier[] {
                    new MetaVar("path"),
                }),

    /** location of the wordlist folder */
    GUESS_WORDLIST_FOLDER("--wordlist-folder",
            "location of the wordlist folder",
            Arguments.store(),
            RMGOptionGroup.ACTION,
            new IArgumentModifier[] {
                    new MetaVar("path"),
                }),

    /** create sample classes for identified methods */
    GUESS_CREATE_SAMPLES("--create-samples",
            "create sample classes for identified methods",
            Arguments.storeTrue(),
            RMGOptionGroup.ACTION),

    /** folder used for sample generation */
    GUESS_SAMPLE_FOLDER("--sample-folder",
            "folder used for sample generation",
            Arguments.store(),
            RMGOptionGroup.ACTION,
            new IArgumentModifier[] {
                    new MetaVar("path"),
                }),

    /** location of the template folder */
    GUESS_TEMPLATE_FOLDER("--template-folder",
            "location of the template folder",
            Arguments.store(),
            RMGOptionGroup.ACTION,
            new IArgumentModifier[] {
                    new MetaVar("path"),
                }),

    /** disable bound name filtering */
    GUESS_TRUSTED("--trusted",
            "disable bound name filtering",
            Arguments.storeTrue(),
            RMGOptionGroup.ACTION),

    /** force guessing on known remote objects */
    GUESS_FORCE_GUESSING("--force-guessing",
            "force guessing on known remote objects",
            Arguments.storeTrue(),
            RMGOptionGroup.ACTION),

    /** guess duplicate remote classes */
    GUESS_DUPLICATES("--guess-duplicates",
            "guess duplicate remote classes",
            Arguments.storeTrue(),
            RMGOptionGroup.ACTION),

    /** update wordlist file with method hashes */
    GUESS_UPDATE("--update",
            "update wordlist file with method hashes",
            Arguments.storeTrue(),
            RMGOptionGroup.ACTION),

    /** allow guessing on void functions (dangerous) */
    GUESS_ZERO_ARG("--zero-arg",
            "allow guessing on void functions (dangerous)",
            Arguments.storeTrue(),
            RMGOptionGroup.ACTION),

    /** gadget name to use for the deserialization attack */
    GADGET_NAME("gadget",
            "gadget name to use for the deserialization attack",
            Arguments.store(),
            RMGOptionGroup.NONE,
            new IArgumentModifier[] {
                    new MetaVar("gadget"),
                }),

    /** command to pass for the specified gadget */
    GADGET_CMD("cmd",
            "command to pass for the specified gadget",
            Arguments.store(),
            RMGOptionGroup.NONE,
            new IArgumentModifier[] {
                    new MetaVar("cmd"),
                }),

    /** attempt localhost bypass during enum */
    ENUM_BYPASS("--localhost-bypass",
            "attempt localhost bypass during enum",
            Arguments.storeTrue(),
            RMGOptionGroup.ACTION),

    /** scan actions to perform during the enumeration */
    ENUM_ACTION("--scan-action",
            "scan actions to perform during the enumeration",
            Arguments.store(),
            RMGOptionGroup.ACTION,
            new IArgumentModifier[] {
                    new MetaVar("action"),
                    new Choices("activator", "codebase", "filter-bypass", "jep290",
                        "list", "localhost-bypass", "security-manager", "string-marshalling"),
                    new NArgs("+"),
                }),

    /** host to perform the scan on */
    SCAN_HOST("host",
            "host to perform the scan on",
            Arguments.store(),
            RMGOptionGroup.NONE,
            new IArgumentModifier[] {
                    new MetaVar("host"),
                }),

    /** port specifications to perform the portscan on */
    SCAN_PORTS("--ports",
            "port specifications to perform the portscan on",
            Arguments.store(),
            RMGOptionGroup.ACTION,
            new IArgumentModifier[] {
                    new MetaVar("port"),
                    new NArgs("+")
                }),

    /** argument string to use for the call */
    CALL_ARGUMENTS("arguments",
            "argument string to use for the call",
            Arguments.store(),
            RMGOptionGroup.NONE,
            new IArgumentModifier[] {
                    new MetaVar("args"),
                }),

    /** ObjID string to parse */
    OBJID_OBJID("objid",
            "ObjID string to parse",
            Arguments.store(),
            RMGOptionGroup.NONE,
            new IArgumentModifier[] {
                    new MetaVar("objid"),
                }),

    /** classname to check within the database */
    KNOWN_CLASS("classname",
            "classname to check within the database",
            Arguments.store(),
            RMGOptionGroup.NONE,
            new IArgumentModifier[] {
                    new MetaVar("name"),
                }),

    /** enable activation for ActivatableRef */
    ACTIVATION("--activate",
            "enable activation for ActivatableRef",
            Arguments.storeTrue(),
            RMGOptionGroup.ACTION),

    /** force activation of ActivatableRef */
    FORCE_ACTIVATION("--force-activation",
            "force activation of ActivatableRef",
            Arguments.storeTrue(),
            RMGOptionGroup.ACTION),

    /** payload argument position */
    ARGUMENT_POS("--position",
            "payload argument position",
            Arguments.store(),
            RMGOptionGroup.ACTION,
            new IArgumentModifier[] {
                    new MetaVar("pos"),
                    new Type(Integer.class),
                }),

    /** do not use a canary during RMI attacks */
    NO_CANARY("--no-canary",
            "do not use a canary during RMI attacks",
            Arguments.storeTrue(),
            RMGOptionGroup.ACTION),

    /** disable progress bars */
    NO_PROGRESS("--no-progress",
            "disable progress bars",
            Arguments.storeTrue(),
            RMGOptionGroup.ACTION),

    /** maximum number of threads (default: 5) */
    THREADS("--threads",
            "maximum number of threads (default: 5)",
            Arguments.store(),
            RMGOptionGroup.ACTION,
            new IArgumentModifier[] {
                    new MetaVar("threads"),
                    new Type(Integer.class)
                }),

    /** location of ysoserial.jar for deserialization attacks */
    YSO("--yso",
            "location of ysoserial.jar for deserialization attacks",
            Arguments.store(),
            RMGOptionGroup.ACTION,
            new IArgumentModifier[] {
                    new MetaVar("path"),
                }),

    /** method to use for dgc operations */
    DGC_METHOD("--dgc-method",
            "method to use for dgc operations",
            Arguments.store(),
            RMGOptionGroup.ACTION,
            new IArgumentModifier[] {
                    new MetaVar("method"),
                    new Choices("clean", "dirty"),
                }),

    /** method to use for registry operations */
    REG_METHOD("--registry-method",
            "method to use for registry operations",
            Arguments.store(),
            RMGOptionGroup.ACTION,
            new IArgumentModifier[] {
                    new MetaVar("method"),
                    new Choices("lookup", "unbind", "rebind", "bind"),
                }),

    /** serialVersionUID to use for RMI stubs */
    SERIAL_VERSION_UID("--serial-version-uid",
            "serialVersionUID to use for RMI stubs",
            Arguments.store(),
            RMGOptionGroup.ACTION,
            new IArgumentModifier[] {
                    new MetaVar("uid"),
                    new Type(Long.class)
                }),

    /** serialVersionUID to use for payload classes */
    PAYLOAD_SERIAL_VERSION_UID("--payload-serial-version-uid",
            "serialVersionUID to use for payload classes",
            Arguments.store(),
            RMGOptionGroup.ACTION,
            new IArgumentModifier[] {
                    new MetaVar("uid"),
                    new Type(Long.class)
                }),

    /** enforce plaintext connections from dynamically created socket factories */
    SOCKET_FACTORY_PLAIN("--socket-factory-plain",
            "enforce plaintext connections from dynamically created socket factories",
            Arguments.storeTrue(),
            RMGOptionGroup.CONNECTION),

    /** enforce SSL connections from dynamically created socket factories */
    SOCKET_FACTORY_SSL("--socket-factory-ssl",
            "enforce SSL connections from dynamically created socket factories",
            Arguments.storeTrue(),
            RMGOptionGroup.CONNECTION),

    /** dynamically create a socket factory class with the specified name */
    SOCKET_FACTORY("--socket-factory",
            "dynamically create a socket factory class with the specified name",
            Arguments.store(),
            RMGOptionGroup.CONNECTION,
            new IArgumentModifier[] {
                    new MetaVar("class-name"),
                }),

    /** enforce method calls to be dispatched via spring remoting */
    SPRING_REMOTING("--spring-remoting",
            "enforce method calls to be dispatched via spring remoting",
            Arguments.storeTrue(),
            RMGOptionGroup.CONNECTION),

    /** attempt to output the return value using GenericPrint */
    GENERIC_PRINT("--generic-print",
            "attempt to output the return value using GenericPrint",
            Arguments.storeTrue(),
            RMGOptionGroup.ACTION);

    /** the name of the option */
    private final String name;
    /** description of the option */
    private final String description;
    /** argumentAction of the option */
    private final ArgumentAction argumentAction;
    /** argumentAction of the option */
    private final IArgumentModifier[] modifiers;
    /**  RMGOptionGroup of the option */
    private IOptionGroup optionGroup = null;
    /** the value of the option */
    public Object value = null;

    /**
     * Initialize an RMGOption.
     *
     * @param name the name of the option
     * @param description the description of the option
     * @param argumentAction the associated argument action (store, storeTrue, etc.)
     * @param optionGroup the associated option group
     */
    RMGOption(String name, String description, ArgumentAction argumentAction, IOptionGroup optionGroup)
    {
        this(name, description, argumentAction, optionGroup, new IArgumentModifier[] {});
    }

    /**
     * Initialize an RMGOption.
     *
     * @param name the name of the option
     * @param description the description of the option
     * @param argumentAction the associated argument action (store, storeTrue, etc.)
     * @param optionGroup the associated option group
     * @param modifiers the argumentModifiers for the option
     */
    RMGOption(String name, String description, ArgumentAction argumentAction, IOptionGroup optionGroup, IArgumentModifier[] modifiers)
    {
        this.name = name;
        this.description = description;
        this.argumentAction = argumentAction;
        this.optionGroup = optionGroup;
        this.modifiers = modifiers;
    }

    /**
     * Returns the value stored within the option.
     *
     * @param <T> type of the value
     * @return value stored within the option
     */
    @SuppressWarnings("unchecked")
    public <T> T getValue()
    {
        try {
            return (T)value;

        } catch( ClassCastException e ) {
            ExceptionHandler.internalError("RMGOption.getValue", "ClassCastException was caught.");
        }

        return null;
    }

    /**
     * Sets the option to the specified value.
     *
     * @param value Object value to set for this option
     */
    public void setValue(Object value)
    {
        this.value = value;
    }

    /**
     * Helper function that calls requireOneOf with target related options. This is used by functions that require
     * a target that could either be an RMI component, a bound name or an ObjID.
     */
    public static void requireTarget()
    {
        try
        {
            IOption.requireOneOf(RMGOption.TARGET_COMPONENT, RMGOption.TARGET_OBJID, RMGOption.TARGET_BOUND_NAME);
        }

        catch (RequirementException e)
        {
            ExceptionHandler.requirementException(e);
        }
    }

    @Override
    public ArgumentAction getArgumentAction()
    {
        return argumentAction;
    }

    @Override
    public IArgumentModifier[] getArgumentModifiers()
    {
        return modifiers;
    }

    @Override
    public String getDescription()
    {
        return description;
    }

    @Override
    public IOptionGroup getGroup()
    {
        return optionGroup;
    }

    @Override
    public String getName()
    {
        return name;
    }
}
