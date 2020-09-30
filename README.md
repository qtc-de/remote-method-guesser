### Remote Method Guesser

---

*remote-method-guesser* (*rmg*) is a command line utility written in *Java*. It allows to identify available methods
on *Java RMI* endpoints without requiring the corresponding interface definition. Exposed methods are identified by
using a bruteforce approach that relies on *method-wordlists* that can be defined by the user.

![](https://github.com/qtc-de/remote-method-guesser/workflows/master%20maven%20CI/badge.svg?branch=master)
![](https://github.com/qtc-de/remote-method-guesser/workflows/develop%20maven%20CI/badge.svg?branch=develop)


### Remote Method Guessing

-----

*Remote Method Guessing* is a technique to identify available methods on *Java* interfaces that are exposed by *Java RMI* servers.
Before talking about the tool itself, let's look do a brief reminder on *Java RMI*:

#### What is Java RMI?

*Java RMI* stands for *Java Remote Method Invocation* and can be used to invoke methods on remote objects. With *Java RMI*,
an *RMI* server can implement a class and make it available over the network. Other clients can then create instances
of this class and invoke methods on it, as with classes that are defined locally. However, the clue is that these method
calls are dispatched and executed on the *RMI* server.

![Java RMI](/resources/images/01-rmi-overview.png)

#### The Registry

When an *RMI* server wants to expose a *Java Object* over the network, it usually registers the object on a *RMI registry* server.
The *RMI registry* is basically like a *DNS* service for *Remote Objects*. Then a client wants to communicate with a remote
object, it looks up the name inside the *RMI registry*, which responds with the location (``ip:port:ObjectID``) where the remote object 
can be found. Therefore, one could also describe the *RMI registry* as a portmapper for *RMI* services.

#### Hidden Interfaces

With builtin methods of *Java RMI* one can easily dump the names of all registered objects on an *RMI registry* endpoint.
However, in order to instantiate a remote class and to do something useful with it, the local *Java Virtual Machine*
needs to know the remote class interface. In the actual use cases of *Java RMI* this is reasonable, since a vendor can
ship the class interfaces together with the actual client software. But for a black box security assessment, it is pretty frustrating,
as you may encounter promising remote class names like 'server-manager' and cannot communicate to them.

Here comes *Remote Method Guessing* into play. The idea is pretty simple: One creates a dummy interface for the targeted class
and fills it with some guessed method names:

```java
package <PACKAGENAME>;

import java.rmi.Remote;
import java.rmi.RemoteException;

public interface <CLASSNAME> extends Remote {
    String exec(String dummy) throws RemoteException;
    String exec(String dummy, String dummy2) throws RemoteException;
    String exec(String dummy, String dummy2, String dummy3) throws RemoteException;
    String execute(String dummy) throws RemoteException;
    String execute(String dummy, String dummy2) throws RemoteException;
    String execute(String dummy, String dummy2, String dummy3) throws RemoteException;
    [...]
```

By calling all the defined methods in the *dummy interface*, it is now possible to enumerate available methods on the remote object.
Method class will fail when the corresponding method signature does not exist on the server side, which leads to a corresponding
(*RMI* specific) exception. This exception can be caught and interpreted as ``method does not exist``.
However, once an existing method is hit, the *RMI* server will respond with a different exception, like e.g. a ``NullPointer Exception``
or non exception at all. Such a result can be interpreted as ``method exists on the remote object``.


### Installation

------

*rmg* is a *maven* project and the installation should be straight forward. With maven installed, just execute
the following commands to create an executable ``.jar`` file:

```console
$ git clone https://github.com/qtc-de/remote-method-guesser
$ cd remote-method-guesser
$ mvn package
```

*rmg* does also support autocompletion for bash. To take advantage of autocompletion, you need to have the
[completion-helpers](https://github.com/qtc-de/completion-helpers) project installed. If setup correctly, just
copying the [completion script](./resources/bash_completion.d/rmg) to your ``~/.bash_completion.d`` folder enables
autocompletion.

```console
$ cp resources/bash_completion.d/rmg ~/bash_completion.d/
```


### Example Workflow & Proof of Concept

-----

Apart from the actual *rmg* tool, this repository also contains an example server in form of a docker container. In the following,
this container is used for demonstration purposes. If you want to try out *rmg* yourself, you can either build the container from
[source](./docker) or use the pre-build container from [GitHub Packages](https://github.com/qtc-de/remote-method-guesser/packages/414459).

The following output shows an *nmap scan* that was run against the example server:

```console
[qtc@kali ~]$ nmap -p- -sV 172.17.0.2
Starting Nmap 7.80 ( https://nmap.org ) at 2020-09-30 06:20 CEST
Nmap scan report for iinsecure.dev (172.17.0.2)
Host is up (0.000077s latency).
Not shown: 65532 closed ports
PORT      STATE SERVICE     VERSION
1090/tcp  open  ssl/ff-fms?
33917/tcp open  ssl/unknown
36813/tcp open  java-rmi    Java RMI

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.55 seconds
```

Although the version detection (``-sV``) switch was used, *nmap* was not able to detect the *rmiregistry* running on port ``1090``.
The reason is that the *rmiregistry* of the provided example container is *SSL* protected, which is not recognized by *nmap*. However,
from the appearance of some *RMI related* ports, it can be guessed that there has to be a *rmiregistry*.

After detecting an *rmiregistry* endpoint, the first thing you probably want to do is to list the available *bound names*. Using *nmap*
or *Metasploit* would not work in this case, as these tools are not compatible with *SSL* protected registry servers. However,
*rmg* can get the job done:

```console
[pentester@kali ~]$ rmg --ssl 172.17.0.2 1090
[+] Connecting to RMI registry... done.
[+] Obtaining a list of bound names... done.
[+] 3 names are bound to the registry.
[+] Listing bound names in registry:
[+]	• plain-server
[+]	• ssl-server
[+]	• secure-server
```

If you want to obtain more information on the exposed *bound names*, you can add the ``--classes`` switch. This displays the
*package* and *classname* behind the available *bound names*.

```console
[pentester@kali ~]$ rmg --ssl --classes 172.17.0.2 1090
[+] Connecting to RMI registry... done.
[+] Obtaining a list of bound names... done.
[+] 3 names are bound to the registry.
[-] RMI object tries to connect to different remote host: iinsecure.dev
[-] 	Redirecting the connection back to 172.17.0.2... 
[-] 	This is done for all further requests. This message is not shown again. 
[-] RMI object tries to connect to different remote host: iinsecure.dev
[-] 	Redirecting the ssl connection back to 172.17.0.2... 
[-] 	This is done for all further requests. This message is not shown again. 
[+] Listing bound names in registry:
[+]	• plain-server
[+]	  --> de.qtc.rmg.IPlainServer (unknown class)
[+]	• ssl-server
[+]	  --> de.qtc.rmg.ISslServer (unknown class)
[+]	• secure-server
[+]	  --> de.qtc.rmg.ISecureServer (unknown class)
```

In the above example, you can see another feature of *rmg*: *automatic redirection*. During the startup of the *rmiregistry*, developers
can assign a *hostname* that is inherited to all exported *remote objects*. All connection attempts are then targeted to this *host name*
instead of the actual targeted server. You can usually circumvent this issue by adding the corresponding hostname to your ``/etc/hosts``
file, but *rmg* does take care of it automatically for you.

After listing the available *bound names* you may finally want to attempt a *method guessing attack*. This can be done by using the
``--guess`` switch. Additionally, you can specify the ``--create-samples`` switch to create *code samples* for each identified method.
The code samples contain a basic skeleton that can be used to interact with the identified remote method and can be used for further
investigations. The default output of *rmg* is pretty verbose, but the important information is highlighted within color aware terminals.

```console
[qtc@kali ~]$ rmg --ssl --guess --create-samples 172.17.0.2 1090
[+] Connecting to RMI registry... done.
[+] Obtaining a list of bound names... done.
[+] 3 names are bound to the registry.
[-] RMI object tries to connect to different remote host: iinsecure.dev
[-] 	Redirecting the connection back to 172.17.0.2... 
[-] 	This is done for all further requests. This message is not shown again. 
[-] RMI object tries to connect to different remote host: iinsecure.dev
[-] 	Redirecting the ssl connection back to 172.17.0.2... 
[-] 	This is done for all further requests. This message is not shown again. 
[+] 
[+] Starting RMG Attack
[+] 	4 template files found.
[+] 	Compiling file /opt/remote-method-guesser/templates//LookupDummy.java... done.
[+] 	
[+] 	Current template file: 'VoidTemplate.java'
[+] 	
[+] 		Attacking boundName 'ssl-server'.
[+] 		Reading template file: '/opt/remote-method-guesser/templates//VoidTemplate.java'... done
[+] 		Writing class './rmg-src/ISslServer.java' to disk... done.
[+] 		Compiling file ./rmg-src/ISslServer.java... done.
[+] 		Getting instance of 'ssl-server'...
[+] 		Guessing methods...
[+]
[+] 		
[+] 		0 valid method names were identified for 'VoidTemplate.java'.
[+] 		Attacking boundName 'plain-server'.
[+] 		Reading template file: '/opt/remote-method-guesser/templates//VoidTemplate.java'... done
[+] 		Writing class './rmg-src/IPlainServer.java' to disk... done.
[+] 		Compiling file ./rmg-src/IPlainServer.java... done.
[+] 		Getting instance of 'plain-server'...
[+] 		Guessing methods...
[+]
[+] 		
[+] 		0 valid method names were identified for 'VoidTemplate.java'.
[+] 		Attacking boundName 'secure-server'.
[+] 		Reading template file: '/opt/remote-method-guesser/templates//VoidTemplate.java'... done
[+] 		Writing class './rmg-src/ISecureServer.java' to disk... done.
[+] 		Compiling file ./rmg-src/ISecureServer.java... done.
[+] 		Getting instance of 'secure-server'...
[+] 		Guessing methods...
[+]
[+] 			HIT: public abstract void de.qtc.rmg.ISecureServer.logMessage(int,java.lang.Object) throws java.rmi.RemoteException --> exists!
[+] 			HIT: public abstract void de.qtc.rmg.ISecureServer.updatePreferences(java.util.ArrayList) throws java.rmi.RemoteException --> exists!
[+] 		
[+] 		2 valid method names were identified for 'VoidTemplate.java'.
[+] 		Writing sample class for method 'logMessage'.
[+] 			Reading template file: '/opt/remote-method-guesser/templates//SampleTemplate.java'... done
[+] 			Preparing sample... done.
[+] 			Writing sample '/home/pentester/rmg-samples/ISecureServerLogMessageSample/ISecureServerLogMessageSample.java' to disk... done.
[+] 			Writing sample interface '/home/pentester/rmg-samples/ISecureServerLogMessageSample/ISecureServer.java' to disk... done.
[+] 		
[+] 		Writing sample class for method 'updatePreferences'.
[+] 			Reading template file: '/opt/remote-method-guesser/templates//SampleTemplate.java'... done
[+] 			Preparing sample... done.
[+] 			Writing sample '/home/pentester/rmg-samples/ISecureServerUpdatePreferencesSample/ISecureServerUpdatePreferencesSample.java' to disk... done.
[+] 			Writing sample interface '/home/pentester/rmg-samples/ISecureServerUpdatePreferencesSample/ISecureServer.java' to disk... done.
[+] 		
[+] 	
[+] 	Current template file: 'StringTemplate.java'
[+] 	
[+] 		Attacking boundName 'ssl-server'.
[+] 		Reading template file: '/opt/remote-method-guesser/templates//StringTemplate.java'... done
[+] 		Writing class './rmg-src/ISslServer.java' to disk... done.
[+] 		Compiling file ./rmg-src/ISslServer.java... done.
[+] 		Getting instance of 'ssl-server'...
[+] 		Guessing methods...
[+]
[+] 			HIT: public abstract java.lang.String de.qtc.rmg.ISslServer.system(java.lang.String[]) throws java.rmi.RemoteException --> exists!
[+] 		
[+] 		1 valid method names were identified for 'StringTemplate.java'.
[+] 		Writing sample class for method 'system'.
[+] 			Reading template file: '/opt/remote-method-guesser/templates//SampleTemplate.java'... done
[+] 			Preparing sample... done.
[+] 			Writing sample '/home/pentester/rmg-samples/ISslServerSystemSample/ISslServerSystemSample.java' to disk... done.
[+] 			Writing sample interface '/home/pentester/rmg-samples/ISslServerSystemSample/ISslServer.java' to disk... done.
[+] 		
[+] 		Attacking boundName 'plain-server'.
[+] 		Reading template file: '/opt/remote-method-guesser/templates//StringTemplate.java'... done
[+] 		Writing class './rmg-src/IPlainServer.java' to disk... done.
[+] 		Compiling file ./rmg-src/IPlainServer.java... done.
[+] 		Getting instance of 'plain-server'...
[+] 		Guessing methods...
[+]
[+] 			HIT: public abstract java.lang.String de.qtc.rmg.IPlainServer.execute(java.lang.String) throws java.rmi.RemoteException --> exists!
[+] 			HIT: public abstract java.lang.String de.qtc.rmg.IPlainServer.system(java.lang.String,java.lang.String[]) throws java.rmi.RemoteException --> exists!
[+] 		
[+] 		2 valid method names were identified for 'StringTemplate.java'.
[+] 		Writing sample class for method 'execute'.
[+] 			Reading template file: '/opt/remote-method-guesser/templates//SampleTemplate.java'... done
[+] 			Preparing sample... done.
[+] 			Writing sample '/home/pentester/rmg-samples/IPlainServerExecuteSample/IPlainServerExecuteSample.java' to disk... done.
[+] 			Writing sample interface '/home/pentester/rmg-samples/IPlainServerExecuteSample/IPlainServer.java' to disk... done.
[+] 		
[+] 		Writing sample class for method 'system'.
[+] 			Reading template file: '/opt/remote-method-guesser/templates//SampleTemplate.java'... done
[+] 			Preparing sample... done.
[+] 			Writing sample '/home/pentester/rmg-samples/IPlainServerSystemSample/IPlainServerSystemSample.java' to disk... done.
[+] 			Writing sample interface '/home/pentester/rmg-samples/IPlainServerSystemSample/IPlainServer.java' to disk... done.
[+] 		
[+] 		Attacking boundName 'secure-server'.
[+] 		Reading template file: '/opt/remote-method-guesser/templates//StringTemplate.java'... done
[+] 		Writing class './rmg-src/ISecureServer.java' to disk... done.
[+] 		Compiling file ./rmg-src/ISecureServer.java... done.
[+] 		Getting instance of 'secure-server'...
[+] 		Guessing methods...
[+]
[+] 			HIT: public abstract java.lang.String de.qtc.rmg.ISecureServer.login(java.util.HashMap) throws java.rmi.RemoteException --> exists!
[+] 		
[+] 		1 valid method names were identified for 'StringTemplate.java'.
[+] 		Writing sample class for method 'login'.
[+] 			Reading template file: '/opt/remote-method-guesser/templates//SampleTemplate.java'... done
[+] 			Preparing sample... done.
[+] 			Writing sample '/home/pentester/rmg-samples/ISecureServerLoginSample/ISecureServerLoginSample.java' to disk... done.
[+] 			Writing sample interface '/home/pentester/rmg-samples/ISecureServerLoginSample/ISecureServer.java' to disk... done.
[+] 		
[+] 	
[+] 	Current template file: 'BooleanTemplate.java'
[+] 	
[+] 		Attacking boundName 'ssl-server'.
[+] 		Reading template file: '/opt/remote-method-guesser/templates//BooleanTemplate.java'... done
[+] 		Writing class './rmg-src/ISslServer.java' to disk... done.
[+] 		Compiling file ./rmg-src/ISslServer.java... done.
[+] 		Getting instance of 'ssl-server'...
[+] 		Guessing methods...
[+]
[+] 		
[+] 		0 valid method names were identified for 'BooleanTemplate.java'.
[+] 		Attacking boundName 'plain-server'.
[+] 		Reading template file: '/opt/remote-method-guesser/templates//BooleanTemplate.java'... done
[+] 		Writing class './rmg-src/IPlainServer.java' to disk... done.
[+] 		Compiling file ./rmg-src/IPlainServer.java... done.
[+] 		Getting instance of 'plain-server'...
[+] 		Guessing methods...
[+]
[+] 		
[+] 		0 valid method names were identified for 'BooleanTemplate.java'.
[+] 		Attacking boundName 'secure-server'.
[+] 		Reading template file: '/opt/remote-method-guesser/templates//BooleanTemplate.java'... done
[+] 		Writing class './rmg-src/ISecureServer.java' to disk... done.
[+] 		Compiling file ./rmg-src/ISecureServer.java... done.
[+] 		Getting instance of 'secure-server'...
[+] 		Guessing methods...
[+]
[+] 		
[+] 		0 valid method names were identified for 'BooleanTemplate.java'.
[+] 	
[+] 	Current template file: 'IntegerTemplate.java'
[+] 	
[+] 		Attacking boundName 'ssl-server'.
[+] 		Reading template file: '/opt/remote-method-guesser/templates//IntegerTemplate.java'... done
[+] 		Writing class './rmg-src/ISslServer.java' to disk... done.
[+] 		Compiling file ./rmg-src/ISslServer.java... done.
[+] 		Getting instance of 'ssl-server'...
[+] 		Guessing methods...
[+]
[+] 			HIT: public abstract int de.qtc.rmg.ISslServer.execute(java.lang.String) throws java.rmi.RemoteException --> exists!
[+] 		
[+] 		1 valid method names were identified for 'IntegerTemplate.java'.
[+] 		Writing sample class for method 'execute'.
[+] 			Reading template file: '/opt/remote-method-guesser/templates//SampleTemplate.java'... done
[+] 			Preparing sample... done.
[+] 			Writing sample '/home/pentester/rmg-samples/ISslServerExecuteSample/ISslServerExecuteSample.java' to disk... done.
[+] 			Writing sample interface '/home/pentester/rmg-samples/ISslServerExecuteSample/ISslServer.java' to disk... done.
[+] 		
[+] 		Attacking boundName 'plain-server'.
[+] 		Reading template file: '/opt/remote-method-guesser/templates//IntegerTemplate.java'... done
[+] 		Writing class './rmg-src/IPlainServer.java' to disk... done.
[+] 		Compiling file ./rmg-src/IPlainServer.java... done.
[+] 		Getting instance of 'plain-server'...
[+] 		Guessing methods...
[+]
[+] 		
[+] 		0 valid method names were identified for 'IntegerTemplate.java'.
[+] 		Attacking boundName 'secure-server'.
[+] 		Reading template file: '/opt/remote-method-guesser/templates//IntegerTemplate.java'... done
[+] 		Writing class './rmg-src/ISecureServer.java' to disk... done.
[+] 		Compiling file ./rmg-src/ISecureServer.java... done.
[+] 		Getting instance of 'secure-server'...
[+] 		Guessing methods...
[+]
[+] 		
[+] 		0 valid method names were identified for 'IntegerTemplate.java'.
[+] Successfully guessed methods:
[+]	• ssl-server
[+]		--> public abstract java.lang.String de.qtc.rmg.ISslServer.system(java.lang.String[]) throws java.rmi.RemoteException
[+]		--> public abstract int de.qtc.rmg.ISslServer.execute(java.lang.String) throws java.rmi.RemoteException
[+]	• plain-server
[+]		--> public abstract java.lang.String de.qtc.rmg.IPlainServer.execute(java.lang.String) throws java.rmi.RemoteException
[+]		--> public abstract java.lang.String de.qtc.rmg.IPlainServer.system(java.lang.String,java.lang.String[]) throws java.rmi.RemoteException
[+]	• secure-server
[+]		--> public abstract void de.qtc.rmg.ISecureServer.logMessage(int,java.lang.Object) throws java.rmi.RemoteException
[+]		--> public abstract void de.qtc.rmg.ISecureServer.updatePreferences(java.util.ArrayList) throws java.rmi.RemoteException
[+]		--> public abstract java.lang.String de.qtc.rmg.ISecureServer.login(java.util.HashMap) throws java.rmi.RemoteException
```

If you do no like that verbose output, you may run *rmg* with the ``--quite`` switch, to reduce the verbosity to a minimum:

```console
[qtc@kali ~]$ rmg --ssl --guess --create-samples --quite 172.17.0.2 1090
[-] RMI object tries to connect to different remote host: iinsecure.dev
[-] 	Redirecting the connection back to 172.17.0.2... 
[-] 	This is done for all further requests. This message is not shown again. 
[-] RMI object tries to connect to different remote host: iinsecure.dev
[-] 	Redirecting the ssl connection back to 172.17.0.2... 
[-] 	This is done for all further requests. This message is not shown again. 
[+] Successfully guessed methods:
[+]	• ssl-server
[+]		--> public abstract java.lang.String de.qtc.rmg.ISslServer.system(java.lang.String[]) throws java.rmi.RemoteException
[+]		--> public abstract int de.qtc.rmg.ISslServer.execute(java.lang.String) throws java.rmi.RemoteException
[+]	• plain-server
[+]		--> public abstract java.lang.String de.qtc.rmg.IPlainServer.execute(java.lang.String) throws java.rmi.RemoteException
[+]		--> public abstract java.lang.String de.qtc.rmg.IPlainServer.system(java.lang.String,java.lang.String[]) throws java.rmi.RemoteException
[+]	• secure-server
[+]		--> public abstract void de.qtc.rmg.ISecureServer.logMessage(int,java.lang.Object) throws java.rmi.RemoteException
[+]		--> public abstract void de.qtc.rmg.ISecureServer.updatePreferences(java.util.ArrayList) throws java.rmi.RemoteException
[+]		--> public abstract java.lang.String de.qtc.rmg.ISecureServer.login(java.util.HashMap) throws java.rmi.RemoteException
```

In the above case, *rmg* was able to identify a total of seven methods distributed around the three different bound names. Furthermore,
as *rmg* was run with the ``--create-samples`` switch, a new folder with name ``rmg-samples`` was created within our current working
directory.

```console
[qtc@kali ~]$ ls -l rmg-samples/
total 28
drwxr-xr-x 3 qtc qtc 4096 Sep 28 06:57 IPlainServerExecuteSample
drwxr-xr-x 3 qtc qtc 4096 Sep 28 06:57 IPlainServerSystemSample
drwxr-xr-x 3 qtc qtc 4096 Sep 28 07:16 ISecureServerLogMessageSample
drwxr-xr-x 3 qtc qtc 4096 Sep 29 13:52 ISecureServerLoginSample
drwxr-xr-x 3 qtc qtc 4096 Sep 28 06:57 ISecureServerUpdatePreferencesSample
drwxr-xr-x 3 qtc qtc 4096 Sep 28 06:57 ISslServerExecuteSample
drwxr-xr-x 3 qtc qtc 4096 Sep 28 06:57 ISslServerSystemSample
```

For this demonstration, we take a look at the ``IPlainServerExecuteSample`` folder. This folder contains the following files:

```console
[qtc@kali rmg-samples]$ ls -l IPlainServerExecuteSample
total 32
-rw-r--r-- 1 qtc qtc 13325 Sep 30 06:36 IPlainServer.java
-rw-r--r-- 1 qtc qtc  8486 Sep 30 06:36 IPlainServerExecuteSample.java
drwxr-xr-x 3 qtc qtc  4096 Sep 28 06:57 de
```

* The folder ``de`` contains the compiled class file of the *Java* interface, that was used to guess the method on the corresponding
  *bound name*. It is required to interact with the method and since it was already compiled for the method guessing process, it is
  just copied to this directory. This safes you from recompiling the interface.
* ``IPlainServer.java`` contains the source of the *Java* interface that was used to guess the method on the corresponding *bound name*.
  Usually, you should not need to interact with this file, as the compiled version is already present.
* ``IPlainServerExecuteSample.java`` contains all required code to invoke the ``execute`` method on the ``IPlainServer`` interface.
  You can use this file for further investigations on the corresponding method.

The method signature of the ``execute`` method suggests, that it may allows the execution of operating system commands. To verify this,
we need to open the ``IPlainServerExecuteSample.java`` file and modify all lines that contain a *TODO* marker. *rmg* creates a *TODO* for
each method argument and expects you to replace these *TODOs* with the method arguments of your choice.

```java
System.out.print("[+] Connecting to registry on " + remoteHost + ":" + remotePort + "... ");
Registry registry = null;

if( true ) {
    RMIClientSocketFactory csf = new SslRMIClientSocketFactory();
    registry = LocateRegistry.getRegistry(remoteHost, remotePort, csf);
} else {
    registry = LocateRegistry.getRegistry(remoteHost, remotePort);
}

System.out.println("done!");

System.out.println("[+] Starting lookup on plain-server... ");
IPlainServer stub = (IPlainServer) registry.lookup("plain-server");

java.lang.String argument0 = TODO;

System.out.print("[+] Invoking method execute... ");
java.lang.String response = stub.execute(argument0);
System.out.println("done!");

System.out.println("[+] The servers response is: " + response);
```

In the current case, we replace the *TODO* with the value ``"id"`` and are then able to compile and run the code:

```console
[qtc@kali IPlainServerExecuteSample]$ javac IPlainServerExecuteSample.java 
[qtc@kali IPlainServerExecuteSample]$ java IPlainServerExecuteSample 
[+] Connecting to registry on 172.17.0.2:1090... done!
[+] Starting lookup on plain-server... 
[+] RMI object tries to connect to different remote host: iinsecure.dev
[+]	Redirecting the connection back to 172.17.0.2... 
[+]	This is done for all further requests. This message is not shown again. 
[+] Invoking method execute... done!
[+] The servers response is: uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```

As expected, the ``execute`` method allowed the execution of operating system commands. However, at this point it is important
to mention that not only dangerous methods like ``execute`` or ``system`` can be exploited. As explained in [this awesome blog post](https://mogwailabs.de/blog/2019/03/attacking-java-rmi-services-after-jep-290/)
by *Hans-Martin Münch*, methods like ``java.lang.String de.qtc.rmg.ISecureServer.login(java.util.HashMap)`` can be vulnerable to
*deserialization attacks*. A corresponding example can also be found inside of the [container description](./docker).


### Templates

-----

*rmg's method guessing attack* is based on template files that are defined in the [template folder](./templates). Currently,
four default templates are defined:

* ``VoidTemplate.java``
* ``StringTemplate.java``
* ``BooleanTemplate.java``
* ``IntegerTemplate.java``

It is of course possible that remote objects define other methods with different signatures and you may want to extend the provided
templates or create a new one. Notice that the default location for template files is ``/opt/remote-method-guesser/templates/``. You
can change this with a custom configuration file (see below) or by using the corresponding commandline option ``--template-folder``.

To extend a template, simply add your desired method signatures to the existing template files. However, notice that Java only allows
one return type per method name with the same argument types. Thus, if you want to add an existing  method signature for other return types, 
you need to add a new template file. 

For new template files, just make sure that their filename ends with ``Template.java`` and they should be automatically recognized by *rmg*.
Of course, also make sure that they follow the same format as the already existing template files.

The ``SampleTemplate.java`` is not a *wordlist-template*, but is used for sample generation. This file should be left untouched.
Also ``LookupDummy.java`` is not a *wordlist-template*. This file is required because of the way *Java class loading* works. Just
leave it untouched and do not care about it (unless you know what you do).


### Configuration

-----

*rmg* does provide some command line switches to modify its behavior. However, typing and remembering all these switches might be a pain
and therefore you can also use a configuration file for some options. The default configuration file that is used by *rmg* internally looks
like this:

```properties
templateFolder  = /opt/remote-method-guesser/templates/
sampleFolder    = ./rmg-samples
sourceFolder    = ./rmg-src
buildFolder     = ./rmg-build

javacPath = /usr/bin/javac

threads = 5
```

You can simply create a *.properties* file with your own configuration and feed it into *rmg* using the ``--config`` option. Moreover,
you could also modify the [default configuration](./src/config.properties) before compiling the project.


### About Performance

-----

The *rmg* was not designed with performance in mind. Even the actual method guessing procedure is multi threaded, all the slow stuff
(like the compilation of dummy interfaces) is done single threaded. From my point of view this behavior should be fine, but if you
think definitely, feel free to improve the code in that regard :)


### A word of caution

-----

*Remote Method Guessing* should not be used on production systems. The reason is simple: During the method guessing process, the method 
guesser will try to invoke each method from the template file on the remote object. Even this is a dummy call (with all arguments set to
*null*), it is still a valid Java function call and depending on the implementation of the remote class, bad things could happen.

Consider a developer thought it might be a good idea to create a ``command(String cmd)`` function, that executes the specified command, but
shuts down the server after the execution has finished. Starting *Remote Method Guessing* on such 
a remote class would shutdown the server pretty quickly. This example seems may a little bit over the top, but also other bad side effects could occur.

Blindly invoking Java methods on a production system is dangerous and should not be done.


*Copyright 2020, Tobias Neitzel and the *remote-method-guesser* contributors.*
