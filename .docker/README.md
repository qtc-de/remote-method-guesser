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
  $ sudo docker login https://docker.pkg.github.com -u <USERNAME>
  Password:

  Login Succeeded
  $ sudo docker pull docker.pkg.github.com/qtc-de/remote-method-guesser/rmg-example-server:1.0
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

