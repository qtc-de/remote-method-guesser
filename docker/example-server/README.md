### Docker Files

----

The *example-server* provided by this repository can be used to test all features of *remote-method-guesser*.
You can either build the container from source or pull it from *GitHub Packages*.

* To build from source, just clone the repository, switch to the [docker directory](/docker/example-server), remove the version suffix
  of the desired version and run `docker build .` to create the container. If you also want to make adjustments to the example server,
  modify the [source code](/docker/example-server/resources/server) and rebuild the container.

* To load the container from the *GitHub Container Registry* just use the corresponding pull command:
  ```console
  $ docker pull ghcr.io/qtc-de/remote-method-guesser/rmg-example-server:3.2-jdk8
  $ docker pull ghcr.io/qtc-de/remote-method-guesser/rmg-example-server:3.2-jdk9
  $ docker pull ghcr.io/qtc-de/remote-method-guesser/rmg-example-server:3.2-jdk11
  ```

To change the default configuration of the container (like e.g. the *SSL* certificate), you can modify the [docker-compose.yml](./docker-compose-jdk8.yml)
and start the container using `docker-compose up`. From container version *v3.0* on, the container is available in three different versions: *jdk8*, *jdk9*
and *jdk11*. As the names suggest, the first one is build based on *openjdk-8*, whereas the others are based on *openjdk-9* and *openjdk-11*. The Java
versions associated with the *jdk8* and *jdk9* container are intentionally outdated to experiment with different *RMI* vulnerabilities.


### Configuration Details

----

When launched in its default configuration, the container starts *Java rmiregistry* instances on port `1090`, `1098` and `9010`.
The registry on port `1090` is *SSL* protected and contains three available bound names:

```console
[qtc@devbox ~]$ rmg enum --ssl 172.17.0.2 1090
[+] RMI registry bound names:
[+]
[+] 	- plain-server
[+] 		--> de.qtc.rmg.server.interfaces.IPlainServer (unknown class)
[+] 		    Endpoint: iinsecure.dev:40579  TLS: no  ObjID: [-492549a8:1809adab6bf:-7fff, 8831379559932805383]
[+] 	- ssl-server
[+] 		--> de.qtc.rmg.server.interfaces.ISslServer (unknown class)
[+] 		    Endpoint: iinsecure.dev:42031  TLS: yes  ObjID: [-492549a8:1809adab6bf:-7ffe, -8819602238278920745]
[+] 	- secure-server
[+] 		--> de.qtc.rmg.server.interfaces.ISecureServer (unknown class)
[+] 		    Endpoint: iinsecure.dev:40579  TLS: no  ObjID: [-492549a8:1809adab6bf:-7ffd, -5037949272481440924]
[+]
[+] RMI server codebase enumeration:
[+]
[+] 	- http://iinsecure.dev/well-hidden-development-folder/
[+] 		--> de.qtc.rmg.server.interfaces.ISslServer
[+] 		--> de.qtc.rmg.server.interfaces.IPlainServer
[+] 		--> de.qtc.rmg.server.interfaces.ISecureServer
[+]
[+] RMI server String unmarshalling enumeration:
[+]
[+] 	- Caught ClassNotFoundException during lookup call.
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
[+] RMI Security Manager enumeration:
[+]
[+] 	- Security Manager rejected access to the class loader.
[+] 	  --> The server does use a Security Manager.
[+] 	  Configuration Status: Current Default
[+]
[+] RMI server JEP290 enumeration:
[+]
[+] 	- DGC rejected deserialization of java.util.HashMap (JEP290 is installed).
[+] 	  Vulnerability Status: Non Vulnerable
[+]
[+] RMI registry JEP290 bypass enumeration:
[+]
[+] 	- Caught IllegalArgumentException after sending An Trinh gadget.
[+] 	  Vulnerability Status: Vulnerable
[+]
[+] RMI ActivationSystem enumeration:
[+]
[+] 	- Caught NoSuchObjectException during activate call (activator not present).
[+] 	  Configuration Status: Current Default
```

The registry on port `1098` hosts an *Activation System* and has some *activatable remote objects* bound:

```console
[qtc@devbox ~]$ rmg enum 172.17.0.2 1098
[+] RMI registry bound names:
[+]
[+] 	- activation-test
[+] 		--> de.qtc.rmg.server.activation.IActivationService (unknown class)
[+] 		    Activator: iinsecure.dev:1098  ActivationID: -492549a8:1809adab6bf:-7ff1
[+] 	- activation-test2
[+] 		--> de.qtc.rmg.server.activation.IActivationService2 (unknown class)
[+] 		    Activator: iinsecure.dev:1098  ActivationID: -492549a8:1809adab6bf:-7fee
[+] 	- plain-server
[+] 		--> de.qtc.rmg.server.interfaces.IPlainServer (unknown class)
[+] 		    Endpoint: iinsecure.dev:40579  TLS: no  ObjID: [-492549a8:1809adab6bf:-7fec, 5541025679742310482]
[+] 	- java.rmi.activation.ActivationSystem
[+] 		--> sun.rmi.server.Activation$ActivationSystemImpl_Stub (known class: RMI Activator)
[+] 		    Endpoint: iinsecure.dev:1098  TLS: no  ObjID: [0:0:0, 4]
[+]
[+] RMI server codebase enumeration:
[+]
[+] 	- http://iinsecure.dev/well-hidden-development-folder/
[+] 		--> de.qtc.rmg.server.interfaces.IPlainServer
[+] 		--> de.qtc.rmg.server.activation.IActivationService
[+] 		--> sun.rmi.server.Activation$ActivationSystemImpl_Stub
[+] 		--> de.qtc.rmg.server.activation.IActivationService2
[+]
[+] RMI server String unmarshalling enumeration:
[+]
[+] 	- Caught ClassNotFoundException during lookup call.
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
[+] 	- Registry rejected unbind call cause it was not send from localhost.
[+] 	  Vulnerability Status: Non Vulnerable
[+]
[+] RMI Security Manager enumeration:
[+]
[+] 	- Security Manager rejected access to the class loader.
[+] 	  --> The server does use a Security Manager.
[+] 	  Configuration Status: Current Default
[+]
[+] RMI server JEP290 enumeration:
[+]
[+] 	- DGC rejected deserialization of java.util.HashMap (JEP290 is installed).
[+] 	  Vulnerability Status: Non Vulnerable
[+]
[+] RMI registry JEP290 bypass enumeration:
[+]
[+] 	- Caught IllegalArgumentException after sending An Trinh gadget.
[+] 	  Vulnerability Status: Vulnerable
[+]
[+] RMI ActivationSystem enumeration:
[+]
[+] 	- Caught IllegalArgumentException during activate call (activator is present).
[+] 	  --> Deserialization allowed	 - Vulnerability Status: Vulnerable
[+] 	  --> Client codebase enabled	 - Configuration Status: Non Default
```

The registry on port ``9010`` can be contacted without *SSL* and exposes three bound names. In contrast to the first setup, two of the
exposed bound names belong to the same remote interface. Furthermore, the last remaining bound name belongs to a remote class that uses
*statically compiled stubs* ([legacy-rmi](https://docs.oracle.com/javase/7/docs/technotes/tools/windows/rmic.html)). Additionally, this
registry port binds an *RMI Activator instance*, but not a full working *Activation System*.


```console
[qtc@devbox ~]$ rmg enum 172.17.0.2 9010
[+] RMI registry bound names:
[+]
[+] 	- plain-server2
[+] 		--> de.qtc.rmg.server.interfaces.IPlainServer (unknown class)
[+] 		    Endpoint: iinsecure.dev:40579  TLS: no  ObjID: [-492549a8:1809adab6bf:-7ff7, 8893583921173173865]
[+] 	- legacy-service
[+] 		--> de.qtc.rmg.server.legacy.LegacyServiceImpl_Stub (unknown class)
[+] 		    Endpoint: iinsecure.dev:40579  TLS: no  ObjID: [-492549a8:1809adab6bf:-7ffc, -5452660335673756521]
[+] 	- plain-server
[+] 		--> de.qtc.rmg.server.interfaces.IPlainServer (unknown class)
[+] 		    Endpoint: iinsecure.dev:40579  TLS: no  ObjID: [-492549a8:1809adab6bf:-7ff8, 5860842907020657289]
[+]
[+] RMI server codebase enumeration:
[+]
[+] 	- http://iinsecure.dev/well-hidden-development-folder/
[+] 		--> de.qtc.rmg.server.legacy.LegacyServiceImpl_Stub
[+] 		--> de.qtc.rmg.server.interfaces.IPlainServer
[+]
[+] RMI server String unmarshalling enumeration:
[+]
[+] 	- Caught ClassNotFoundException during lookup call.
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
[+] RMI Security Manager enumeration:
[+]
[+] 	- Security Manager rejected access to the class loader.
[+] 	  --> The server does use a Security Manager.
[+] 	  Configuration Status: Current Default
[+]
[+] RMI server JEP290 enumeration:
[+]
[+] 	- DGC rejected deserialization of java.util.HashMap (JEP290 is installed).
[+] 	  Vulnerability Status: Non Vulnerable
[+]
[+] RMI registry JEP290 bypass enumeration:
[+]
[+] 	- Caught IllegalArgumentException after sending An Trinh gadget.
[+] 	  Vulnerability Status: Vulnerable
[+]
[+] RMI ActivationSystem enumeration:
[+]
[+] 	- Caught IllegalArgumentException during activate call (activator is present).
[+] 	  --> Deserialization allowed	 - Vulnerability Status: Vulnerable
[+] 	  --> Client codebase enabled	 - Configuration Status: Non Default
```

The corresponding remote objects get assigned a random port during the server startup. By default, the
example server uses colored output. You can disable it by using the corresponding environment variable
within the [docker-compose.yml](./docker-compose-jdk8.yml) file. Another environment variable can be used
to enable *codebase logging*:

```yaml
environment:
  [...]
    -Djava.rmi.server.RMIClassLoaderSpi=de.qtc.rmg.server.utils.CodebaseLogger
    -Dde.qtc.rmg.server.disableColor=true
```

Each successful method call is logged on the server side. The following listing shows the output after the server
was started. Additionally, one successful method call on the ``login`` method was logged:

```console
[qtc@devbox ~]$ docker run ghcr.io/qtc-de/remote-method-guesser/rmg-example-server:3.2-jdk9
[+] IP address of the container: 172.17.0.2
[+] Adding gateway address to /etc/hosts file...
[+] Adding RMI hostname to /etc/hosts file...
[+] Starting rmi server...
Picked up _JAVA_OPTIONS: -Djava.rmi.server.hostname=iinsecure.dev     -Djavax.net.ssl.keyStorePassword=password     -Djavax.net.ssl.keyStore=/opt/store.p12     -Djavax.net.ssl.keyStoreType=pkcs12     -Djava.rmi.server.useCodebaseOnly=false     -Djava.security.policy=/opt/policy     -Djava.rmi.server.codebase=http://iinsecure.dev/well-hidden-development-folder/
[2022.05.06 - 19:45:12] Initializing Java RMI Server:
[2022.05.06 - 19:45:12] 
[2022.05.06 - 19:45:12]     Creating RMI-Registry on port 1090
[2022.05.06 - 19:45:12]     
[2022.05.06 - 19:45:12]     Creating PlainServer object.
[2022.05.06 - 19:45:12]         Binding Object as plain-server
[2022.05.06 - 19:45:12]         Boundname plain-server with interface IPlainServer is ready.
[2022.05.06 - 19:45:12]     Creating SSLServer object.
[2022.05.06 - 19:45:12]         Binding Object as ssl-server
[2022.05.06 - 19:45:12]         Boundname ssl-server with interface ISslServer is ready.
[2022.05.06 - 19:45:12]     Creating SecureServer object.
[2022.05.06 - 19:45:12]         Binding Object as secure-server
[2022.05.06 - 19:45:12]         Boundname secure-server with interface ISecureServer is ready.
[2022.05.06 - 19:45:12] 
[2022.05.06 - 19:45:12] Server setup finished.
[2022.05.06 - 19:45:12] Initializing legacy server.
[2022.05.06 - 19:45:12] 
[2022.05.06 - 19:45:12]     Creating RMI-Registry on port 9010
[2022.05.06 - 19:45:12]     
[2022.05.06 - 19:45:12]     Creating LegacyServiceImpl object.
[2022.05.06 - 19:45:12]         Binding LegacyServiceImpl as legacy-service
[2022.05.06 - 19:45:12]         Boundname legacy-service with class de.qtc.rmg.server.legacy.LegacyServiceImpl_Stub is ready.
[2022.05.06 - 19:45:12]     Creating PlainServer object.
[2022.05.06 - 19:45:12]         Binding Object as plain-server
[2022.05.06 - 19:45:12]         Boundname plain-server with interface IPlainServer is ready.
[2022.05.06 - 19:45:12]     Creating another PlainServer object.
[2022.05.06 - 19:45:12]         Binding Object as plain-server2
[2022.05.06 - 19:45:12]         Boundname plain-server2 with interface IPlainServer is ready.
[2022.05.06 - 19:45:12]     Creating ActivatorImp object.
[2022.05.06 - 19:45:12]         Activator is ready.
[2022.05.06 - 19:45:12]     
[2022.05.06 - 19:45:12] Server setup finished.
[2022.05.06 - 19:45:12] 
[2022.05.06 - 19:45:12]     Creating ActivationSystem on port 1098
[2022.05.06 - 19:45:12]         Binding Object as activation-test
[2022.05.06 - 19:45:12]         Boundname activation-test with interface Remote is ready.
[2022.05.06 - 19:45:12]         Binding Object as activation-test2
[2022.05.06 - 19:45:12]         Boundname activation-test2 with interface Remote is ready.
[2022.05.06 - 19:45:12]         Binding Object as plain-server
[2022.05.06 - 19:45:12]         Boundname plain-server with interface IPlainServer is ready.
[2022.05.06 - 19:45:12]     
[2022.05.06 - 19:45:12] Server setup finished.
[2022.05.06 - 19:45:12] Waiting for incoming connections.
[2022.05.06 - 19:45:12] 
[2022.05.06 - 19:45:12] [SecureServer]: Processing call for String login(HashMap<String, String> credentials)
```

One core feature of *remote-method-guesser* is that it allows *safe method guessing* without invoking method calls on the server side.
The above mentioned logging of server-side method calls can be used to verify this. During a usual run of *rmg's* ``guess``, ``method``
and ``codebase`` actions, no valid calls should be logged on the server side.


### Remote Interfaces

----

Each remote object on the *example-server* implements different kinds of vulnerable remote methods that can be
detected by *rmg*. Some methods are vulnerably by design (e.g. execute operating system commands on invocation)
others can be exploited by *deserialization* or *codebase* attacks as mentioned in the [README.md](/README.md)
of this project. In the following, the corresponding interfaces are listed.


#### IPlainServer

```java
public interface IPlainServer extends Remote
{
    String notRelevant() throws RemoteException;
    String execute(String cmd) throws RemoteException;
    String system(String cmd, String[] args) throws RemoteException;
    String upload(int size, int id, byte[] content) throws RemoteException;
    int math(int num1, int num2) throws RemoteException;
}
```

#### ISslServer

```java
public interface ISslServer extends Remote
{
    String notRelevant() throws RemoteException;
    int execute(String cmd) throws RemoteException;
    String system(String[] args) throws RemoteException;
    void releaseRecord(int recordID, String tableName, Integer remoteHashCode) throws RemoteException;
}
```

#### ISecureServer

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

#### LegacyService

```java
public interface LegacyService extends Remote
{
    public String getMotd() throws RemoteException;
    String login(HashMap<String, String> credentials) throws RemoteException;
    void logMessage(int type, String msg) throws RemoteException;
    void logMessage(int type, StringContainer msg) throws RemoteException;
    int math(int num1, int num2) throws RemoteException;
    void releaseRecord(int recordID, String tableName, Integer remoteHashCode) throws RemoteException;
}
```

#### IActivationService

```java
public interface IActivationService extends Remote
{
    String execute(String cmd) throws RemoteException;
    String system(String cmd, String[] args) throws RemoteException;
}
```

#### IActivationService2

```java
public interface IActivationService2 extends Remote
{
    String login(HashMap<String, String> credentials) throws RemoteException;
    void logMessage(int logLevel, Object message) throws RemoteException;
    void updatePreferences(ArrayList<String> preferences) throws RemoteException;
}
```
