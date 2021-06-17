### Docker Files

----

The *example-server* provided by this repository can be used to test all features of *remote-method-guesser*.
You can either build the container from source or pull it from *GitHub Packages*.

* To build from source, just clone the repository, switch to the [docker directory](/.docker) and run ``docker build .``
  to create the container. If you also want to make adjustments to the example server, just modify the [source code](/.docker/resources/example-server)
  and rebuild the container.

* To load the container from *GitHub Packages*, just authenticate using your personal access token and run the corresponding pull command:
  ```console
  $ docker login https://docker.pkg.github.com -u <USERNAME>
  Password:

  Login Succeeded
  $ docker pull docker.pkg.github.com/qtc-de/remote-method-guesser/rmg-example-server:3.1-jdk9
  ```

To change the default configuration of the container (like e.g. the *SSL* certificate), you can modify the [docker-compose.yml](/.docker/docker-compose.yml)
and start the container using ``docker-compose up``. From container version *v3.0* on, the container is available in two different versions: *jdk9* and *jdk11*.
As the names suggest, the first one is build based on *openjdk-9*, whereas the second one is based on *openjdk-11*. Since *openjdk-9* is no longer maintained,
this container version is vulnerable to some older *RMI* vulnerabilities (e.g. *localhost* and *An Trinh bypass*). The *jdk11* version, on the other hand,
is fully patched at the time of building.


### Configuration Details

----

When launched in its default configuration, the container starts two *Java rmiregistry* instances on port ``1090`` and port ``9010``.
The registry on port ``1090`` is *SSL* protected and contains three available bound names:

```console
[qtc@kali ~]$ rmg --ssl 172.17.0.2 1090
[+] RMI registry bound names:
[+]
[+]     - ssl-server
[+]         --> de.qtc.rmg.server.interfaces.ISslServer (unknown class)
[+]     - plain-server
[+]         --> de.qtc.rmg.server.interfaces.IPlainServer (unknown class)
[+]     - secure-server
[+]         --> de.qtc.rmg.server.interfaces.ISecureServer (unknown class)
[+]
[+] RMI server codebase enumeration:
[+]
[+]     - http://iinsecure.dev/well-hidden-development-folder/
[+]         --> de.qtc.rmg.server.interfaces.ISslServer
[+]         --> de.qtc.rmg.server.interfaces.IPlainServer
[+]         --> javax.rmi.ssl.SslRMIClientSocketFactory
[+]         --> de.qtc.rmg.server.interfaces.ISecureServer
[+]
[+] RMI server String unmarshalling enumeration:
[+]
[+]     - Caught ClassNotFoundException during lookup call.
[+]       --> The type java.lang.String is unmarshalled via readObject().
[+]       Configuration Status: Outdated
[+]
[+] RMI server useCodebaseOnly enumeration:
[+]
[+]     - Caught MalformedURLException during lookup call.
[+]       --> The server attempted to parse the provided codebase (useCodebaseOnly=false).
[+]       Configuration Status: Non Default
[+]
[+] RMI registry localhost bypass enumeration (CVE-2019-2684):
[+]
[+]     - Caught NotBoundException during unbind call (unbind was accepeted).
[+]       Vulnerability Status: Vulnerable
[+]
[+] RMI DGC enumeration:
[+]
[+]     - Security Manager rejected access to the class loader.
[+]       --> The DGC uses most likely a separate security policy.
[+]       Configuration Status: Current Default
[+]
[+] RMI server JEP290 enumeration:
[+]
[+]     - DGC rejected deserialization of java.util.HashMap (JEP290 is installed).
[+]       Vulnerability Status: Non Vulnerable
[+]
[+] RMI registry JEP290 bypass enmeration:
[+]
[+]     - Caught IllegalArgumentException after sending An Trinh gadget.
[+]       Vulnerability Status: Vulnerable
[+]
[+] RMI ActivationSystem enumeration:
[+]
[+]     - Caught NoSuchObjectException during activate call (activator not present).
[+]       Configuration Status: Current Default
```

The registry on port ``9010`` can be contacted without *SSL* and exposes also three bound names. In contrast to the previous setup, two of
the exposed bound names belong to the same remote interface. Furthermore, the last remaining bound name belongs to a remote class that uses
*statically compiled stubs* ([legacy-rmi](https://docs.oracle.com/javase/7/docs/technotes/tools/windows/rmic.html)). Additionally, this
registry port binds an RMI Activator instance.


```console
[qtc@kali ~]$ rmg 172.17.0.2 9010
[+] RMI registry bound names:
[+]
[+]     - plain-server2
[+]         --> de.qtc.rmg.server.interfaces.IPlainServer (unknown class)
[+]     - plain-server
[+]         --> de.qtc.rmg.server.interfaces.IPlainServer (unknown class)
[+]     - legacy-service
[+]         --> de.qtc.rmg.server.legacy.LegacyServiceImpl_Stub (unknown class)
[+]
[+] RMI server codebase enumeration:
[+]
[+]     - http://iinsecure.dev/well-hidden-development-folder/
[+]         --> de.qtc.rmg.server.legacy.LegacyServiceImpl_Stub
[+]         --> de.qtc.rmg.server.interfaces.IPlainServer
[+]
[...]
[+]
[+] RMI ActivationSystem enumeration:
[+]
[+]     - Caught IllegalArgumentException during activate call (activator is present).
[+]       --> Deserialization allowed     - Vulnerability Status: Vulnerable
[+]       --> Client codebase enabled     - Configuration Status: Non Default
```

The corresponding remote objects get assigned a random port during the server startup. By default, the
example server uses colored output. You can disable it by using the corresponding environment variable
within the ``docker-compose.yml`` file. Another environment variable can be used to enable *codebase logging*:

```yaml
environment:
  [...]
    -Djava.rmi.server.RMIClassLoaderSpi=de.qtc.rmg.server.utils.CodebaseLogger
    -Dde.qtc.rmg.server.disableColor=true
```

Each successful method call is logged on the server side. The following listing shows the output after the server
was started. Additionally, one successful method call on the ``login`` method was logged:

```console
[qtc@kali ~]$ docker run docker.pkg.github.com/qtc-de/remote-method-guesser/rmg-example-server:3.1-jdk9
[+] IP address of the container: 172.17.0.2
[+] Adding gateway address to /etc/hosts file...
[+] Adding RMI hostname to /etc/hosts file...
[+] Starting rmi server...
Picked up _JAVA_OPTIONS: -Djava.rmi.server.hostname=iinsecure.dev     -Djavax.net.ssl.keyStorePassword=password     -Djavax.net.ssl.keyStore=/opt/store.p12     -Djavax.net.ssl.keyStoreType=pkcs12     -Djava.rmi.server.useCodebaseOnly=false     -Djava.security.policy=/opt/policy     -Djava.rmi.server.codebase=http://iinsecure.dev/well-hidden-development-folder/
[2021.03.26 - 05:16:47] Initializing Java RMI Server:
[2021.03.26 - 05:16:47]
[2021.03.26 - 05:16:47]     Creating RMI-Registry on port 1090
[2021.03.26 - 05:16:47]
[2021.03.26 - 05:16:47]     Creating PlainServer object.
[2021.03.26 - 05:16:47]         Binding Object as plain-server
[2021.03.26 - 05:16:47]         Boundname plain-server with interface IPlainServer is ready.
[2021.03.26 - 05:16:47]     Creating SSLServer object.
[2021.03.26 - 05:16:47]         Binding Object as ssl-server
[2021.03.26 - 05:16:47]         Boundname ssl-server with interface ISslServer is ready.
[2021.03.26 - 05:16:47]     Creating SecureServer object.
[2021.03.26 - 05:16:47]         Binding Object as secure-server
[2021.03.26 - 05:16:47]         Boundname secure-server with interface ISecureServer is ready.
[2021.03.26 - 05:16:47]
[2021.03.26 - 05:16:47] Server setup finished.
[2021.03.26 - 05:16:47] Initializing legacy server.
[2021.03.26 - 05:16:47]
[2021.03.26 - 05:16:47]     Creating RMI-Registry on port 9010
[2021.03.26 - 05:16:47]
[2021.03.26 - 05:16:47]     Creating LegacyServiceImpl object.
[2021.03.26 - 05:16:47]         Binding LegacyServiceImpl as legacy-service
[2021.03.26 - 05:16:47]         Boundname legacy-service with class de.qtc.rmg.server.legacy.LegacyServiceImpl_Stub is ready.
[2021.03.26 - 05:16:47]     Creating PlainServer object.
[2021.03.26 - 05:16:47]         Binding Object as plain-server
[2021.03.26 - 05:16:47]         Boundname plain-server with interface IPlainServer is ready.
[2021.03.26 - 05:16:47]     Creating another PlainServer object.
[2021.03.26 - 05:16:47]         Binding Object as plain-server2
[2021.03.26 - 05:16:47]         Boundname plain-server2 with interface IPlainServer is ready.
[2021.03.26 - 05:16:47]     Creating ActivatorImp object.
[2021.03.26 - 05:16:47]         Activator is ready.
[2021.03.26 - 05:16:47]
[2021.03.26 - 05:16:47] Server setup finished.
[2021.03.26 - 05:16:47] Waiting for incoming connections.
```

One core feature of *remote-method-guesser* is that it allows *safe method guessing* without invoking method calls on the server side.
The above mentioned logging of server-side method calls can be used to verify this. During a usual run of *rmg's* ``guess``, ``method``
and ``codebase`` actions, no valid calls should be logged on the server side.


### Remote Interfaces

----

Each remote object on the *example-server* implements different kinds of vulnerable remote methods that can be
detected by *rmg*. Some methods are vulnerably by design (e.g. execute operating system commands on invocation)
others can be exploited by *deserialization* or *codebase* attacks as mentioned in the [README.md](../README.md)
of this project. In the following, the corresponding interfaces are listed.


#### Plain Server

The remote object that is bound as ``plain-server`` uses a plain *TCP* connection without *SSL*. It implements
the following interface:

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


#### SSL Server

The remote object that is bound as ``ssl-server`` uses an *SSL* protected *TCP* connection. It implements
the following interface:

```java
public interface ISslServer extends Remote
{
    String notRelevant() throws RemoteException;
    int execute(String cmd) throws RemoteException;
    String system(String[] args) throws RemoteException;
    void releaseRecord(int recordID, String tableName, Integer remoteHashCode) throws RemoteException;
}
```


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


#### Legacy Service

The remote object that is bound as ``legacy-service`` uses a plain *TCP* connection without *SSL*. It implements
the following interface:

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


### Example Run

----

The following listing shows an example run of *remote-method-guessers* ``guess`` action against both of the exposed
*rmiregistry* endpoints:

#### 1090 Registry

```console
[qtc@kali ~]$ rmg --ssl 172.17.0.2 1090 guess --zero-arg
[+] Reading method candidates from internal wordlist rmg.txt
[+]   757 methods were successfully parsed.
[+] Reading method candidates from internal wordlist rmiscout.txt
[+]   2550 methods were successfully parsed.
[+]
[+] Starting Method Guessing on 3299 method signature(s).
[+]
[+]   MethodGuesser is running:
[+]     --------------------------------
[+]     [ ssl-server    ] HIT! Method with signature String system(String[] dummy) exists!
[+]     [ ssl-server    ] HIT! Method with signature int execute(String dummy) exists!
[+]     [ ssl-server    ] HIT! Method with signature void releaseRecord(int recordID, String tableName, Integer remoteHashCode) exists!
[+]     [ plain-server  ] HIT! Method with signature String system(String dummy, String[] dummy2) exists!
[+]     [ secure-server ] HIT! Method with signature void logMessage(int dummy1, Object dummy2) exists!
[+]     [ plain-server  ] HIT! Method with signature String execute(String dummy) exists!
[+]     [ secure-server ] HIT! Method with signature void updatePreferences(java.util.ArrayList dummy1) exists!
[+]     [ secure-server ] HIT! Method with signature String login(java.util.HashMap dummy1) exists!
[+]   done.
[+]
[+] Listing successfully guessed methods:
[+]   - plain-server
[+]     --> String system(String dummy, String[] dummy2)
[+]     --> String execute(String dummy)
[+]   - secure-server
[+]     --> void logMessage(int dummy1, Object dummy2)
[+]     --> void updatePreferences(java.util.ArrayList dummy1)
[+]     --> String login(java.util.HashMap dummy1)
[+]   - ssl-server
[+]     --> String system(String[] dummy)
[+]     --> int execute(String dummy)
[+]     --> void releaseRecord(int recordID, String tableName, Integer remoteHashCode)
```

#### 9010 Registry

```console
[qtc@kali ~]$ rmg 172.17.0.2 9010 guess --zero-arg
[+] Reading method candidates from internal wordlist rmg.txt
[+]     757 methods were successfully parsed.
[+] Reading method candidates from internal wordlist rmiscout.txt
[+]     2550 methods were successfully parsed.
[+]
[+] Starting Method Guessing on 3299 method signature(s).
[+]
[+]     MethodGuesser is running:
[+]         --------------------------------
[+]         [ legacy-service ] HIT! Method with signature void logMessage(int dummy1, String dummy2) exists!
[+]         [ legacy-service ] HIT! Method with signature void releaseRecord(int recordID, String tableName, Integer remoteHashCode) exists!
[+]         [ legacy-service ] HIT! Method with signature String login(java.util.HashMap dummy1) exists!
[+]         [ plain-server2  ] HIT! Method with signature String system(String dummy, String[] dummy2) exists!
[+]         [ plain-server2  ] HIT! Method with signature String execute(String dummy) exists!
[+]     done.
[+]
[+] Listing successfully guessed methods:
[+]     - legacy-service
[+]         --> void logMessage(int dummy1, String dummy2)
[+]         --> void releaseRecord(int recordID, String tableName, Integer remoteHashCode)
[+]         --> String login(java.util.HashMap dummy1)
[+]     - plain-server (== plain-server2)
[+]         --> String system(String dummy, String[] dummy2)
[+]         --> String execute(String dummy)
[+]     - plain-server2
[+]         --> String system(String dummy, String[] dummy2)
[+]         --> String execute(String dummy)
```
