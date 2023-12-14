### Spring Remoting Example Server

----

The *Spring Remoting* example server provided by this repository can be used to test the
*Spring Remoting* related features of *remote-method-guesser*. You can either build the
container from source or pull it from [GitHub Packages](https://github.com/qtc-de/remote-method-guesser/pkgs/container/remote-method-guesser%2Fspring-remoting-server).

* To build from source, just clone the repository, switch to the [docker directory](/docker/spring-remoting) and run `docker build .`.
* To load the container from the *GitHub Container Registry* just use the corresponding pull command:
  ```console
  [user@host ~]$ docker pull ghcr.io/qtc-de/remote-method-guesser/spring-remoting-server:1.0
  ```


### Configuration Details

----

The *Spring Remoting* example server exposes an *RMI* registry port on `tcp/1099`. Scanning this
port with *remote-method-guesser* version *v5.0.0* or higher should provide the following results:

```console
[user@host ~]$ rmg enum 172.17.0.2 1099
[+] RMI registry bound names:
[+]
[+] 	- spring-remoting
[+] 		--> org.springframework.remoting.rmi.RmiInvocationHandler (known class: Spring RmiInvocationHandler)
[+] 		    Spring Remoting Interface: eu.tneitzel.rmg.springremoting.ServerOperations (unknown class)
[+] 		    Endpoint: iinsecure.example:33779  CSF: RMISocketFactory  ObjID: [43861eb7:18c69d6d219:-7fff, 8901450872606600476]
[+]
[+] RMI server codebase enumeration:
[+]
[+] 	- The remote server does not expose any codebases.
[+]
[+] RMI server String unmarshalling enumeration:
[+]
[+] 	- Server complained that object cannot be casted to java.lang.String.
[+] 	  --> The type java.lang.String is unmarshalled via readString().
[+] 	  Configuration Status: Current Default
[+]
[+] RMI server useCodebaseOnly enumeration:
[+]
[+] 	- RMI registry uses readString() for unmarshalling java.lang.String.
[+] 	  This prevents useCodebaseOnly enumeration from remote.
[+]
[+] RMI registry localhost bypass enumeration (CVE-2019-2684):
[+]
[+] 	- Registry rejected unbind call cause it was not sent from localhost.
[+] 	  Vulnerability Status: Non Vulnerable
[+]
[+] RMI Security Manager enumeration:
[+]
[+] 	- Caught Exception containing 'no security manager' during RMI call.
[+] 	  --> The server does not use a Security Manager.
[+] 	  Configuration Status: Current Default
[+]
[+] RMI server JEP290 enumeration:
[+]
[+] 	- DGC rejected deserialization of java.util.HashMap (JEP290 is installed).
[+] 	  Vulnerability Status: Non Vulnerable
[+]
[+] RMI registry JEP290 bypass enumeration:
[+]
[+] 	- RMI registry uses readString() for unmarshalling java.lang.String.
[+] 	  This prevents JEP 290 bypass enumeration from remote.
[+]
[+] RMI ActivationSystem enumeration:
[+]
[+] 	- Caught NoSuchObjectException during activate call (activator not present).
[+] 	  Configuration Status: Current Default
```

As one can see in the output above, the actual exposed remote object implements `org.springframework.remoting.rmi.RmiInvocationHandler`,
as it is always the case for *Spring Remoting*. The underlying interface type however is `eu.tneitzel.rmg.springremoting.ServerOperations`.
This interface supports the following methods:

```java
package eu.tneitzel.rmg.springremoting;

public interface ServerOperations
{
    String notRelevant();
    String execute(String cmd);
    String system(String cmd, String[] args);
    String upload(int size, int id, byte[] content);
    int math(int num1, int num2);
}
```

If you want to learn more about *Spring Remoting* and the associated features of *remote-method-guesser*,
it is recommended to read the corresponding [documentation article](/docs/rmg/spring-remoting.md).
