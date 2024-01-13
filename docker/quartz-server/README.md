### Quartz Scheduler Server

----

[Quartz](https://github.com/quartz-scheduler/quartz) is a great example for the dangers of exposing
*RMI* services to untrusted networks. Quartz Scheduler is a Java library that makes it easy to build
a (remotely accessible) job scheduler. Remote access is implemented via RMI and usually allows remote
code execution when accssible.

Notice that this is **not** a security vulnerability. Quartz is just a library and it is the developers
responsibility to use it correctly. The documentation [clearly outlines]http://www.quartz-scheduler.org/documentation/2.4.0-SNAPSHOT/best-practices.html#exposing-scheduler-functionality-through-applications)
that unrestricted access to Quartz allows remote code execution.


### Configuration Details

----

The implementation is basically the same as [this example](https://github.com/quartz-scheduler/quartz/blob/main/examples/src/main/java/org/quartz/examples/example12/RemoteServerExample.java)
from the Quartz [GitHub repository](https://github.com/quartz-scheduler/quartz). The scheduler is
configured to create an *RMI registry* on port `1099` and is listening itself on port `4444`.
Performing the `enum` action of *remote-method-guesser* should provide the following results:

```console
[user@host ~]$ rmg enum 172.17.0.2 1099
[+] RMI registry bound names:
[+]
[+] 	- DefaultQuartzScheduler_$_NON_CLUSTERED
[+] 		--> org.quartz.core.QuartzScheduler_Stub (unknown class)
[+] 		    Endpoint: iinsecure.example:4444  CSF: RMISocketFactory  ObjID: [-29528512:18d0471d7d0:-7fff, 3126757509392163867]
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

The different methods that can be invoked via RMI can be found [here](http://www.quartz-scheduler.org/api/2.2.2/org/quartz/core/QuartzScheduler.html).
