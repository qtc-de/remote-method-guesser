### Method Guessing

----

One of the core features of *remote-method-guesser* is it's ``guess`` action, which allows
to identify valid method signatures on *RMI endpoints* by using a wordlist approach. With
*rmg v3.3.0*, the guessing speed increases up to a factor of ``4`` for plain *TCP* connections
and up to a factor of ``8`` for *TLS* protected *RMI* communication. We take this as an opportunity
to write a more detailed explanation on how we perform method guessing and how we achieved the above
mentioned speedup.


### Why Method Guessing?

----

*Java RMI* is a *remote procedure call* (*RPC*) technology for *Java* and allows a client to invoke
remote methods that are defined on the server side. Knowledge of these exposed methods is an important
part to evaluate the attack surface on a *RMI endpoint*. However, apart from some well known (and in
current *Java* versions, well protected) methods, that are available on (almost) each *RMI endpoint*,
it is usually not possible to obtain the signature of other methods that may be exposed.

This makes evaluating the security state of *RMI endpoints* difficult, because the analyst has only
a limit view on the actual exposed services. The simplest example could be a method with signature
``String execute(String cmd)``, which is obviously dangerous but hidden during a blackbox assessment.
But not only such obviously dangerous functions are of interest. As [Hans-Martin Münch](https://twitter.com/h0ng10) explains in
[this blog post](https://mogwailabs.de/en/blog/2019/03/attacking-java-rmi-services-after-jep-290/), also
harmless looking method signatures can be exploited for deserialization attacks, if the methods
signature is known to the attacker.

Despite *Java RMI* does not expose any *API* calls to obtain the available methods signatures defined on
a *RMI endpoint*, it is possible to guess valid signatures by using a wordlist approach. The idea is pretty
simple: For each method defined in the wordlist, an *RMI* call with invalid argument types is dispatched and
send to the server. Depending on the server exception, it can be determined whether the corresponding method
exists. More details on the different challenges and pitfalls when implementing this technique can be found
within the next chapters.


### Implementation

----

One challenge of implementing *method guessing* is that *Java RMI* is an object oriented *RPC* mechanism.
Invoking remote methods is done via local objects, that wrap references to a corresponding remote object. 
The class of the local object (usually an interface) needs to match the class (interface) name on the server
side and needs to contain the desired method definitions. The following code snipped shows an simple
example on how to obtain such a local object that wraps a reference to the remote object that is bound as
``example-server`` within the registry.

```java
Registry registry = LocateRegistry.getRegistry(rmiHost);
ExampleInterface stub = (ExampleInterface)registry.lookup("example-server");
```

For the ``lookup`` operation to work, it is required that the ``ExampleInterface`` is available within
the classpath before the lookup. Otherwise, *Java* throws a ``ClassNotFoundException`` and the lookup
fails. This design is fine for ordinary *RMI* use cases, as the *RMI* developer can include all required
interface into the clients codebase. From a blackbox perspective however, this behavior is an obstacle.


#### Most Naive Approach

To overcome the obstacle mentioned before and to implement a first approach to *method guessing*, one could
do the following steps:

  1. Lookup the associated class or interface name that belongs to the desired bound name (e.g. ``org.example.ExampleInterface``).
  2. Create the corresponding class or interface dynamically (e.g. by using [Javassist](https://www.javassist.org/)).
  3. Add the desired methods to the dynamically created class or interface.
  4. Invoke the methods and use the servers exceptions to identify valid methods.

This approach works fine, but has some drawbacks. The most significant one is that you perform valid method calls
that lead to real method invocations on the server side. Even when using dummy arguments (e.g. ``null`` for each
object type argument, ``true`` for each boolean, ``0`` for each numeric, ...) the method call could still cause an
undesired behavior on the server. 


#### Guessing Without Invoking

The [rmiscout](https://github.com/BishopFox/rmiscout) project was the first one (best to my knowledge) that allowed
guessing of remote methods without actually invoking them on the server side. To understand how it works, we should
take a look at the structure of a *Java RMI* call:

![RMI Message Structure](https://tneitzel.eu/73201a92878c0aba7c3419b7403ab604/rmg-method-guessing-01.png)

The first three parts of the call are not that interesting for method guessing:

  * The *OperationType* is always ``0x50`` in our case, as we want to perform a method call
  * The *ObjID* is obtained during the ``lookup`` operation from the registry and is just a
    static identifier for the targeted remote object.
  * The *OperationNumber* is always set to ``-1``, as we call methods by their method hash.
    In earlier *RMI* implementations, methods could also be called by using an *interface hash*
    that was valid for the whole interface and by specifying the desired method as a numeric
    identifier (compare e.g. to [RegistryImpl_Skel.java](https://github.com/openjdk/jdk/blob/90c1034cd4077e63afc0aad53191a04699a816ce/src/java.rmi/share/classes/sun/rmi/registry/RegistryImpl_Skel.java)).

The *MethodHash* is used by modern *RMI* servers to obtain a reference to the desired remote method. It is calculated
by using the methods signature, which includes the *method name*, *return type* and all *argument types*. When an *RMI server*
encounters an unknown method hast (method is not defined on the server side) it throws a corresponding exception (see
implementation of [UnicastServerRef](https://github.com/openjdk/jdk/blob/90c1034cd4077e63afc0aad53191a04699a816ce/src/java.rmi/share/classes/sun/rmi/server/UnicastServerRef.java)):

```java
try {
    op = in.readLong();
} catch (Exception readEx) {
    throw new UnmarshalException("error unmarshalling call header",
            readEx);
}

[...]

Method method = hashToMethod_Map.get(op);
if (method == null) {
    throw new UnmarshalException("unrecognized method hash: " +
        "method not supported by remote object");
}
```

This exception is used to determine invalid remote methods during method guessing. In case of an existing
method call, ``UnicastServerRef`` goes ahead and unmarshals the call arguments by using the methods parameter
types that were obtained using reflection:

```java
Class<?>[] types = method.getParameterTypes();
Object[] params = new Object[types.length];

try {
    unmarshalCustomCallData(in);
    // Unmarshal the parameters
    for (int i = 0; i < types.length; i++) {
        params[i] = unmarshalValue(types[i], in);
    }
```

When using the high-level *Java RMI API*, *Java* automatically computes the method hash for you and makes sure
that all specified parameters match the expected parameter types. The *rmiscout* project uses low level *Java RMI*
calls instead, to manipulate the call arguments. Instead of the expected parameter types, a randomly generated class
is send to the *RMI server* and the servers exception is inspected:

  * When the method does not exist on the *RMI* endpoint, the ``unrecognized method hash`` exception is thrown as usual.
  * When the method does exist, the *RMI endpoint* attempts to unmarshal the call arguments but cannot find the randomly
    generated class within it's own class path. This aborts the actual method call and leads to a different exception that
    indicates the existence of the remote method.


#### Making it Fast

Before *rmg v3.3.0* we basically used the same approach as the *rmiscout* project. Instead of randomly generated classes,
we used a *type confusion approach* (sending object types when the server expects primitive ones and the other way around),
but this is only a minor difference. In the current version however, we changed the implementation to achieve a noticeable
speedup. To understand how, we need again to take a look at the internal structure and the server-side processing of *RMI messages*.

*Java RMI* allows reuse of already existing *TCP connections*. After invoking a remote method once, subsequent remote method
invocations may use the same *TCP channel* and do not have to establish a new connection. This behavior is handled by *Java RMI*
automatically and does not require manual control by the developer. However, reusing *TCP streams* is only possible if they are in a
non corrupted state, which is usually not the case for method guessing.

Internally, *Java RMI* uses the ``invoke`` method from the [UnicastRef](https://github.com/openjdk/jdk/blob/master/src/java.rmi/share/classes/sun/rmi/server/UnicastRef.java) class
to invoke remote methods from the client side. This is also the call that the *rmiscout* project and (in earlier versions)
*remote-method-guesser* used. The problem with this method is that it sends the above visualized *RMI* message at once, without
handling intermediate exceptions. The following diagram tries to visualize that behavior when calling an non existing remote method:

![RMI Message Structure](https://tneitzel.eu/73201a92878c0aba7c3419b7403ab604/rmg-method-guessing-02.png)

As one can see, this behavior causes the *MethodArguments* to stay within the *TCP stream*, which makes the stream corrupted
and not reusable. This behavior can also be observed within the ``invoke`` method of the [UnicastRef](https://github.com/openjdk/jdk/blob/master/src/java.rmi/share/classes/sun/rmi/server/UnicastRef.java) class.

```java
public void invoke(RemoteCall call) throws Exception {
  try {
      clientRefLog.log(Log.VERBOSE, "execute call");

      call.executeCall();

  } catch (RemoteException e) {
      /*
       * Call did not complete; connection can't be reused.
       */
      clientRefLog.log(Log.BRIEF, "exception: ", e);
      free(call, false);
      throw e;
```

TODO...
