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

Not reusing existing *TCP streams* slows down the overall speed of method guessing, as *TCP connections* need to be reestablished.
For plain *TCP* connections the impact is not that big of a deal, although it increases with a larger wordlist size. For *TLS* protected
connections, the slowdown is more significant and we observed speedups up to a factor of ``8`` when implementing reusable streams.


#### Preventing Stream Corruption

The open question is now how to prevent stream corruption during method guessing. From our perspective there are two approaches to that:

  1. *Argument less guessing* - When looking at the *RMI* message structure displayed above and the behavior how *RMI endpoints* parse
     the corresponding data, it seems that one can just skip sending of method arguments during method guessing. In case of non existing
     remote methods this is indeed fine, as the *RMI endpoint* will only parse the data up to the method hash and then raise an exception.
     When no arguments were sent, the *TCP* streams stays clean and can be reused.

     In case of existing methods, *argument less guessing* causes a small problem: The *RMI endpoint* waits for the method arguments to appear
     within the *TCP* stream. When not sending any arguments, this will cause a timeout. Obviously, this timeout would be sufficient as an
     indicator that the corresponding method exists, but such time based approaches are not that reliable an error prone.

  2. *Polyglot argument* - Method arguments usually corrupt the *TCP* stream, as they do not match the format of a valid *RMI call*. If it is
     possible to send method arguments that form a valid *RMI call* on their own, stream corruption could be prevented and the *TCP* connection
     could be reused. Moreover, in the case of existing methods, the method arguments lead to an invalid *RMI call* on the server side, to prevent
     the method from actually being invoked.

In *rmg v3.3.0*, we implemented the second approach and looked for a corresponding *polyglot* method argument, that was surprisingly simple to find.
*RMI messages* usually start with a *TransportConstant* as it was explained earlier. During method calls, this transport constant is always set to
``0x50``, but also other transport constants exist. In case of other transport constants, the structure of an *RMI* differs from the above mentioned
structure and it is parsed differently by the server. The following snipped shows an excerpt of the [TCPTransport](https://github.com/openjdk/jdk/blob/master/src/java.rmi/share/classes/sun/rmi/transport/tcp/TCPTransport.java) class, that handles the different
message types:

```java
do {
    int op = in.read();     // transport op
    [...]

    switch (op) {

      case TransportConstants.Call:
          // service incoming RMI call
          RemoteCall call = new StreamRemoteCall(conn);
          if (serviceCall(call) == false)
              return;
          break;

      case TransportConstants.Ping:
          // send ack for ping
          DataOutputStream out =
              new DataOutputStream(conn.getOutputStream());
          out.writeByte(TransportConstants.PingAck);
          conn.releaseOutputStream();
          break;

      case TransportConstants.DGCAck:
          DGCAckHandler.received(UID.read(in));
          break;

      default:
          throw new IOException("unknown transport op " + op);
    }

} while (persistent);
```

Notice that in case of the *TransportConstant* being *Ping* (``0x52``), no further data is read from the input stream.
Therefore, an *RMI Ping* message just consists out of the *TransportConstant*, which is pretty handy for our purposes.
The following diagram shows, how the used the *RMI Ping* message as a *polyglot* method argument:

![RMI Ping Polyglot](https://tneitzel.eu/73201a92878c0aba7c3419b7403ab604/rmg-method-guessing-03.png)

With the *RMI Ping* message being used as a method argument, the *TCP* streams stays in a clean state and can be reused
for further guessing attempts in case of non existing methods. But how about existing methods? The *RMI Ping TransportConstant*
is just an ``int`` doesn't this cause problems with methods that expected an ``int`` as argument? Luckily, the answer is *no*
if you write the data to the correct output stream.

Almost all data written during a *RMI call* is wrapped within an ``ObjectOutputStream`` (only the *TransportConstant* is written
to the raw ``OutputStream`` directly). Within an ``ObjectOuputStream``, data is aligned to match a specific format. This is not only
true for non primitive data (e.g. objects or classes), but also primitive types are aligned within a special data structure.
The following listing shows an example of this situation, where the contents of an *RMI call* are visualized by using the tool
[SerializationDumper](https://github.com/NickstaDB/SerializationDumper) (the *TransportConstant* was stripped before):

```
STREAM_MAGIC - 0xac ed
STREAM_VERSION - 0x00 05
Contents
  TC_BLOCKDATA - 0x77
    Length - 38 - 0x26
    Contents - 0x6ca04bad45b46f47b2def1540000017a039eabde8009ffffffff67e2a9311d3dd3ec00000001
```

Instead of raw bytes, the *ObjID*, *OperationNumber* and the *MethodHash* are wrapped into a ``TC_BLOCKDATA`` element,
that includes the length of the contained data. During method guessing, we write the *RMI Ping* message not on the
``ObjectOutputStream``, but on the underlying raw ``OutputStream``. The *RMI Ping* message is then not treated as part
of the ``TC_BLOCKDATA`` structure, but as a new element within the ``ObjectOutputStream``. However, as the code ``0x52``
is not a valid element type, parsing the corresponding ``ObjectInputStream`` now leads to an error:

```
STREAM_MAGIC - 0xac ed
STREAM_VERSION - 0x00 05
Contents
  TC_BLOCKDATA - 0x77
    Length - 38 - 0x26
    Contents - 0x6ca04bad45b46f47b2def1540000017a039eabde8009ffffffff67e2a9311d3dd3ec00000001
  Invalid content element type 0x52
```

This is exactly the behavior we want during method guessing. As the ``ObjectInputStream`` is valid up to the method hash,
the *RMI endpoint* successfully parses all the elements before the *RMI Ping* message. When attempting to read the method arguments
however, the *RMI endpoint* will read the next ``ObjectInputStream`` element (``0x52``) and raise an exception. Due to the different
exception message, we know that the method exists and because the *RMI Ping* message was read and removed from the *TCP stream*, the
stream stays clean and can be reused. Furthermore, the corresponding remote method was never really invoked, as there was an error when
parsing the method arguments.

TODO...
