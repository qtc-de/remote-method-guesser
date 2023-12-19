### Spring Remoting

----

The *Spring Framework* offers several methods of remoting and also provides a wrapper
around *RMI*. Despite support for serialization based remoting was removed in most recent 
Spring versions (v6), it can still be encountered quite often.

RMI via Spring Remoting is a little bit different than plain Java RMI. Instead of creating
a `RemoteObject` and registering it within an *RMI Registry*, Spring uses a wrapper `RemoteObject`
that gets registered within the registry instead. This wrapper contains a reference to the actual
object where calls should be performed on and supports the following methods:

```java
java.lang.String getTargetInterfaceName()
java.lang.Object invoke(org.springframework.remoting.support.RemoteInvocation invo)
```

As you probably already guessed `getTargetInterfaceName` returns the name of the interface that
is implemented by the underlying object. The `invoke` method on the other hand is used to forward
method calls to the underlying object. The `RemoteInvocation` type contains all information required
for the method call, including the method name, the method argument types and the respective
argument values. The `invoke` method looks up the requested method via reflection and calls it
using the specified argument types.


### remote-method-guesser and Spring Remoting

----

When *remote-method-guesser* encounters a Spring Remoting `RemoteObject` it highlights this already
during the enum action. For Spring Remoting based RemoteObjects, the underlying interface type is
displayed along with the usual information.

Method calls dispatched via the [call](https://github.com/qtc-de/remote-method-guesser#call) action
are always wrapped into `RemoteInvocation` calls instead. This means that remote-method-guesser always
performs calls on the underlying object that is enclosed in the Spring Remoting wrapper. Exceptions
are made for the two known methods mentioned above. These will be dispatched on the wrapper object
itself. If you want to enforce forwarding via `RemoteInvocation`, you can use the `--spring-remoting`
option.

Method guessing is always performed on the underlying object contained within the Spring Remoting
wrapper. All method candidates are wrapped into `RemoteInvocations` and send to the underlying object
via the `invoke` method. Since valid RMI calls have to be used, the different protocol based performance
boost techniques described in the [guessing docs](https://github.com/qtc-de/remote-method-guesser/blob/master/docs/rmg/method-guessing.md)
do not apply to Spring Remoting. However, as method lookups are done via reflection and the methods
argument types and argument values are passed separately, it is still possible to use argument-confusion
to prevent accidental calls of RMI methods. Another advantage of Spring Remotings reflection based lookup
is that return values are not taken into account. Therefore, methods can be guessed by name and argument
types alone. remote-method-guesser automatically filters return value based duplicates out of method
wordlists.
