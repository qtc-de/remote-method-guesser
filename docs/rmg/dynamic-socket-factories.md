### Dynamic Socket Factories

----

With version *v4.5.0* support for dynamically created socket factories
were added to *remote-method-guesser*. This basically means the following:

*RMI* servers can register a custom socket factory that has to be used
to connect to their exposed remote objects. If this is done by an *RMI*
server, you usually see an error message like the following when you
attempt to connect with *remote-method-guesser*:

> The class custom.socket.Factory could not be resolved within your class path

With this error message, *Java* simply complains that it can't find the
implementation of `custom.socket.Factory`, which is required to establish
a connection to the *RMI* server.

In some cases, this means that you cannot further enumerate the *RMI*
service, but often times it is possible anyways. Custom socket factory
classes often still rely on the default socket implementations. This means
that at the end of the day, the socket factory still outputs a regular
socket, as it can also be obtained from *Java's* default socket *APIs*.

From version *v4.5.0* on, *remote-method-guesser* attempts to detect
errors caused by missing socket factory classes. In these cases, *rmg*
attempts to create the class dynamically. Since the actual implementation
is unknown, the dynamically created socket factory is simply the default
socket factory used by *remote-method-guesser*. Surprisingly often, this
is sufficient to connect.

But why people implement custom socket factories when you can also connect
to them with the default one? Well, most of the time developers only add some
small behavior changes for their sockets, like e.g. a specific socket timeout
or trust for a self signed certificate. As these changes do not matter for an
successful connection (as *remote-method-guesser* trusts all certificates anyway)
dynamic socket factory creation works in these cases.

However, some developers like it special. You could for example create a socket
factory that applies *XOR* encoding to all bytes before they are transmitted.
In such a case, dynamic socket factory creation will not work, as the default
sockets created by *remote-method-guesser* will not apply the *XOR* encoding
and the server side socket will not understand our data.


### User Options

----

By default, *remote-method-guesser* attempts to create a socket factory
for classes that contain the string `SocketFactory` or end with `Factory`
or `SF`. If you want to dynamically create a socket factory for a different
class, you can specify the class name using the `--socket-factory` option.
Each class that cannot be found locally will then be checked whether it contains
the specified pattern and a socket factory will be created if this is the case.

You can also use the `--socket-factory` option to prevent the dynamic creation
of socket factories. When a pattern was specified, the default patterns are not
checked. Therefore, using something like `--socket-factory nobody.uses.a.class.name.like.this`
will prevent socket factory creation.
