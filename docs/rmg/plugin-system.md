### rmg Plugin System

----

This document contains information on *remote-method-guesser's* plugin system, a simple way to extend
the functionality of *remote-method-guesser* and to allow custom deserialization payloads or method arguments.


### When you need a Plugin System

----

The base functionality of *remote-method-guesser* is usually sufficient to enumerate and identify
security vulnerabilities on a *Java RMI* endpoint. However, in some situations you may need
more control on the payloads and objects that are send by *remote-method-guesser* and the plugin system
can be used to achieve this.

*remote-method-guesser's* plugin system consist out of four different interfaces that can be implemented by the
user to overwrite *remote-method-guesser's* default behavior.

* ``IPayloadProvider`` - This interface is always used when *rmg* creates payload objects. In
  it's default implementation, it falls back to ``ysoserial`` and creates the user specified
  ``ysoserial`` *gadget*. *rmg* actions like ``act``, ``dgc``, ``method``, ``reg`` or ``listen``
  expect usually the *gadget name* and the *gadget arguments* as input parameters. Both are passed
  to ``ysoserial`` to create the corresponding *gadget object*. By overwriting the default implementation
  of ``IPayloadProvider``, you can obtain the *gadget name* and *gadget argument* parameters
  within your own class and return a payload object of your choice.

* ``IArgumentProvider`` - The ``IArgumentProvider`` interface is used for *rmg's* ``call`` action
  and is responsible for creating the parameter array that is send to the server to dispatch the
  specified method call. In it's default implementation, it uses ``javassist`` to perform basically
  an ``eval`` on the user specified argument string. *RMI* method invocations expect an array of
  *Objects* as argument and a corresponding argument string looks like this in *rmg*:
  ```
  '"argument1", new Integer(2), new StringBuilder("argument3")'
  ```
  Invoking more complex methods using this ``ArgumentProvider`` is often not possible or at least
  not comfortable. By overwriting the default implementation of ``IArgumentProvider`` you can
  create your own handler that accepts the user specified argument string as input and returns
  the corresponding *Object array*.

* ``IResponseHandler`` - This is the only plugin interface that does not has a default implementation.
  ``IResponseHandler`` is used during *rmg's* ``call`` action to handle the servers response to the
  method call. When not implemented, *rmg* simply ignores the servers response without parsing it at all.
  from the ``ObjectInputStream``. On the other hand, when implemented, *rmg* reads the response object
  and passes it to the ``IResponseHandler`` implementation. The general idea behind this concept is,
  that *rmg* cannot known what you want to do with a response object. *RMI* method invocations can return
  arbitrary *Java* objects and how to handle them strongly depends on the particular situation.
  By overwriting ``IResponseHandler``, you can implement your own method that accepts the return object
  as input and performs the desired action.

* ``ISocketFactoryProvider`` - *RMI* communication usually uses the default socket implementations,
  but *RMI* developers are free to choose a different *SocketFactory* to create *RMI* sockets. In these
  situations, you may need to change the default *SocketFactory* that is used by *remote-method-guesser*.
  The ``ISocketFactoryProvider`` interface allows you to do this by using the plugin system.
  

### Interface Classes

----

In this section you find a more detailed description of the interface classes.


#### IPayloadProvider

```java
public interface IPayloadProvider {
    Object getPayloadObject(Operation action, String name, String args);
}
```

The ``IPlayloadProvider`` interface is used to generate payload objects during *rmi* calls. It contains
a single method ``getPayloadObject``, that expects three arguments:

1. ``action`` - This argument represents the current *rmg* action that requests the payload object.
   It can be used to create different payload for different situations. In the default implementation,
   a fallback to ``ysoserial`` is used for most actions, but for actions like ``bind`` the method returns
   an ``RMIServerImpl_Stub`` object instead.

2. ``name`` - Is the gadget name specified on the command line. ``ysoserial`` gadgets usually require a *gadget
   name* and a set of *gadget arguments*. As the default implementation always falls back to ``ysoserial``
   these are also the default requirements for most actions that require payload objects. Within your own
   ``PayloadProvider`` you can use these arguments as you like. If you only want to return a static payload
   object, you can just ignore the parameters, although they still need to be specified on the command line.

3. ``args`` - *Gadget* parameters as explained above.


#### IArgumentProvider

```java
public interface IArgumentProvider {
    Object[] getArgumentArray(String argumentString);
}
```

The ``IArgumentProvider`` interface is used during the ``call`` action to create the parameter array for
method calls. It's only method ``getArgumentArray`` expects a single argument that is the user specified
argument string. In its default implementation, the argument string is basically evaluated using an ``eval``
like construct to create the required object array. Within your own ``ArgumentProvider`` class, you can use
the argument string as you like.  For simply returning a static set of arguments, it can be completely ignored,
although the argument string parameter has still to be specified on the command line during the ``call`` action.


#### IResponseHandler

```java
public interface IResponseHandler {
	void handleResponse(Object responseObject);
}
```

The ``IResponseHandler`` is used during the ``call`` action to handle the servers method invocation response.
By default, it is not implemented and the response is ignored. When implementing it, you need to implement
the ``handleResponse`` method, that is called after the method invocation with the servers response object
as argument.


#### IResponseHandler

```java
public interface ISocketFactoryProvider {
	public RMIClientSocketFactory getClientSocketFactory(String host, int port);
	public RMISocketFactory getDefaultSocketFactory(String host, int port);
	public String getDefaultSSLSocketFactory(String host, int port);
}
```

The ``ISocketFactoryProvider`` interface can be used to overwrite *SocketFactory* implementations that are used during
RMI communication. This is usually not required, but when the RMI server uses a customized *SocketFactory* for *RMI*
communications, you may want to use it.

The ``getClientSocketFactory`` function can be used to overwrite the ``RMIClientSocketFactory`` that is used for direct
connections (e.g. connecting to the *RMI registry* or an *RMI* endpoint directly).

The ``getDefaultSocketFactory`` function can be used to overwrite the ``RMISocketFactory`` that is used on *RMI* operations
that are invoked on remote objects obtained from an *RMI* registry.

The ``getDefaultSSLSocketFactory`` function can be used to overwrite the ``RMISocketFactory`` that is used on RMI operations
that are invoked on remote objects obtained from an *RMI registry*, that use the default ``SSLSocketFactory`` implementation.

When an RMI server implements a custom ``RMISocketFactory`` on the *RMI registry* and for it's remote objects, you usually
need to do the following:

1. Add an compiled version of the server's ``RMISocketFactory`` class to your class path
2. Use the PluginSystem and the getClientSocketFactory function to make it the SocketFactory used for direct calls

This should already be sufficient. If only remote objects use the custom ``RMISocketFactory``, but the RMI registry is not,
you only need the first step. The *PluginSystem* is not even required in this case.

The ``getDefaultSocketFactory`` and ``getDefaultSSLSocketFactory`` functions are only required to modify the connection behavior
on default *RMI* connections. *remote-method-guesser* for example uses these functions to prevent the automatic redirection
that is applied by RMI when the RMI server location was set to *localhost*.


### Default Implementation

----

The following listing contains the default implementation that is used by *remote-method-guesser* internally:

```java
package eu.tneitzel.rmg.plugin;

import java.lang.reflect.Method;
import java.rmi.server.RMIClientSocketFactory;
import java.rmi.server.RMISocketFactory;

import eu.tneitzel.rmg.internal.ExceptionHandler;
import eu.tneitzel.rmg.internal.RMGOption;
import eu.tneitzel.rmg.io.Logger;
import eu.tneitzel.rmg.networking.DGCClientSocketFactory;
import eu.tneitzel.rmg.networking.LoopbackSocketFactory;
import eu.tneitzel.rmg.networking.LoopbackSslSocketFactory;
import eu.tneitzel.rmg.networking.SSRFResponseSocketFactory;
import eu.tneitzel.rmg.networking.SSRFSocketFactory;
import eu.tneitzel.rmg.networking.TrustAllSocketFactory;
import eu.tneitzel.rmg.operations.Operation;
import eu.tneitzel.rmg.operations.RegistryClient;
import eu.tneitzel.rmg.utils.RMGUtils;
import eu.tneitzel.rmg.utils.YsoIntegration;
import javassist.CannotCompileException;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;
import javassist.CtNewMethod;

/**
 * The DefaultProvider is a default implementation of an rmg plugin. It implements the IArgumentProvider,
 * IPayloadProvider and ISocketFactoryProvider interfaces and is always loaded when no user specified
 * plugin overwrites one of these interfaces.
 *
 * Within it's IPayloadProvider override, it returns either a RMIServerImpl object as used by JMX (for bind, rebind
 * and unbin actions) or a ysoserial gadget (for basically all other actions). The IArgumentProvider override attempts
 * to evaluate the user specified argument string as Java code and attempts to create an Object array out of it that
 * is used for method calls. The ISocketFactoryProvider implementation returns remote-method-guesser's loopback
 * factories that prevent redirections from the server side.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class DefaultProvider implements IArgumentProvider, IPayloadProvider, ISocketFactoryProvider {

    /**
     * Return an RMIServerImpl object as used by JMX endpoints when invoked from the bind, rebind or unbind
     * actions. In this case, name is expected to be 'jmx' or args is expected to be null. When the name is
     * 'jmx', the args parameter is expected to contain the address definition for the remote object (host:port).
     * Otherwise, if args is null and the name is not 'jmx', name is expected to contain the listener definition.
     * This allows to perform the bind like 'rmg 127.0.0.1 9010 bind jmx 127.0.0.1:4444' or like
     * 'rmg 127.0.0.1 9010 bind 127.0.0.1:4444'.
     *
     * Otherwise, pass the user specified gadget name and gadget arguments to ysoserial and return the
     * corresponding gadget.
     */
    @Override
    public Object getPayloadObject(Operation action, String name, String args)
    {
        switch(action) {

            case BIND:
            case REBIND:
            case UNBIND:

                if(name.equalsIgnoreCase("jmx")) {
                    String[] split = RMGUtils.splitListener(args);
                    return RegistryClient.prepareRMIServerImpl(split[0], Integer.valueOf(split[1]));

                } else if(args == null) {
                    String[] split = RMGUtils.splitListener(name);
                    return RegistryClient.prepareRMIServerImpl(split[0], Integer.valueOf(split[1]));

                } else {
                    Logger.eprintlnMixedYellow("The specified gadget", name, "is not supported for this action.");
                    RMGUtils.exit();
                }

                break;

            default:

                if(args == null) {
                    Logger.eprintlnMixedBlue("Specifying a", "gadget argument", "is required for this action.");
                    RMGUtils.exit();
                }

                return YsoIntegration.getPayloadObject(name, args);
        }

        return null;
    }

    /**
     * This function performs basically an eval operation on the user specified argumentString. The argument string is
     * inserted into the following expression: return new Object[] { " + argumentString + "};
     * This expression is evaluated and the resulting Object array is returned by this function. For this to work it is
     * important that all arguments within the argumentString are valid Java Object definitions. E.g. one has to use
     * new Integer(5) instead of a plain 5.
     */
    @Override
    public Object[] getArgumentArray(String argumentString)
    {
        Object[] result = null;
        ClassPool pool = ClassPool.getDefault();

        try {
            CtClass evaluator = pool.makeClass("eu.tneitzel.rmg.plugin.DefaultProviderEval");
            String evalFunction = "public static Object[] eval() {"
                                + "        return new Object[] { " + argumentString + "};"
                                + "}";

            CtMethod me = CtNewMethod.make(evalFunction, evaluator);
            evaluator.addMethod(me);
            Class<?> evalClass = evaluator.toClass();

            Method m = evalClass.getDeclaredMethods()[0];
            result = (Object[]) m.invoke(evalClass, (Object[])null);

        } catch(VerifyError | CannotCompileException e) {
            Logger.eprintlnMixedYellow("Specified argument string", argumentString, "is invalid.");
            Logger.eprintlnMixedBlue("Argument string has to be a valid Java expression like:", "'\"id\", new Integer(4)'.");
            Logger.eprintMixedYellow("Make sure that each argument is an", "Object", "not a ");
            Logger.printlnPlainYellow("Primitive.");
            ExceptionHandler.showStackTrace(e);
            RMGUtils.exit();

        } catch (Exception e) {
            ExceptionHandler.unexpectedException(e, "argument array", "generation", true);
        }

        return result;
    }

    /**
     * Returns an RMIClientSocketFactory according to the specified options on the command line.
     */
    @Override
    public RMIClientSocketFactory getClientSocketFactory(String host, int port)
    {
        if( RMGOption.SSRF.getBool() ) {
            return new SSRFSocketFactory();

        } else if( RMGOption.SSRFRESPONSE.notNull() ) {
            byte[] content = RMGUtils.hexToBytes(RMGOption.SSRFRESPONSE.getValue());
            return new SSRFResponseSocketFactory(content);

        } else if( RMGOption.CONN_SSL.getBool() ) {
            return new TrustAllSocketFactory();

        } else {
            return RMISocketFactory.getDefaultSocketFactory();
        }
    }

    /**
     * The default RMISocketFactory used by remote-method-guesser is the LoopbackSocketFactory, which
     * redirects all connection to the original target and thus prevents unwanted RMI redirections.
     *
     * This function is only used for 'managed' RMI calls that rely on an RMI registry. Remote objects that
     * are looked up from the RMI registry use the RMISocketFactory.getDefaultSocketFactory function to
     * obtain a SocketFactory. This factory is then used for explicit calls (method invocations) and for
     * implicit calls (DGC actions like clean or dirty). When contacting an RMI endpoint directly (by
     * using the RMIEndpoint class) we do not need to call this function as we specify a socket factory
     * already during the call. When using the RMI registry (RMIRegistryEndpoint class), it is required.
     * In this case, this function should be called and the result should be used within the
     * RMISocketFactory.setSocketFactory function.
     *
     * When the --ssrf-response option is used, we do neither perform any explicit calls nor we want
     * DGC actions to take place. For this purpose, we use a custom socket factory that ignores writes
     * of outgoing DGC requests and simulates incoming DGC responses.
     *
     * Notice, that the --ssrf option does not affect this function. This is because sockets created
     * by this function are only used for 'managed' RMI calls. SSRF calls in remote-method-guesser are
     * always unmanaged.
     */
    @Override
    public RMISocketFactory getDefaultSocketFactory(String host, int port)
    {
        if( RMGOption.SSRFRESPONSE.notNull() )
            return new DGCClientSocketFactory();

        RMISocketFactory fac = RMISocketFactory.getDefaultSocketFactory();
        return new LoopbackSocketFactory(host, fac, RMGOption.CONN_FOLLOW.getBool());
    }

    /**
     * The default SSLRMISocketFactory used by remote-method-guesser is the LoopbackSslSocketFactory, which
     * redirects all connection to the original target and thus prevents unwanted RMI redirections.
     *
     * As in the case of plain TCP connections, we use different socket factory if --ssrf-response
     * was specified on the command line. Check the getDefaultSocketFactory function for more details.
     *
     * Notice, that the --ssrf option does not affect this function. This is because sockets created
     * by this function are only used for 'managed' RMI calls. SSRF calls in remote-method-guesser are
     * always unmanaged.
     */
    @Override
    public String getDefaultSSLSocketFactory(String host, int port)
    {
        if( RMGOption.SSRFRESPONSE.notNull() )
            return "eu.tneitzel.rmg.networking.DGCClientSslSocketFactory";

        TrustAllSocketFactory trustAllFax = new TrustAllSocketFactory();

        LoopbackSslSocketFactory.host = host;
        LoopbackSslSocketFactory.fac = trustAllFax.getSSLSocketFactory();
        LoopbackSslSocketFactory.followRedirect = RMGOption.CONN_FOLLOW.getBool();

        return "eu.tneitzel.rmg.networking.LoopbackSslSocketFactory";
    }
}
```


### An Example Plugin

----

*remote-method-guesser* currently ships one example plugin within of it's [plugin folder](/plugins). This plugin
implements the ``IResponseHandler`` interface and attempts to perform a *generic print* on the servers
return object. It can be used as a basis for your own plugin development.


### Building Plugins

----

An *remote-method-guesser* plugin can be specified on the command line using the ``--plugin <PATH>`` option.
The plugin needs to be in *JAR* format and *remote-method-guesser* requires it to contain the name of the
actual plugin class as attribute within of it's *JAR manifest*. E.g. for the ``GenericPrint`` plugin, this attribute
looks like this:

```yaml
RmgPluginClass: GenericPrint
```

To make building of plugin classes more simple, *remote-method-guesser* includes a [build script](/plugins/build.sh)
that should work for most situations. The following listing shows an example on how to build and use the
[GenericPrint](/plugins/GenericPrint.java) plugin:

```console
[qtc@devbox remote-method-guesser]$ bash plugins/build.sh target/rmg-4.0.0-jar-with-dependencies.jar plugins/GenericPrint.java GenericPrint.jar
[qtc@devbox remote-method-guesser]$ rmg call 172.17.0.2 9010 '"id"' --signature "String execute(String arg)" --bound-name plain-server --plugin GenericPrint.jar
[+] uid=0(root) gid=0(root) groups=0(root)
```
