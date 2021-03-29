### rmg Plugin System

----

This document contains information on *rmg's* plugin system, a simple way to extend
the functionality of *rmg* and to allow custom deserialization payloads or method arguments.


### When you need a Plugin System

----

The base functionality of *rmg* is usually sufficient to enumerate and identify all relevant
security vulnerabilities on a *Java RMI* endpoint. However, in some situations you may need
more control on the *Payloads* and *Objects* that are send by *rmg* and the plugin system
can be used to achieve this.

*rmg's* plugin system consist out of three different interfaces that can be implemented by the
user to overwrite *rmg's* default behavior.

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

* ``IResponseHandler`` - This is the only plugin interface that does not have a default implementation.
  ``IResponseHandler`` is used during *rmg's* ``call`` action to handle the servers response to the
  method call. When not implemented, *rmg* simply ignores the servers response without parsing it at all.
  from the ``ObjectInputStream``. On the other hand, when implemented, *rmg* reads the response object
  and passes it to the ``IResponseHandler`` implementation. The general idea behind this concept is,
  that *rmg* cannot known what you want to do with a response object. *RMI* method invocations can return
  arbitrary *Java* objects and how to handle them strongly depends on the particular situation.
  By overwriting ``IResponseHandler``, you can implement your own method that accepts the return object
  as input and performs the desired action.
  

### Interface Classes

----

In this section you find a more detailed description of the interface classes.


#### IPayloadProvider

```java
package de.qtc.rmg.plugin;

import de.qtc.rmg.operations.Operation;

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
package de.qtc.rmg.plugin;

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
package de.qtc.rmg.plugin;

public interface IResponseHandler {
	void handleResponse(Object responseObject);
}
```

The ``IResponseHandler`` is used during the ``call`` action to handle the servers method invocation response.
By default, it is not implemented and the response is ignored. When implementing it, you need to implement
the ``handleResponse`` method, that is called after the method invocation with the servers response object
as argument.


### Default Implementation

----

The following listing contains the default implementation that is used by *rmg* internally:

```java
package de.qtc.rmg.plugin;

import java.lang.reflect.Method;

import de.qtc.rmg.internal.ExceptionHandler;
import de.qtc.rmg.io.Logger;
import de.qtc.rmg.operations.Operation;
import de.qtc.rmg.operations.RegistryClient;
import de.qtc.rmg.utils.RMGUtils;
import de.qtc.rmg.utils.YsoIntegration;
import javassist.CannotCompileException;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;
import javassist.CtNewMethod;

public class DefaultProvider implements IArgumentProvider, IPayloadProvider {

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

    @Override
    public Object[] getArgumentArray(String argumentString)
    {
        Object[] result = null;
        ClassPool pool = ClassPool.getDefault();

        try {
            CtClass evaluator = pool.makeClass("de.qtc.rmg.plugin.DefaultProviderEval");
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
            RMGUtils.exit();

        } catch (Exception e) {
            ExceptionHandler.unexpectedException(e, "argument array", "generation", true);
        }

        return result;
    }
}
```


### An Example Plugin

----

*rmg* does currently ship one example plugin within of it's [plugin folder](/plugins). This plugin
implements the ``IResponseHandler`` interface and attempts to perform a *generic print* on the servers
return object. When interested in the servers response object, you often want to print it in some way.
The [GenericPrint Plugin](./plugins/GenericPrint.java) attempts exactly this for different sorts of
response objects.

```java
import java.util.Map;
import java.util.Collection;

import de.qtc.rmg.plugin.IResponseHandler;

public class GenericPrint implements IResponseHandler {

	public void handleResponse(Object responseObject)
    {
        if(responseObject instanceof Collection<?>) {
        
            for(Object o: (Collection<?>)responseObject) {
                System.out.println(o.toString());
            }

        } else if(responseObject instanceof Map<?,?>) {

            Map<?,?> map = (Map<?,?>)responseObject;

            for(Object o: map.keySet()) {
                System.out.print(o.toString());
                System.out.println(" --> " + map.get(o).toString());
            }

        } else if(responseObject.getClass().isArray()) {

            for(Object o: (Object[])responseObject) {
                System.out.println(o.toString());
            }

        } else {
            System.out.println(responseObject.toString());
        }
    }
}
```


### Building Plugins

----

An *rmg* plugin can be specified on the command line using the ``--plugin <PATH>`` option.
The plugin needs to be in *JAR* format and *rmg* requires it to contain the name of the
actual plugin class as attribute within of it's *JAR manifest*. E.g. for the ``GenericPrint``
plugin, this attribute looks like this:

```yaml
RmgPluginClass: GenericPrint
```

To make building of plugin classes more simple, *rmg* includes a [build script](/plugins/build.sh)
that should work for most situations. The following listing shows an example on how to build
and use the [GenericPrint](/plugins/GenericPrint.java) plugin:

```console
[qtc@kali remote-method-guesser]$ bash plugins/build.sh target/rmg-3.2.0-jar-with-dependencies.jar plugins/GenericPrint.java Plugin.jar
[qtc@kali remote-method-guesser]$ rmg 172.17.0.2 9010 call '"id"' --signature "String execute(String arg)" --bound-name plain-server --plugin ./Plugin.jar
[+] RMI object tries to connect to different remote host: iinsecure.dev.
[+] 	Redirecting the connection back to 172.17.0.2... 
[+] 	This is done for all further requests. This message is not shown again. 
uid=0(root) gid=0(root) groups=0(root)
```
