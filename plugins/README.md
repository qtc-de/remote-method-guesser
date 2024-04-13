### Plugins

----

*remote-method-guesser* can be extended with plugins. Plugins are *jar* files that
can provide implementations for certain interfaces used by *remote-method-guesser*.
If a plugin was specified using the `--plugin` option, *remote-method-guesser* uses
the plugin implementation for the corresponding interface instead of using it's own
one.


### Available plugins

----

Useful plugins can be added to the *remote-method-guesser* repository to make them
visible and available to everyone. Currently, the following plugins are available
within *remote-method-guessers* [plugin folder](/plugins):

* [quartz-scheduler](/plugins/quartz-scheduler) - A plugin for interacting with a
  remote Quartz Scheduler via RMI.


### Plugin Development

----

When developing a new plugin, it is recommended to use the [plugin template](/plugins/template)
provided in this repository. It provides a ready to use *maven* template to get
started with plugin development. [Template.java](/plugins/template/src/main/java/eu/tneitzel/rmg/plugin/Template.java)
contains a class with dummy implementations for all supported interfaces.

Plugin *jar* files need to contain a specific entry within their manifest to be usable
with *remote-method-guesser*:

```
RmgPluginClass: eu.tneitzel.rmg.plugin.Template
```

This entry is set automatically when using the provided maven template. Otherwise,
it needs to be added manually. For access to *remote-method-guesser* classes and
methods, you can import it via maven:

```xml
<dependencies>
    <dependency>
        <groupId>eu.tneitzel</groupId>
        <artifactId>remote-method-guesser</artifactId>
        <version>5.1.0</version>
        <scope>provided</scope>
    </dependency>
</dependencies>
```


### Supported Interfaces

----

This section contains a list of currently supported interfaces. More details can be
found within the [plugin template](/plugins/template).

#### IActionProvider

`IActionProvider` is one of the most powerful plugin interfaces. By implementing this
interface, you can provide custom command line actions for *remote-method-guesser*. These
actions are displayed within a separate *Plugin* section within the help menu and can
be used as regular command line actions - including user specified options.

Custom command line actions can perform arbitrary operations written in Java with access
to the complete *remote-method-guesser* codebase. The implementation of arguments and
optiosn follows the *global arguments* implementation by [this](https://github.com/qtc-de/argparse4j)
*argparse4j* fork.

#### IArgumentProvider

`IArgumentProvider` is used when performing RMI calls using the `call` action. It can be
used to provide more complex command line arguments that cannot be created using *remote-method-guessers*
eval machanism.

#### IPayloadProvider

`IPayloadProvider` is used during deserialization attacks. It can be used to provide custom
gadgets that should be delivered to the remote server.

#### IResponseHandler

`IResponseHandler` can be used to interact with RMI responses obtained via the `call` action.
By default, *remote-method-guesser* ignores return values of RMI calls. By implementing `IResponseHandler`,
you can interact with the RMI response with user specified code.

#### ISocketFactoryProvider

RMI services can use custom socket factory classes that perform additional stuff during connection
or transmission. Despite *remote-method-guesser* uses custom socket factory classes that should match
the most regular use cases, you may need to define custom socket factories in certain situations. The
`ISocketFactoryProvider` allows you to do so.
