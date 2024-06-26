### Plugin Template

----

This folder contains a template for developing *remote-method-guesser* plugins.
Simply adjust the [Template Class](src/main/java/eu/tneitzel/rmg/plugin/Template.java)
to your requirements and compile the template using *maven*. If you change the
template class' classname, make sure to also reflect this change within the `RmgPluginClass`
property within [pom.xml](https://github.com/qtc-de/remote-method-guesser/blob/master/plugin/template/pom.xml#L39).

The template contains placeholder implementations for all available plugin interfaces.
Make sure to remove all interfaces and the associated methods that are not actually used
by your plugin.
