### Documentation

-----

In this folder you can find more detailed documentation on *remote-method-guesser*. This folder is currently
work in progress and will be updated from time to time. So far, the following topics are documented:

* *Java RMI*
  * [AccessControlContext List](./rmi/access-control-contexts.md)
  * [Known Remote Objects](./rmi/known-endpoints.md)
  * [Serialization Filter List](./rmi/serialization-filter-list.md)
  * [Unicast Remote Object](./rmi/unicast-remote-object.md)

* *remote-method-gusser*
  * [Actions](./rmg/actions.md)
  * [Activation System](./rmg/activation-system.md)
  * [Media](./rmg/media.md)
  * [Method-Guessing](./rmg/method-guessing.md)
  * [Plugin System](./rmg/plugin-system.md)


### Java RMI - Attack Surface

----

The following mindmap is an attempt to visualize the attack surface on *Java RMI* servers. It is
far from being complete and mostly covers vulnerabilities that can be identifed by *remote-method-guesser*.

![rmi-mindmap](https://tneitzel.eu/73201a92878c0aba7c3419b7403ab604/rmi-mindmap.png)
