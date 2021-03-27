### rmg Plugin System

----

This document contains information on *rmg's* plugin system, a simple way to extend
the functionality of *rmg* and to allow custom deserialization payloads or method arguments.


### When you need a Plugin System

----

The base functionality of *rmg* is usually sufficient to enumerate and identify all relevant
security vulnerabilities on a *Java RMI* endpoint. However, in some situations you may need
more controll on the *Payloads* and *Objects* that are send by *rmg* and the plugin system
can be used to achieve this.

*rmg's* plugin system consits out of three different interfaces that can be implemented by the
user to overwrite *rmg's* default behvaior.

* ``IPayloadProvider``
* ``IArgumentProvider``
* ``IResponseHandler``
