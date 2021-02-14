### RMI Serialization Filters

----

In this document you find a small list of serialization filters that are implemented on modern
RMI endpoints for the internal RMI communication. The source code samples for the filters were
copied from the current state (at the time of writing) of the [openjdk GitHub repository](https://github.com/openjdk/jdk).


### RMI Registry Filter

----

* Filter applies to all communication that targets the registry *RemoteObject*.
* The filter is defined in ``RegistryImpl.java`` within the ``registryFilter`` function.
* Can be customized using the ``sun.rmi.registry.registryFilter`` property.
* Relevant part of the filter definition:
  ```java
  if (String.class == clazz
          || java.lang.Number.class.isAssignableFrom(clazz)
          || Remote.class.isAssignableFrom(clazz)
          || java.lang.reflect.Proxy.class.isAssignableFrom(clazz)
          || UnicastRef.class.isAssignableFrom(clazz)
          || RMIClientSocketFactory.class.isAssignableFrom(clazz)
          || RMIServerSocketFactory.class.isAssignableFrom(clazz)
          || java.rmi.activation.ActivationID.class.isAssignableFrom(clazz)
          || java.rmi.server.UID.class.isAssignableFrom(clazz)) {
      return ObjectInputFilter.Status.ALLOWED;
  } else {
      return ObjectInputFilter.Status.REJECTED;
  }
  ```


### Distributed Garbage Collector Filter (Inbound)

-----

* Filter applies to all inbound communication to *DGC* remote objects.
* The filter is defined in ``DGCImpl.java`` within the ``checkInput`` function.
* Can be customized using the ``sun.rmi.transport.dgcFilter`` property.
* Relevant part of the filter definition:
  ```java
  if (clazz.isPrimitive()) {
      return ObjectInputFilter.Status.ALLOWED;
  }
  return (clazz == ObjID.class ||
          clazz == UID.class ||
          clazz == VMID.class ||
          clazz == Lease.class)
          ? ObjectInputFilter.Status.ALLOWED
          : ObjectInputFilter.Status.REJECTED;
  ```


### Distributed Garbage Collector Filter (Outbound)

-----

* Filter applies to outbound *DGC* communication. 
  * When a new ``LiveRef`` enters the *Java Virtual Machine*, the ``registerRefs`` function of the
    ``DGCClient`` class is used, to register the object to participate in distributed garbage collection.
  * During the registration process, the *DGCClient* sends an initial ``dirty`` call to the server side
    *DGC* on the endpoint specified within the ``LiveRef``.
  * This ``dirty`` call is affected by the outbound serialization filters.

* The filter is defined in ``DGCImpl_Stub.java`` within the ``leaseFilter`` function.
  * Notice that usage of the *Stub* is enforced by the ``DGCCLient`` class.
  * ``DGCCLient`` uses ``Util.createProxy(DGCImpl.class, new UnicastRef(dgcRef), true);`` to create
    the *Stub*, where the last boolean argument is the *forceStubUse* argument.

* The outbound *DGC* filter cannot be customized.
* Relevant part of the filter definition:
  ```java
  if (clazz.isPrimitive()) {
      // Arrays of primitives are allowed
      return ObjectInputFilter.Status.ALLOWED;
  }
  return (clazz == UID.class ||
          clazz == VMID.class ||
          clazz == Lease.class ||
          (Throwable.class.isAssignableFrom(clazz) &&
                  (Object.class.getModule() == clazz.getModule() ||
                          RemoteException.class.getModule() == clazz.getModule())) ||
          clazz == StackTraceElement.class ||
          clazz == ArrayList.class ||     // for suppressed exceptions, if any
          clazz == Object.class ||
          clazz.getName().equals("java.util.Collections$EmptyList"))
          ? ObjectInputFilter.Status.ALLOWED
          : ObjectInputFilter.Status.REJECTED;
  }
  ```


### Activator Filter

----

* The *Activator* is another well known *RemoteObject* with an ``ObjID`` value of ``1``.
* An *Activator* is not used by default and needs to be configured manually. However,
  at the time of writing, it is still part of *RMI*.
* The *Activator* was never protected by serialization filters. An *RMI* instance
  running the default *Activator* implementation is therefore **always vulnerable** to
  deserialization attacks.
* *JEP 385* suggests to finally remove the *Activation mechanism* from RMI.
