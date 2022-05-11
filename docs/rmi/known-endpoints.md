### Distributed Garbage Collector

---

* Name: `Distributed Garbage Collector`
* Class Names:
    * `sun.rmi.transport.DGCImpl_Stub`
* Description:

    > The Distributed Garbage Collector (DGC) tracks the number of active instances for remote objects
    > and cleans them up if they are no longer used. Clients indicate usage of a remote object by calling
    > the DGC.dirty method. The server returns a Lease that indicates how long it will keep the corresponding
    > remote object from where. Within this lifetime, clients can call the DGC.dirty method again to renew
    > the lease. When a remote object is garbage collected locally on the client side, a DGC.clean call is
    > made that indicates that the corresponding remote object is no longer used by the client. In case of
    > remote objects that are bound to the RMI registry, the registry itself is the Lease holder. Usually,
    > DGC remote objects can be found on each RMI endpoint.

* Remote Methods:

    ```java
    java.rmi.dgc.Lease dirty(java.rmi.server.ObjID[] ids, long sequenceNum, java.rmi.dgc.Lease lease)
    void clean(java.rmi.server.ObjID[] ids, long sequenceNum, java.rmi.dgc.VMID vmid, boolean strong)
    ```
* References:
    * [https://docs.oracle.com/javase/8/docs/platform/rmi/spec/rmi-arch4.html](https://docs.oracle.com/javase/8/docs/platform/rmi/spec/rmi-arch4.html)
    * [https://github.com/openjdk/jdk/tree/master/src/java.rmi/share/classes/sun/rmi/transport](https://github.com/openjdk/jdk/tree/master/src/java.rmi/share/classes/sun/rmi/transport)
* Known Vulnerabilities:

    * Deserialization
        * Description:

            > Distributed Garbage Collector instances where JEP290 was not applied are vulnerable to deserialization
            > attacks. With JEP290, deserialization filters were introduced. The deserialization filters of DGC
            > endpoints are more restrictive than for the RMI registry and there a no known bypasses.
        * References:
            * [https://github.com/qtc-de/remote-method-guesser](https://github.com/qtc-de/remote-method-guesser)


### JMX Connection

---

* Name: `JMX Connection`
* Class Names:
    * `javax.management.remote.rmi.RMIConnectionImpl_Stub`
* Description:

    > Java Management Extensions (JMX) can be used to monitor and manage a running Java virtual machine.
    > This remote object can be used to send instructions to a running JMX agent. It is usually obtained
    > by calling the newClient method on a JMX RMIServerImpl_Stub object.

* Remote Methods:

    ```java
    String getConnectionId() throws IOException;
    void close() throws IOException;
    ObjectInstance createMBean(String className, ObjectName name, Subject delegationSubject)
    ObjectInstance createMBean(String className, ObjectName name, ObjectName loaderName, Subject delegationSubject)
    ObjectInstance createMBean(String className, ObjectName name, MarshalledObject params, String signature[], Subject delegationSubject)
    ObjectInstance createMBean(String className, ObjectName name, ObjectName loaderName, MarshalledObject params, String signature[], Subject delegationSubject)
    void unregisterMBean(ObjectName name, Subject delegationSubject)
    ObjectInstance getObjectInstance(ObjectName name, Subject delegationSubject)
    Set<ObjectInstance> queryMBeans(ObjectName name, MarshalledObject query, Subject delegationSubject)
    Set<ObjectName> queryNames(ObjectName name, MarshalledObject query, Subject delegationSubject)
    boolean isRegistered(ObjectName name, Subject delegationSubject)
    Integer getMBeanCount(Subject delegationSubject)
    Object getAttribute(ObjectName name, String attribute, Subject delegationSubject)
    AttributeList getAttributes(ObjectName name, String[] attributes, Subject delegationSubject)
    void setAttribute(ObjectName name, MarshalledObject attribute, Subject delegationSubject)
    AttributeList setAttributes(ObjectName name, MarshalledObject attributes, Subject delegationSubject)
    Object invoke(ObjectName name, String operationName, MarshalledObject params, String signature[], Subject delegationSubject)
    String getDefaultDomain(Subject delegationSubject)
    String[] getDomains(Subject delegationSubject)
    MBeanInfo getMBeanInfo(ObjectName name, Subject delegationSubject)
    boolean isInstanceOf(ObjectName name, String className, Subject delegationSubject)
    void addNotificationListener(ObjectName name, ObjectName listener, MarshalledObject filter, MarshalledObject handback, Subject delegationSubject)
    void removeNotificationListener(ObjectName name, ObjectName listener, Subject delegationSubject)
    void removeNotificationListener(ObjectName name, ObjectName listener, MarshalledObject filter, MarshalledObject handback, Subject delegationSubject)
    Integer[] addNotificationListeners(ObjectName[] names, MarshalledObject[] filters, Subject[] delegationSubjects)
    void removeNotificationListeners(ObjectName name, Integer[] listenerIDs, Subject delegationSubject)
    NotificationResult fetchNotifications(long clientSequenceNumber, int maxNotifications, long timeout)
    ```
* References:
    * [https://docs.oracle.com/javase/8/docs/technotes/guides/management/agent.html](https://docs.oracle.com/javase/8/docs/technotes/guides/management/agent.html)
    * [https://github.com/openjdk/jdk/tree/master/src/java.management.rmi/share/classes/javax/management/remote/rmi](https://github.com/openjdk/jdk/tree/master/src/java.management.rmi/share/classes/javax/management/remote/rmi)
* Known Vulnerabilities:

    * MLet
        * Description:

            > MLet is the name of an MBean that is usually available on JMX servers. It can be used to load
            > other MBeans dynamically from user specified codebase locations (URLs). Access to the MLet MBean
            > is therefore most of the time equivalent to remote code execution.
        * References:
            * [https://github.com/qtc-de/beanshooter](https://github.com/qtc-de/beanshooter)

    * Deserialization
        * Description:

            > All communication to JMX that is dispatched over this remote object is not filtered for deserialization
            > attacks. Therefore, each suitable method can be used to pass a deserialization payload to the server.
        * References:
            * [https://github.com/qtc-de/beanshooter](https://github.com/qtc-de/beanshooter)


### JMX Server

---

* Name: `JMX Server`
* Class Names:
    * `javax.management.remote.rmi.RMIServerImpl_Stub`
    * `javax.management.remote.rmi.RMIServer`
* Description:

    > Java Management Extensions (JMX) can be used to monitor and manage a running Java virtual machine.
    > This remote object is the entrypoint for initiating a JMX connection. Clients call the newClient
    > method usually passing a HashMap that contains connection options (e.g. credentials). The return
    > value (RMIConnection object) is another remote object that is when used to perform JMX related
    > actions. JMX uses the randomly assigned ObjID of the RMIConnection object as a session id.

* Remote Methods:

    ```java
    String getVersion()
    javax.management.remote.rmi.RMIConnection newClient(Object params)
    ```
* References:
    * [https://docs.oracle.com/javase/8/docs/technotes/guides/management/agent.html](https://docs.oracle.com/javase/8/docs/technotes/guides/management/agent.html)
    * [https://github.com/openjdk/jdk/tree/master/src/java.management.rmi/share/classes/javax/management/remote/rmi](https://github.com/openjdk/jdk/tree/master/src/java.management.rmi/share/classes/javax/management/remote/rmi)
* Known Vulnerabilities:

    * MLet
        * Description:

            > MLet is the name of an MBean that is usually available on JMX servers. It can be used to load
            > other MBeans dynamically from user specified codebase locations (URLs). Access to the MLet MBean
            > is therefore most of the time equivalent to remote code execution.
        * References:
            * [https://github.com/qtc-de/beanshooter](https://github.com/qtc-de/beanshooter)

    * Deserialization
        * Description:

            > Before CVE-2016-3427 got resolved, JMX accepted arbitrary objects during a call to the newClient
            > method, resulting in insecure deserialization of untrusted objects. Despite being fixed, the
            > actual JMX communication using the RMIConnection object is not filtered. Therefore, if you can
            > establish a working JMX connection, you can also perform deserialization attacks.
        * References:
            * [https://github.com/qtc-de/beanshooter](https://github.com/qtc-de/beanshooter)


### RMI Activation Group

---

* Name: `RMI Activation Group`
* Class Names:
    * `java.rmi.activation.ActivationGroup_Stub`
    * `java.rmi.activation.ActivationGroup`
    * `java.rmi.activation.ActivationInstantiator`
* Description:

    > Remote object that is associated with an ActivationGroup. Can be used to create new instances of activatable
    > objects that are registered within the group. The activation system was deprecated and removed in 2021.

* Remote Methods:

    ```java
    java.rmi.MarshalledObject newInstance(java.rmi.activation.ActivationID id, java.rmi.activation.ActivationDesc desc)
    ```
* References:
    * [https://docs.oracle.com/javase/7/docs/technotes/tools/windows/rmid.html](https://docs.oracle.com/javase/7/docs/technotes/tools/windows/rmid.html)
    * [https://github.com/openjdk/jdk/tree/ed477da9c69bbb4bae3c9e5bc80b67dcfc31b2b1/src/java.rmi/share/classes/sun/rmi/server](https://github.com/openjdk/jdk/tree/ed477da9c69bbb4bae3c9e5bc80b67dcfc31b2b1/src/java.rmi/share/classes/sun/rmi/server)
* Known Vulnerabilities:

    * Deserialization
        * Description:

            > ActivationGroup remote objects do not use a deserialization filter.
        * References:
            * [https://github.com/qtc-de/remote-method-guesser](https://github.com/qtc-de/remote-method-guesser)


### RMI Activation System

---

* Name: `RMI Activation System`
* Class Names:
    * `sun.rmi.server.Activation$ActivationSystemImpl_Stub`
    * `java.rmi.activation.ActivationSystem`
* Description:

    > The activation system is a legacy component of Java RMI. It allows remote objects to become inactive
    > and allows clients to activate them when required. The ActivationSystemImpl remote object can be
    > understood as a management interface for activation. It is only accessible from localhost and this
    > restriction cannot be bypassed by the --localhost-bypass option. By accessing the ActivationSystemImpl,
    > it is possible to register new activatable objects and activation groups. The activation system was
    > deprecated and removed in 2021.

* Remote Methods:

    ```java
    java.rmi.activation.ActivationID registerObject(java.rmi.activation.ActivationDesc arg)
    void unregisterObject(java.rmi.activation.ActivationID arg)
    java.rmi.activation.ActivationGroupID registerGroup(java.rmi.activation.ActivationGroupDesc arg)
    java.rmi.activation.ActivationMonitor activeGroup(java.rmi.activation.ActivationGroupID arg, java.rmi.activation.ActivationInstantiator arg, long arg)
    void unregisterGroup(java.rmi.activation.ActivationGroupID arg)
    void shutdown()
    java.rmi.activation.ActivationDesc setActivationDesc(java.rmi.activation.ActivationID arg, java.rmi.activation.ActivationDesc arg)
    java.rmi.activation.ActivationGroupDesc setActivationGroupDesc(java.rmi.activation.ActivationGroupID arg, java.rmi.activation.ActivationGroupDesc arg)
    java.rmi.activation.ActivationDesc getActivationDesc(java.rmi.activation.ActivationID arg)
    java.rmi.activation.ActivationGroupDesc getActivationGroupDesc(java.rmi.activation.ActivationGroupID arg)
    ```
* References:
    * [https://docs.oracle.com/javase/7/docs/technotes/tools/windows/rmid.html](https://docs.oracle.com/javase/7/docs/technotes/tools/windows/rmid.html)
    * [https://github.com/openjdk/jdk/tree/ed477da9c69bbb4bae3c9e5bc80b67dcfc31b2b1/src/java.rmi/share/classes/sun/rmi/server](https://github.com/openjdk/jdk/tree/ed477da9c69bbb4bae3c9e5bc80b67dcfc31b2b1/src/java.rmi/share/classes/sun/rmi/server)
* Known Vulnerabilities:

    * Deserialization
        * Description:

            > When accessed from localhost, the ActivationSystem is vulnerable to deserialization attacks.
        * References:
            * [https://github.com/qtc-de/remote-method-guesser](https://github.com/qtc-de/remote-method-guesser)


### RMI Activator

---

* Name: `RMI Activator`
* Class Names:
    * `java.rmi.activation.Activator`
* Description:

    > An Activator can be used to create new instances of activatable objects. It has normally a fixed
    > ObjID and is not bound to an RMI registry by name. The activation system was deprecated and removed in 2021.

* Remote Methods:

    ```java
    java.rmi.MarshalledObject newInstance(java.rmi.activation.ActivationID id, boolean force)
    ```
* References:
    * [https://docs.oracle.com/javase/7/docs/technotes/tools/windows/rmid.html](https://docs.oracle.com/javase/7/docs/technotes/tools/windows/rmid.html)
    * [https://github.com/openjdk/jdk/tree/ed477da9c69bbb4bae3c9e5bc80b67dcfc31b2b1/src/java.rmi/share/classes/sun/rmi/server](https://github.com/openjdk/jdk/tree/ed477da9c69bbb4bae3c9e5bc80b67dcfc31b2b1/src/java.rmi/share/classes/sun/rmi/server)
* Known Vulnerabilities:

    * Deserialization
        * Description:

            > Deserialization filters were never applied to the activation system and the Activator can be used
            > for deserialization attacks.
        * References:
            * [https://github.com/qtc-de/remote-method-guesser](https://github.com/qtc-de/remote-method-guesser)


### RMI Registry

---

* Name: `RMI Registry`
* Class Names:
    * `sun.rmi.registry.RegistryImpl_Stub`
* Description:

    > The RMI registry is used as a naming service for RMI endpoints. It maps endpoint locations and their corresponding
    > ObjID values to human readable names. Clients obtain endpoint information from the RMI registry by looking up the
    > corresponding bound names and are then able to communicate to the desired remote objects.

* Remote Methods:

    ```java
    Remote lookup(String name)
    void bind(String name, Remote obj)
    void unbind(String name)
    void rebind(String name, Remote obj)
    String[] list() throws RemoteException, AccessException;
    ```
* References:
    * [https://docs.oracle.com/javase/7/docs/technotes/guides/rmi/hello/hello-world.html](https://docs.oracle.com/javase/7/docs/technotes/guides/rmi/hello/hello-world.html)
    * [https://github.com/openjdk/jdk/tree/master/src/java.rmi/share/classes/sun/rmi/registry](https://github.com/openjdk/jdk/tree/master/src/java.rmi/share/classes/sun/rmi/registry)
* Known Vulnerabilities:

    * Deserialization
        * Description:

            > RMI registry instances where JEP290 was not applied are vulnerable to deserialization attacks. With
            > JEP290, deserialization filters were introduced. Depending on the patch level of the corresponding
            > Java instance, the filters may be bypassed.
        * References:
            * [https://github.com/qtc-de/remote-method-guesser](https://github.com/qtc-de/remote-method-guesser)

    * Localhost Bypass
        * Description:

            > Bound names within the RMI registry can be modified by each client that runs on the same host as the
            > RMI registry instance. In 2019, a bypass for this localhost restriction was identified, that may allows
            > an attacker to bind, rebind or unbind names from remote.
        * References:
            * [https://github.com/qtc-de/remote-method-guesser](https://github.com/qtc-de/remote-method-guesser)

    * UnicastRemoteObject
        * Description:

            > UnicastRemoteObjects have an auto-export mechanism, that exports the objects during deserialization in the
            > context of the user that deserialized the data. This can be used to force application to create temporarily
            > existing remote objects that are listening on an user specified TCP port.
        * References:
            * [https://github.com/qtc-de/remote-method-guesser/blob/master/docs/rmi/unicast-remote-object.md](https://github.com/qtc-de/remote-method-guesser/blob/master/docs/rmi/unicast-remote-object.md)
