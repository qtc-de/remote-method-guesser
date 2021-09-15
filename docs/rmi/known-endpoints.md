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
    public String getConnectionId() throws IOException;
    public void close() throws IOException;
    public ObjectInstance createMBean(String className, ObjectName name, Subject delegationSubject)
    public ObjectInstance createMBean(String className, ObjectName name, ObjectName loaderName, Subject delegationSubject)
    public ObjectInstance createMBean(String className, ObjectName name, MarshalledObject params, String signature[], Subject delegationSubject)
    public ObjectInstance createMBean(String className, ObjectName name, ObjectName loaderName, MarshalledObject params, String signature[], Subject delegationSubject)
    public void unregisterMBean(ObjectName name, Subject delegationSubject)
    public ObjectInstance getObjectInstance(ObjectName name, Subject delegationSubject)
    public Set<ObjectInstance> queryMBeans(ObjectName name, MarshalledObject query, Subject delegationSubject)
    public Set<ObjectName> queryNames(ObjectName name, MarshalledObject query, Subject delegationSubject)
    public boolean isRegistered(ObjectName name, Subject delegationSubject)
    public Integer getMBeanCount(Subject delegationSubject)
    public Object getAttribute(ObjectName name, String attribute, Subject delegationSubject)
    public AttributeList getAttributes(ObjectName name, String[] attributes, Subject delegationSubject)
    public void setAttribute(ObjectName name, MarshalledObject attribute, Subject delegationSubject)
    public AttributeList setAttributes(ObjectName name, MarshalledObject attributes, Subject delegationSubject)
    public Object invoke(ObjectName name, String operationName, MarshalledObject params, String signature[], Subject delegationSubject)
    public String getDefaultDomain(Subject delegationSubject)
    public String[] getDomains(Subject delegationSubject)
    public MBeanInfo getMBeanInfo(ObjectName name, Subject delegationSubject)
    public boolean isInstanceOf(ObjectName name, String className, Subject delegationSubject)
    public void addNotificationListener(ObjectName name, ObjectName listener, MarshalledObject filter, MarshalledObject handback, Subject delegationSubject)
    public void removeNotificationListener(ObjectName name, ObjectName listener, Subject delegationSubject)
    public void removeNotificationListener(ObjectName name, ObjectName listener, MarshalledObject filter, MarshalledObject handback, Subject delegationSubject)
    public Integer[] addNotificationListeners(ObjectName[] names, MarshalledObject[] filters, Subject[] delegationSubjects)
    public void removeNotificationListeners(ObjectName name, Integer[] listenerIDs, Subject delegationSubject)
    public NotificationResult fetchNotifications(long clientSequenceNumber, int maxNotifications, long timeout)
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


### RMI Activator

---

* Name: `RMI Activator`
* Class Names:
    * `sun.rmi.server.Activation$ActivationSystemImpl_Stub`
* Description:

    > The activation system is a legacy component of Java RMI. It allows remote objects to become inactive
    > and allows clients to activate them when required. The activation system has been removed from newer
    > versions of Java. Due to the legacy status and the rare usage in practice, the activation system never
    > got the JEP290 proposals implemented.

* Remote Methods:

    ```java
    java.rmi.MarshalledObject activate(java.rmi.Activation.ActivationID id, boolean force)
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
    public Remote lookup(String name)
    public void bind(String name, Remote obj)
    public void unbind(String name)
    public void rebind(String name, Remote obj)
    public String[] list() throws RemoteException, AccessException;
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
