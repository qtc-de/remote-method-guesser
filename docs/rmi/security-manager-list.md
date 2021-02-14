### RMI Security Managers

----

During remote class loading attacks, the existence and configuration of a *SecurityManager* is a crucial point that can limit
the impact of the vulnerability. Whereas remote class loading attacks on the application level fully depend on a user defined
*SecurityManager*, internal RMI communication uses *SecurityManagers* per default with different configurations. This document
provides a short list of the default *SecurityManagers* with their corresponding configuration. The source code samples for the filters were
copied from the current state (at the time of writing) of the [openjdk GitHub repository](https://github.com/openjdk/jdk).


### LoaderHandler - Security Manager

----

* The ``LoaderHandler.java`` class is responsible for remote class loading and its *SecurityManager* settings
  are therefore probably the most important.
* Within it's ``loadClass`` method, the ``LoaderHandler`` stops class loading on its own and delegates the request
  to the parent class loader if no *SecurityManager* is defined:
  ```java
  SecurityManager sm = System.getSecurityManager();
  if (sm == null) {
      try {
          Class<?> c = Class.forName(name, false, parent);
          if (loaderLog.isLoggable(Log.VERBOSE)) {
              loaderLog.log(Log.VERBOSE,
                  "class \"" + name + "\" found via " +
                  "thread context class loader " +
                  "(no security manager: codebase disabled), " +
                  "defined by " + c.getClassLoader());
          }
          return c;
      } catch (ClassNotFoundException e) {
          if (loaderLog.isLoggable(Log.BRIEF)) {
              loaderLog.log(Log.BRIEF,
                  "class \"" + name + "\" not found via " +
                  "thread context class loader " +
                  "(no security manager: codebase disabled)", e);
          }
          throw new ClassNotFoundException(e.getMessage() +
              " (no security manager: RMI class loader disabled)",
              e.getException());
      }
  }
  ```

* When a *SecurityManager* is defined, the actual loader is created within an ``AccessControlContext`` that includes
  permissions only for the specified codebase. That means:
  * File system permissions for the corresponding folder on the file system if the codebase is a file system URL.
  * Network permissions for the corresponding remote host, if the codebase is a  remote URL.

* The ``AccessControlContext`` is created by the ``getLoaderAccessControlContext`` function:
  ```java
  private static AccessControlContext getLoaderAccessControlContext(
      URL[] urls)
  {
      [...]

      // createClassLoader permission needed to create loader in context
      perms.add(new RuntimePermission("createClassLoader"));

      // add permissions to read any "java.*" property
      perms.add(new java.util.PropertyPermission("java.*","read"));

      // add permissions reuiqred to load from codebase URL path
      addPermissionsForURLs(urls, perms, true);

      [...]
  }
  ```

* Apart from it's own ``AccessControlContext``, the loader also always checks if the calling code has the required
  security permissions. This check is performed within the ``checkPermissions`` function.
  ```java
  private void checkPermissions() {
      SecurityManager sm = System.getSecurityManager();
      if (sm != null) {           // should never be null?
          Enumeration<Permission> enum_ = permissions.elements();
          while (enum_.hasMoreElements()) {
              sm.checkPermission(enum_.nextElement());
          }
      }
  }
  ```

* Summarized: Without a manually defined security policy, classes loaded in remote class loading attacks are always
  restricted by the ``LoaderHandler``. Effectively, they are only allowed to access their own codebase, to read
  *java* properties and to create new class loaders with the same security permissions. Furthermore, the parent
  ``AccessControlContext`` (e.g. the one of the RMI registry or the DGC) must also allow access to the requested
  codebase.


### RMI Registry - Security Manager

----

* The RMI registry defines it's ``AccessControlContext`` in the ``RegistryImpl`` class, within the ``getAccessControlContext`` function.
* Apart from the default permissions, custom permissions can be added by specifying a custom policy file.
* Relevant permission definitions:
  ```java
  perms.add(new SocketPermission("*", "connect,accept"));
  perms.add(new SocketPermission("localhost:"+port, "listen,accept"));

  perms.add(new RuntimePermission("accessClassInPackage.sun.jvmstat.*"));
  perms.add(new RuntimePermission("accessClassInPackage.sun.jvm.hotspot.*"));

  perms.add(new FilePermission("<<ALL FILES>>", "read"));
  ```

* With these permission definitions, the RMI registry allows remote class loading in general. However, the ``<<ALL FILES>>`` permission
  does not effectively apply, as it is overwritten by the ``AccessControlContext`` used by the ``LoaderHandler``.
  

### Distributed Garbage Collector (Inbound) - Security Manager

-----

* The ``AccessControlContext`` for *inbound DGC traffic* is defined in ``DGCImpl.java`` within a *static* block.
* Custom policy files are ignored by the *DGC* and only the hard coded permissions are used.
* The hard coded permissions are rather straight forward:
  ```java
  Permissions perms = new Permissions();
  perms.add(new SocketPermission("*", "accept,resolve"));
  ProtectionDomain[] pd = { new ProtectionDomain(null, perms) };
  AccessControlContext acceptAcc = new AccessControlContext(pd);
  ```

* This means, that the *DGC* does always reject remote class loading attempts, as it's security policy does not even allow
  remote connections.
* Additionally (although not really related to the *SecurityManager*), ``UnicastServerRef`` checks whether a call is targeting
  the *DGC* during the dispatching process. If the target is the *DGC*, ``useCodebaseOnly`` is explicitly set to ``true`` for
  the ``MarshalInputStream`` of the call.
  ```java
  Class<?> clazz = Class.forName("sun.rmi.transport.DGCImpl_Skel");
  if (clazz.isAssignableFrom(skel.getClass())) {
      ((MarshalInputStream)in).useCodebaseOnly();
  }
  ```

* Therefore, remote class loading should never work on a modern *DGC*.


### Distributed Garbage Collector (Outbound) - Security Manager

-----

* Outbound *DGC connections* are usually not used for remote class loading attacks, but theoretically it is possible.
  To perform such an attack, one could use the ``JRMPClient`` *ysoserial gadget* to create an outbound *DGC call*
  to a custom listener. This listener needs to return an annotated, non existing class as return value.
  When ``useCodebaseOnly`` is set to ``false`` this should trigger remote class loading as usual.
* The ``AccessControlContext`` for outbound *DGC connections* is defined in the ``DGCClient`` class within a static property named ``SOCKET_ACC``:
  ```java
  private static final AccessControlContext SOCKET_ACC;
  static {
      Permissions perms = new Permissions();
      perms.add(new SocketPermission("*", "connect,resolve"));
      ProtectionDomain[] pd = { new ProtectionDomain(null, perms) };
      SOCKET_ACC = new AccessControlContext(pd);
  }
  ```

* The corresponding ``AccessControlContext`` is used for all calls to the ``dirty`` and ``clean`` methods.
* As the ``LoaderHandler`` class requests ``connect,accept`` socket permissions within it's ``addPermissionsForURLs`` function,
  remote class loading would probably be rejected by the ``LoaderHandler``.
