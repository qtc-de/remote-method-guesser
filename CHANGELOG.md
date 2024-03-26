# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## v5.0.0 - Dec 23, 2023

### Added

* Add support for dynamically created socket factory classes ([docs](/docs/rmg/dynamic-socket-factories.md))
* Add support for method guessing on spring-remoting endpoints ([docs](/docs/rmg/spring-remoting.md))
* Add a *Spring Remoting* example server ([src](docker/spring-remoting/), [package](https://github.com/qtc-de/remote-method-guesser/pkgs/container/remote-method-guesser%2Fspring-remoting-server))

### Changed

* Changed the namespace of the project from `de.qtc` to `eu.tneitzel`
* Fix leak of local ysoserial path (e30f52c)
* The GenericPrint plugin is now included in *rmg* per default (b09e9a5)
* Stream corruption errors during method guessing are only displayed if `--verbose` is used


## v4.4.1 - Jun 22, 2023

### Added

* Add pull request template (see #46)

### Changed

* Fix many typos (see #46)
* Improve *rmg*s Java16+ compatibility (see #49)


## v4.4.0 - Jan 19, 2023

### Changed

* Add support for non default `serialVersionUID` values
* Refactored test configurations
* Update dependencies
* Make *rmg* Java16+ compatible


## v4.3.1 - Sep 19, 2022

### Changed

* Updated snakeyaml dependency to `v1.32`
* Changed the default *ysoserial* path to `/opt/ysoserial.jar`
* Typofix `enmeration` -> `enumeration`


## v4.3.0 - May 11, 2022

### Added

* Add support for `ActivatableRef` ([docs](/docs/rmg/actions.md#activatable-bound-names))
* Add test cases for `ActivatableRef`

### Changed

* Update list of known endpoints ([docs](/docs/rmi/known-endpoints.md))
* Update outdated documentation

### Docker

* The [example server](/docker/example-server) now provides a full working *Activation System* on port `1098`


## v4.2.2 - Jan 11, 2022

### Changed

* Fix missing ``--no-progress`` option for some actions
* Fix some typos inside the help menu


## v4.2.1 - Jan 07, 2022

### Changed

* Fix missing ``--yso`` option for some actions (resolves issue #26)
* Improve the bash completion script
* Improve test cases


## v4.2.0 - Dec 30, 2021

### Changed

* *SSRF* payloads are now created using the *SingleOpProtocol* by default.
  The ``--stream-protocol`` option can be used to create *SSRF* payloads using
  the *Stream Protocol*.
* Updated test cases.


## v4.1.0 - Dec 23, 2021

### Added

* Add *TLS* enumeration during ``enum`` action.

### Changed

* Error messages are now printed to stderr.
* Bugfix: Error messages not being shown when using ``--raw``
* Bugfix: Uncaught ``UnknownHostException``
* Bugfix: Uncaught exception during ``call`` action when used with wrong argument count
* Bugfix: Uncaught exception during ``call`` action when no signature was specified
* Bugfix: Uncaught exception when the specified port number is out of range

### Docker

* The *SSRF* server now logs in hexdump format
* Bugfix: Indentation issue within the *SSRF* server


## v4.0.0 - Dec 05, 2021

### Added

* Added the ``scan`` action, that performs a simple portscan for *RMI* services.
* Added the ``roguejmx`` action, that spawns a rogue *JMX* listener.
* Added the ``objid`` action, that inspects ``ObjID`` values.
* Added the ``known`` action, that lists information about known *RMI* classes.
* Added [SSRF support](/docs/rmg/actions.md#ssrf-support) in form of the ``--ssrf``
  and ``--ssrf-response`` options.
* Added an [SSRF example server](/docker/ssrf-server) (docker container).
* Added the ``--scan-action`` option that can be used during the ``enum`` action
  to perform only the specified enumeration.
* Added support for custom socket factories within *remote-method-guesser's*
  [plugin system](/docs/rmg/plugin-system.md).
* Added a progress bar for the ``guess`` action.
* Added ``ObjID`` and ``TCPEndpoint`` enumeration during the ``enum`` action.

### Changed

* Changed the argument layout. *remote-method-guesser* now uses a modular argument layout
  based on [argparse4j](https://github.com/argparse4j/argparse4j).
* Changed action layout. Previously existing actions like ``method``, ``reg``, ``dgc`` or
  ``act`` are now bundled into the ``serial`` action.
* Changed target specification during *codebase attacks*. To target *RMI* default components,
  you now use the ``--component`` option.
* Changed codebase enumeration. Now also works for non registry ports.
* Changed the *DGC enumeration* to *Security Manager* enumeration.


## v3.3.0 - June 20, 2021

### Added

* Added the ``--verbose`` option. The output of *rmg* is now less verbose, but you can
  get the full details by using this option.
* Added the ``--guess-duplicate`` option. *rmg-v3.3.0* no longer guesses methods on identical
  remote classes (only one instance will be used, the others are considered duplicates).
  If you want to guess them anyway, you can use this option.
* Added documentation on [method guessing](/docs/rmg/method-guessing.md)

### Changed

* Changed the underlying implementation of method guessing. The new implementation is
  way faster an reduces the runtime of the ``guess`` action up to a factor of ``8``.
  The new implementation is described in more detail here: [method guessing](/docs/rmg/method-guessing.md)
* Changed the wordlist format slightly. The overall format stays the same, but the meaning
  of one field was changed. Old wordlists (in optimized format) should be updated.
* Changed option implementation. Options are now handled by an *Enum*. Although this makes only
  a difference internally.
* Some small bug fixes


## v3.2.0 - Apr 02, 2021

### Added

* Add ``call`` operation to regularly call remote methods
  * Can be used with bound names (``--bound-name``)
  * And also with ObjID values (``--objid``)
* Add plugin system to allow custom gadgets, call arguments and return handlers
  * Add some example plugins and a build script
* Add tests based on [tricot](https://github.com/qtc-de/tricot)

### Changed

* Global refactoring - Renamed and moved many classes and functions
  * The calling convention changed slightly for some actions
* The ``guess`` operation now also lists methods for known remote objects
  * These are obtained via reflection, not by guessing
  * You can force guessing anyway by using ``--force-guessing``
* Method arguments are now marshalled correctly (previously, always writeObject was used)
* The default wordlist and template files are now contained within the *rmg* JAR file


## v3.1.1 - Feb 16, 2021

### Changed

* Fixed bug in ``RMIWhisperer.java`` that lead to nullpointer exceptions during the
  ``method`` operation. The bugfix is basically a workaround for a more general problem
  that will be resolved in version ``v3.2.0``.


## v3.1.0 - Feb 14, 2021

### Added

*New Enumeration Techniques*

* Add *JEP290* enumeration during ``enum`` operation
* Add *JEP290* bypass enumeration during ``enum`` action
* Add *String marshalling* enumeration during ``enum`` operation
* Add ``useCodebaseOnly`` enumeration during ``enum`` operation
* Add *localhost bypass* (CVE-2019-2684) enumeration during ``enum`` operation
* Add *DGC* enumeration during ``enum`` action
* Add *Activator* enumeration during ``enum`` action

*New Actions*

* Add support for deserialization attacks on *Activator*, *DGC* and *registry* objects
* Add support for codebase attacks on *Activator*, *DGC* and *registry* objects
* Add support for deserialization filter bypass (credits: @\_tint0 & @h0ng10)
* Add ``bind``, ``rebind`` and ``unbind`` operations
  * Add *localhost-bypass* option for ``bind``, ``rebind`` and ``unbind`` operations (CVE-2019-2684)
* Add ``listen`` operation to spawn a *JRMP listener* (based on [ysoserial](https://github.com/frohoff/ysoserial))

*Other*

* Global refactoring - Some action names changed
* Add ``--stack-trace`` options for easier debugging
* Add improved error and exception handling
* Add options to use different *registry* / *DGC* methods during enum action
* Add documentation to the source code
* Add some other RMI related documentation

### Removed

* Removed support for JSON output


## v3.0.0 - Nov 28, 2020

### Added

*rmg*

* Add support for guessing without invoking (using invalid argument types)
* Add server-side codebase detection
* Add codebase operation for *remote-codebase* attacks
* Add support for *legacy RMI stubs*
* Add colored output

*Docker*

* Add additional remote method to example server
* Add non-ssl registry on port 9010
* Add legacy RMI service using static stubs
* Add server-codebase and remote-codebase support
* Add improved logging

### Changed

* Remote classes are now generated dynamically with *Javassist*
* Different operations are now invoked using actions, no longer command line switches
* The docker container compiles the *example-server* now during build time


## v2.0.0 - Sep 30, 2020

### Added

* Add *SSL* support (for registry and remote objects)
* Add automatic redirection feature
* Add security checks for *bound names*
* Add new templates
* Add new example server (available as *docker source* and *GitHub Packages*)

### Changed

* Changed the sample template. Now supports:
  * *SSL*
  * Automatic redirection
  * void return types
* Samples are no longer compiled by default
* Change folder structure created by guessing process
* Remove old example server


## v1.1.0 - Aug 06, 2020

### Added

* Add Maven CI
* Add additional templates
* Add bash completion script
* Add support for primitive types in interfaces


## v1.0.0 - Nov 26, 2020

Initial release :)
