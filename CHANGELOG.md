# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [3.3.0] - June 20, 2021

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



## [3.2.0] - Apr 02, 2021

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


## [3.1.1] - Feb 16, 2021

### Changed

* Fixed bug in ``RMIWhisperer.java`` that lead to nullpointer exceptions during the
  ``method`` operation. The bugfix is basically a workaround for a more general problem
  that will be resolved in version ``v3.2.0``.


## [3.1.0] - Feb 14, 2021

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


## [3.0.0] - Nov 28, 2020

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


## [2.0.0] - Sep 30, 2020

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


## [1.1.0] - Aug 06, 2020

### Added

* Add Maven CI
* Add additional templates
* Add bash completion script
* Add support for primitive types in interfaces


## [1.0.0] - Nov 26, 2020

Initial release :)
