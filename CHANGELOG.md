# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [3.0.0] - Nov 28, 2020

### Added

*rmg*

* Add support for guessing without invoking (using invalid argument types)
* Add server-side codebase detection
* Add codebase operation
* Add support for 
*Docker*

* Add additional remote method to example server
* Add non-ssl registry on port 9010
* Add legacy RMI service using static stubs
* Add server-codebase and remote-codebase support
* Add improved logging


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
