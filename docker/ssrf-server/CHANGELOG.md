# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## v2.0.0 - Dec 10, 2023

### Changed

* Changed the servers namespace from `de.qtc` to `eu.tneitzel`
* Since Java 9 is no longer available in the alpine default package
  repositories, the JDK is now obtained from an older image of the
  rmg-ssrf-server.


## v1.4.0 - Jan 19, 2023

### Changed

* Remove unused hostname from startup script


## v1.3.0 - May 08, 2022

### Changed

* Fix timestamp for log messages
