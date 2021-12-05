### Docker Containers

----

The *remote-method-guesser* repository contains two example servers that can be used to practice *Java RMI* enumeration and attacks.
The [rmg-example-server](/docker/example-server) exposes regular *RMI* services that can be enumerated and exploited using *remote-method-guesser*.
The [rmg-ssrf-server](/docker/ssrf-server) exposes an *HTTP* service that is vulnerable to *SSRF* attacks and runs *RMI* services that are only
listening on localhost. This can be used to practice with *remote-method-guesser's* ``--ssrf`` and ``--ssrf-response`` options.
Both servers are available as containers within the *GitHub Container Registry*:

* [SSRF Server GitHub Package](https://github.com/qtc-de/remote-method-guesser/pkgs/container/remote-method-guesser%2Frmg-ssrf-server)
* [Example Server GitHub Package](https://github.com/qtc-de/remote-method-guesser/pkgs/container/remote-method-guesser%2Frmg-example-server)
