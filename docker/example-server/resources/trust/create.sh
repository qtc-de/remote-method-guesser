#!/bin/bash

set -e

openssl req -x509 -nodes -keyout key.pem -out cert.pem -new -config openssl.config -days 999999
openssl pkcs12 -export -out store.p12 -inkey key.pem -in cert.pem -password pass:password -legacy

rm key.pem cert.pem
