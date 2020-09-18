#!/bin/bash

echo -n  "[+] Starting registry on port 1099... "
rmiregistry 1099 &
sleep 8
echo "done."

echo "[+] Starting Server.java"
java de/qtc/rmg/testserver/Server &
java de/qtc/rmg/testserver/Server2
