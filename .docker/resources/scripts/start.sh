#!/bin/sh

echo "[+] Adding gateway address to /etc/hosts file..."
GATEWAY=$(ip r | grep "default via" | cut -d" " -f 3)
echo "$GATEWAY prevent.reverse.dns" >> /etc/hosts

echo "[+] Starting rmi server..."
exec /usr/lib/jvm/java-1.8-openjdk/bin/java -jar /opt/example-server.jar
