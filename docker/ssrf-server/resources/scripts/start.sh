#!/bin/sh

IP=$(ip a | grep inet | grep -v 127.0.0.1 | grep -o "\([0-9]\{1,3\}\.\?\)\{4\}" | head -n 1)
echo "[+] IP address of the container: ${IP}" 

echo "[+] Adding gateway address to /etc/hosts file..."
GATEWAY=$(ip r | grep "default via" | cut -d" " -f 3)
echo "$GATEWAY prevent.reverse.dns" >> /etc/hosts

echo "[+] Adding RMI hostname to /etc/hosts file..."
echo "127.0.0.1 iinsecure.dev" >> /etc/hosts

echo "[+] Starting rmi server..."
exec /usr/bin/java -jar /opt/ssrf-server.jar
