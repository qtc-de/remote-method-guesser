#!/bin/bash

set -e

if [ $# -lt 1 ]; then
    echo "$0 [<version>] [<version>] ..."
    exit 1
fi

for VERSION in $@; do

    if [[ $VERSION -ne 8 && $VERSION -ne 9 && $VERSION -ne 11 ]]; then
        echo "[-] Unsupported version: ${VERSION}"
        continue
    fi

    echo "[+] Starting build for jdk${VERSION}."
    sleep 1.5

    mv "docker-compose-jdk${VERSION}.yml" docker-compose.yml 
    mv "Dockerfile-jdk${VERSION}" Dockerfile 

    set +e
    docker compose build

    mv docker-compose.yml "docker-compose-jdk${VERSION}.yml"
    mv Dockerfile "Dockerfile-jdk${VERSION}"

done
