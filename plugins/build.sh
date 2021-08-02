#!/bin/bash

if [[ $# -lt 3 ]]; then
    echo "$0 <RMG-FILE> <PLUGIN-FILE> <OUTPUT>"
    exit 1
fi

RMG=$1
SRC=$2
JAR=$3

DIR=$(dirname $SRC)
CLASS=$(basename $SRC .java)
MANIFEST="${DIR}/RMG-MANIFEST.MF"

echo "RmgPluginClass: $CLASS" > $MANIFEST

javac -cp $RMG $SRC \
&& jar -cfm $JAR $MANIFEST -C ${DIR} ${CLASS}.class

rm -f "${DIR}/${CLASS}.class" $MANIFEST
