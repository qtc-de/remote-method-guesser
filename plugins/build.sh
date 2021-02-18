#!/bin/bash

if [[ $# -lt 3 ]]; then
    echo "$0 <RMG-JAR> <SOURCE> <JAR>"
    exit 1
fi

RMG=$1
SRC=$2
JAR=$3
MANIFEST="RMG-MANIFEST.MF"

CLASS=$(echo $SRC | cut -d. -f1)
echo "RmgPluginClass: $CLASS" > $MANIFEST

javac -cp $RMG $SRC
jar -cfm $JAR $MANIFEST "$CLASS.class"

rm "$CLASS.class" $MANIFEST
