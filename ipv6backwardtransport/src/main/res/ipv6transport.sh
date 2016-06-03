#!/bin/bash
mydir="$(dirname "$0")"
cd "$mydir"
java -classpath . -Djava.util.logging.config.file=de/flyingsnail/ipv6backwardserver/logging.properties de.flyingsnail.ipv6backwardserver.transporter.TransporterStart
echo "Transporter finished with return code $?"
