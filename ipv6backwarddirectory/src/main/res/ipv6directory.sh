#!/bin/bash
mydir="$(dirname "$0")"
cd "$mydir"
java -classpath ipv6backwarddata*.jar:ipv6backwarddirectory.jar -Djava.util.logging.config.file=logging.properties de.flyingsnail.ipv6backwardserver.directory.DirectoryStart
echo "Transporter finished with return code $?"
