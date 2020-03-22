#!/bin/bash
mydir="$(dirname "$0")"
mydir="${mydir/#./$PWD/.}"
mydir="${mydir/\/bin//lib}"
tmpdir="$(mktemp -d)"
cd "$tmpdir"
mkfifo -m 600 fromdevice || exit 1
mkfifo -m 600 todevice || exit 2
mkfifo -m 600 toayiya || exit 3
cp "${mydir}"/logging*.properties "${tmpdir}"
tuntopipe -i tun0 -u < todevice > fromdevice 2> ${mydir}/tuntopipe.log &
java -Djava.util.logging.config.file="${mydir}/logging_dtls.properties" -jar "${mydir}/ipv6dtlstransport-1.3.1-SNAPSHOT.jar"  fromdevice todevice > toayiya &
java -Djava.util.logging.config.file="${mydir}/logging_ayiya.properties" -jar "${mydir}/ipv6transport-1.3.1-SNAPSHOT.jar" toayiya todevice
retcode=$?
echo "Transporter finished with return code $retcode"
kill %1 %2
exit $retcode
