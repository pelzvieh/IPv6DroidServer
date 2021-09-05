#!/bin/bash
mydir="$(dirname "$0")"
mydir="${mydir/#./$PWD/.}"
mydir="${mydir/\/bin//lib}"
tmpdir="$(mktemp -d)" || { echo "Could not create temporary directory" >&2; exit 1; }
cd "$tmpdir"
mkfifo -m 600 fromayiya || { echo "Could not create fromayiya fifo" >&2; exit 2; }
mkfifo -m 600 toayiya || { echo "Could not create toayiya fifo" >&2; exit 3; }
cp "${mydir}"/logging*.properties "${tmpdir}"
java -Djava.util.logging.config.file="${mydir}/logging_dtls.properties" -jar "${mydir}/ipv6dtlstransport-1.3.1-SNAPSHOT.jar"  fromayiya toayiya &
java -Djava.util.logging.config.file="${mydir}/logging_ayiya.properties" -jar "${mydir}/ipv6transport-1.3.1-SNAPSHOT.jar" toayiya fromayiya
retcode=$?
echo "Transporter ayiya finished with return code $retcode"
kill %1
cd
rm -r "$tmpdir"
exit $retcode
