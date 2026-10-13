#!/bin/sh
# Start Orthanc, and — unless asked not to — a forwarder that hands the
# published port to Orthanc on the container's loopback interface.
#
# Why this exists is written down at length in `Dockerfile.orthanc` above this
# file's image build. In one line: `RemoteAccessAllowed: true` in Orthanc
# 1.10.1 turns on HTTP authentication, and a DICOM archive behind a credential
# that has to live in a tracked file is worse than an archive that believes it
# is only being talked to locally.
#
# `socat` is doing the whole of it. The listener is on the container's
# interfaces, because Docker's published port is a connection to the
# container's address and not to its loopback; the *target* is loopback, which
# is the part Orthanc sees.
set -eu

FORWARD_PORT="${MEDARX_DICOMWEB_FORWARD_PORT-8043}"
ORTHANC_PORT="${ORTHANC_HTTP_PORT-8042}"
FORWARD_PID=""
ORTHANC_PID=""

stop() {
  # Reverse order, and never fail on an already-dead pid: `docker stop` sends
  # SIGTERM to this shell, and a shell that exits before the forwarder does
  # leaves the container running for the full kill timeout.
  [ -z "$ORTHANC_PID" ] || kill "$ORTHANC_PID" 2>/dev/null || true
  [ -z "$FORWARD_PID" ] || kill "$FORWARD_PID" 2>/dev/null || true
  exit 0
}
trap stop TERM INT

if [ -n "$FORWARD_PORT" ]; then
  socat "TCP-LISTEN:${FORWARD_PORT},fork,reuseaddr" "TCP:127.0.0.1:${ORTHANC_PORT}" &
  FORWARD_PID=$!
fi

/usr/sbin/Orthanc "$@" &
ORTHANC_PID=$!

# `wait` returns the server's own exit status, so a bad configuration file is
# a non-zero container exit rather than a container that stopped cleanly.
wait "$ORTHANC_PID"
