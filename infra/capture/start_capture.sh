#!/usr/bin/env bash
#
# Start, stop and read back the host-network packet capture — component I's
# second observer.
#
#   start_capture.sh start <network> <seconds> <out-dir>
#   start_capture.sh stop  <out-dir>
#   start_capture.sh readback <out-dir>
#   start_capture.sh interface <network>
#
# ## The one thing this script exists to get right
#
# **The pcap is always written with `-w` and read back with `-r`.** It is never
# produced by piping `tcpdump -A` through `tee`. Under `timeout`, SIGTERM kills
# tcpdump before its block-buffered stdout is flushed, and the run then reports
# "0 packets captured" having actually seen the traffic. A capture that silently
# catches nothing is worse than no capture, because everything downstream of it
# is then a check that passed over an empty evidence set.
#
# ## The topology, and why it is the verified one
#
# `docker run --network host --cap-add=NET_RAW` on the bridge interface
# `br-<network id>`. No root, no `--privileged`. The network id is discovered
# here, at run time, and is never written into a file: a hard-coded `br-...` is
# a capture pointed at an interface that does not exist until the next
# `docker network rm`, and tcpdump's answer to a missing interface is an error
# that is easy to scroll past.
#
# Do not replace this with a third container on the same bridge. A bridge
# switches A's veth straight to B's; frames between A and B never reach a third
# container's interface. That topology was measured on this host and captured 21
# packets of mDNS/ARP and zero of the traffic, while the observer was actively
# receiving the requests it was supposed to be watching.
#
# ## The stopped capture is checked, not assumed
#
# `stop` prints the packet count the readback reports. A run that captured zero
# packets exits non-zero, so "the capture ran" and "the capture saw something"
# are different facts and a caller that only checks the exit status of `start`
# cannot be misled.

set -euo pipefail

IMAGE="${MEDARX_CAPTURE_IMAGE:-medarx-capture:latest}"
CONTAINER_PREFIX="medarx-capture"
STATE_FILE=".capture-state"

die() { printf 'start_capture: %s\n' "$*" >&2; exit 1; }

# The bridge interface for a Docker network, discovered at run time. `cut -c1-12`
# because Linux truncates the interface name to IFNAMSIZ - 1 = 15 characters:
# "br-" plus 12 hex.
bridge_for_network() {
    local network="$1" id
    id="$(docker network inspect -f '{{.Id}}' "$network" 2>/dev/null || true)"
    [ -n "$id" ] || die "no such docker network: $network"
    [ "${#id}" -ge 12 ] || die "network id '$id' is too short to form an interface name"
    printf 'br-%s' "$(printf '%s' "$id" | cut -c1-12)"
}

container_name_for() { printf '%s-%s' "$CONTAINER_PREFIX" "$(printf '%s' "$1" | cksum | cut -d' ' -f1)"; }

cmd_start() {
    [ "$#" -eq 3 ] || die "usage: start_capture.sh start <network> <seconds> <out-dir>"
    local network="$1" seconds="$2" out_dir="$3"
    local iface name
    iface="$(bridge_for_network "$network")"
    mkdir -p "$out_dir"
    out_dir="$(cd "$out_dir" && pwd)"

    docker image inspect "$IMAGE" >/dev/null 2>&1 \
        || die "image $IMAGE is not built; build it from infra/capture/Dockerfile"
    # A leftover container from an interrupted run would hold the old capture and
    # silently serve it again under the new name.
    name="$(container_name_for "$out_dir")"
    docker rm -f "$name" >/dev/null 2>&1 || true

    # SIGINT always, not only for the timed path. tcpdump flushes and closes
    # the file it is writing on SIGINT; `docker stop`'s default SIGTERM kills it
    # mid-write, and the pcap that comes back is short by whatever was in
    # flight. Measured here: a run reported "48 packets received by filter, 44
    # packets captured" and lost the very request the check was about.
    local -a limits=(--stop-signal SIGINT)

    # `-B` enlarges the kernel capture buffer. tcpdump's default is small
    # enough to overflow while the process is still starting, and an overflow
    # drops the earliest frames — which is where a capture that begins just
    # before the traffic of interest keeps losing it. `-U` writes each packet
    # out as it arrives rather than in blocks, so what is in the buffer is what
    # is on disk if the process is killed.
    docker run -d \
        --name "$name" \
        --network host \
        --cap-add=NET_RAW \
        -v "$out_dir:/out" \
        "${limits[@]}" \
        "$IMAGE" -n -i "$iface" -s 0 -U -B 16384 -w /out/out.pcap >/dev/null \
        || die "the capture container did not start"

    printf 'interface=%s\ncontainer=%s\nout_dir=%s\nseconds=%s\n' \
        "$iface" "$name" "$out_dir" "$seconds" > "$out_dir/$STATE_FILE"

    # Wait until the capture has **frames**, not merely a file. `docker run -d`
    # returns before tcpdump has opened its output, and a file that exists is
    # only the 24-byte pcap global header. Returning from `start` before a
    # single packet has been written is how the request that follows gets
    # missed while the capture reports no error at all.
    local waited=0
    while [ ! -s "$out_dir/out.pcap" ] || [ "$(wc -c < "$out_dir/out.pcap")" -le 24 ]; do
        [ "$waited" -lt 300 ] || die "the capture never wrote a frame to $out_dir/out.pcap"
        sleep 0.1
        waited=$((waited + 1))
    done
    # One more beat, so the socket is genuinely draining rather than merely open.
    sleep 0.5
    printf 'capturing on %s (docker network %s) into %s/out.pcap\n' \
        "$iface" "$network" "$out_dir"

    if [ "$seconds" -gt 0 ] 2>/dev/null; then
        sleep "$seconds"
        "$0" stop "$out_dir"
    fi
}

cmd_stop() {
    [ "$#" -eq 1 ] || die "usage: start_capture.sh stop <out-dir>"
    local out_dir="$1"
    [ -f "$out_dir/$STATE_FILE" ] || die "no capture was started into $out_dir"
    # shellcheck disable=SC1091
    . "$out_dir/$STATE_FILE"

    # `docker stop --time 10` sends SIGINT (set at start). The one-second beat
    # before it is for the traffic still in flight when the caller decided the
    # run was over: a request whose last segment has not left yet is a request
    # the capture would otherwise truncate mid-body, and a truncated body is
    # one the agreement check cannot reassemble.
    sleep 1
    docker stop --time 10 "$container" >/dev/null 2>&1 || true
    # `docker cp` before `docker rm`: the container's writable layer holds the
    # pcap until it is copied out, and removing first would delete the evidence.
    docker cp "$container:/out/out.pcap" "$out_dir/out.pcap" >/dev/null 2>&1 || true
    # tcpdump's own exit summary, kept rather than tailed away: it is the only
    # place the "received by filter" and "captured" counts both appear, and the
    # gap between them is packets this capture lost.
    docker logs "$container" > "$out_dir/tcpdump.log" 2>&1 || true
    tail -5 "$out_dir/tcpdump.log" >&2 || true
    docker rm -f "$container" >/dev/null 2>&1 || true

    [ -s "$out_dir/out.pcap" ] || die "the capture produced no pcap at $out_dir/out.pcap"
    "$0" readback "$out_dir"
}

cmd_readback() {
    [ "$#" -eq 1 ] || die "usage: start_capture.sh readback <out-dir>"
    local out_dir="$1"
    [ -s "$out_dir/out.pcap" ] || die "no pcap to read at $out_dir/out.pcap"

    # The hex readback is what `infra/capture/agreement.py` parses: it is the
    # one tcpdump format that carries the payload bytes verbatim rather than
    # tcpdump's own rendering of them.
    docker run --rm -v "$out_dir:/out:ro" "$IMAGE" \
        -n -X -s 0 -r /out/out.pcap > "$out_dir/out.pcap.txt" 2> "$out_dir/out.pcap.stderr"
    # The plain readback is what a human reads.
    docker run --rm -v "$out_dir:/out:ro" "$IMAGE" \
        -n -r /out/out.pcap > "$out_dir/out.pcap.plain" 2>/dev/null || true

    # The frame count is counted here rather than read out of tcpdump's own
    # summary, because `tcpdump -r` prints no summary: the "N packets captured"
    # line belongs to a live capture and this is a read of a finished one. Each
    # frame in the hex readback begins with a timestamp, so counting those is
    # counting packets — from the artifact the check will parse, which is the
    # only place a count can be checked.
    local packets
    packets="$(grep -cE '^[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6} ' "$out_dir/out.pcap.txt" || true)"
    packets="${packets:-0}"
    printf 'readback: %s frames, %s bytes of pcap\n' "$packets" "$(wc -c < "$out_dir/out.pcap")"
    printf '  hex readback    %s\n' "$out_dir/out.pcap.txt"
    printf '  plain readback  %s\n' "$out_dir/out.pcap.plain"
    if [ "$packets" -eq 0 ]; then
        printf 'start_capture: the capture saw NOTHING; any check over it is vacuous\n' >&2
        return 1
    fi

    # A capture that *lost* packets is not a capture that can support a
    # conclusion about what did not appear in it. tcpdump's own exit summary
    # distinguishes "received by filter" from "captured", and the gap between
    # them is the loss. Measured here: a run reported 48 received and 44
    # captured, and the four that went missing included the request the whole
    # check was about.
    local received lost
    received="$(grep -oE '^[0-9]+ packets? received by filter' "$out_dir/tcpdump.log" 2>/dev/null \
        | grep -oE '^[0-9]+' | head -1)"
    received="${received:-0}"
    lost=$((received - packets))
    if [ "$received" -gt 0 ] && [ "$lost" -gt 0 ]; then
        printf 'start_capture: the capture LOST %s of %s packets (kernel buffer overflow)\n' \
            "$lost" "$received" >&2
        return 1
    fi
}

cmd_interface() {
    [ "$#" -eq 1 ] || die "usage: start_capture.sh interface <network>"
    bridge_for_network "$1"
    printf '\n'
}

case "${1:-}" in
    start)    shift; cmd_start "$@" ;;
    stop)     shift; cmd_stop "$@" ;;
    readback) shift; cmd_readback "$@" ;;
    interface) shift; cmd_interface "$@" ;;
    *) die "usage: start_capture.sh {start <network> <seconds> <out-dir>|stop <out-dir>|readback <out-dir>|interface <network>}" ;;
esac
