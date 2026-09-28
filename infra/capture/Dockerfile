# The second observer: a packet capture on the project's Docker bridge.
#
# This image is deliberately tiny and deliberately not privileged. It is given
# exactly one capability, `NET_RAW`, and it runs in the **host** network
# namespace, because that is the only topology in which the traffic is visible
# to it.
#
# ## Why the host network namespace, and not a third container on the bridge
#
# A Linux bridge switches container A's virtual interface straight to container
# B's. Frames between two containers on one bridge are switched at layer 2 and
# **never traverse a third container's interface**, however that container is
# attached. A sniffer placed on the bridge as a third container therefore sees
# the bridge's own chatter — mDNS, ARP, SSDP — and none of the traffic between
# the other two. That was measured on this host: 21 packets captured, zero of
# the probe's, with the observer actively receiving the requests.
#
# The host's own interface on the bridge is `br-<first 12 hex of the network
# id>`, and it *is* in the forwarding path for traffic between the host and a
# container. Capturing on it needs `--network host` (to reach the host
# namespace) and `--cap-add=NET_RAW` (to open a raw socket) — not root, not
# `--privileged`. The interface name is discovered at run time by
# `start_capture.sh` and is never written into a file here.
FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends tcpdump \
 && rm -rf /var/lib/apt/lists/*

# The pcap is written to a bind mount, never to the container's writable layer:
# a capture that disappears with the container is not evidence.
WORKDIR /out
VOLUME ["/out"]

# `-n` throughout: name resolution would make the readback depend on the host's
# DNS at the moment it is read, and the evidence must not.
ENTRYPOINT ["tcpdump"]
CMD ["-n", "-i", "any", "-w", "/out/out.pcap"]
