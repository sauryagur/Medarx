"""Component I: what the two observers saw, and whether that is the approved payload.

Two files' worth of work, in the order the evidence flows.

**The byte comparison** (`compare_bytes_to_payload`) is the arithmetic: the bytes
the observer wrote to disk against the bytes the capture reassembled off the
wire, and each against an expected digest. **The agreement rule**
(`check_agreement`) is the policy built on it, and it is where the component's
real claim lives.

**Why the comparison answers two questions, not one.** The first,
`observer_bytes_match`, says the two observers saw the same bytes. The second,
`hash_matches`, says those bytes are the approved ones. A `True` on the first
and a `False` on the second is precisely the shape of the failure this project
has already suffered: the gateway verified one payload, sent another, and both
external observers faithfully agreed about the one that actually went. A check
written as "do the observers agree with each other?" scores that run green. The
fields are separate so that reading only the first is a visible omission rather
than a correct answer.

**Why the approved-payload hash is reported rather than compared to the wire.**
`medarx.models.payload_hash_of` hashes the approved **payload object**. The
OpenAI-wire body that carries it adds `model`, `messages`, `temperature` and
`max_tokens` around the payload's own fields, so no digest of the transmitted
bytes can equal it, and a check that compared them would be the one comparison
here capable of passing without meaning anything. The binding is made through
`expected_content` instead: the approved payload's report text, read by the
caller from the very object whose hash is reported. Both observers must carry
that text, so a payload substituted before transmission fails *even when the
two observers agree perfectly with each other* — which is the case
`test_two_observers_that_agree_on_unapproved_bytes_do_not_agree` builds out of
a real capture.

**Why the capture is parsed from `-X` and not from `-A`.** `-X` is the one
readback that carries the packet's bytes verbatim, offset-prefixed. The ASCII
column beside them is tcpdump's own rendering of the same bytes, and reading
that as hex would be a second definition of what the capture said.

**Why the link-layer offset is detected.** On this host the frames on the
Docker bridge arrive beginning at the IPv4 header, with no Ethernet header in
front of them, even though tcpdump reports the capture as `link-type EN10MB`.
A parser that assumed 14 bytes of Ethernet would read the IP header as a MAC
address and extract nothing at all — and would report "no request was seen" for
every capture, which is a check that cannot fail.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path

__all__ = [
    "AgreementReport",
    "Comparison",
    "check_agreement",
    "compare_bytes_to_payload",
    "frames_in",
    "observer_index",
    "request_bodies",
]


# =============================================================================
# The byte-level comparison
# =============================================================================


@dataclass
class Comparison:
    """The result of comparing the two observers against the approved hash.

    `observer_bytes_match` and `hash_matches` are booleans rather than one
    verdict because the caller has to be able to say *which* half failed. A
    single `ok: bool` would force the interesting case — both observers agree,
    neither is right — to be reported as a plain failure with no indication
    that the two observers were in fact consistent.
    """

    observer_bytes_match: bool
    hash_matches: bool
    differences: list[str] = field(default_factory=list)
    #: Only the byte-level findings, without the hash note.
    #:
    #: Split out because the two mean different things to a caller. The
    #: kernel's approved-payload hash covers the payload *object*, so on a
    #: correctly-behaving run the body never hashes to it — and a report whose
    #: `differences` list carries that as a finding would be crying wolf on
    #: every passing run, which is how a reader learns to skip the list.
    byte_differences: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        """Plain data, for a JSON report that a human reads."""
        return {
            "observer_bytes_match": self.observer_bytes_match,
            "hash_matches": self.hash_matches,
            "differences": list(self.differences),
            "byte_differences": list(self.byte_differences),
        }


def _first_difference(observer_bytes: bytes, capture_bytes: bytes) -> int | None:
    """The offset of the first differing byte, or `None` if the prefix matches.

    Scanned by index rather than compared in one step, because a report has to
    name the offset and `!=` does not say where.
    """
    shared = min(len(observer_bytes), len(capture_bytes))
    for offset in range(shared):
        if observer_bytes[offset] != capture_bytes[offset]:
            return offset
    return None


def compare_bytes_to_payload(
    observer_bytes: bytes,
    capture_bytes: bytes,
    approved_payload_hash: str,
) -> Comparison:
    """Compare the observer's record with the capture's reassembled body.

    `observer_bytes` is the byte sequence the observer wrote to disk.
    `capture_bytes` is the request body reassembled out of the captured frames.
    `approved_payload_hash` is the digest both are to equal — see the module
    docstring for what that digest covers, and for why the live path binds the
    wire bytes to the approved payload through content rather than through this
    field.

    Three outcomes, all reachable and all distinguishable in the return value:

    - identical, and hashing to the approved digest: both flags true;
    - identical, and not hashing to it: the two observers agree about a payload
      that is not the approved one — `observer_bytes_match` true,
      `hash_matches` false, and `differences` says which digest was expected;
    - different: `observer_bytes_match` false, with the offset of the first
      difference and which side is longer.
    """
    differences: list[str] = []
    offset = _first_difference(observer_bytes, capture_bytes)
    bytes_match = offset is None and len(observer_bytes) == len(capture_bytes)

    if offset is not None:
        differences.append(
            f"first difference at byte offset {offset}: "
            f"observer 0x{observer_bytes[offset]:02x} against "
            f"capture 0x{capture_bytes[offset]:02x}"
        )
    if len(observer_bytes) != len(capture_bytes):
        longer, shorter = (
            ("observer", "capture")
            if len(observer_bytes) > len(capture_bytes)
            else ("capture", "observer")
        )
        extra = abs(len(observer_bytes) - len(capture_bytes))
        plural = "" if extra == 1 else "s"
        sizes = {"observer": len(observer_bytes), "capture": len(capture_bytes)}
        differences.append(
            f"{longer}-only: {extra} byte{plural} present in the {longer} and "
            f"absent from the {shorter} "
            f"({longer} is {sizes[longer]} bytes, {shorter} is {sizes[shorter]})"
        )

    observed = hashlib.sha256(observer_bytes).hexdigest()
    hash_matches = observed == approved_payload_hash.removeprefix("sha256:")
    hash_note = ""
    if not hash_matches:
        hash_note = (
            f"the observer's bytes hash to {observed}, which is not the "
            f"approved hash {approved_payload_hash}"
        )

    return Comparison(
        observer_bytes_match=bytes_match,
        hash_matches=hash_matches,
        differences=[*differences, *([hash_note] if hash_note else [])],
        byte_differences=differences,
    )


# =============================================================================
# The capture, read back
# =============================================================================

#: One frame header line of a `tcpdump -X` readback: a timestamp, then the
#: packet's own summary. The timestamp is what distinguishes a header from the
#: hexadecimal dump lines that follow it, and it is also how the capture script
#: counts packets — a read of a finished capture prints no summary of its own.
_FRAME_LINE = re.compile(r"^(\d{2}:\d{2}:\d{2}\.\d{6})\s+(.*)$")

#: One line of tcpdump's hexadecimal dump: an offset, then the hex column, then
#: the ASCII rendering. Only the hex column is bytes; the ASCII column is
#: tcpdump's printable rendering of the same bytes, and reading it as hex would
#: be a second, different source of evidence.
_HEX_LINE = re.compile(r"^\s*0x[0-9a-fA-F]+:\s{2,}(.*)$")

#: A TCP frame's summary, with `-n`: addresses are numeric and the sequence
#: numbers are absolute, which is what makes placement rather than concatenation
#: the correct way to reassemble.
_TCP_LINE = re.compile(
    r"^IP (\d+(?:\.\d+){3})\.(\d+) > (\d+(?:\.\d+){3})\.(\d+):"
    r" Flags \[([^\]]*)\], seq (\d+):(\d+)"
)

_ETHERTYPE_IPV4 = 0x0800
_IPPROTO_TCP = 6


@dataclass
class _Frame:
    """One captured packet, as far as the agreement check cares."""

    stream: tuple[str, int, str, int] | None
    seq: int
    data: bytes


def frames_in(pcap_text: str) -> list[_Frame]:
    """Every frame in a `tcpdump -X` readback, as bytes.

    The link-layer offset is **detected, not assumed**: each frame is tested at
    offset 0 and, failing that, at offset 14 behind an IPv4 ethertype. The
    alternative — assuming one of them — is a parser that reads an IP header as
    a MAC address, extracts nothing, and reports "no request was seen" for
    every capture it is ever given.
    """
    frames: list[_Frame] = []
    current: _Frame | None = None
    for line in pcap_text.splitlines():
        header = _FRAME_LINE.match(line)
        if header:
            tcp = _TCP_LINE.match(header.group(2))
            current = _Frame(
                stream=(
                    (tcp.group(1), int(tcp.group(2)), tcp.group(3), int(tcp.group(4)))
                    if tcp else None
                ),
                seq=int(tcp.group(6)) if tcp else 0,
                data=b"",
            )
            frames.append(current)
            continue
        dump = _HEX_LINE.match(line)
        if dump and current is not None:
            column = re.split(r"\s{2,}", dump.group(1).strip(), maxsplit=1)[0]
            payload = bytearray()
            for group in column.split():
                if len(group) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", group):
                    payload += bytes.fromhex(group)
            current.data += bytes(payload)
    return frames


def _tcp_payload(data: bytes) -> bytes | None:
    """The TCP payload of one frame, or `None` if the frame carries none.

    Header lengths are read from the packet rather than assumed: an IPv4 header
    with options and a TCP header carrying timestamps are both longer than the
    20 bytes a fixed offset would allow, and assuming would shift the payload —
    producing a body that is nearly right, which is the worst shape for a byte
    comparison to fail in.
    """
    if len(data) >= 20 and data[0] >> 4 == 4:
        ip = 0
    elif len(data) > 34 and struct.unpack("!H", data[12:14])[0] == _ETHERTYPE_IPV4:
        ip = 14
    else:
        return None
    if data[ip] >> 4 != 4 or data[ip + 9] != _IPPROTO_TCP:
        return None
    ip_header_length = (data[ip] & 0x0F) * 4
    if ip_header_length < 20 or len(data) < ip + ip_header_length + 20:
        return None
    tcp = ip + ip_header_length
    tcp_header_length = (data[tcp + 12] >> 4) * 4
    return data[tcp + tcp_header_length:]


def _http_body(stream: bytes) -> bytes | None:
    """The request body of one reassembled TCP stream, or `None`.

    Sliced by the stream's own `Content-Length` rather than by "everything after
    the blank line": a keep-alive connection carries the next request in the
    same stream, and taking the tail would return a body with another message
    glued onto it.
    """
    separator = stream.find(b"\r\n\r\n")
    if separator < 0:
        return None
    head = stream[:separator].decode("latin-1")
    if not head.startswith("POST "):
        return None
    length: int | None = None
    for line in head.split("\r\n")[1:]:
        name, delimiter, value = line.partition(":")
        if delimiter and name.strip().lower() == "content-length":
            try:
                length = int(value.strip())
            except ValueError:
                return None
            break
    if length is None:
        return None
    body = stream[separator + 4: separator + 4 + length]
    return body if len(body) == length else None


def request_bodies(pcap_text: str) -> list[bytes]:
    """Every HTTP request body visible in the capture, reassembled.

    Reassembly is by TCP stream and by sequence number, not by capture order: a
    request body larger than one segment arrives across several frames, and
    concatenating in capture order would put a needle that straddles a segment
    boundary permanently out of reach — a check reporting zero hits because it
    looked in the wrong place, which is indistinguishable from one reporting
    zero because nothing was sent.

    A stream with a **gap** contributes nothing at all. A missing segment means
    the reassembly would be a plausible reconstruction rather than the bytes
    that were transmitted, and a check that accepted one would be comparing
    evidence against an invention.
    """
    streams: dict[tuple[str, int, str, int], list[tuple[int, bytes]]] = {}
    for frame in frames_in(pcap_text):
        if frame.stream is None or not frame.data:
            continue
        payload = _tcp_payload(frame.data)
        if payload is None:
            continue
        streams.setdefault(frame.stream, []).append((frame.seq, payload))

    bodies: list[bytes] = []
    for segments in streams.values():
        base = min(seq for seq, _ in segments)
        ordered = bytearray()
        complete = True
        for seq, payload in sorted(segments, key=lambda item: item[0]):
            offset = seq - base
            if offset > len(ordered):
                complete = False
                break
            ordered[offset:offset + len(payload)] = payload
        if not complete:
            continue
        body = _http_body(bytes(ordered))
        if body is not None:
            bodies.append(body)
    return bodies


# =============================================================================
# The observer's own statements
# =============================================================================


def observer_index(record_dir: Path) -> list[dict]:
    """The observer's index entries, or `[]` when it has never written one.

    A missing file is zero records, not an error: measured on this host, an
    observer that received nothing never creates `index.jsonl` at all, so "no
    file" is the ordinary state of the blocked path and reading it as a failure
    would make the correct answer the wrong one.
    """
    index_path = Path(record_dir) / "index.jsonl"
    if not index_path.exists():
        return []
    entries: list[dict] = []
    for line in index_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            entries.append(json.loads(line))
    return entries


def _record_bytes(record_dir: Path, entry: dict) -> bytes | None:
    """The bytes an index entry claims, or `None` when the entry is not honest.

    Three refusals, all of them ways a record can look present and be nothing:
    the path escapes the record directory, the file is absent, or the file does
    not match the length and digest the index states. Trusting the index would
    make a tampered or truncated record read as a verified one — the observer's
    index is a *claim* about a file, and the file is the evidence.
    """
    name = entry.get("path")
    if not isinstance(name, str) or "/" in name or "\\" in name or ".." in name:
        return None
    path = Path(record_dir) / name
    if not path.is_file():
        return None
    body = path.read_bytes()
    if entry.get("byte_length") != len(body):
        return None
    if entry.get("sha256") != hashlib.sha256(body).hexdigest():
        return None
    return body


def _block_receipt(record_dir: Path, request_id: str) -> dict | None:
    """The block receipt for `request_id`, or `None`.

    A receipt counts only when it is *this* request's and it says `blocked`. A
    receipt for another id says nothing about this one, and a receipt whose
    status is anything else is not a statement that nothing was sent.
    """
    path = Path(record_dir) / "block_receipt.json"
    if not path.is_file():
        return None
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return None
    if not isinstance(receipt, dict):
        return None
    if receipt.get("request_id") != request_id or receipt.get("status") != "blocked":
        return None
    return receipt


# =============================================================================
# The agreement rule
# =============================================================================


@dataclass
class AgreementReport:
    """What the two observers concluded, and which check produced it.

    `agree` is a conjunction of independently-named conditions rather than a
    verdict with no explanation, because "the check failed" and "the check
    failed *because the capture saw a request while the observer recorded
    none*" are different facts and only one of them points at a bug.
    """

    request_id: str
    observer_record_count: int
    pcap_hit_count: int
    agree: bool
    approved_hash: str
    details: list[str] = field(default_factory=list)
    differences: list[str] = field(default_factory=list)
    pcap_frame_count: int = 0

    def as_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "observer_record_count": self.observer_record_count,
            "pcap_hit_count": self.pcap_hit_count,
            "pcap_frame_count": self.pcap_frame_count,
            "agree": self.agree,
            "approved_hash": self.approved_hash,
            "details": list(self.details),
            "differences": list(self.differences),
        }


def check_agreement(
    approved_payload_hash: str,
    expected_content: str,
    record_dir: Path,
    pcap_text: str,
    request_id: str,
    *,
    observer_live: bool | None = None,
    records_before: int = 0,
    bodies_before: int = 0,
) -> AgreementReport:
    """Do the two observers agree, and was what they saw the approved payload?

    The two observers agree when either

    **(a)** both saw the request, the bytes the observer wrote to disk equal the
    bytes the capture reassembled off the wire, and those bytes carry the
    approved payload's content; or

    **(b)** neither observer saw anything **and** a block receipt for
    `request_id` exists.

    Everything else is a failure, and every failure names itself in `details`.

    Clause (b) is the whole reason `request_id` is a parameter. From the
    observers alone, "the gateway never fired" and "the request was refused
    before it could fire" are the same observation — nothing left — and scoring
    that as agreement would certify a gateway that silently stopped calling the
    provider, and a deployment whose observer was never reachable. Only a third,
    independent statement about the same request id separates them.

    `observer_live` is what the caller knows and this function cannot: whether
    the process that was supposed to be writing `record_dir` was answering at
    all. `None` means the caller did not say, and the silence clause is then
    decided by the block receipt alone. `False` refuses it outright, because a
    block receipt beside an observer that was down is not evidence that nothing
    was sent.

    `records_before` and `bodies_before` say how much of each shared artifact
    earlier requests already accounted for. They default to zero, which is
    right when one check covers one request and **wrong the moment a record
    directory and a capture cover more than one** — and that is not a
    hypothetical. A live run of this component asked about a *blocked* request
    in a directory that already held the *approved* request's record, and the
    approved request's bytes satisfied it: a request that sent nothing was
    certified by an earlier request that sent something. The delta is what
    makes the answer about this request rather than about the directory.
    """
    details: list[str] = []
    differences: list[str] = []
    approved = approved_payload_hash.removeprefix("sha256:")

    frames = frames_in(pcap_text)
    # The needle is searched for in the form the **wire** carries it, which is
    # JSON: a report text containing a newline travels as the two characters
    # `\` and `n`, so searching for the decoded string would find nothing in a
    # body that plainly contains it. `json.dumps` of the content, without its
    # surrounding quotes, is exactly the substring the encoder emitted — one
    # definition, shared with the encoder, rather than a second guess at how a
    # string is escaped.
    needle = json.dumps(expected_content, ensure_ascii=False)[1:-1].encode("utf-8")
    capture_hits = [
        body for body in request_bodies(pcap_text)[bodies_before:] if needle in body
    ]

    records: list[bytes] = []
    for entry in observer_index(record_dir)[records_before:]:
        body = _record_bytes(record_dir, entry)
        if body is None:
            # Refused, and said so: the observer's index claims a record that
            # cannot be produced from the file on disk, so this entry
            # contributes nothing and the report says which one and why.
            differences.append(
                f"the observer's index names record {entry.get('id')!r} but no file "
                f"at {entry.get('path')!r} matches its stated length and digest"
            )
            details.append(
                f"the observer's record {entry.get('id')!r} was refused: it does not "
                f"match its own index entry, so it is not evidence of anything"
            )
            continue
        records.append(body)
    record_hits = [body for body in records if needle in body]

    if not frames:
        details.append(
            "the capture readback contains no frames at all: the sniffer saw "
            "nothing, which is not the same as having watched and seen nothing"
        )

    if record_hits and capture_hits:
        # Both observers saw the request. They still have to agree with each
        # other, byte for byte, and on what they saw.
        comparison = compare_bytes_to_payload(record_hits[0], capture_hits[0], approved)
        # Only the byte-level findings go into `differences`. The hash note is
        # a `details` line, because on a correctly-behaving run the body does
        # not hash to the approved payload hash and a report that listed that as
        # a difference would be crying wolf on every passing run.
        differences.extend(comparison.byte_differences)
        agree = comparison.observer_bytes_match
        if not agree:
            details.append(
                "the two observers disagree: the bytes the observer wrote to disk "
                "are not the bytes the capture reassembled off the wire"
            )
        if comparison.hash_matches:
            details.append(
                "the transmitted bytes hash to the approved payload hash, which can "
                "only mean the caller passed a digest of the body; that is not what "
                "binds the wire to the approved payload, and the approved content "
                "is checked separately"
            )
        else:
            details.append(
                f"the approved payload hash {approved} covers the payload object, "
                f"not the request body, so the transmitted bytes do not hash to it "
                f"and the approved content is what binds the wire to the payload"
            )
    elif record_hits or capture_hits:
        # One observer saw the approved content and the other saw something
        # else. This is the leak shape: both saw traffic, they did not see the
        # same traffic, and the thing that failed is the approved payload.
        if capture_hits and not record_hits:
            details.append(
                "the capture carries the approved payload's content and the "
                "observer's records do not, so the bytes on the wire are not the "
                "bytes the observer recorded"
            )
        elif record_hits and not capture_hits:
            details.append(
                "the observer's records carry the approved payload's content and "
                "the capture does not, so what the observer recorded is not what "
                "was on the wire"
            )
        else:
            seen = "the observer's records" if records else "the captured request"
            missing = "the capture" if records else "the observer"
            details.append(
                f"asymmetric observation: {seen} carry a request and {missing} "
                f"carries no trace of it, so the two observers do not agree"
            )
        agree = False
    elif records or capture_hits:
        seen = "the observer's records" if records else "the captured request"
        missing = "the capture" if records else "the observer"
        details.append(
            f"asymmetric observation: {seen} carry a request and {missing} carries "
            f"no trace of it, so the two observers do not agree"
        )
        agree = False
    else:
        # Neither observer saw anything. On its own this is not agreement: a
        # gateway that never fired and a request that was never sent are the
        # same observation, and only a block receipt for this request id tells
        # them apart.
        receipt = _block_receipt(record_dir, request_id)
        if receipt is None:
            details.append(
                f"neither observer saw anything and there is no block receipt for "
                f"{request_id!r}: a gateway that never fired and a request that was "
                f"never sent look identical from here, so this is not agreement"
            )
            agree = False
        elif observer_live is False:
            details.append(
                f"a block receipt for {request_id!r} says nothing was sent, but the "
                f"caller reports the observer was not answering, so an empty record "
                f"directory is not evidence that nothing was sent"
            )
            agree = False
        else:
            details.append(
                f"neither observer saw anything and a block receipt for "
                f"{request_id!r} says it was refused at layer {receipt.get('layer')!r} "
                f"with {receipt.get('action_codes')!r}, so nothing left"
            )
            agree = True

    return AgreementReport(
        request_id=request_id,
        observer_record_count=len(records),
        pcap_hit_count=len(capture_hits),
        agree=agree,
        approved_hash=approved,
        details=details,
        differences=differences,
        pcap_frame_count=len(frames),
    )
