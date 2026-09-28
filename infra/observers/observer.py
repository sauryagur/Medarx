"""Component I, first observer: a provider that writes down the bytes it received.

This process is the **observer**, not the model. It answers the OpenAI
chat-completions shape so `medarx.gateway.openai_gateway.ModelGateway` can send
to it unchanged, and every byte of every request body it receives is written to
disk before it replies. **No model is consulted, ever** — the reply is a
constant. That is the point: a second observer that asked a real provider
anything would itself be an egress, and the two observers would have to agree
about a conversation three of them were in.

**Raw bytes, not a re-encoding.** What lands in ``<record-dir>/<id>.bin`` is the
exact byte sequence read off the socket, and what ``index.jsonl`` records as
``sha256`` is the hash of *those bytes*. Parsing the body to find a model id is
fine; parsing it to decide what to keep is not — a re-encoding is exactly where
evidence quietly changes, and the whole agreement check in ``infra/capture`` is
a byte comparison that a normalising step would defeat without anything failing.

**"I received nothing" has to be as loud as "here is what I received".** Three
surfaces make it say so: ``GET /v1/records`` returns a ``count`` rather than
404-ing, ``GET /v1/records/{id}`` answers 404 naming the id it has no record of,
and ``GET /healthz`` answers at all. A check that asks an observer that is down
gets a connection error, which is distinguishable from an empty index; what it
cannot distinguish is an observer that was up and received nothing, unless the
observer is asked while it is up. That is why the blocked-path demo reads
``/healthz`` and the index in the same run.

**The index is written after the bytes are durable.** A crash between the two
leaves an unreferenced ``.bin`` — a file with no claim attached to it — rather
than an index entry pointing at a file that is not there. The evidence that
exists is always readable, which is the direction to fail in.

Configuration is by environment variable, which is the one thing this process
does that the kernel may not: it is not a ``medarx`` module, it is not in the
import graph of anything that sends data, and the rule that only ``config.py``
reads the environment exists so that kernel behaviour is a function of an
injected ``Settings`` object. Injecting the record directory through a process
boundary is the same property, reached a different way.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

__all__ = ["Observer", "RecordStore", "build_completion", "main"]

#: The path the OpenAI chat-completions spec puts the request at, relative to
#: the base URL in ``Settings.gateway_base_url`` (which already ends in ``/v1``).
#: The same constant the gateway builds its URL from, spelled once here so the
#: two ends of the wire cannot drift apart silently.
CHAT_COMPLETIONS_PATH = "/v1/chat/completions"

#: The fixed reply. Deterministic, synthetic, and generated from nothing: the
#: observer models an inference provider and has no inference provider behind
#: it, and a drafting assistant whose output varied would make the demo
#: irreproducible for no benefit.
DEFAULT_REPLY = "Findings: 7mm nodule."

#: The identifier the reply reports, when the request did not name one. It is
#: the observer's own configured model, not a value read from the request,
#: because the observer's job is to be an endpoint and not to be a second copy
#: of the gateway's model-resolution rules.
DEFAULT_MODEL = "medarx-demo-model"

#: Refuse a body larger than this. A cap rather than a trust: this process
#: writes every byte it is given to a disk that is meant to be evidence, so an
#: unbounded body is a way to fill the disk that holds the evidence.
MAX_BODY_BYTES = 8 * 1024 * 1024

#: Guards the index append. ``O_APPEND`` already makes each ``write`` land whole
#: at the end of the file, but a line assembled from several writes could still
#: interleave with a concurrent request's, and a torn JSONL line is an index
#: that cannot be read at all.
_INDEX_LOCK = threading.Lock()


def _now_iso() -> str:
    """UTC, second resolution, with the ``Z`` suffix — never a naive timestamp."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


class RecordStore:
    """The observer's disk: one file of raw bytes per request, and an index.

    Split out from the HTTP layer so that "what did you receive" is one object
    with one write path, rather than a sequence of statements spread through a
    request handler where a reader has to trust that all of them ran.
    """

    def __init__(self, record_dir: Path) -> None:
        self._dir = Path(record_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        # **Refuse to start if the record directory is not writable.** An
        # observer that cannot record is worse than no observer, and the
        # failure is far cheaper to diagnose here than downstream: measured on
        # this host, a container running as uid 10001 against a bind mount
        # owned by another user raised `PermissionError` on the *first request*,
        # and the request handler died with the connection closed and no reply
        # at all — which reads, from the gateway, as a transport failure, and
        # from an observer index, as "I received nothing".
        probe = self._dir / ".writable"
        try:
            probe.write_bytes(b"")
            probe.unlink()
        except OSError as exc:
            raise SystemExit(
                f"observer: {self._dir} is not writable by this process "
                f"({type(exc).__name__}: {exc}). The observer records every byte "
                f"it receives and an observer that cannot write is not an "
                f"observer, so it will not start. Point OBSERVER_RECORD_DIR at "
                f"a directory this process owns."
            ) from exc

    @property
    def index_path(self) -> Path:
        return self._dir / "index.jsonl"

    def record(self, body: bytes) -> dict:
        """Write `body` verbatim and return the index entry describing it.

        The order is the whole of the durability argument: the payload file is
        written, flushed and fsynced *before* the index line that claims it
        exists. An interrupted run therefore leaves an orphan file — visible,
        harmless, and not referenced by anything — rather than an index entry
        whose bytes are missing, which would make the index assert something
        false.
        """
        record_id = uuid.uuid4().hex
        path = self._dir / f"{record_id}.bin"
        with open(path, "wb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        entry = {
            "id": record_id,
            "path": f"{record_id}.bin",
            "sha256": hashlib.sha256(body).hexdigest(),
            "byte_length": len(body),
            "received_at": _now_iso(),
        }
        line = json.dumps(entry, separators=(",", ":"), sort_keys=True) + "\n"
        with _INDEX_LOCK:
            with open(self.index_path, "a", encoding="utf-8") as index:
                index.write(line)
                index.flush()
                os.fsync(index.fileno())
        return entry

    def index(self) -> list[dict]:
        """Every index entry, in receipt order.

        A line that does not parse is **not** skipped silently. It is returned
        as a ``{"id": None, "error": ...}`` marker so the caller counts it: an
        index whose last line is torn is an index that is missing an entry, and
        a check that silently drops what it cannot read reports agreement over
        a record set it never actually saw.
        """
        if not self.index_path.exists():
            return []
        entries: list[dict] = []
        with open(self.index_path, "r", encoding="utf-8") as index:
            for number, line in enumerate(index, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    entries.append(json.loads(stripped))
                except ValueError as exc:
                    entries.append(
                        {"id": None, "line": number, "error": str(exc), "raw": stripped}
                    )
        return entries

    def path_for(self, record_id: str) -> Path | None:
        """The recorded bytes for `record_id`, or `None` if there are none.

        `None` is a real answer and is returned for three different situations,
        which the caller may want to tell apart: the id was never issued, the id
        was issued and the file is gone, or the id is not one this store could
        have produced at all. A path that would escape the record directory is
        refused outright rather than resolved — the id arrives on a URL.
        """
        if not record_id or "/" in record_id or "\\" in record_id or ".." in record_id:
            return None
        candidate = self._dir / f"{record_id}.bin"
        if not candidate.is_file():
            return None
        return candidate


def build_completion(model: str, content: str, completion_id: str) -> dict:
    """The OpenAI-shaped reply the gateway's `_content_of` reads.

    Exactly the fields the wire spec's response carries and the kernel's
    `ModelResponse` names: `choices[0].message.content` is what the gateway
    requires, `model` and `finish_reason` are what the contract carries, and
    `usage` is what the contract's `ModelResponse.usage` describes. The
    `id` is derived from the record id, so the reply names the file on disk that
    is the evidence for it.
    """
    return {
        "id": f"chatcmpl-{completion_id}",
        "object": "chat.completion",
        "created": int(datetime.now(timezone.utc).timestamp()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }


class Observer:
    """The HTTP surface, kept free of I/O so a test can drive the store alone."""

    def __init__(self, store: RecordStore, model: str = DEFAULT_MODEL,
                 reply: str = DEFAULT_REPLY) -> None:
        self.store = store
        self.model = model
        self.reply = reply

    def requested_model(self, body: bytes) -> str:
        """The model the request named, or the configured one.

        Read with a decode that cannot raise. The body is evidence and this
        process must never fail on it: a request whose body is not UTF-8, or is
        not JSON, or is not an object, is still recorded byte for byte, and the
        reply carries the observer's own model id rather than nothing.
        """
        try:
            parsed = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return self.model
        if isinstance(parsed, dict) and isinstance(parsed.get("model"), str):
            return parsed["model"]
        return self.model


class _Handler(BaseHTTPRequestHandler):
    # HTTP/1.1 so the length of every response is declared; the gateway's
    # httpx client keeps the connection alive and a second request on it must
    # not be read as part of the first reply.
    protocol_version = "HTTP/1.1"
    server_version = "medarx-observer/1.0"

    # -- Plumbing ----------------------------------------------------------

    def log_message(self, fmt: str, *args: object) -> None:
        """Route the access log to stderr with the record id in it.

        stderr, never the record directory: the record directory is evidence and
        a log line written into it would be a file the index does not describe.
        """
        sys.stderr.write("observer %s - %s\n" % (self.address_string(), fmt % args))

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_json(self, status: int, payload: dict) -> None:
        self._send(status, json.dumps(payload, separators=(",", ":")).encode("utf-8"),
                   "application/json")

    @property
    def observer(self) -> Observer:
        return self.server.observer  # type: ignore[attr-defined]

    def _read_body(self) -> bytes | None:
        """Every byte of the request body, read from the socket to its end.

        Read as a *stream* and never as `rfile.read(length)` alone: a body that
        arrives in several TCP segments is the normal case for the JSON the
        gateway builds, and a partial read would be recorded as the request. A
        read that ends early raises, and the handler answers 400 rather than
        storing truncated bytes as though they were what the gateway sent — a
        short record is worse than no record, because it is a record.
        """
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            # A chunked request carries no length. `httpx` with `content=<bytes>`
            # always sets one, and a chunked body would need a de-chunker whose
            # output is a re-assembly — refused rather than approximated.
            return b"" if self.headers.get("Transfer-Encoding") is None else None
        try:
            length = int(raw_length)
        except ValueError:
            return None
        if length < 0 or length > MAX_BODY_BYTES:
            return None
        chunks: list[bytes] = []
        remaining = length
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 65536))
            if not chunk:
                raise ConnectionError("the body ended before Content-Length bytes")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    # -- Routes ------------------------------------------------------------

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's name
        if self.path.split("?", 1)[0] != CHAT_COMPLETIONS_PATH:
            self._send_json(404, {"error": "no such path", "path": self.path})
            return
        try:
            body = self._read_body()
        except ConnectionError as exc:
            self._send_json(400, {"error": str(exc)})
            return
        if body is None:
            self._send_json(400, {"error": "unsupported or oversized request body"})
            return
        try:
            entry = self.observer.store.record(body)
        except OSError as exc:
            # A 500, never a 200 and never a closed connection. The bytes
            # arrived and could not be written down, and the only honest answer
            # says so: a 200 would tell the gateway the send succeeded and the
            # run would carry on with an observer holding no evidence of it.
            sys.stderr.write(f"observer could not record: {type(exc).__name__}: {exc}\n")
            self._send_json(500, {
                "error": "the observer could not write this request to its record "
                         "directory, so it has no evidence of it and will not "
                         "answer as though it had",
                "detail": f"{type(exc).__name__}: {exc}",
            })
            return
        completion = build_completion(
            self.observer.requested_model(body), self.observer.reply, entry["id"]
        )
        self._send_json(200, completion)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's name
        path = self.path.split("?", 1)[0]
        if path == "/healthz":
            entries = self.observer.store.index()
            self._send_json(200, {
                "status": "ok",
                "role": "observer",
                "record_count": len([e for e in entries if e.get("id")]),
                "record_dir": str(self.observer.store.index_path.parent),
            })
            return
        if path == "/v1/records":
            entries = self.observer.store.index()
            self._send_json(200, {"count": len(entries), "records": entries})
            return
        if path.startswith("/v1/records/"):
            record_id = path[len("/v1/records/"):]
            found = self.observer.store.path_for(record_id)
            if found is None:
                # 404, and a body that says so in as many words. "Nothing here"
                # is an answer this observer gives positively; a bare 404 with
                # no body could equally be a routing mistake.
                self._send_json(404, {
                    "error": "no record with that id",
                    "id": record_id,
                    "record_count": len(self.observer.store.index()),
                })
                return
            self._send(200, found.read_bytes(), "application/octet-stream")
            return
        self._send_json(404, {"error": "no such path", "path": self.path})

    def do_HEAD(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's name
        self.do_GET()


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], observer: Observer) -> None:
        self.observer = observer
        super().__init__(address, _Handler)


def main(argv: list[str] | None = None) -> int:
    """Read the environment once, build the observer, and serve until stopped."""
    del argv
    record_dir = Path(os.environ.get("OBSERVER_RECORD_DIR", "/records"))
    host = os.environ.get("OBSERVER_HOST", "0.0.0.0")
    port = int(os.environ.get("OBSERVER_PORT", "8080"))
    model = os.environ.get("OBSERVER_MODEL", DEFAULT_MODEL)
    reply = os.environ.get("OBSERVER_REPLY", DEFAULT_REPLY)

    observer = Observer(RecordStore(record_dir), model=model, reply=reply)
    server = _Server((host, port), observer)
    # The *bound* port, not the requested one. `OBSERVER_PORT=0` then hands the
    # observer an ephemeral port, which is how the test suite starts one
    # without reserving a port first and racing another process for it.
    sys.stderr.write(
        f"observer listening on {host}:{server.server_address[1]}; "
        f"records in {record_dir}; no model is contacted by this process\n"
    )
    sys.stderr.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
