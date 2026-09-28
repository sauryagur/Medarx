"""The machinery both demo beats share: a real observer, a real capture, a real run.

**Nothing in here is a stub.** The observer is the container built from
`infra/observers/Dockerfile`, running on a real Docker bridge and reachable only
over a published TCP port. The second observer is `infra/capture/start_capture.sh`
in the host network namespace, pointed at that bridge. The Medarx process is the
real composition root — `create_app`, `build_pipeline`, the same gateway — driven
through its own HTTP surface. The only synthetic thing in the whole arrangement
is the text, which is this repository's fabricated corpus throughout.

## Why the app runs in this process and the observers do not

The observers must be containers: a packet capture on a Docker bridge is only
meaningful from outside the Medarx process, and an observer running in the same
interpreter as the thing it observes is not an observer. The Medarx process is
the opposite: it is the system under demonstration, and running it here rather
than in a second subprocess is what lets the demo read the **approved payload
object** out of the kernel itself instead of asking a provider what it received.
That distinction is the whole argument of the project, so the demo is built to
preserve it rather than to save a process.

The client-to-Medarx hop is in-process ASGI (`TestClient`). The
Medarx-to-provider hop is a real socket across a real bridge, and that is the
hop every byte of evidence in this component is about.

## Where the approved payload comes from, and why it matters

`expected_content` for the agreement check is the report text of the
`StructuredPayload` that component E approved, captured at the moment component F
verified it. It is **not** read out of the observer's record, and not out of the
packet capture. This project has already shipped the version of this check that
did read it from the observer: the gateway's record of what it sent turned out to
return the bytes of a *substituted* payload, the needle matched, and the check
certified a leak. A needle taken from an observer is an observer agreeing with
itself. The needle is taken from the kernel, and the observers are what has to
agree with it.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CAPTURE_SCRIPT = REPO_ROOT / "infra" / "capture" / "start_capture.sh"
SRC = REPO_ROOT / "backend" / "src"

#: A synthetic, non-secret audit key. The beats fabricate everything, including
#: this, and a demo that asked for a credential would be a demo nobody can run.
AUDIT_KEY = "medarx-beat-demo-key-not-a-credential"  # noqa: S105

#: The date order the beats run under. Declared rather than inherited from the
#: environment, because a beat whose outcome depends on an unset environment
#: variable is a beat that blocks or approves for different reasons on different
#: machines. `MDY` is what the corpus was written in.
DATE_ORDER = "MDY"

#: The policy mode the beats run under, and they say so rather than inheriting
#: it. `Settings.policy_mode` defaults to `"cloud"`, and the default is right for
#: a deployment pointed at a real provider and **wrong for these beats**: every
#: audit record a beat writes would then carry `policy_mode: "cloud"` for a run
#: whose bytes never left the machine. The audit log is a permanent record an
#: auditor reads, and a deployment mode recorded in it that the deployment is
#: not in is a false fact in the one store the design names as an asset. The
#: observer is on loopback on the same host, which is what `strict_local` says.
POLICY_MODE = "strict_local"

#: The observer's fixed reply and model, restated here **on purpose**. The
#: observer computes them itself; if a beat imported the constants from its
#: source, a change to that source would move the constant and the beat would
#: keep agreeing with it. Spelling them out here makes the same change a failure,
#: which is the only kind of agreement worth having.
OBSERVER_REPLY = "Findings: 7mm nodule."
OBSERVER_MODEL = "medarx-demo-model"

#: The identifiers `mask_identifiers` removes from the `--json` rendering. The
#: keys, not a regex over everything: masking `modality` would turn "CT" into a
#: placeholder and make the report unreadable, and the point of the list is that
#: a reader can check it against `identifiers.json` line by line.
MASKED_IDENTIFIER_KEYS = (
    "mrn",
    "accession",
    "patient_id",
    "date_of_birth",
    "ambiguous_reference",
    "institution_name",
    "patient_reference",
    "study_date",
    "prior_study_date",
    "patient_age",
    "spelling.patient_id_canonical",
    "spelling.patient_id_no_space",
)

MASK = "<synthetic-identifier>"

_IDENTIFIER_PATH = re.compile(r"\A([A-Za-z_][A-Za-z0-9_]*)(?:\.([A-Za-z_][A-Za-z0-9_]*))?\Z")


def _value_at(dotted: str) -> str:
    """The `identifiers.json` value a masked-key path names.

    Raises rather than returning a default. A key that does not resolve means
    the masking list and the inventory have drifted apart, and a mask that
    silently matches nothing is not a mask.
    """
    from evals.synthetic_phi import seed_corpus

    match = _IDENTIFIER_PATH.match(dotted)
    if match is None:
        raise ValueError(
            f"{dotted!r} is not a dotted identifier key; MASKED_IDENTIFIER_KEYS is "
            f"a list of paths into identifiers.json and a key that does not parse "
            f"would stop masking whatever it named"
        )
    node: object = seed_corpus.identifiers()
    for part in match.groups():
        if part is None:
            continue
        if not isinstance(node, dict) or part not in node:
            raise ValueError(
                f"identifiers.json has no {dotted!r}; the masking list and the "
                f"inventory have drifted apart"
            )
        node = node[part]
    return str(node)


def identifier_values() -> "list[str]":
    """Every fabricated identifier value in `identifiers.json`, longest first.

    Longest first so that a value which contains another is replaced whole; a
    shorter value matched first would leave a fragment of the longer one behind,
    and a fragment of an MRN is still evidence.
    """
    return sorted({_value_at(key) for key in MASKED_IDENTIFIER_KEYS
                   if len(_value_at(key)) >= 3}, key=len, reverse=True)


def value_of(dotted: str) -> str:
    """The `identifiers.json` value a masked-key path names."""
    return _value_at(dotted)


def planted_identifier_keys(text: str) -> "list[str]":
    """Which `MASKED_IDENTIFIER_KEYS` entries occur in `text`, as key names.

    Names rather than values, deliberately. A report that lists the values it
    planted is a report that publishes them, and the `--json` rendering is the
    part most likely to be pasted into an issue. The names say the same thing to
    a reader who has `identifiers.json` open and say nothing to one who does
    not.
    """
    return [key for key in MASKED_IDENTIFIER_KEYS
            if len(_value_at(key)) >= 3 and _value_at(key) in text]


def mask_identifiers(text: str) -> str:
    """`text` with every fabricated identifier value replaced by `MASK`.

    Applied only to the `--json` rendering, and only to text the demo *received*:
    the request body it built. The transformed payload, the model reply and the
    captured bytes are shown as they are, because showing them truthfully is how
    a reader sees that the identifiers are gone rather than being told so. In
    print mode nothing is masked, because the data is fabricated and the full
    before/after diff is the most useful thing on the screen.
    """
    for value in identifier_values():
        text = text.replace(value, MASK)
    return text


def mask_tree(node):
    """Every string in a JSON-shaped structure, masked."""
    if isinstance(node, str):
        return mask_identifiers(node)
    if isinstance(node, list):
        return [mask_tree(item) for item in node]
    if isinstance(node, dict):
        return {key: mask_tree(value) for key, value in node.items()}
    return node


# =============================================================================
# Docker, and the observer container
# =============================================================================


def _docker(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, check=check, timeout=900
    )


def docker_usable() -> bool:
    return shutil.which("docker") is not None and _docker("info", check=False).returncode == 0


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def wait_for_health(url: str, timeout: float = 90.0) -> dict:
    import httpx

    deadline = time.monotonic() + timeout
    last: "Exception | None" = None
    while time.monotonic() < deadline:
        try:
            response = httpx.get(url, timeout=3.0)
            if response.status_code == 200:
                return response.json()
        except httpx.HTTPError as exc:
            last = exc
        time.sleep(0.2)
    raise AssertionError(f"the observer never became healthy at {url}: {last}")


@dataclass
class BeatEnvironment:
    """An observer container, a capture directory, and a place to leave evidence.

    A context manager rather than a function, because a demo that raises before
    its teardown would otherwise leave a container and a bridge behind, and the
    next run would capture on a network it does not own.
    """

    workdir: Path
    network: str
    observer_image: str
    capture_image: str
    records: Path = field(init=False)
    capture_dir: Path = field(init=False)
    port: int = field(init=False, default=0)
    health_before: dict = field(init=False, default_factory=dict)
    health_after: dict = field(init=False, default_factory=dict)
    capture_readback: str = field(init=False, default="")
    pcap_text: str = field(init=False, default="")
    _container: str = field(init=False, default="")
    _volume: str = field(init=False, default="")
    _capturing: bool = field(init=False, default=False)

    def __enter__(self) -> "BeatEnvironment":
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.records = self.workdir / "records"
        self.records.mkdir(exist_ok=True)
        self.capture_dir = self.workdir / "capture"
        self.capture_dir.mkdir(exist_ok=True)

        self._container = f"{self.network}-observer"
        self._volume = f"{self.network}-records"
        _docker("network", "create", self.network, check=False)
        _docker("build", "-t", self.observer_image, str(REPO_ROOT / "infra" / "observers"))
        _docker("build", "-t", self.capture_image, str(REPO_ROOT / "infra" / "capture"))
        _docker("volume", "rm", "-f", self._volume, check=False)
        _docker("volume", "create", self._volume)
        self.port = _free_port()
        _docker("run", "-d", "--name", self._container, "--network", self.network,
                "-p", f"127.0.0.1:{self.port}:8080", "-v", f"{self._volume}:/records",
                self.observer_image)
        self.health_before = wait_for_health(f"http://127.0.0.1:{self.port}/healthz")
        return self

    def __exit__(self, *exc_info) -> None:
        if self._capturing:
            try:
                self.stop_capture()
            except Exception:  # noqa: BLE001 - teardown must not mask the real error
                pass
        _docker("rm", "-f", self._container, check=False)
        _docker("volume", "rm", "-f", self._volume, check=False)
        _docker("network", "rm", self.network, check=False)

    # -- The provider --------------------------------------------------------

    @property
    def base_url(self) -> str:
        """The OpenAI-wire base URL the gateway is pointed at: the observer."""
        return f"http://127.0.0.1:{self.port}/v1"

    def health(self) -> dict:
        return wait_for_health(f"http://127.0.0.1:{self.port}/healthz")

    def collect(self) -> None:
        """Copy the observer's records out and read its health, after the run.

        `docker cp` rather than a bind mount: the observer runs as an
        unprivileged uid that cannot write a host directory this user owns, and a
        bind mount raises `PermissionError` on the first request and the observer
        answers nothing at all.
        """
        self.health_after = self.health()
        _docker("cp", f"{self._container}:/records/.", str(self.records))

    # -- The capture ---------------------------------------------------------

    def start_capture(self) -> None:
        if self._capturing:
            raise RuntimeError("a capture is already running into this directory")
        completed = subprocess.run(
            [str(CAPTURE_SCRIPT), "start", self.network, "0", str(self.capture_dir)],
            capture_output=True, text=True, timeout=300,
            env={**os.environ, "MEDARX_CAPTURE_IMAGE": self.capture_image},
        )
        if completed.returncode != 0:
            raise AssertionError(
                "the capture did not start:\n" + completed.stdout + completed.stderr
            )
        self._capturing = True

    def stop_capture(self) -> subprocess.CompletedProcess:
        completed = subprocess.run(
            [str(CAPTURE_SCRIPT), "stop", str(self.capture_dir)],
            capture_output=True, text=True, timeout=300,
            env={**os.environ, "MEDARX_CAPTURE_IMAGE": self.capture_image},
        )
        self._capturing = False
        self.capture_readback = completed.stdout + completed.stderr
        pcap_text = self.capture_dir / "out.pcap.txt"
        if pcap_text.exists():
            self.pcap_text = pcap_text.read_text(encoding="utf-8")
        return completed

    # -- Evidence about the observers themselves ----------------------------

    def capture_saw_frames(self) -> int:
        """Frames in the readback, counted from the file the check will parse."""
        return len(re.findall(r"^\d{2}:\d{2}:\d{2}\.\d{6} ", self.pcap_text, re.MULTILINE))

    def control_evidence(self, content: str) -> dict:
        """See `control_evidence_from`, with this run's own observers."""
        return control_evidence_from(
            self.records,
            self.pcap_text,
            observer_live=self.health_after.get("status") == "ok",
            health_record_count=int(self.health_after.get("record_count", -1)),
            content=content,
        )


def control_evidence_from(record_dir: Path, pcap_text: str, *,
                          observer_live: bool, health_record_count: int,
                          content: str) -> dict:
    """Whether this evidence can tell "saw nothing" from "was not looking".

    **This is the guard that stops the blocked beat being decorative.** A zero
    at both observers is the whole of beat 2's claim, and a zero is exactly what
    a broken observer, a sniffer on the wrong interface, or a record directory
    someone emptied would also produce. Four independent statements have to
    hold for that zero to mean anything:

    - `records_complete`: the observer's own record count equals the number of
      index entries actually on disk. This is the statement that closes "delete
      a record and the check passes vacuously" — a deletion from the record
      directory makes the two disagree, and a record the observer counted but
      that is not on disk is exactly the tampering this project has already paid
      for once.
    - `pcap_frame_count`: the sniffer saw the bridge at all.
    - `pcap_request_bodies`: it saw the **control** request, so "no request
      body was captured" is a statement about this run and not about the tool.
    - `pcap_carries_approved_content`: what the control put on the wire is
      visible in the capture, so a capture that saw traffic but no request is
      distinguishable from one that was not watching at all.

    The control request is what makes all of it a statement about the *blocked*
    request. Without one, "neither observer saw anything" and "the observers
    were not running" are the same observation, and the beat would prove
    nothing.
    """
    from infra.capture.agreement import observer_index, request_bodies

    needle = json.dumps(content, ensure_ascii=False)[1:-1].encode("utf-8")
    bodies = request_bodies(pcap_text)
    index_entries = len(observer_index(record_dir))
    return {
        "observer_live": observer_live,
        "observer_record_count": health_record_count,
        "observer_index_entries": index_entries,
        "records_complete": index_entries == health_record_count,
        "pcap_frame_count": len(
            re.findall(r"^\d{2}:\d{2}:\d{2}\.\d{6} ", pcap_text, re.MULTILINE)
        ),
        "pcap_request_bodies": len(bodies),
        "pcap_carries_approved_content": any(needle in body for body in bodies),
    }


def guard_holds(evidence: dict) -> bool:
    """Whether every one of `control_evidence_from`'s statements holds.

    One predicate, used by the demo and re-used by the tests that damage the
    evidence in order to watch it fall. A second copy of this rule inside a test
    would be a second thing to keep correct, and the copy is the part that would
    quietly disagree.
    """
    return bool(
        evidence.get("records_complete")
        and evidence.get("observer_live", True)
        and evidence.get("observer_record_count", 0) >= 1
        and evidence.get("pcap_frame_count", 0) > 0
        and evidence.get("pcap_request_bodies", 0) >= 1
        and evidence.get("pcap_carries_approved_content")
    )


def assert_nothing_left(report, *, request_id: str) -> None:
    """Raise unless both observers saw nothing for this request.

    The blocked beat's exit status is part of its claim, so the decision lives
    in one named function the script calls and a test can call against a
    doctored report. A script that printed a non-zero count and exited 0 would
    have buried the one thing it exists to show, and putting the rule behind a
    CLI flag would have been a test seam in the demonstration.
    """
    if report.observer_record_count or report.pcap_hit_count:
        raise AssertionError(
            f"A BLOCKED REQUEST TRANSMITTED BYTES ({request_id!r}). observer "
            f"records: {report.observer_record_count}; captured request bodies: "
            f"{report.pcap_hit_count}. A blocked beat that shows outbound bytes is "
            f"a failed demo."
        )


def assert_capture_sound(stopped, readback: str, *,
                         control_fully_observed: bool) -> None:
    """Raise unless the capture can support a conclusion about an absence.

    `start_capture.sh stop` exits non-zero for the two ways a capture can be
    worthless: it saw nothing at all, or it lost packets. Neither may be
    ignored, and a beat that ignored the exit status once did — it reported a
    clean zero over a capture that had dropped frames, which is a zero
    indistinguishable from the zero the request would have produced.

    **The two failures are not equally fatal, and treating them as equal is
    wrong in the other direction.** A capture that saw *nothing* is worthless
    outright. A capture that lost frames is a problem only to the extent that
    the loss could have hidden the thing being concluded about, and the
    **control request settles that**: if the capture reassembled the control's
    entire request body and those bytes are exactly the bytes the observer
    recorded, then reassembly demonstrably works on this capture, so a request
    body that was not there would have been found had one existed. That is a
    demonstration rather than a hope, and it is the same `check_agreement` call
    the beat's real conclusion rests on — not a second, weaker one.

    The bridge carries continuous background chatter, so the frames lost at
    `tcpdump`'s shutdown are usually not the request's, and a rule that failed
    on any of them would be a rule that fails intermittently and teaches a
    reader to re-run a failing demo rather than to believe it. The loss is
    reported in every output either way; it is only fatal when it could have
    hidden the conclusion.
    """
    if stopped.returncode == 0:
        return
    if "saw NOTHING" not in readback and control_fully_observed:
        return
    raise AssertionError(
        "the packet capture did not come back clean, so nothing can be "
        "concluded about what did not appear in it:\n"
        f"{readback.strip()}"
    )


# =============================================================================
# Driving the real application
# =============================================================================


@dataclass(frozen=True)
class DrivenRequest:
    """One request to put through the real HTTP surface."""

    request_id: str
    body: dict


@dataclass
class DrivenRun:
    """What the application returned, and the payload component E approved."""

    responses: list[dict] = field(default_factory=list)
    approved_payloads: list[dict] = field(default_factory=list)
    audit_records: list[dict] = field(default_factory=list)

    def for_request(self, request_id: str) -> dict:
        for response in self.responses:
            if response["request_id"] == request_id:
                return response
        raise KeyError(f"no response was driven for request {request_id!r}")

    def approved_payload(self, request_id: str) -> dict:
        for payload in self.approved_payloads:
            if payload["request_id"] == request_id:
                return payload
        raise KeyError(f"no payload was approved for request {request_id!r}")


def _ensure_importable() -> None:
    """Put `backend/src` and the repository root on `sys.path`, once.

    The documented command is `cd backend && uv run python ../evals/demo_*.py`,
    where `sys.path[0]` is this file's own directory and neither `medarx` nor
    `evals` is importable. Making the script work from the directory a reader is
    standing in is worth two lines; making them export `PYTHONPATH` instead would
    be a second thing to remember.
    """
    for entry in (str(SRC), str(REPO_ROOT)):
        if entry not in sys.path:
            sys.path.insert(0, entry)


def drive(database: Path, gateway_base_url: str,
          requests: Sequence[DrivenRequest], *,
          scope_study: str, function: str = "Draft") -> DrivenRun:
    """Put `requests` through the real application and read the audit log back.

    The approved payload is captured by wrapping `verify_approved_payload` on the
    gateway the composition root built — a read-only tap at the exact point
    component F re-derives the payload's hash and the exact object component E
    approved. Nothing is altered and nothing is stubbed; the wrapper returns the
    token it was handed.

    The audit readback goes through `GET /v1/audit/records/{request_id}` rather
    than through `AuditLog` directly, so the beat shows what an auditor would
    actually be served.
    """
    _ensure_importable()
    from fastapi.testclient import TestClient  # noqa: PLC0415 - after sys.path setup

    from medarx.api.app import create_app  # noqa: PLC0415
    from medarx.config import Settings  # noqa: PLC0415
    from medarx.models import payload_hash_of  # noqa: PLC0415

    settings = Settings(
        audit_key=AUDIT_KEY,
        date_order=DATE_ORDER,
        policy_mode=POLICY_MODE,
        gateway_base_url=gateway_base_url,
    )
    app = create_app(settings, f"sqlite:///{database}")
    gateway = app.state.pipeline.gateway
    original = gateway.verify_approved_payload
    run = DrivenRun()
    current_id: list[str] = [""]

    def tap(payload, approved_hash, request):  # type: ignore[no-untyped-def]
        if payload is not None:
            run.approved_payloads.append({
                "request_id": current_id[0],
                "report_text": payload.report_text,
                "dicom_fields": dict(payload.dicom_fields),
                "function": payload.function,
                "policy_version": payload.policy_version,
                "approved_payload_hash": str(payload.payload_hash),
                "recomputed_payload_hash": payload_hash_of(payload),
                # The hash the API reports, against the hash recomputed here
                # from the object's own content. If these ever differ the hash
                # is a claim rather than a fact, and every comparison made
                # downstream of it is a comparison over nothing.
                "claimed_hash_matches_content":
                    str(payload.payload_hash) == payload_hash_of(payload),
            })
        return original(payload, approved_hash, request)

    gateway.verify_approved_payload = tap  # type: ignore[method-assign]
    execution_url = f"/v1/functions/{function}/executions"
    headers = {"X-Scope": f"scope:study:{scope_study},scope:function:{function}"}
    try:
        with TestClient(app) as client:
            for driven in requests:
                current_id[0] = driven.request_id
                response = client.post(
                    execution_url, json=driven.body,
                    headers={**headers, "X-Request-Id": driven.request_id},
                )
                run.responses.append({
                    "request_id": driven.request_id,
                    "status": response.status_code,
                    "body": response.json(),
                })
            for driven in requests:
                response = client.get(
                    f"/v1/audit/records/{driven.request_id}", headers=headers,
                )
                run.audit_records.append({
                    "request_id": driven.request_id,
                    "status": response.status_code,
                    "body": response.json() if response.status_code == 200 else None,
                })
    finally:
        gateway.verify_approved_payload = original  # type: ignore[method-assign]
        try:
            app.state.pipeline.close()
        except Exception:  # noqa: BLE001 - teardown must not mask a real failure
            pass
    return run


# =============================================================================
# Reading the evidence
# =============================================================================


def observer_records(record_dir: Path) -> "list[bytes]":
    """Every record the observer wrote, in the order its index lists them.

    A record whose bytes do not match its own index entry is dropped rather than
    returned, which is the same refusal `check_agreement` applies. Two callers
    disagreeing about which records exist would be a worse bug than either of
    them being wrong alone.
    """
    from infra.capture import agreement

    bodies: list[bytes] = []
    for entry in agreement.observer_index(record_dir):
        body = agreement.record_bytes(record_dir, entry)
        if body is not None:
            bodies.append(body)
    return bodies


def captured_request_bodies(pcap_text: str) -> "list[bytes]":
    """Every HTTP request body the capture reassembled off the wire."""
    from infra.capture.agreement import request_bodies

    return request_bodies(pcap_text)


def write_block_receipt(record_dir: Path, receipt: dict) -> Path:
    """Put the API's own 422 body where the agreement check looks for it.

    Not a stand-in: `receipt` is the block receipt this run's HTTP response
    carried, byte for byte, and the check reads it back. It is written into the
    observer's record directory because the check's silence clause needs a third
    statement about the request id and the record directory is where the check
    looks — see `check_agreement`'s clause (b).
    """
    path = record_dir / "block_receipt.json"
    path.write_text(json.dumps(receipt), encoding="utf-8")
    return path


def read_back(evidence_dir: Path) -> "tuple[Path, str, str]":
    """`(record_dir, pcap_text, capture_readback)` for a beat that already ran."""
    capture_dir = evidence_dir / "capture"
    pcap_text_path = capture_dir / "out.pcap.txt"
    return (
        evidence_dir / "records",
        pcap_text_path.read_text(encoding="utf-8") if pcap_text_path.exists() else "",
        (capture_dir / "tcpdump.log").read_text(encoding="utf-8")
        if (capture_dir / "tcpdump.log").exists() else "",
    )


def render_text(title: str, body: "str | dict") -> str:
    if isinstance(body, str):
        return f"{title}\n{body}"
    return f"{title}\n{json.dumps(body, indent=2, ensure_ascii=False, sort_keys=False)}"
