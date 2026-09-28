"""Component I, end to end: the real containers, the real capture, the real check.

**Everything here is live.** The observer runs as a container on a real Docker
bridge, the Medarx process runs on the host and sends to it through the real
gateway, and the capture runs in the host network namespace against the bridge
interface `start_capture.sh` discovered at run time. Nothing is mocked and
nothing is stubbed; the only synthetic part is the data, which is the synthetic
PHI corpus throughout the project.

Marked `e2e` and skipped when Docker is not usable, because a check that can
only run on the machine that built it is not a check. When it does run it is the
only test in the suite that produces its own evidence, and the evidence is what
it then argues about.

**One run, five tests.** The fixture is module-scoped on purpose: the last three
tests are about the *same* captured traffic and the *same* observer record, and
a fresh run per test would make "the same run" a phrase rather than a fact. The
tests that mutate the record directory put it back.

**It asserts the property that matters, in both directions**, on artifacts this
run produced:

- the approved request — both observers saw the same bytes and the check agrees;
- the blocked request — the observer recorded nothing for it, the capture saw
  no `POST` for it, the API's own 422 receipt says why, and the check agrees;
- the same evidence with the record deleted, and again with the record rewritten
  and its index entry re-hashed over the rewrite — the check **disagrees** both
  times. A check that only ever returns agreement is not evidence, and this run
  demonstrates the difference rather than asserting it.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

from infra.capture.agreement import check_agreement

from conftest import EXEC_URL, KEY, SCOPE_HEADERS, body_with_dicom

REPO_ROOT = Path(__file__).resolve().parents[2]
CAPTURE_SCRIPT = REPO_ROOT / "infra" / "capture" / "start_capture.sh"
NETWORK = "medarx-e2e"
OBSERVER_IMAGE = "medarx-observer:e2e"
CAPTURE_IMAGE = "medarx-capture:e2e"

#: The observer's fixed reply, spelled here so a change to its default is a
#: failure rather than a silent agreement between a constant and its source.
OBSERVER_REPLY = "Findings: 7mm nodule."

APPROVED_REQUEST_ID = "req-e2e-approved-0001"
BLOCKED_REQUEST_ID = "req-e2e-blocked-0002"

#: A frame addressed to the observer's port, from the capture readback. The
#: proof that the sniffer was on the right interface and watching: it is what
#: distinguishes "the capture saw the request" from "the capture was somewhere
#: else entirely", and a blocked-path run that could not show this would be
#: asserting silence from a broken tool.
TO_OBSERVER = re.compile(r"\bIP \d+(?:\.\d+){3}\.\d+ > \d+(?:\.\d+){3}\.8080: ")


def _docker(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, check=check, timeout=600
    )


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    return _docker("info", check=False).returncode == 0


pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(not _docker_available(), reason="docker is not usable here"),
]


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _wait_for_health(url: str, timeout: float = 90.0) -> dict:
    deadline = time.monotonic() + timeout
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            response = httpx.get(url, timeout=3.0)
            if response.status_code == 200:
                return response.json()
        except httpx.HTTPError as exc:
            last = exc
        time.sleep(0.2)
    raise AssertionError(f"the observer never became healthy at {url}: {last}")


def _drive(base_url: str, database: Path) -> dict:
    """The real composition root, pointed at the containerised observer.

    Run in a child process so the observer's base URL and the SQLite file are
    this test module's own, and so the session's `sys.path` and fixtures cannot
    leak into a request that is supposed to be an ordinary deployment.

    Exactly two requests, in this order. The counts in the assertions are exact
    counts, and a probe would put a second of each in the way without proving
    anything the driven requests do not.
    """
    script = f"""
import json, sys
from fastapi.testclient import TestClient
sys.path.insert(0, {str(REPO_ROOT / 'backend' / 'src')!r})
sys.path.insert(0, {str(REPO_ROOT / 'backend' / 'tests')!r})
from medarx.api.app import create_app
from medarx.config import Settings
from conftest import EXEC_URL, SCOPE_HEADERS, body_with_dicom

settings = Settings(audit_key={KEY!r}, date_order="MDY", gateway_base_url={base_url!r})
app = create_app(settings, "sqlite:///" + {str(database)!r})
client = TestClient(app)
approved = client.post(EXEC_URL, json=body_with_dicom(StudyDate="20260114"),
                       headers={{**SCOPE_HEADERS, "X-Request-Id": {APPROVED_REQUEST_ID!r}}})
blocked = client.post(EXEC_URL, json=body_with_dicom(StudyDate="20260230"),
                      headers={{**SCOPE_HEADERS, "X-Request-Id": {BLOCKED_REQUEST_ID!r}}})
print(json.dumps({{"approved": {{"status": approved.status_code,
                                 "body": approved.json()}},
                  "blocked": {{"status": blocked.status_code,
                               "body": blocked.json()}}}}))
"""
    completed = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=900
    )
    if completed.returncode != 0:
        raise AssertionError(f"the driver failed:\n{completed.stderr[-4000:]}")
    return json.loads(completed.stdout.strip().splitlines()[-1])


@pytest.fixture(scope="module")
def live_run(tmp_path_factory):
    """One observer container, one capture, two driven requests, and the lot."""
    tmp_path = tmp_path_factory.mktemp("egress-e2e")
    _docker("network", "create", NETWORK, check=False)
    _docker("build", "-t", OBSERVER_IMAGE, str(REPO_ROOT / "infra" / "observers"))
    _docker("build", "-t", CAPTURE_IMAGE, str(REPO_ROOT / "infra" / "capture"))
    volume = f"{NETWORK}-records"
    container = f"{NETWORK}-observer"
    _docker("volume", "rm", "-f", volume, check=False)

    port = _free_port()
    records = tmp_path / "records"
    records.mkdir()
    capture = tmp_path / "capture"
    capture.mkdir()

    try:
        _docker("volume", "create", volume)
        _docker("run", "-d", "--name", container, "--network", NETWORK,
                "-p", f"127.0.0.1:{port}:8080", "-v", f"{volume}:/records",
                OBSERVER_IMAGE)
        health_before = _wait_for_health(f"http://127.0.0.1:{port}/healthz")
        assert health_before["record_count"] == 0, "a fresh observer holds nothing"

        subprocess.run(
            [str(CAPTURE_SCRIPT), "start", NETWORK, "0", str(capture)],
            check=True, capture_output=True, text=True, timeout=180,
        )
        driven = _drive(f"http://127.0.0.1:{port}/v1", tmp_path / "kernel.db")
        stopped = subprocess.run(
            [str(CAPTURE_SCRIPT), "stop", str(capture)],
            capture_output=True, text=True, timeout=300,
        )
        health_after = _wait_for_health(f"http://127.0.0.1:{port}/healthz")
        # `docker cp` out of the named volume: the container runs as an
        # unprivileged uid that cannot write a host directory this user owns.
        # Measured, not assumed — a bind mount raised PermissionError on the
        # first request and the observer answered nothing at all.
        _docker("cp", f"{container}:/records/.", str(records))
        return {
            "records": records,
            "index_text": (records / "index.jsonl").read_text(encoding="utf-8"),
            "pcap_text": (capture / "out.pcap.txt").read_text(encoding="utf-8"),
            "capture_readback": stopped.stdout + stopped.stderr,
            "driven": driven,
            "health_before": health_before,
            "health_after": health_after,
        }
    finally:
        _docker("rm", "-f", container, check=False)
        _docker("volume", "rm", "-f", volume, check=False)
        _docker("network", "rm", NETWORK, check=False)


def _only_record(live_run: dict) -> Path:
    """The single `.bin` the observer wrote: the approved request's, and only it."""
    found = list(live_run["records"].glob("*.bin"))
    assert len(found) == 1, f"expected one record, found {[p.name for p in found]}"
    return found[0]


def _approved_content(live_run: dict) -> str:
    """The approved payload's report text, read out of the wire body itself.

    Taken from the bytes the observer recorded rather than from a constant in
    this file, so the needle the check is given comes from the run.
    """
    return json.loads(_only_record(live_run).read_bytes())["messages"][1]["content"]


def _approved_hash(live_run: dict) -> str:
    return live_run["driven"]["approved"]["body"]["approved_payload_hash"]


def test_the_observer_is_the_provider_and_no_model_is_contacted(live_run: dict):
    """The draft the API returned is the observer's fixed constant.

    What this proves: the reply that came back through the real gateway is a
    string the observer computed for itself, with no model in the path. What it
    does not prove — and nothing in a test can — is that no code path anywhere
    could reach a model; that the image contains no model client is a fact
    about the Dockerfile rather than about a run.
    """
    draft = live_run["driven"]["approved"]["body"]["draft"]
    assert draft["content"] == OBSERVER_REPLY
    assert draft["model_id"] == "medarx-demo-model"
    assert draft["finish_reason"] == "stop"


def test_the_capture_was_on_the_right_interface_and_was_watching(live_run: dict):
    """Before anything is concluded from the capture, establish that it saw.

    Two independent facts: the readback is not empty, and it contains frames
    addressed to the observer's port. Without this, every zero in the tests
    below would be a zero produced by a sniffer pointed at the wrong
    interface — which is the failure mode this project has already paid for
    once, where a third container on the bridge captured 21 packets of mDNS and
    none of the traffic.
    """
    assert "frames," in live_run["capture_readback"], live_run["capture_readback"]
    assert len(TO_OBSERVER.findall(live_run["pcap_text"])) > 1, (
        "the capture must contain frames in both directions to the observer"
    )
    assert live_run["pcap_text"].count("POST /v1/chat/completions") == 1


def test_the_two_observers_agree_on_an_approved_request(live_run: dict):
    """Both observers saw the same bytes, and they were the approved ones."""
    assert live_run["driven"]["approved"]["status"] == 200
    assert live_run["health_after"]["record_count"] == 1

    report = check_agreement(
        _approved_hash(live_run),
        _approved_content(live_run),
        live_run["records"],
        live_run["pcap_text"],
        APPROVED_REQUEST_ID,
        observer_live=True,
    )
    assert report.agree is True, report.as_dict()
    assert report.observer_record_count == 1
    assert report.pcap_hit_count == 1
    assert report.pcap_frame_count > 0
    assert report.differences == [], (
        "a passing run must have no byte-level differences between the observers"
    )


def test_a_422_reached_neither_observer(live_run: dict):
    """The blocked path, proven against artifacts this run produced.

    The observer reported itself live before and after, so "no record for this
    request" is a statement about the request and not about the observer being
    unreachable. And the check is given the **delta**: one record and one
    captured body belonged to the approved request, and without that the
    approved request's bytes would answer a question about the blocked one.
    """
    driven = live_run["driven"]
    assert driven["blocked"]["status"] == 422
    receipt = driven["blocked"]["body"]
    assert receipt["status"] == "blocked"
    assert receipt["request_id"] == BLOCKED_REQUEST_ID
    assert live_run["health_after"]["status"] == "ok"
    assert live_run["health_after"]["record_count"] == 1, (
        "one record only: the approved request was recorded, the blocked one was not"
    )
    assert live_run["pcap_text"].count("POST /v1/chat/completions") == 1, (
        "exactly one request body crossed the bridge, and it was the approved one"
    )

    # The receipt the API actually returned, written where the check looks for
    # it. Not a hand-written stand-in: it is this run's own 422 body.
    receipt_path = live_run["records"] / "block_receipt.json"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    try:
        report = check_agreement(
            _approved_hash(live_run),
            _approved_content(live_run),
            live_run["records"],
            live_run["pcap_text"],
            BLOCKED_REQUEST_ID,
            observer_live=True,
            records_before=1,
            bodies_before=1,
        )
        assert report.agree is True, report.as_dict()
        assert report.observer_record_count == 0, (
            "the blocked request added no record; the one that exists belongs to "
            "the approved request, and the delta is what stops it answering this one"
        )
        assert report.pcap_hit_count == 0
        assert any("block receipt" in d for d in report.details), report.details
    finally:
        receipt_path.unlink(missing_ok=True)


def test_deleting_the_observers_record_makes_the_same_run_disagree(live_run: dict):
    """The check must be capable of failing on this run's own evidence.

    The record is removed and the check is asked about the approved request
    again. The capture has not changed and the approved content has not
    changed; what changed is that one observer no longer holds anything, and
    that asymmetry is a failure. An evidence mechanism that survives the loss of
    half its evidence by still saying "agree" is decorative.
    """
    records = live_run["records"]
    removed = _only_record(live_run)
    payload = removed.read_bytes()
    index_text = live_run["index_text"]
    removed.unlink()
    (records / "index.jsonl").unlink(missing_ok=True)
    try:
        report = check_agreement(
            _approved_hash(live_run),
            json.loads(payload)["messages"][1]["content"],
            records,
            live_run["pcap_text"],
            APPROVED_REQUEST_ID,
            observer_live=True,
        )
        assert report.agree is False, report.as_dict()
        assert report.observer_record_count == 0
        assert report.pcap_hit_count == 1
    finally:
        removed.write_bytes(payload)
        (records / "index.jsonl").write_text(index_text, encoding="utf-8")


def test_a_substituted_payload_is_refused_even_when_both_observers_see_it(live_run: dict):
    """The leak, on this run's own bytes.

    The record is rewritten with a different report text and its index entry is
    re-hashed over the rewritten bytes, so the observer stays internally
    consistent and is not merely broken. The capture still carries the approved
    body. The check refuses, and says that what does not match is the approved
    payload rather than the two observers.
    """
    records = live_run["records"]
    record = _only_record(live_run)
    original = record.read_bytes()
    # Length-preserving on purpose. A substitution that changed the length
    # would be caught by a size comparison, and the point is the one a size
    # check cannot see: the same number of bytes, carrying something else.
    substituted = original.replace(b"7 mm", b"9 mm")
    assert substituted != original, "the fixture must actually contain the report text"
    assert len(substituted) == len(original)
    index = json.loads(live_run["index_text"].strip())
    try:
        record.write_bytes(substituted)
        index["sha256"] = hashlib.sha256(substituted).hexdigest()
        index["byte_length"] = len(substituted)
        (records / "index.jsonl").write_text(json.dumps(index) + "\n", encoding="utf-8")

        report = check_agreement(
            _approved_hash(live_run),
            json.loads(original)["messages"][1]["content"],
            records,
            live_run["pcap_text"],
            APPROVED_REQUEST_ID,
            observer_live=True,
        )
        assert report.agree is False, report.as_dict()
        assert report.observer_record_count == 1, "the observer did record something"
        assert report.pcap_hit_count == 1, "and the capture did too"
        assert any("approved" in d for d in report.details), report.details
    finally:
        record.write_bytes(original)
        index["sha256"] = hashlib.sha256(original).hexdigest()
        index["byte_length"] = len(original)
        (records / "index.jsonl").write_text(json.dumps(index) + "\n", encoding="utf-8")
