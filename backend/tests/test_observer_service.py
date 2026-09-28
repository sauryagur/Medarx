"""Component I, the observer itself: real process, real socket, real disk.

**The observer is started, not stubbed.** Every test here launches
`infra/observers/observer.py` as a subprocess on an ephemeral loopback port
with its own record directory, and drives it with the real
`medarx.gateway.openai_gateway.ModelGateway` or with `httpx`. A stub of the
observer would be a test of the stub: the properties being checked — that the
bytes on disk are the bytes on the wire, that a body which is not JSON is still
recorded intact, that a refused request writes nothing — are all properties of
what actually crosses a socket, and a mock is exactly where they would be lost.

No container is needed and none is used: this exercises the same `observer.py`
the image runs. The container path, and the packet capture that can only see
traffic between a host and a container, are exercised separately in the `e2e`
tests.

**The blocked-path assertion is the load-bearing one.** A `422` must mean zero
bytes reached the observer — and zero *and* the observer still answering, since
an observer that is down also reports nothing and would make the assertion
vacuously true. Each blocked test therefore reads `/healthz` in the same run.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from medarx.api.app import create_app
from medarx.config import Settings
from medarx.gateway.openai_gateway import ModelGateway
from medarx.models import ModelRequest, StructuredPayload, payload_hash_of

from conftest import EXEC_URL, KEY, SCOPE_HEADERS, body_with_dicom

REPO_ROOT = Path(__file__).resolve().parents[2]
OBSERVER_SOURCE = REPO_ROOT / "infra" / "observers" / "observer.py"

#: The reply the observer is built to send. Spelled here rather than imported
#: from the observer, so that a change to the observer's default is a test
#: failure rather than a silent agreement between a constant and its source.
OBSERVER_REPLY = "Findings: 7mm nodule."

_LISTENING = re.compile(r"observer listening on \S+:(\d+)")


class ObserverProcess:
    """A running `observer.py`, and the base URL the gateway should be given."""

    def __init__(self, record_dir: Path) -> None:
        self.record_dir = record_dir
        self._process: subprocess.Popen | None = None
        self.base_url = ""

    def __enter__(self) -> "ObserverProcess":
        environment = {
            **os.environ,
            "OBSERVER_RECORD_DIR": str(self.record_dir),
            "OBSERVER_HOST": "127.0.0.1",
            "OBSERVER_PORT": "0",
        }
        self._process = subprocess.Popen(
            [sys.executable, str(OBSERVER_SOURCE)],
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.base_url = f"http://127.0.0.1:{self._await_port()}/v1"
        self._await_health()
        return self

    def _await_port(self) -> str:
        assert self._process is not None and self._process.stderr is not None
        deadline = time.monotonic() + 20.0
        while time.monotonic() < deadline:
            line = self._process.stderr.readline()
            if not line:
                break
            found = _LISTENING.search(line)
            if found:
                return found.group(1)
        self.__exit__(None, None, None)
        raise AssertionError("the observer never reported a listening port")

    def _await_health(self) -> None:
        deadline = time.monotonic() + 20.0
        while time.monotonic() < deadline:
            try:
                if httpx.get(f"{self.root}/healthz", timeout=2.0).status_code == 200:
                    return
            except httpx.HTTPError:
                time.sleep(0.05)
        raise AssertionError("the observer never became healthy")

    def __exit__(self, *exc: object) -> None:
        if self._process is not None:
            self._process.terminate()
            try:
                self._process.wait(timeout=10)
            except subprocess.TimeoutExpired:  # pragma: no cover - a stuck child
                self._process.kill()
                self._process.wait(timeout=10)

    # -- Reading the observer's own statements ------------------------------

    @property
    def root(self) -> str:
        return self.base_url.removesuffix("/v1")

    def health(self) -> dict:
        """What the observer says about itself, while it is up."""
        response = httpx.get(f"{self.root}/healthz", timeout=5.0)
        response.raise_for_status()
        return response.json()

    def index(self) -> list[dict]:
        response = httpx.get(f"{self.base_url}/records", timeout=5.0)
        response.raise_for_status()
        return response.json()["records"]

    def record(self, record_id: str) -> bytes:
        response = httpx.get(f"{self.base_url}/records/{record_id}", timeout=5.0)
        response.raise_for_status()
        return response.content


@pytest.fixture
def observer(tmp_path):
    """One observer per test, with its own empty record directory."""
    with ObserverProcess(tmp_path / "records") as running:
        yield running


def _observer_backed_client(observer: ObserverProcess, tmp_path: Path) -> TestClient:
    """The application, built by the one path the server builds it by.

    `create_app` again rather than the shared `app` fixture, because that
    fixture points the gateway at the loopback stub in `conftest`; the observer
    has to be the provider for these assertions to mean anything. The
    composition root is the same one — no component is built by hand.
    """
    settings = Settings(
        audit_key=KEY,
        date_order="MDY",
        gateway_base_url=observer.base_url,
    )
    app = create_app(settings, f"sqlite:///{tmp_path / 'observer-kernel.db'}")
    return TestClient(app)


#: 30 February: component C cannot shift a date that does not exist, so layer D.1
#: flags it and the request is refused before the gateway is reached.
UNSHIFTABLE_DATE_BODY = body_with_dicom(StudyDate="20260230")


def _approved_payload(report_text: str) -> StructuredPayload:
    payload = StructuredPayload(
        function="Draft",
        report_text=report_text,
        dicom_fields={"modality": "CT"},
        study_ref="medarx-study-0000abcd",
        policy_version="medarx-policy-1.0.0",
    )
    return payload.model_copy(update={"payload_hash": payload_hash_of(payload)})


def _send_through_the_gateway(observer: ObserverProcess, report_text: str):
    """The real path: verify, then send, through the real `ModelGateway`."""
    gateway = ModelGateway(Settings(audit_key=KEY, gateway_base_url=observer.base_url))
    payload = _approved_payload(report_text)
    token = gateway.verify_approved_payload(
        payload,
        str(payload.payload_hash),
        ModelRequest(
            model="medarx-demo-model",
            messages=[{"role": "user", "content": report_text}],
            temperature=0.0,
            max_tokens=512,
        ),
    )
    return gateway, gateway.send(token)


# -- The observer records the bytes, not a reading of them --------------------


def test_the_observer_records_the_exact_bytes_the_gateway_sent(observer):
    """The disk record is the transmitted body, byte for byte.

    Not "the same JSON" and not "the same report text": the equality is on the
    whole byte sequence, because a re-encoding that preserved the JSON would
    still be a different object of comparison, and the agreement check in
    `infra/capture` compares bytes.
    """
    gateway, response = _send_through_the_gateway(observer, "FINDINGS: 7mm nodule.")
    sent = gateway.last_request_body()
    assert sent is not None

    entries = observer.index()
    assert len(entries) == 1, "exactly one request was made, so one record exists"
    entry = entries[0]
    assert entry["byte_length"] == len(sent)
    assert entry["sha256"] == hashlib.sha256(sent).hexdigest()
    assert observer.record(entry["id"]) == sent
    assert response.content == OBSERVER_REPLY


def test_a_body_that_is_not_json_is_still_recorded_intact(observer):
    """The observer is an observer, not a parser.

    A body it cannot interpret must still be stored unchanged. An implementation
    that parsed, re-serialised and stored would produce a record that differs
    from the wire bytes for exactly the inputs most worth inspecting — and the
    difference would be invisible in every test that only ever sent JSON.
    """
    payload = b"\xff\xfe not json at all \x00\r\n\n  trailing spaces   "
    response = httpx.post(
        f"{observer.base_url}/chat/completions",
        content=payload,
        headers={"Content-Type": "application/json"},
        timeout=5.0,
    )
    assert response.status_code == 200, "the observer must not fail on evidence"
    entry = observer.index()[0]
    assert entry["byte_length"] == len(payload)
    assert observer.record(entry["id"]) == payload


def test_the_reply_names_the_record_it_wrote(observer):
    """The response id is the id of the file on disk.

    So an operator holding a draft knows which file is its evidence without a
    second lookup, and a reader of the wire can be handed the record by name.
    """
    gateway, response = _send_through_the_gateway(observer, "FINDINGS: 7mm nodule.")
    assert response.raw["id"] == f"chatcmpl-{observer.index()[0]['id']}"
    assert response.raw["object"] == "chat.completion"
    assert response.raw["choices"][0]["finish_reason"] == "stop"
    assert response.raw["model"] == "medarx-demo-model"
    assert gateway.last_request_body() is not None


# -- "I received nothing" is as loud as "here is what I received" -------------


def test_an_id_the_observer_never_issued_is_a_positive_answer_not_a_crash(observer):
    before = observer.index()
    response = httpx.get(f"{observer.base_url}/records/deadbeefdeadbeef", timeout=5.0)
    assert response.status_code == 404
    body = response.json()
    assert body["id"] == "deadbeefdeadbeef"
    assert body["record_count"] == len(before) == 0
    assert observer.index() == before, "asking must not change what was received"


def test_the_observer_reports_itself_live_and_empty_before_anything_is_sent(observer):
    """Liveness and emptiness are two different statements, and both are made.

    The blocked-path assertions below are only meaningful because this holds: a
    check that reads "zero records" from an observer that is down would be
    asserting nothing at all.
    """
    health = observer.health()
    assert health["status"] == "ok" and health["record_count"] == 0
    assert observer.index() == []


# -- A 422 must mean nothing was sent ---------------------------------------


def test_a_422_writes_zero_bytes_at_the_observer(observer, tmp_path):
    """The blocked-path demo's entire content, in one assertion.

    Three claims, all needed: the request was refused (`422`), the observer
    recorded nothing, and the observer was up while it recorded nothing. Drop
    the third and this test passes for a broken observer, which is the shape of
    the false green this project has already been bitten by.
    """
    client = _observer_backed_client(observer, tmp_path)
    assert observer.health()["record_count"] == 0

    response = client.post(
        EXEC_URL, json=UNSHIFTABLE_DATE_BODY,
        headers={**SCOPE_HEADERS, "X-Request-Id": "req-blocked-observer-0001"},
    )
    assert response.status_code == 422
    assert response.json()["status"] == "blocked"

    assert observer.index() == [], "a refused request must leave no record at all"
    assert observer.health()["status"] == "ok", (
        "the observer must have been live; otherwise 'no record' proves nothing"
    )
    assert observer.health()["record_count"] == 0


def test_a_403_also_writes_zero_bytes_and_is_not_a_privacy_block(observer, tmp_path):
    """The other refusal, so 'nothing was sent' is not read as 'blocked'."""
    client = _observer_backed_client(observer, tmp_path)
    response = client.post(EXEC_URL, json=body_with_dicom(StudyDate="20260114"))
    assert response.status_code == 403
    assert observer.index() == []
    assert observer.health()["status"] == "ok"


def test_the_approved_request_against_the_same_observer_does_leave_a_record(
    observer, tmp_path
):
    """The control for the two tests above.

    Without it, "the observer recorded nothing" and "the observer was not
    actually reachable" are the same observation. Here the observer is proven to
    record, through the same gateway, the same client and the same application,
    in the same test module.
    """
    client = _observer_backed_client(observer, tmp_path)
    response = client.post(
        EXEC_URL, json=body_with_dicom(StudyDate="20260114"),
        headers={**SCOPE_HEADERS, "X-Request-Id": "req-approved-observer-0001"},
    )
    assert response.status_code == 200, response.text
    entries = observer.index()
    assert len(entries) == 1
    recorded = json.loads(observer.record(entries[0]["id"]))
    assert recorded["model"] == "medarx-demo-model"
    assert [message["role"] for message in recorded["messages"]] == ["system", "user"]


def test_nothing_planted_in_the_request_reaches_the_observers_disk(observer, tmp_path):
    """The synthetic MRN and accession are in the request and absent from disk.

    Read at the observer rather than at the gateway, because that is the point
    of an observer: the claim is about the bytes that left, not about a
    variable inside the process that sent them. The request is checked too — an
    assertion that the digits are absent from the record is only evidence if
    they were genuinely present in what the caller sent.
    """
    body = body_with_dicom(StudyDate="20260114")
    request_text = json.dumps(body)
    client = _observer_backed_client(observer, tmp_path)
    response = client.post(EXEC_URL, json=body, headers=SCOPE_HEADERS)
    assert response.status_code == 200, response.text
    raw = observer.record(observer.index()[0]["id"])
    for planted in ("4452819", "ACC0000417"):
        assert planted in request_text, "the identifier is genuinely in the request"
        assert planted.encode() not in raw, f"{planted!r} reached the wire"


# -- Concurrency: the index is an index, not a log of torn lines --------------


def test_concurrent_requests_produce_one_readable_record_each(observer):
    """Ten requests at once, ten records, every index line parseable.

    The index is JSON Lines, so a line torn by two concurrent appends is an
    index that cannot be read at all — and a check that silently skipped the
    line it could not parse would then be checking a record set smaller than
    the one that exists.
    """
    body = json.dumps({"model": "medarx-demo-model", "messages": []},
                      separators=(",", ":")).encode()
    errors: list[Exception] = []

    def send() -> None:
        try:
            httpx.post(
                f"{observer.base_url}/chat/completions",
                content=body,
                headers={"Content-Type": "application/json"},
                timeout=20.0,
            ).raise_for_status()
        except Exception as exc:  # noqa: BLE001 - reported below, not swallowed
            errors.append(exc)

    threads = [threading.Thread(target=send) for _ in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert not errors, f"concurrent sends failed: {errors}"
    entries = observer.index()
    assert len(entries) == 10
    assert all("error" not in entry for entry in entries), (
        "an unparseable index line must be visible, not skipped"
    )
    assert len({entry["id"] for entry in entries}) == 10
    for entry in entries:
        assert observer.record(entry["id"]) == body
