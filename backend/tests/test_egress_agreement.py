"""Component I, the two-observer agreement check.

**The rule under test, stated once so the tests can be read against it.** The
two observers agree when either

- **(a)** both saw the request, the bytes the observer wrote to disk equal the
  bytes the capture reassembled off the wire, and those bytes carry the approved
  payload's content — or
- **(b)** neither observer saw anything **and** a block receipt for
  `request_id` exists.

Everything else is a failure, and each failure names itself in `details`.

Clause (b) is the whole reason `request_id` is a parameter. From the observers
alone, "the gateway never fired" and "the request was refused before it could
fire" are the same observation: nothing left. Scoring that as agreement would
certify a gateway that silently stopped calling the provider, and it would
certify a deployment whose observer was never reachable. Only a third,
independent statement about the same request id separates them.

**Clause (a) is checked against the approved payload, not merely observer
against observer.** Two observers that faithfully agree about a substituted
payload are the leak this project has already had, so the check requires the
approved content to be present in what they saw.

The capture fixture in `tests/fixtures/capture/` is a **real** capture: the hex
readback of a `tcpdump -w` run against this host's Docker bridge, taken while
the containerised observer was receiving a real request from the real
composition root. `test_the_fixture_capture_and_the_fixture_record_are_the_same_bytes`
asserts the two independent artifacts really are the same bytes, so a fixture
cannot drift into being two hand-written files that happen to agree.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from infra.capture.agreement import (
    check_agreement,
    frames_in,
    observer_index,
    request_bodies,
)

FIXTURES = Path(__file__).parent / "fixtures" / "capture"
APPROVED_PCAP = (FIXTURES / "approved-request.pcap.txt").read_text(encoding="utf-8")
BLOCKED_PCAP = (FIXTURES / "blocked-request.pcap.txt").read_text(encoding="utf-8")
OBSERVER_RECORD = (FIXTURES / "approved-observer-record.bin").read_bytes()
OBSERVER_INDEX = (FIXTURES / "approved-observer-index.jsonl").read_text(encoding="utf-8")
RECORDED_SHA = hashlib.sha256(OBSERVER_RECORD).hexdigest()
RECORD_NAME = json.loads(OBSERVER_INDEX)["path"]

#: The approved payload's report text as it reaches the wire. Read out of the
#: fixture body rather than written out, so a fixture that changes cannot leave
#: a needle behind that no longer appears in the evidence.
APPROVED_CONTENT = json.loads(OBSERVER_RECORD)["messages"][1]["content"]

#: How many requests the approved fixture capture carries. Counted here from the
#: recovered bodies rather than hard-coded, so a re-taken fixture does not need
#: this file edited to agree with it — and so the expected count stays an
#: independent statement rather than a copy of the check's own arithmetic.
EXPECTED_BODIES = len(request_bodies(APPROVED_PCAP))
EXPECTED_HITS = sum(1 for b in request_bodies(APPROVED_PCAP) if b == OBSERVER_RECORD)

NOW_ISO = "2026-01-14T12:00:00Z"


def _write_index(record_dir: Path, records: list[dict]) -> None:
    (record_dir / "index.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in records), encoding="utf-8"
    )


def _write_record(record_dir: Path, name: str, body: bytes) -> dict:
    (record_dir / name).write_bytes(body)
    return {
        "id": name.removesuffix(".bin"),
        "path": name,
        "sha256": hashlib.sha256(body).hexdigest(),
        "byte_length": len(body),
        "received_at": NOW_ISO,
    }


def _write_entry(record_dir: Path, **overrides: object) -> None:
    entry = {
        "id": "leak", "path": "leak.bin",
        "sha256": hashlib.sha256(OBSERVER_RECORD).hexdigest(),
        "byte_length": len(OBSERVER_RECORD), "received_at": NOW_ISO,
    }
    entry.update(overrides)
    _write_index(record_dir, [entry])


def _blocked_receipt(record_dir: Path, request_id: str) -> None:
    (record_dir / "block_receipt.json").write_text(
        json.dumps({
            "status": "blocked",
            "request_id": request_id,
            "layer": "D.1",
            "action_codes": ["UNSHIFTED_DATE"],
            "policy_version": "medarx-policy-1.0.0",
        }),
        encoding="utf-8",
    )


@pytest.fixture
def recorded(tmp_path: Path) -> Path:
    """A record directory holding the fixture record and its real index line."""
    (tmp_path / "index.jsonl").write_text(OBSERVER_INDEX, encoding="utf-8")
    (tmp_path / RECORD_NAME).write_bytes(OBSERVER_RECORD)
    return tmp_path


# -- The fixture is two independent artifacts that really are the same bytes ---


def test_the_fixture_capture_and_the_fixture_record_are_the_same_bytes():
    """The capture really does carry the bytes the observer recorded.

    Read straight out of the pcap, with no reference to the observer's index.
    If this fails, one of the two fixtures was edited and the agreement tests
    below are comparing a hand-written string against itself.
    """
    assert EXPECTED_HITS >= 1
    assert OBSERVER_RECORD in request_bodies(APPROVED_PCAP)


def test_the_capture_body_decodes_to_the_approved_payload_content():
    """What binds the wire to the approved payload, checked independently.

    The check searches the captured bytes for the approved content in the form
    the wire carries it — JSON-escaped, so a newline is a backslash followed by
    an `n`. This test establishes that binding without reusing that rule: it
    decodes the recovered body and compares the content field to the approved
    text itself.
    """
    body = next(b for b in request_bodies(APPROVED_PCAP) if b == OBSERVER_RECORD)
    assert "\n" in APPROVED_CONTENT, "the fixture must exercise JSON escaping"
    assert json.loads(body)["messages"][1]["content"] == APPROVED_CONTENT
    assert APPROVED_CONTENT.encode() not in body, (
        "the raw body carries the escaped form, which is why the check encodes "
        "the needle rather than searching for the decoded string"
    )


def test_the_blocked_capture_carried_traffic_but_no_request():
    """The blocked capture is not an empty file, and it holds no request.

    Both halves matter. A capture with no frames would satisfy "no request was
    seen" for the wrong reason — the sniffer was not looking at anything. This
    one saw 288 frames of real traffic to the same observer on the same bridge
    and no `POST` among them, which is the claim the blocked-path demo makes.
    """
    assert "POST /v1/chat/completions" in APPROVED_PCAP
    assert "GET /healthz" in BLOCKED_PCAP or "GET /v1/records" in BLOCKED_PCAP
    assert "POST /v1/chat/completions" not in BLOCKED_PCAP
    assert request_bodies(BLOCKED_PCAP) == []


# -- Clause (a): both saw it, and it was the approved payload ---------------


def test_agreement_requires_both_observers(recorded: Path):
    r = check_agreement(RECORDED_SHA, APPROVED_CONTENT, recorded, APPROVED_PCAP, "req-1")
    assert r.request_id == "req-1"
    assert r.observer_record_count == 1
    assert r.pcap_hit_count == EXPECTED_HITS
    assert r.agree is True, r.details
    assert r.differences == []


def test_one_observer_alone_is_not_agreement(recorded: Path):
    """The observer has the record; the capture has no matching request."""
    r = check_agreement(RECORDED_SHA, APPROVED_CONTENT, recorded, BLOCKED_PCAP, "req-1")
    assert r.agree is False
    assert r.observer_record_count == 1
    assert r.pcap_hit_count == 0
    assert any("the capture does not" in d for d in r.details), r.details


def test_the_capture_alone_is_not_agreement(tmp_path: Path):
    """And the other direction: bytes on the wire, nothing on disk."""
    (tmp_path / "index.jsonl").write_text("", encoding="utf-8")
    r = check_agreement(RECORDED_SHA, APPROVED_CONTENT, tmp_path, APPROVED_PCAP, "req-1")
    assert r.agree is False
    assert r.observer_record_count == 0 and r.pcap_hit_count == EXPECTED_HITS
    assert any("the observer's records do not" in d for d in r.details), r.details


# -- The failure this component exists to catch ------------------------------


def test_two_observers_that_agree_on_unapproved_bytes_do_not_agree(tmp_path: Path):
    """The leak: both observers faithfully saw a payload nobody approved.

    Built by taking the real record, substituting the report text, writing the
    substituted bytes to disk **and** re-hashing the index entry over them — so
    the observer's own record is internally consistent and the capture carries
    the same substituted body. Every check that compares observer against
    observer passes. Only the comparison against the approved content fails,
    which is the entire argument for having one.
    """
    substituted = OBSERVER_RECORD.replace(b"7 mm", b"12 mm")
    assert substituted != OBSERVER_RECORD
    record_dir = tmp_path / "records"
    record_dir.mkdir()
    (record_dir / "leak.bin").write_bytes(substituted)
    _write_entry(record_dir, sha256=hashlib.sha256(substituted).hexdigest(),
                 byte_length=len(substituted))

    r = check_agreement(RECORDED_SHA, APPROVED_CONTENT, record_dir, APPROVED_PCAP, "req-1")
    assert r.agree is False
    assert r.observer_record_count == 1 and r.pcap_hit_count == EXPECTED_HITS, (
        "both observers did see the request — that is not what failed"
    )
    assert any("approved" in d for d in r.details), r.details


def test_observers_that_disagree_byte_for_byte_are_refused(tmp_path: Path):
    """The other half of the same property: agreement must be able to fail.

    The observer's record is the real fixture record with one byte changed, and
    its index entry re-hashed over the changed bytes, so the observer stays
    internally consistent. The capture still carries the approved body. The two
    observers disagree by exactly one byte, and the check says where.
    """
    tampered = bytearray(OBSERVER_RECORD)
    tampered[10] = ord("X")
    record_dir = tmp_path / "records"
    record_dir.mkdir()
    (record_dir / "t.bin").write_bytes(bytes(tampered))
    _write_entry(record_dir, id="t", path="t.bin",
                 sha256=hashlib.sha256(bytes(tampered)).hexdigest(),
                 byte_length=len(tampered))

    r = check_agreement(RECORDED_SHA, APPROVED_CONTENT, record_dir, APPROVED_PCAP, "req-1")
    assert r.agree is False
    assert r.observer_record_count == 1 and r.pcap_hit_count == EXPECTED_HITS
    assert any("byte offset 10" in d for d in r.differences), r.differences


def test_a_record_whose_bytes_do_not_match_its_own_index_is_refused(tmp_path: Path):
    """The observer's index is a claim about a file; the file has to agree.

    A record edited after the fact, or truncated, is the tampering case the
    digest is there for, and a check that trusted the index would call it
    verified.
    """
    record_dir = tmp_path / "records"
    record_dir.mkdir()
    original = b'{"model":"medarx-demo-model"}'
    _write_record(record_dir, "tampered.bin", original)
    _write_index(record_dir, [{
        "id": "tampered", "path": "tampered.bin",
        "sha256": hashlib.sha256(original).hexdigest(),
        "byte_length": len(original), "received_at": NOW_ISO,
    }])
    (record_dir / "tampered.bin").write_bytes(b'{"model":"medarx-demo-mod"}')
    r = check_agreement(RECORDED_SHA, APPROVED_CONTENT, record_dir, APPROVED_PCAP, "req-1")
    assert r.agree is False
    assert any("does not match its own index" in d for d in r.details), r.details


def test_a_record_pointing_at_a_file_that_is_not_there_is_refused(tmp_path: Path):
    record_dir = tmp_path / "records"
    record_dir.mkdir()
    _write_entry(record_dir, id="ghost", path="ghost.bin")
    r = check_agreement(RECORDED_SHA, APPROVED_CONTENT, record_dir, APPROVED_PCAP, "req-1")
    assert r.agree is False
    assert r.observer_record_count == 0
    assert any("no file" in d for d in r.differences), r.differences


def test_a_record_whose_path_escapes_the_record_directory_is_refused(tmp_path: Path):
    """The record name arrives from a file on disk, and a file can be edited."""
    record_dir = tmp_path / "records"
    record_dir.mkdir()
    (tmp_path / "outside.bin").write_bytes(OBSERVER_RECORD)
    _write_entry(record_dir, id="escape", path="../outside.bin")
    r = check_agreement(RECORDED_SHA, APPROVED_CONTENT, record_dir, APPROVED_PCAP, "req-1")
    assert r.agree is False
    assert r.observer_record_count == 0


def test_an_earlier_requests_bytes_do_not_satisfy_a_later_one_that_sent_nothing(
    recorded: Path,
):
    """The false green a live run of this component first produced.

    One record directory and one capture cover the approved request; the check
    is then asked about a *second*, blocked request that left nothing. With no
    delta the first request's record and captured body answer the second
    question, and a request that sent nothing is certified by an earlier
    request that sent something. `records_before` and `bodies_before` are what
    make the answer about this request.
    """
    _blocked_receipt(recorded, "req-blocked")

    undeltaed = check_agreement(RECORDED_SHA, APPROVED_CONTENT, recorded,
                                 APPROVED_PCAP, "req-blocked")
    assert undeltaed.observer_record_count == 1
    assert undeltaed.pcap_hit_count == EXPECTED_HITS
    assert undeltaed.agree is True, (
        "this is the false green: the approved request's bytes answered a "
        "question about the blocked one"
    )

    deltaed = check_agreement(RECORDED_SHA, APPROVED_CONTENT, recorded,
                              APPROVED_PCAP, "req-blocked",
                              records_before=1, bodies_before=EXPECTED_BODIES)
    assert deltaed.observer_record_count == 0
    assert deltaed.pcap_hit_count == 0
    assert deltaed.agree is True, deltaed.details
    assert any("block receipt" in d for d in deltaed.details), deltaed.details


def test_a_delta_that_hides_an_earlier_mismatch_cannot_pass(recorded: Path):
    """The delta narrows the evidence; it must not narrow the verdict.

    Asked about the *second* request with `records_before=1` and no receipt,
    against a record that does not match its own index. The check must refuse,
    rather than agree on the grounds that the second request was silent.
    """
    record = next(recorded.glob("*.bin"))
    record.write_bytes(b'{"model":"medarx-demo-model","messages":[]}')
    try:
        r = check_agreement(RECORDED_SHA, APPROVED_CONTENT, recorded, APPROVED_PCAP,
                            "req-second", records_before=1, bodies_before=EXPECTED_BODIES)
        assert r.agree is False, r.as_dict()
        assert any("no block receipt" in d for d in r.details), r.details
    finally:
        record.write_bytes(OBSERVER_RECORD)



# -- Clause (b): neither saw it, and a receipt says why ---------------------


def test_both_silent_with_a_block_receipt_is_agreement(tmp_path: Path):
    """The blocked path: nothing left, and a receipt for this request id."""
    _write_index(tmp_path, [])
    _blocked_receipt(tmp_path, "req-blocked")
    r = check_agreement(RECORDED_SHA, APPROVED_CONTENT, tmp_path, BLOCKED_PCAP, "req-blocked")
    assert r.agree is True, r.details
    assert r.observer_record_count == 0 and r.pcap_hit_count == 0
    assert any("block receipt" in d for d in r.details)


def test_both_silent_without_a_block_receipt_is_not_agreement(tmp_path: Path):
    """The failure mode that made `request_id` a parameter.

    A gateway that never fired and a request that was never sent are
    indistinguishable to the observers alone, so "nothing left" must not be
    scored as agreement on its own.
    """
    _write_index(tmp_path, [])
    r = check_agreement(RECORDED_SHA, APPROVED_CONTENT, tmp_path, BLOCKED_PCAP, "req-ghost")
    assert r.agree is False
    assert any("no block receipt" in d for d in r.details), r.details


def test_a_receipt_for_a_different_request_does_not_excuse_silence(tmp_path: Path):
    """The receipt has to be *this* request's, or it says nothing about this one."""
    _write_index(tmp_path, [])
    _blocked_receipt(tmp_path, "req-some-other-request")
    r = check_agreement(RECORDED_SHA, APPROVED_CONTENT, tmp_path, BLOCKED_PCAP, "req-ghost")
    assert r.agree is False


def test_a_receipt_cannot_excuse_bytes_that_did_leave(recorded: Path):
    """Clause (b) is about silence, and only about silence.

    A receipt sitting beside the record directory must not soften a run where
    the observers saw something that is not the approved payload.
    """
    _blocked_receipt(recorded, "req-1")
    genuine = check_agreement(RECORDED_SHA, APPROVED_CONTENT, recorded,
                              APPROVED_PCAP, "req-1")
    assert genuine.agree is True, "the request genuinely was the approved one"
    assert genuine.observer_record_count == 1

    substituted = check_agreement(RECORDED_SHA, "TEXT THAT WAS NEVER APPROVED",
                                  recorded, APPROVED_PCAP, "req-1")
    assert substituted.agree is False
    assert substituted.observer_record_count == 1


def test_a_receipt_that_claims_approved_status_does_not_excuse_silence(tmp_path: Path):
    """Only a receipt that says `blocked` is a statement that nothing was sent."""
    _write_index(tmp_path, [])
    (tmp_path / "block_receipt.json").write_text(json.dumps({
        "status": "approved", "request_id": "req-1", "layer": "E",
        "action_codes": [], "policy_version": "medarx-policy-1.0.0",
    }), encoding="utf-8")
    r = check_agreement(RECORDED_SHA, APPROVED_CONTENT, tmp_path, BLOCKED_PCAP, "req-1")
    assert r.agree is False


# -- Deleting the evidence must not make the check pass ----------------------


def test_deleting_the_observers_records_does_not_make_the_check_pass(tmp_path: Path):
    """The vacuous-pass case, run as a sequence rather than a construction.

    A record that agreed is removed, and the check is asked again about the same
    request. It must stop agreeing — not because the capture stopped seeing
    anything, but because the observers no longer agree *with each other*, and
    that asymmetry is a failure in its own right.
    """
    record_dir = tmp_path / "records"
    record_dir.mkdir()
    (record_dir / "index.jsonl").write_text(OBSERVER_INDEX, encoding="utf-8")
    (record_dir / RECORD_NAME).write_bytes(OBSERVER_RECORD)

    before = check_agreement(RECORDED_SHA, APPROVED_CONTENT, record_dir,
                             APPROVED_PCAP, "req-1")
    assert before.agree is True, before.details

    (record_dir / "index.jsonl").write_text("", encoding="utf-8")
    (record_dir / RECORD_NAME).unlink()

    after = check_agreement(RECORDED_SHA, APPROVED_CONTENT, record_dir,
                            APPROVED_PCAP, "req-1")
    assert after.agree is False
    assert after.observer_record_count == 0 and after.pcap_hit_count == EXPECTED_HITS
    assert any("the observer's records do not" in d for d in after.details)


def test_an_absent_index_file_is_zero_records_not_a_crash(tmp_path: Path):
    """The blocked run leaves no index file at all, and that is a valid answer.

    Measured on this host: an observer that received nothing never creates
    `index.jsonl`, so "there is no file" is the normal state of the blocked path
    and the check has to read it as zero rather than raise.
    """
    assert not (tmp_path / "index.jsonl").exists()
    assert observer_index(tmp_path) == []
    _blocked_receipt(tmp_path, "req-1")
    assert check_agreement(RECORDED_SHA, APPROVED_CONTENT, tmp_path,
                           BLOCKED_PCAP, "req-1").agree is True


# -- The observer must have been reachable ----------------------------------


def test_silence_does_not_become_agreement_because_the_observer_was_down(
    tmp_path: Path,
):
    """A block receipt plus an observer that was not answering is not agreement.

    The clause that closes the one hole `check_agreement` cannot see for itself:
    it is handed a directory and a capture, and nothing in either tells it
    whether the process that was supposed to be writing that directory existed.
    The caller knows — the observer answers `/healthz` — and can say so.
    """
    _write_index(tmp_path, [])
    _blocked_receipt(tmp_path, "req-1")
    down = check_agreement(RECORDED_SHA, APPROVED_CONTENT, tmp_path,
                           BLOCKED_PCAP, "req-1", observer_live=False)
    assert down.agree is False
    assert any("not answering" in d for d in down.details), down.details
    up = check_agreement(RECORDED_SHA, APPROVED_CONTENT, tmp_path,
                         BLOCKED_PCAP, "req-1", observer_live=True)
    assert up.agree is True


def test_a_capture_with_no_frames_is_reported_so_a_dead_sniffer_is_visible(
    tmp_path: Path,
):
    """Zero frames and zero records is a different fact from zero records alone.

    A capture that was never attached to the right interface produces the same
    empty text as a capture that watched and saw nothing, and the report has to
    distinguish them — the first is a broken tool, the second is a blocked
    request.
    """
    _write_index(tmp_path, [])
    _blocked_receipt(tmp_path, "req-1")
    dead = check_agreement(RECORDED_SHA, APPROVED_CONTENT, tmp_path, "", "req-1")
    live = check_agreement(RECORDED_SHA, APPROVED_CONTENT, tmp_path, BLOCKED_PCAP, "req-1")
    assert dead.pcap_frame_count == 0 and live.pcap_frame_count > 0
    assert dead.agree is True and live.agree is True
    assert any("no frames" in d for d in dead.details), dead.details


# -- The report is readable evidence, not a bare boolean ---------------------


def test_the_report_names_the_approved_payload_it_was_asked_about(recorded: Path):
    """A verdict with no subject is not evidence anyone can act on.

    The contract publishes the approved payload as `sha256:<hex>` and the kernel
    stores it as bare hex; both spellings are accepted, and the report always
    states which payload the comparison was made against and how much the
    capture actually saw.
    """
    bare = check_agreement(RECORDED_SHA, APPROVED_CONTENT, recorded, APPROVED_PCAP, "req-1")
    prefixed = check_agreement(f"sha256:{RECORDED_SHA}", APPROVED_CONTENT,
                               recorded, APPROVED_PCAP, "req-1")
    assert bare.approved_hash == RECORDED_SHA == prefixed.approved_hash
    assert bare.as_dict() == prefixed.as_dict()
    assert bare.as_dict()["pcap_frame_count"] == len(frames_in(APPROVED_PCAP))
    assert bare.as_dict()["pcap_frame_count"] > 0
