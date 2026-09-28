"""Beat 2, end to end: the blocked path, and a zero that means something.

**Everything below is live**, exactly as in `test_e2e_approved.py`: a real
observer container, a real `tcpdump` on that container's bridge in the host
network namespace, and the real composition root driving its own HTTP surface.

**Beat 2 is the load-bearing beat.** Beat 1 shows a payload crossing the
boundary; beat 2 shows the boundary refusing one that cannot be safely
transformed, with **zero bytes** reaching either observer. A block that is only
logged proves nothing, and a leak that passes every check is worse than no check
at all, so the property under test here is not "a 422 came back" — it is that
the two observers, which are not the system under test, both saw nothing.

**The zero is a measurement, and the four tests at the end are the proof.**

From the observers alone, "the request was refused" and "the gateway never
fired" are the same observation, and so are "the observers were not running" and
"nothing was sent". The run therefore sends a **control** request first — the
same beat-1 input, approved, on the same observer, the same bridge and the same
capture — and the blocked request is measured as a delta against it. Four tests
below then damage that evidence in specific ways and assert the run's guard or
its check falls:

- the control's record and index line deleted, so the observer's own count no
  longer matches what is on disk;
- the block receipt removed, so nothing distinguishes a refusal from a gateway
  that stopped calling the provider;
- a record injected for the blocked request, i.e. the leak itself;
- a doctored agreement report put through the rule the script's exit status
  depends on.

A guard that survives all four is decorative. These say it does not.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from evals import beat_support
from evals.demo_beat2_blocked import BLOCKED_REQUEST_ID, CONTROL_REQUEST_ID
from infra.capture.agreement import AgreementReport, check_agreement

REPO_ROOT = Path(__file__).resolve().parents[2]
DEMO = REPO_ROOT / "evals" / "demo_beat2_blocked.py"

#: The fabricated MRN, spelled here so a change to the inventory cannot move the
#: needle these assertions check for.
MRN = "4452819"

#: The contract's closed layer set, minus the two that cannot be reached by a
#: request that made it this far. The plan's acceptance criterion allows any of
#: `D.1, D.2, D.3, E, F`; `J` and `C` are listed too because a request that was
#: refused at the surface or at pseudonymization is still a `422` with a receipt
#: naming the component that refused.
REFUSAL_LAYERS = {"J", "A", "C", "D.1", "D.2", "D.3", "E", "F"}

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(
        not beat_support.docker_usable(),
        reason="docker is not usable here; the observer and the capture are real",
    ),
]


def _run(case: str, out_dir: Path) -> dict:
    """Run the demo script the way the README documents it; return its report."""
    completed = subprocess.run(
        [sys.executable, str(DEMO), "--case", case, "--json", "--out", str(out_dir)],
        capture_output=True, text=True, timeout=1800, cwd=str(REPO_ROOT / "backend"),
    )
    assert completed.returncode == 0, (
        f"beat 2 ({case}) did not run:\n{completed.stdout[-4000:]}\n"
        f"{completed.stderr[-4000:]}"
    )
    return {
        "report": json.loads(completed.stdout),
        "stdout": completed.stdout,
        "records": out_dir / "records",
        "pcap_text": (out_dir / "capture" / "out.pcap.txt").read_text(encoding="utf-8"),
    }


@pytest.fixture(scope="module")
def beat(tmp_path_factory):
    """The `unresolved` case: an identifier with no safe transformation."""
    return _run("unresolved", tmp_path_factory.mktemp("beat2"))


@pytest.fixture(scope="module")
def all_phi_beat(tmp_path_factory):
    """The other case, driven end to end. Two refusals, two reasons."""
    return _run("all_phi", tmp_path_factory.mktemp("beat2-allphi"))


# -- The refusal --------------------------------------------------------------


def test_the_request_was_refused_with_a_422_block_receipt(beat: dict):
    report = beat["report"]
    assert report["status"] == "blocked"
    assert report["http_status"] == 422
    receipt = report["block_receipt"]
    assert receipt["status"] == "blocked"
    assert receipt["request_id"] == BLOCKED_REQUEST_ID
    assert receipt["layer"] in REFUSAL_LAYERS
    assert receipt["action_codes"], "a receipt with no action code names no refusal"


def test_the_receipt_names_the_component_that_actually_refused(beat: dict):
    """Not "something refused": the layer tag *and* the component behind it.

    The block is `NER_UNRESOLVED` at layer D.2, and `NER_UNRESOLVED` is
    specifically the condition this project holds as an invariant: the block
    comes from a detected entity having **no registered replacer**, so there is
    no safe transformation of it, rather than from a score falling below a
    threshold. A threshold is a configuration value, and one settings change
    would turn a deterministic refusal into a pass.
    """
    report = beat["report"]
    assert report["layer"] == "D.2"
    assert report["refusing_component"].startswith("component D layer 2")
    assert "NER_UNRESOLVED" in report["action_codes"]
    assert "no registered replacer" in report["code_meaning"]["NER_UNRESOLVED"]


def test_the_all_phi_case_is_blocked_rather_than_silently_emptied(all_phi_beat: dict):
    """A report that is nothing but identifiers must not be quietly reduced.

    Approving it would send a payload that no longer says anything, which is a
    different failure from refusing it and a worse one to notice later.
    """
    report = all_phi_beat["report"]
    assert report["status"] == "blocked"
    assert report["http_status"] == 422
    assert report["observer_record_count"] == 0
    assert report["pcap_hit_count"] == 0
    assert "mrn" in report["planted_identifier_keys"], report["planted_identifier_keys"]


# -- The zero -----------------------------------------------------------------


def test_zero_bytes_reached_either_observer(beat: dict):
    report = beat["report"]
    assert report["observer_record_count"] == 0
    assert report["pcap_hit_count"] == 0
    assert report["agree"] is True, report["details"]
    assert report["bytes_leaked"] is False
    assert any("block receipt" in detail for detail in report["details"]), report["details"]


def test_the_observers_were_watching_and_the_control_was_observed_by_both(beat: dict):
    """The four statements that make the zero mean something.

    Each one is a statement about the *observers*, not about the request. A
    blocked beat without them would be asserting silence it has not established,
    and a `422` that looks like agreement is the worst outcome available.
    """
    report = beat["report"]
    guard = report["vacuity_guard"]
    assert beat_support.guard_holds(guard), guard
    assert guard["observer_live"] is True
    assert guard["records_complete"] is True
    assert guard["observer_record_count"] >= 1
    assert guard["pcap_frame_count"] > 0
    assert guard["pcap_request_bodies"] >= 1
    assert guard["pcap_carries_approved_content"] is True

    control = report["control"]
    assert control["request_id"] == CONTROL_REQUEST_ID
    assert control["http_status"] == 200
    assert control["observer_record_count"] == 1
    assert control["pcap_hit_count"] >= 1
    assert control["agree"] is True


def test_a_capture_that_lost_packets_is_judged_against_what_it_could_hide():
    """**A real failure this beat hit.** A beat-2 run whose capture reported

        65 packets received by filter
        61 packets captured
        the capture LOST 4 of 65 packets

    still produced a passing report, because nothing acted on the readback's
    exit status. A capture that dropped frames is not a capture that can
    support a claim about what did *not* appear in it: the zero it reports and
    the zero a request that sent nothing would produce are the same number, and
    only one of them means anything.

    `start_capture.sh stop` already exits non-zero for exactly this, and for a
    capture that saw nothing at all. The rule that turns that exit status into a
    failed beat lives in one named function, so a doctored result can be put
    through it here rather than the rule being re-spelled in a test.

    Two cases, and the difference between them is the whole design: a capture
    that saw **nothing** is worthless outright, while a capture that **lost
    frames** is judged against whether it demonstrably reassembled the control's
    whole request body. The bridge carries continuous chatter, so the frames lost
    at `tcpdump`'s shutdown are usually not the request's; a rule that failed on
    any of them would fail intermittently and teach a reader to re-run a failing
    demo rather than to believe it.
    """
    lossy = (
        "readback: 61 frames, 11047 bytes of pcap\n"
        "tcpdump: 61 packets captured\n"
        "tcpdump: 65 packets received by filter\n"
        "start_capture: the capture LOST 4 of 65 packets"
    )

    class Lost:
        returncode = 1
        stdout = lossy
        stderr = ""

    with pytest.raises(AssertionError, match="LOST 4 of 65"):
        beat_support.assert_capture_sound(Lost(), lossy, control_fully_observed=False)

    # The control was reassembled whole and matches the observer byte for byte,
    # so reassembly works on this capture and the loss cannot be hiding the
    # blocked request's body. The loss is still reported in the output, not
    # swallowed.
    beat_support.assert_capture_sound(Lost(), lossy, control_fully_observed=True)

    empty = "start_capture: the capture saw NOTHING; any check over it is vacuous"

    class Silent:
        returncode = 1
        stdout = "readback: 0 frames, 24 bytes of pcap"
        stderr = empty

    with pytest.raises(AssertionError, match="saw NOTHING"):
        beat_support.assert_capture_sound(Silent(), empty, control_fully_observed=True)

    class Clean:
        returncode = 0
        stdout = "readback: 64 frames, 8192 bytes of pcap"
        stderr = ""

    beat_support.assert_capture_sound(Clean(), "", control_fully_observed=False)


def test_both_of_this_runs_captures_saw_frames_and_the_control_was_reassembled(
    beat: dict, all_phi_beat: dict
):
    """The rule above, applied to the two runs this module actually produced.

    Two runs and not one, because a shutdown loss is intermittent: it is a race
    in `tcpdump`, not a property of any one request. Whatever the exit status
    was, the two facts that license the conclusion have to hold in both.
    """
    for run_result in (beat, all_phi_beat):
        report = run_result["report"]
        assert report["pcap_frame_count"] > 0, report["capture_readback"]
        assert report["control"]["agree"] is True, report["control"]
        assert report["control"]["pcap_hit_count"] >= 1, report["control"]


# -- The audit trail ----------------------------------------------------------


def test_the_request_id_is_traceable_in_the_audit_log(beat: dict):
    """Read back over the contract's own endpoint, not out of Medarx's memory."""
    event = beat["report"]["audit_block_event"]
    assert event["request_id"] == BLOCKED_REQUEST_ID
    assert event["final_disposition"] == "blocked"
    assert event["layer"] == "D.2"
    assert event["action_codes"] == beat["report"]["action_codes"]
    assert event["approved_payload_hash"] is None, (
        "a blocked request approved nothing, so there is no approved payload to "
        "record a hash of"
    )
    # The deployment mode is written into every audit record, and
    # `Settings.policy_mode` defaults to "cloud" — right for a real provider,
    # wrong for a beat whose bytes never leave the host. A permanent record that
    # says "cloud" for a local run is a false fact in the store the design names
    # as an asset, so the beats declare the mode they are actually in.
    assert event["policy_mode"] == beat_support.POLICY_MODE == "strict_local"
    assert beat["report"]["policy_mode"] == "strict_local"
    assert beat["report"]["audit_request_id_traceable"] is True


def test_the_audit_record_carries_no_planted_identifier(beat: dict):
    """The audit log is not a second PHI store, and a block record is the case
    where that is easiest to get wrong: the input hash is over the caller's
    bytes, so the temptation is to store what was refused."""
    event = json.dumps(beat["report"]["audit_block_event"], ensure_ascii=False)
    assert MRN not in event
    assert beat_support.mask_tree(beat["report"]["audit_block_event"]) == (
        beat["report"]["audit_block_event"]
    ), "no value in the audit record needed masking, so none was an identifier"


def test_json_mode_does_not_print_the_fabricated_identifiers(beat: dict, all_phi_beat: dict):
    for run_result in (beat, all_phi_beat):
        values = [value for value in beat_support.identifier_values()
                  if value in run_result["stdout"]]
        assert values == [], f"the --json output printed fabricated identifiers: {values}"


# -- The evidence mechanism, shown able to fail ------------------------------
#
# Each of these damages the evidence the beat produced and asserts that the guard
# or the check falls. They are the reason the beat above can be believed.


def _recheck(beat: dict, content: str, **kwargs) -> AgreementReport:
    report = beat["report"]
    return check_agreement(
        report["control"]["approved_payload_hash"],
        content,
        beat["records"],
        beat["pcap_text"],
        BLOCKED_REQUEST_ID,
        observer_live=True,
        **kwargs,
    )


def test_deleting_the_observers_records_fails_the_vacuity_guard(beat: dict):
    """**The requirement, stated as a test.** If emptying the observer's records
    could leave the beat looking green, the beat is decorative.

    The observer's own `/healthz` count is the independent statement that makes
    the deletion visible: the observer counted a record, and the record directory
    no longer holds one. Without that comparison a deleted record directory is
    indistinguishable from a request that sent nothing, and the `422` scores full
    agreement over an empty evidence set.
    """
    record = sorted(beat["records"].glob("*.bin"))[0]
    index = beat["records"] / "index.jsonl"
    index_text = index.read_text(encoding="utf-8")
    payload = record.read_bytes()

    record.unlink()
    index.unlink()
    try:
        damaged = beat_support.control_evidence_from(
            beat["records"],
            beat["pcap_text"],
            observer_live=True,
            health_record_count=beat["report"]["vacuity_guard"]["observer_record_count"],
            content=beat["report"]["control"]["approved_content"],
        )
        assert damaged["records_complete"] is False
        assert beat_support.guard_holds(damaged) is False
    finally:
        record.write_bytes(payload)
        index.write_text(index_text, encoding="utf-8")


def test_silence_without_a_block_receipt_is_not_agreement(beat: dict):
    """Remove the receipt and the same silence stops being evidence.

    From the observers alone, "the gateway never fired" and "the request was
    refused before it could fire" are the same observation. The receipt is the
    third, independent statement about this request id, and it is what makes the
    zero mean something.
    """
    receipt = beat["records"] / "block_receipt.json"
    assert receipt.exists(), "the beat must have left its own 422 body in place"
    receipt.unlink()
    try:
        report = _recheck(beat, beat["report"]["control"]["approved_content"],
                          records_before=1, bodies_before=1)
        assert report.agree is False, report.as_dict()
        assert any("no block receipt" in detail for detail in report.details), (
            report.details
        )
    finally:
        beat_support.write_block_receipt(beat["records"],
                                         beat["report"]["block_receipt"])


def test_a_record_for_the_blocked_request_is_refused(beat: dict):
    """The leak, injected into a run that otherwise passed.

    A record is written to the observer's directory and its index entry is
    re-hashed over those bytes, so the observer is internally consistent and
    cannot be dismissed as broken. The check must refuse, and it must count the
    record rather than explaining it away.
    """
    body = json.dumps({"model": beat_support.OBSERVER_MODEL,
                       "messages": [{"role": "user", "content": "leaked"}]}).encode()
    name = "leaked-blocked.bin"
    (beat["records"] / name).write_bytes(body)
    index = beat["records"] / "index.jsonl"
    index.write_text(
        index.read_text(encoding="utf-8")
        + json.dumps({
            "id": "leaked-blocked", "path": name,
            "sha256": hashlib.sha256(body).hexdigest(),
            "byte_length": len(body), "received_at": "2026-01-14T12:00:00Z",
        }) + "\n",
        encoding="utf-8",
    )
    try:
        report = _recheck(beat, beat["report"]["control"]["approved_content"],
                          records_before=1, bodies_before=1)
        assert report.agree is False, report.as_dict()
        assert report.observer_record_count == 1
        assert report.pcap_hit_count == 0
        assert any("asymmetric observation" in detail for detail in report.details), (
            report.details
        )
        # And the rule the script's exit status depends on refuses it too.
        with pytest.raises(AssertionError, match="TRANSMITTED BYTES"):
            beat_support.assert_nothing_left(report, request_id=BLOCKED_REQUEST_ID)
    finally:
        (beat["records"] / name).unlink(missing_ok=True)
        beat_support.write_block_receipt(beat["records"],
                                         beat["report"]["block_receipt"])


def test_an_observer_that_was_not_answering_is_not_evidence_of_silence(beat: dict):
    """The same evidence, with the caller reporting the observer was down.

    A block receipt beside an observer that never answered is not evidence that
    nothing was sent: the observer might have died between the request and the
    record. The check refuses, which is what stops a deployment whose observer
    was unreachable from scoring full agreement on every request.
    """
    report = check_agreement(
        beat["report"]["control"]["approved_payload_hash"],
        beat["report"]["control"]["approved_content"],
        beat["records"],
        beat["pcap_text"],
        BLOCKED_REQUEST_ID,
        observer_live=False,
        records_before=1, bodies_before=1,
    )
    assert report.agree is False, report.as_dict()
    assert any("not answering" in detail for detail in report.details), report.details
