"""Beat 1, end to end: the approved path, and an evidence check that can fail.

**Everything below is live.** The observer is a container started by this run,
the second observer is a `tcpdump` on that container's bridge in the host network
namespace, and the Medarx process is the real composition root driving its own
HTTP surface. There is no fixture in this module: the four committed capture
artifacts in `tests/fixtures/capture/` are real too, but they are a *recorded*
run, and presenting one as a live capture is the substitution this whole project
is built to rule out.

**One run, several tests.** The module-scoped fixture runs the beat once and
every test below argues about *that* run's evidence. A fresh run per test would
make "the same run" a phrase rather than a fact, and the three negative tests are
only meaningful against bytes that really were on a wire.

**The negative tests are the point.** Three of these take the evidence a passing
beat produced and damage it in a specific way, then assert the check says no:

- the observer's record deleted — one witness gone, the other still holding the
  request;
- the approved payload's own report text rewritten length-preservingly — both
  observers still holding the *same* real bytes, and the check refusing anyway,
  because neither of them is carrying the approved payload. This is the leak
  shape, and it is the one this project has already shipped once.

A check that only ever returns agreement is not evidence. These three say it can
return the other answer.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from evals import beat_support
from evals.demo_beat1_approved import build_input
from infra.capture.agreement import check_agreement

REPO_ROOT = Path(__file__).resolve().parents[2]
DEMO = REPO_ROOT / "evals" / "demo_beat1_approved.py"

#: The fabricated MRN, spelled here rather than read from `identifiers.json` so
#: that a change to the inventory cannot quietly move the needle these
#: assertions check for.
MRN = "4452819"

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(
        not beat_support.docker_usable(),
        reason="docker is not usable here; the observer and the capture are real",
    ),
]


@pytest.fixture(scope="module")
def beat(tmp_path_factory):
    """One live beat: the demo script, run exactly as the README documents it."""
    out_dir = tmp_path_factory.mktemp("beat1")
    completed = subprocess.run(
        [sys.executable, str(DEMO), "--json", "--out", str(out_dir)],
        capture_output=True, text=True, timeout=1800, cwd=str(REPO_ROOT / "backend"),
    )
    assert completed.returncode == 0, (
        f"the beat did not run:\n{completed.stdout[-4000:]}\n{completed.stderr[-4000:]}"
    )
    report = json.loads(completed.stdout)
    return {
        "report": report,
        "raw_stdout": completed.stdout,
        "records": out_dir / "records",
        "pcap_text": (out_dir / "capture" / "out.pcap.txt").read_text(encoding="utf-8"),
    }


def _recheck(beat: dict, content: str, **kwargs):
    """Ask the same check the same question about the same evidence again."""
    return check_agreement(
        beat["report"]["approved_payload_hash"],
        content,
        beat["records"],
        beat["pcap_text"],
        beat["report"]["request_id"],
        observer_live=True,
        **kwargs,
    )


def _corrupt(content: str) -> str:
    """`content` with its finding's width changed, preserving its length.

    Length-preserving on purpose: a substitution that changed the length would
    be caught by a size comparison, and the point is the one a size check cannot
    see — the same number of bytes, carrying something else.
    """
    corrupted = content.replace("6mm", "9mm")
    assert corrupted != content, f"the approved report must contain the text: {content!r}"
    assert len(corrupted) == len(content)
    return corrupted


# -- The beat, on its own terms ----------------------------------------------


def test_the_beat_ran_live_and_the_two_observers_agree(beat: dict):
    """The claim, in the four numbers a reader can check without the code.

    `observer_record_count == 1` and `pcap_hit_count >= 1` are the two
    independent witnesses. `agree` is the check built on them. The frame count is
    the fourth, and it exists because a zero from a sniffer pointed at the wrong
    interface is the failure this project has already paid for once.
    """
    report = beat["report"]
    assert report["live"] is True
    assert report["status"] == "approved"
    assert report["http_status"] == 200
    assert report["observer_record_count"] == 1
    assert report["pcap_hit_count"] >= 1
    assert report["pcap_frame_count"] > 0
    assert report["agree"] is True, report["details"]
    assert report["differences"] == []


def test_the_observers_were_watching_rather_than_absent(beat: dict):
    """Both witnesses have to have been alive for either of their counts to mean
    anything. The observer's own `/healthz` and the capture's frame count are
    the two statements that separate "saw nothing" from "was not looking"."""
    watching = beat["report"]["observers_were_watching"]
    assert watching["observer_live"] is True
    assert watching["pcap_frame_count"] > 0
    assert watching["pcap_request_bodies"] >= 1
    assert watching["observer_record_count"] == 1


def test_the_hash_the_api_reports_is_the_hash_of_the_payload_it_approved(beat: dict):
    """The approval is a fact about content, not a field anyone can populate."""
    payload = beat["report"]["artefacts"]["transformed_payload"]
    assert payload["claimed_hash_matches_content"] is True, (
        "the payload's hash field must equal a hash recomputed from its content"
    )
    assert beat["report"]["approved_payload_hash"] == payload["payload_hash"]


def test_the_audit_record_names_the_deployment_mode_actually_in_force(beat: dict):
    """The beats run with the gateway pointed at a local observer.

    `Settings.policy_mode` defaults to `"cloud"`, and every audit record carries
    it. Inheriting that default would put `policy_mode: "cloud"` in a permanent
    record for a run whose bytes never left the host.
    """
    assert beat["report"]["policy_mode"] == "strict_local"
    assert beat["report"]["audit_record"]["policy_mode"] == "strict_local"
    assert beat["report"]["artefacts"]["model_response"]["provider"].startswith(
        "the observer container"
    )


def test_the_observer_is_the_provider_and_no_model_is_contacted(beat: dict):
    """The reply is the observer's own constant, computed for itself.

    What this proves: the draft that came back through the real gateway is a
    string the observer produced, with no model in the path. What it cannot
    prove, and no test can, is that no code path anywhere could reach one.
    """
    response = beat["report"]["artefacts"]["model_response"]["body"]
    assert response["content"] == beat_support.OBSERVER_REPLY
    assert response["model_id"] == beat_support.OBSERVER_MODEL
    assert response["finish_reason"] == "stop"


# -- The identifiers, in and out ---------------------------------------------


def test_identifiers_went_in_and_none_of_them_came_out(beat: dict):
    """The whole point of the beat, stated as a before and an after.

    The "before" is rebuilt here from the demo's own builder rather than read
    out of its report, so a demo that quietly stopped planting identifiers would
    fail this test rather than pass it with a self-consistent empty claim.
    """
    sent = json.dumps(build_input(), ensure_ascii=False)
    assert MRN in sent, "the input must actually carry a fabricated identifier"
    values = [value for value in beat_support.identifier_values() if value in sent]
    assert values, "the input must carry at least one value from the inventory"

    carried = beat["report"]["captured_bytes"]
    survivors = [value for value in values if value in carried]
    assert survivors == [], f"a fabricated identifier reached the wire: {survivors}"
    assert beat["report"]["identifiers_in_captured_bytes"] == []


def test_the_transformed_payload_is_what_the_wire_carries(beat: dict):
    """The two observers are not merely consistent; they carry this payload.

    Read out of the captured bytes rather than out of a constant, so the
    comparison cannot be a string compared with itself.
    """
    on_wire = json.loads(beat["report"]["captured_bytes"])["messages"]
    payload = beat["report"]["artefacts"]["transformed_payload"]
    assert on_wire[1]["content"].endswith(payload["report_text"])


# -- The evidence mechanism, shown able to fail ------------------------------


def test_deleting_the_observers_record_makes_the_same_run_disagree(beat: dict):
    """One witness destroyed; the other still holding the request.

    The capture has not changed and the approved content has not changed. What
    changed is that one observer no longer holds anything, and that asymmetry is
    a failure. An evidence mechanism that survives the loss of half its evidence
    by still reporting agreement is decorative.
    """
    index = beat["records"] / "index.jsonl"
    index_text = index.read_text(encoding="utf-8")
    records = sorted(beat["records"].glob("*.bin"))
    assert len(records) == 1, f"expected one record, found {[p.name for p in records]}"
    payload = records[0].read_bytes()
    records[0].unlink()
    try:
        report = _recheck(beat, beat["report"]["approved_content"])
        assert report.agree is False, report.as_dict()
        assert report.observer_record_count == 0
        assert report.pcap_hit_count >= 1, "the capture still holds what it saw"
    finally:
        records[0].write_bytes(payload)
        index.write_text(index_text, encoding="utf-8")


def test_corrupting_the_approved_payload_makes_both_observers_disagree_with_it(
    beat: dict,
):
    """**The leak shape, on this run's own bytes.** The load-bearing negative.

    Nothing on the wire is touched. The observer's record still holds exactly
    what the observer wrote; the capture still holds exactly what crossed the
    bridge; the two still agree with each other byte for byte. What is corrupted
    is the *approved payload* — the needle, length-preservingly, so that no size
    comparison could have caught it.

    The check must refuse, and it must refuse for the right stated reason: not
    that one observer is missing, but that **both** of them are carrying bytes
    the approved payload does not contain. Two observers agreeing that the same
    wrong thing was sent is not evidence, and this is the assertion that says so.
    """
    report = _recheck(beat, _corrupt(beat["report"]["approved_content"]))
    assert report.agree is False, report.as_dict()
    assert report.observer_record_count == 1, "the observer did record a request"
    assert report.pcap_hit_count == 0, "and it does not carry the approved content"
    assert any("neither carried the approved payload" in d for d in report.details), (
        f"the failure must name the approved content, not an asymmetry: {report.details}"
    )


def test_a_substituted_record_is_refused_even_though_the_observer_is_consistent(
    beat: dict,
):
    """The other direction: the observer's disk rewritten, and the index re-hashed.

    The observer is made internally consistent — the digest in its index is
    recomputed over the substituted bytes, so the record cannot be dismissed as a
    corrupt file — and the capture still holds the approved body. The check
    refuses, and it names the observer as the one that does not carry the
    approved content.
    """
    record = sorted(beat["records"].glob("*.bin"))[0]
    original = record.read_bytes()
    substituted = original.replace(b"6mm", b"9mm")
    assert substituted != original and len(substituted) == len(original)

    index_path = beat["records"] / "index.jsonl"
    index = json.loads(index_path.read_text(encoding="utf-8").strip())
    try:
        record.write_bytes(substituted)
        index["sha256"] = hashlib.sha256(substituted).hexdigest()
        index["byte_length"] = len(substituted)
        index_path.write_text(json.dumps(index) + "\n", encoding="utf-8")

        report = _recheck(beat, beat["report"]["approved_content"])
        assert report.agree is False, report.as_dict()
        assert report.observer_record_count == 1
        assert report.pcap_hit_count >= 1
        assert any("the observer's records do not" in d for d in report.details), (
            report.details
        )
    finally:
        record.write_bytes(original)
        index["sha256"] = hashlib.sha256(original).hexdigest()
        index["byte_length"] = len(original)
        index_path.write_text(json.dumps(index) + "\n", encoding="utf-8")


# -- The rendering, and the failure mode -------------------------------------


def test_json_mode_does_not_print_the_fabricated_identifiers(beat: dict):
    """The machine-readable output is the part most likely to be pasted into an
    issue, so the input's identifiers are masked in it.

    The transformed payload, the reply and the captured bytes are *not* masked:
    they are the evidence, and a reader has to be able to see that the
    identifiers are absent rather than being told so.
    """
    values = [value for value in beat_support.identifier_values()
              if value in beat["raw_stdout"]]
    assert values == [], f"the --json output printed fabricated identifiers: {values}"
    assert beat_support.MASK in beat["raw_stdout"], "the input must be shown, masked"


def test_a_provider_that_cannot_be_reached_is_not_a_privacy_block(tmp_path: Path):
    """A beat that cannot reach its provider must report a provider failure.

    The plan is explicit that these must fail loudly and never skip, because a
    skipped egress test is indistinguishable from a passing one. The sharper
    half of that is here: pointed at a port with nothing on it, the request must
    come back as a **provider** failure and not as a `422` block. Design §6 has
    no row for an unreachable provider, and recording one as a block would put a
    false privacy event in the one store the design names as an asset.
    """
    body = build_input()
    run = beat_support.drive(
        tmp_path / "kernel.db",
        "http://127.0.0.1:1/v1",
        [beat_support.DrivenRequest("req-beat1-unreachable", body)],
        scope_study=body["study_context"]["study_reference"],
    )
    response = run.for_request("req-beat1-unreachable")
    assert response["status"] == 500, response["body"]
    assert response["body"]["type"].endswith("/provider-unavailable"), response["body"]
    # A `BlockReceipt` carries `status: "blocked"`, a `layer` and
    # `action_codes`. An RFC 9457 problem document also carries a `status`, so
    # the layer and the codes are what tell the two apart — and the audit log is
    # where the difference actually shows: a provider outage recorded as a
    # block would be a false privacy event in the one store the design names as
    # an asset.
    assert "layer" not in response["body"], response["body"]
    assert "action_codes" not in response["body"], response["body"]
    # A provider outage is either recorded as an availability event or not
    # recorded at all; what it must never be is recorded as a privacy block.
    readback = run.audit_records[0]
    if readback["status"] == 200:
        assert readback["body"]["final_disposition"] != "blocked", readback["body"]
