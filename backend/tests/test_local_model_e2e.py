"""Beat 3, end to end: the real kernel against a real local model.

**Everything below is live.** The model is a real qwen3 4.0B served by Ollama
on this host, the application is the real composition root driving its own HTTP
surface, the path is validate-then-send, and the bytes the model received are
reassembled off the wire by a `tcpdump` that never handled the request. There is
no fixture: the four committed capture files in `tests/fixtures/capture/` are a
*recorded* run, and presenting one as a live capture is the substitution this
module exists to rule out.

**The negative tests are the point.** Four of these take the evidence a passing
beat produced and damage it in one specific way each, then assert the check
says no:

- the captured bytes substituted, so what the gateway recorded and what the
  capture saw are no longer the same object — the leak shape, and the one this
  project shipped once;
- the approved report text rewritten in the captured bytes, so both witnesses
  still hold *the same* real bytes and the check refuses anyway, because neither
  of them is carrying the approved payload;
- an identifier from the fabricated inventory written into a **second** body on
  the wire, which the body the check selected would never see;
- a duplicated body, so the "exactly one body is byte-identical" count is wrong
  and the comparison below it is not the comparison it claims to be.

A check that only ever returns is not evidence. These four say it can return
the other answer.

**This module is opt-in, because it loads 2.5 GB of model into memory.** See
`MEDARX_LOCAL_MODEL_E2E` below for the three modes and the reason the default is
off: on a shared host with no swap, a test that silently reserves a gigabyte
class working set does not fail itself, it fails everything else resident.
`=required` makes any skip a collection error, so "the tests passed" can never
mean "the tests did not run".
"""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from evals import beat_support
from evals.demo_beat3_local_model import (
    CAPTURE_INTERFACE,
    DEFAULT_BASE_URL,
    DEFAULT_MODEL,
    ModelUnavailable,
    probe_model,
    verify_wire_evidence,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
DEMO = REPO_ROOT / "evals" / "demo_beat3_local_model.py"

#: Megabytes of headroom the host must have above the model's own size before
#: this module will load it. Not a tuning constant: it is the difference between
#: "the model fits" and "the model fits and something else still can", and a run
#: that tips the host over is not a green run, it is an outage for whatever else
#: the machine was doing.
_HEADROOM_MIB = 512


def _available_mib() -> int:
    for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
        if line.startswith("MemAvailable:"):
            return int(line.split()[1]) // 1024
    return 0


#: How this module is switched on.
#:
#: **This test loads 2.5 GB into memory, so it is opt-in.** A test suite that
#: silently reserves a gigabyte-scale working set on whatever machine it runs on
#: is a suite that can take down something else's work: the host this was built
#: on has 15 GB and **zero swap**, and an OOM kill there does not stop the test,
#: it stops the browser, the editor and everything else resident. Loading a
#: local model is a **resource-coordination decision somebody has to make**, and
#: the honest way to express that is a flag rather than a heuristic nobody set.
#: So:
#:
#: - unset — skipped, with the reason above in the skip line;
#: - `MEDARX_LOCAL_MODEL_E2E=1` — runs, if docker is usable, the model server
#:   answers, and the host has the headroom;
#: - `MEDARX_LOCAL_MODEL_E2E=required` — runs, and **any** of those conditions
#:   failing is a collection error rather than a skip. This is the mode a
#:   deployment that claims this module ran must use, because it is the only
#:   one in which "the tests passed" cannot mean "the tests did not run".
_MODE = os.environ.get("MEDARX_LOCAL_MODEL_E2E", "").strip().lower()


def _availability() -> "str | None":
    """Why this module cannot run here, or `None` when it can.

    A function rather than module-level constants, so the skip reason quotes the
    same numbers the gate measured rather than numbers written down beside it.
    """
    if _MODE not in ("1", "required"):
        return (
            "this module loads a 2.5 GB local model into memory, which is a "
            "resource-coordination decision and not one a test suite should "
            "make unasked on a shared host. Set MEDARX_LOCAL_MODEL_E2E=1 to run "
            "it, or =required to make a skip a failure."
        )
    if not beat_support.docker_usable():
        # The capture is a container. Without a daemon there is no second
        # observer, and the whole module is about the second observer.
        return "docker is not usable here; the capture is real and there is no stand-in"
    try:
        served = probe_model(os.environ.get("MEDARX_GATEWAY_BASE_URL", DEFAULT_BASE_URL))
    except ModelUnavailable as exc:
        return f"no local model server is reachable: {exc}"
    model_mib = int(served["size_bytes"]) // (1024 * 1024)
    available = _available_mib()
    if available < model_mib + _HEADROOM_MIB:
        return (
            f"loading {DEFAULT_MODEL} needs about {model_mib} MiB and this host has "
            f"{available} MiB available with no swap; running it here would risk an "
            f"OOM kill for whatever else the machine is doing"
        )
    return None


_UNAVAILABLE = _availability()

if _MODE == "required" and _UNAVAILABLE:
    # A deployment that insists this module ran must not be able to have it
    # skipped. Raising at import is the only way to make "it was skipped" a
    # collection error rather than a passing run.
    raise AssertionError(f"MEDARX_LOCAL_MODEL_E2E=required and: {_UNAVAILABLE}")

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(_UNAVAILABLE is not None, reason=_UNAVAILABLE or ""),
]


@pytest.fixture(scope="module")
def beat(tmp_path_factory):
    """One live run: the demo script, run exactly as the README documents it."""
    out_dir = tmp_path_factory.mktemp("beat3")
    completed = subprocess.run(
        [sys.executable, str(DEMO), "--json", "--out", str(out_dir)],
        capture_output=True, text=True, timeout=3600, cwd=str(REPO_ROOT / "backend"),
    )
    assert completed.returncode == 0, (
        f"the beat did not run:\n{completed.stdout[-4000:]}\n{completed.stderr[-4000:]}"
    )
    report = json.loads(completed.stdout)
    return {
        "report": report,
        "out_dir": out_dir,
        "pcap_text": (out_dir / "capture" / "out.pcap.txt").read_text(encoding="utf-8"),
    }


# -- What the deployment is pointed at ---------------------------------------


def test_the_model_that_answered_is_a_registered_one(beat):
    # The registry is the closed set of names the kernel will put on the wire.
    # A run that answered with something outside it would mean the registry is
    # not what the gateway checks, which is the whole of §6 row 7's local half.
    report = beat["report"]
    assert report["model"]["registry_member"] == DEFAULT_MODEL
    assert DEFAULT_MODEL in report["model"]["registry"]
    assert report["artefacts"]["model_response"]["body"]["model_id"] in (
        report["model"]["registry"]
    )


def test_the_model_server_reports_no_vision_capability(beat):
    # The mechanical reason the no-pixel-interpretation rule holds by
    # construction rather than by policy: the served model cannot accept pixels,
    # so there is no code path by which an image could reach it.
    served = beat["report"]["model"]["served"]
    assert served["vision_capability_present"] is False
    assert "vision" not in served["capabilities"]


def test_no_module_in_the_kernel_branches_on_a_provider():
    # The provider-neutrality claim, as a sweep over the **abstract syntax tree**
    # rather than over the text. A textual sweep cannot tell a comment from a
    # branch, and the registry carries a comment naming the model server on
    # purpose; a branch would need a string literal, a name, or an attribute,
    # and comments are not in the AST at all. So this finds code and only code.
    #
    # **One module is exempt, and the exemption is the claim rather than a
    # loophole.** `gateway/model_registry.py` holds provider-prefixed
    # identifiers — `openrouter/mock-model` has been a member since Phase 1 —
    # and that is not a branch: it is a set compared for whole-identifier
    # equality, with no ordering, no lookup and no behaviour keyed on which
    # provider a name belongs to. The assertion below is that this module is
    # the *only* one that names a model, so a second one fails the sweep rather
    # than joining the exemption list.
    needles = ("ollama", "openrouter", "11434", "localhost")
    exempt = Path("medarx/gateway/model_registry.py")
    offenders: list[str] = []
    for path in sorted((REPO_ROOT / "backend" / "src").rglob("*.py")):
        relative = path.relative_to(REPO_ROOT / "backend" / "src")
        tree = ast.parse(path.read_text(encoding="utf-8"))
        docstrings = {
            id(node.body[0].value)
            for node in ast.walk(tree)
            if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                                  ast.ClassDef))
            and node.body
            and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)
            and isinstance(node.body[0].value.value, str)
        }
        for node in ast.walk(tree):
            where = f"{relative}:{getattr(node, 'lineno', 0)}"
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if id(node) in docstrings:
                    continue
                low = node.value.lower()
                if any(n in low for n in needles):
                    offenders.append(f"{where}: {node.value!r}")
            elif isinstance(node, ast.Name) and any(n in node.id.lower() for n in needles):
                offenders.append(f"{where}: name {node.id}")
            elif isinstance(node, ast.Attribute) and any(
                n in node.attr.lower() for n in needles
            ):
                offenders.append(f"{where}: attribute {node.attr}")
    # The registry is allowed to name models and nothing else is. Stated as a
    # positive assertion rather than a filter, so a *second* module naming a
    # provider fails rather than quietly joining an exemption.
    outside = [o for o in offenders if not o.startswith(str(exempt))]
    inside = [o for o in offenders if o.startswith(str(exempt))]
    assert outside == [], f"a module other than the model registry names a provider: {outside}"
    assert inside, (
        "the model registry no longer names any provider, so the sweep is "
        "vacuous — the needles and the registry have drifted apart"
    )
    # The exemption is only for names, not for structure: the registry is a
    # set literal compared for equality, and a conditional in it would be a
    # branch dressed as data.
    registry = ast.parse(
        (REPO_ROOT / "backend/src/medarx/gateway/model_registry.py").read_text("utf-8")
    )
    assert not [
        node for node in ast.walk(registry)
        if isinstance(node, (ast.If, ast.Match, ast.IfExp))
    ], "the model registry contains a conditional; it is a set, not a resolver"


def test_the_body_the_model_received_is_the_openai_body_and_only_that(beat):
    # Exactly four keys, the four the OpenAI spec requires, and no image-shaped
    # key of any kind. A body carrying `image_url` or `modalities` would be a
    # leak by construction on a model that cannot read pixels.
    sent = json.loads(beat["report"]["artefacts"]["captured_outbound_request"]["body"])
    assert set(sent) == {"model", "messages", "temperature", "max_tokens"}
    for message in sent["messages"]:
        assert set(message) == {"role", "content"}
        assert isinstance(message["content"], str)
    assert beat["report"]["evidence"]["observer_bytes_match"] is True
    assert beat["report"]["evidence"]["byte_differences"] == []


# -- The timing, and the timeout ---------------------------------------------


def test_the_configured_timeout_is_the_one_the_run_used(beat):
    # Read from the settings the run actually ran under, not from the defaults.
    assert beat["report"]["timing_s"]["configured_timeout_s"] == 120.0


def test_a_cold_inference_is_inside_the_timeout_and_a_warm_one_well_under_it(beat):
    # The failure this guards is a slow first call read as a failure, or a
    # timeout that fires on the one request a user is waiting for.
    cold = beat["report"]["timing_s"]["cold_send"]
    warm = beat["report"]["timing_s"]["warm_send"]
    assert cold < 120.0, cold
    assert warm is not None and warm < 5.0, warm
    assert beat["report"]["timing_s"]["cold_model_was_unloaded_first"] is True


# -- The payload the model received -------------------------------------------


def test_the_approved_payload_is_what_reached_the_model(beat):
    report = beat["report"]
    assert report["evidence"]["bodies_byte_identical_to_the_gateway_record"] == 1
    assert report["evidence"]["approved_content_on_the_wire"] is True
    # The needle is the kernel's own approved object: the report text the kernel
    # redacted, not the text the caller supplied.
    approved = report["artefacts"]["transformed_payload"]["report_text"]
    assert approved in json.dumps(
        json.loads(report["artefacts"]["captured_outbound_request"]["body"])["messages"]
    )


def test_no_planted_identifier_is_in_any_body_on_the_wire(beat):
    # The stronger half: not only the body the check selected. A second body
    # carrying an identifier is as much a leak as the first carrying one.
    report = beat["report"]
    assert report["identifiers_in_captured_bytes"] == []
    assert report["identifiers_in_any_captured_body"] == []
    assert len(report["planted_identifier_keys"]) > 0, (
        "the request planted nothing, so the absence proves nothing"
    )


def test_a_preflight_transmitted_nothing(beat):
    # The third state is only a state if the preflight stopped. The gateway's
    # own evidence is that it had recorded no request body at that point.
    report = beat["report"]
    assert report["evidence"]["preflight_recorded_no_request_body"] is True
    assert report["status"] == "approved"
    assert report["evidence"]["capture_interface"] == CAPTURE_INTERFACE


def test_the_model_answering_did_not_sign_the_draft_off(beat):
    # The disposition after a successful send is `pending_human_approval`, not
    # `approved`. That is the whole point of the nesting in the contract, and it
    # is worth an assertion rather than a reading: a kernel that treated "the
    # model answered" as "a human accepted this" would put `approved` here, and
    # the audit log — the one store the design names as an asset — would carry a
    # sign-off nobody gave. A real 4B model's answer is exactly the kind of
    # answer that must not be able to sign itself off.
    record = beat["report"]["audit_record"]
    assert record is not None
    assert record["final_disposition"] == "pending_human_approval"
    assert record["human_approval"] is None, (
        "no human decision was recorded, and the record must say 'not yet "
        "decided' rather than claiming one"
    )


def test_the_two_observer_rule_refuses_when_only_one_observer_saw_the_request(beat):
    # With a real model there is no recording observer, so the Phase 1 rule has
    # one witness and the gateway's own record as the other — which is Medarx
    # attesting to itself. The rule must say so rather than score it green, and
    # this is the assertion that keeps the beat's own single-observer claim
    # honest rather than a downgrade nobody notices.
    verdict = beat["report"]["evidence"]["two_observer_rule_verdict"]
    assert verdict["agree"] is False
    assert verdict["observer_record_count"] == 0
    assert verdict["pcap_hit_count"] >= 1, (
        "the capture saw nothing, so the refusal above is the 'one observer' "
        "answer rather than the 'nothing was watched' one"
    )


# -- The checks, argued with ---------------------------------------------------


def _evidence(beat):
    """The arguments `verify_wire_evidence` was called with, from the artefacts."""
    report = beat["report"]
    sent = report["artefacts"]["captured_outbound_request"]["body"].encode("utf-8")
    approved = {
        "payload_hash": report["artefacts"]["transformed_payload"]["payload_hash"],
        "report_text": report["artefacts"]["transformed_payload"]["report_text"],
    }
    return [sent], sent, approved, report["planted_identifier_keys"]


def test_the_check_passes_on_the_evidence_a_real_run_produced(beat):
    captured, sent, approved, planted = _evidence(beat)
    assert verify_wire_evidence(
        captured, sent, approved, planted
    )["approved_content_on_the_wire"] is True


def test_substituting_the_captured_bytes_is_caught(beat):
    # The shape this project shipped once: what the gateway recorded and what the
    # observer saw are no longer the same object, and a check that only asked
    # "do the two witnesses agree" would have passed it.
    captured, sent, approved, planted = _evidence(beat)
    with pytest.raises(AssertionError, match="byte-identical"):
        verify_wire_evidence([sent + b" "], sent, approved, planted)


def test_both_witnesses_carrying_the_wrong_payload_is_still_caught(beat):
    # Neither witness is carrying the approved payload, and they agree with each
    # other perfectly. Agreement about unapproved bytes is not evidence.
    captured, sent, approved, planted = _evidence(beat)
    needle = approved["report_text"].encode()
    rewritten = sent.replace(needle, b"X" * len(needle))
    with pytest.raises(AssertionError, match="approved report text is not in"):
        verify_wire_evidence([rewritten], rewritten, approved, planted)


def test_an_identifier_in_a_second_body_is_caught(beat):
    # The body the check selects is untouched; the leak is in another request on
    # the same port. A check that only read the selected body would pass this.
    captured, sent, approved, planted = _evidence(beat)
    other = json.dumps({"note": beat_support.value_of("institution_name")}).encode("utf-8")
    with pytest.raises(AssertionError, match="some other body on the wire"):
        verify_wire_evidence([sent, other], sent, approved, planted)


def test_two_identical_bodies_make_the_count_wrong(beat):
    captured, sent, approved, planted = _evidence(beat)
    with pytest.raises(AssertionError, match="byte-identical"):
        verify_wire_evidence([sent, sent], sent, approved, planted)


def test_an_empty_capture_is_not_a_pass(beat):
    captured, sent, approved, planted = _evidence(beat)
    with pytest.raises(AssertionError, match="no request body at all"):
        verify_wire_evidence([], sent, approved, planted)
