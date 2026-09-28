"""Beat 2 — the blocked path, and the proof that **nothing at all** left.

    cd backend && uv run python ../evals/demo_beat2_blocked.py
    cd backend && uv run python ../evals/demo_beat2_blocked.py --case all_phi --json

**What this demonstrates.** An identifier that cannot be safely transformed
reaches the pipeline; the request is refused; **zero bytes** reach either
observer; the receipt names the component that actually refused; and the request
id is in the audit log. An invisible block is not evidence, and a leak that
passes every check is worse than no check at all, so this beat is the load-bearing
one.

**Why the run also sends a control request.** A control request goes first and is
approved, on the same observer, the same bridge and the same capture. It exists
for one reason: without it, "neither observer saw anything" and "the observers
were not running" are the *same observation*, and the beat would be asserting
silence it has not established. With it, the run can say four things that a bare
zero cannot:

- the observer answered `/healthz` after the run, so it was alive throughout;
- the observer's own record count equals the number of index entries on disk, so
  the record directory has not had anything removed from it;
- the capture saw frames, and it saw the **control's** request body on them;
- the control's approved content is visible in the capture, so a capture that saw
  traffic but no request is distinguishable from one that was not watching.

The blocked request is then measured as a **delta** against the control: the
agreement check is told that one record and one captured body already belonged to
the control, so it cannot answer the blocked request's question with the control's
bytes. That delta is not a nicety. Without it, a request that sent nothing is
certified by an earlier request that sent something, which is a false green this
component produced in a real run once.

**The check is still not allowed to pass on silence alone.** `check_agreement`
scores "neither observer saw anything" as agreement only when a block receipt for
*this* request id exists, because from the observers alone a gateway that never
fired and a request that was never sent are indistinguishable. The receipt
written here is this run's own 422 body, byte for byte.

**The exit status is part of the claim.** If either observer count is non-zero
this script exits non-zero and says so. A blocked beat that shows outbound bytes
is a failed demo, and a demo that prints one and exits 0 has buried it.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

if __package__ in (None, ""):  # run as `python ../evals/demo_beat2_blocked.py`
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evals import beat_support
from evals.demo_beat1_approved import build_input
from evals.synthetic_phi import seed_corpus
from infra.capture.agreement import check_agreement

NETWORK = "medarx-beat2"
OBSERVER_IMAGE = "medarx-observer:latest"
CAPTURE_IMAGE = "medarx-capture:latest"

CONTROL_REQUEST_ID = "req-beat2-control-0001"
BLOCKED_REQUEST_ID = "req-beat2-blocked-0002"

#: The cases this beat can drive. Both are corpus cases that the kernel refuses
#: today, and they refuse for different reasons, which is the point of offering
#: both: an identifier with no registered replacer, and a report that is nothing
#: but identifiers.
CASES = ("unresolved", "all_phi")

#: What each layer tag names, so the report says which *component* refused rather
#: than leaving a reader to know the taxonomy. Verified against
#: `medarx.models.LAYERS` below, so a layer added to the contract without a name
#: here is a failure and not a blank.
REFUSING_COMPONENT = {
    "J": "component J, the application surface",
    "A": "component A, the allowlisted extractor",
    "C": "component C, pseudonymization",
    "D.1": "component D layer 1, deterministic removal and replacement",
    "D.2": "component D layer 2, the NER scan and the clinical recognisers",
    "D.3": "component D layer 3, the second validation pass",
    "E": "component E, the policy engine",
    "F": "component F, the model gateway",
}

#: Why the action codes mean what they mean here. `NER_UNRESOLVED` is the
#: load-bearing one: the block comes from the **absence of a registered
#: replacer** for a detected entity, never from a score falling below a
#: threshold, because a threshold is a configuration value and one settings
#: change would turn a deterministic refusal into a pass.
CODE_MEANING = {
    "NER_UNRESOLVED":
        "a detected entity has no registered replacer, so there is no safe "
        "transformation of it and the kernel refuses rather than guessing",
    "UNSHIFTED_DATE":
        "a date reached the payload without the patient offset applied",
    "LEFTOVER_PATTERN_MATCH":
        "the deterministic re-scan found a pattern that layers 1 and 2 did not "
        "resolve",
    "UNRESOLVED_EMPTY_BODY":
        "the layers resolved nothing at all, so approving would send a payload "
        "that no longer says anything",
}


def build_blocked_input(case_name: str) -> dict:
    """The corpus case's own request body, unchanged.

    Not a paraphrase and not a re-typed fixture: this is
    `Case.to_execution_request()` for the named corpus case, so the identifier
    that cannot be transformed is the one the evaluation harness measures.
    """
    case = next((c for c in seed_corpus.CASES if c.name == case_name), None)
    if case is None:
        raise SystemExit(
            f"unknown case {case_name!r}; this beat drives {', '.join(CASES)}"
        )
    return case.to_execution_request()


def run(case_name: str, out_dir: Path) -> dict:
    """Run the beat and return its report. Raises rather than reporting a red run.

    A demo that returns `agree: true` and exits 0 when a byte left the
    environment has converted its own failure into a data point. Every condition
    below aborts instead.
    """
    from medarx.models import LAYERS

    unknown = sorted(set(REFUSING_COMPONENT) - set(LAYERS))
    if unknown:
        raise AssertionError(
            f"REFUSING_COMPONENT names {unknown}, which the contract's closed "
            f"layer set does not contain; a receipt naming a layer nothing "
            f"defines is worse than a blank"
        )

    blocked_body = build_blocked_input(case_name)
    control_body = build_input()
    with beat_support.BeatEnvironment(
        out_dir, NETWORK, OBSERVER_IMAGE, CAPTURE_IMAGE,
    ) as environment:
        if environment.health_before.get("record_count") != 0:
            raise AssertionError(
                "a fresh observer holds nothing; this one held "
                f"{environment.health_before.get('record_count')!r} records before "
                f"the beat began, so 'zero at the end' would be worth nothing"
            )
        environment.start_capture()
        driven = beat_support.drive(
            out_dir / "kernel.db",
            environment.base_url,
            [
                beat_support.DrivenRequest(CONTROL_REQUEST_ID, control_body),
                beat_support.DrivenRequest(BLOCKED_REQUEST_ID, blocked_body),
            ],
            scope_study=blocked_body["study_context"]["study_reference"],
        )
        stopped = environment.stop_capture()
        environment.collect()

        control = driven.for_request(CONTROL_REQUEST_ID)
        blocked = driven.for_request(BLOCKED_REQUEST_ID)
        control_payload = driven.approved_payload(CONTROL_REQUEST_ID)

        if control["status"] != 200:
            raise AssertionError(
                "the control request was not approved, so this run cannot show "
                f"that the observers would have seen a request: HTTP "
                f"{control['status']} with {json.dumps(control['body'])}"
            )
        if blocked["status"] != 422:
            raise AssertionError(
                f"the {case_name!r} case was not blocked: HTTP {blocked['status']} "
                f"with {json.dumps(blocked['body'])}. A blocked beat that does not "
                f"block is a failed demo."
            )

        receipt = blocked["body"]
        guard = environment.control_evidence(control_payload["report_text"])
        if not beat_support.guard_holds(guard):
            raise AssertionError(
                "this run cannot distinguish 'nothing was sent' from 'nothing was "
                "watched', so its zeros prove nothing: " + json.dumps(guard, indent=2)
            )

        # First the control, on its own terms: both observers must positively
        # agree about it. Without this, the delta below would be a subtraction
        # from numbers nothing had established.
        control_report = check_agreement(
            control["body"]["approved_payload_hash"],
            control_payload["report_text"],
            environment.records,
            environment.pcap_text,
            CONTROL_REQUEST_ID,
            observer_live=True,
        )
        if not (control_report.agree and control_report.observer_record_count == 1
                and control_report.pcap_hit_count >= 1):
            raise AssertionError(
                "the control request was not observed by both observers, so the "
                "blocked request's silence cannot be measured: "
                + json.dumps(control_report.as_dict(), indent=2)
            )

        # The control request is also what licenses the capture's verdict. If it
        # was reassembled whole and matches the observer byte for byte, then a
        # request body that is not in the capture is a body that was not sent.
        beat_support.assert_capture_sound(
            stopped, environment.capture_readback,
            control_fully_observed=bool(control_report.agree
                                        and control_report.observer_record_count == 1
                                        and control_report.pcap_hit_count >= 1),
        )

        beat_support.write_block_receipt(environment.records, receipt)
        report = check_agreement(
            control["body"]["approved_payload_hash"],
            control_payload["report_text"],
            environment.records,
            environment.pcap_text,
            BLOCKED_REQUEST_ID,
            observer_live=True,
            records_before=control_report.observer_record_count,
            bodies_before=control_report.pcap_hit_count,
        )

        audit = next(record for record in driven.audit_records
                     if record["request_id"] == BLOCKED_REQUEST_ID)
        audit_body = audit["body"] or {}
        if audit["status"] != 200:
            raise AssertionError(
                f"the blocked request id is not in the audit log: "
                f"GET /v1/audit/records/{BLOCKED_REQUEST_ID} returned "
                f"{audit['status']}"
            )
        if audit_body.get("final_disposition") != "blocked":
            raise AssertionError(
                "the audit record does not carry the block: "
                + json.dumps(audit_body, indent=2)
            )

        # The claim, and the exit status that goes with it. The rule lives in
        # `beat_support.assert_nothing_left` so that a test can call it against
        # a doctored report and watch it refuse.
        beat_support.assert_nothing_left(report, request_id=BLOCKED_REQUEST_ID)
        if not report.agree:
            raise AssertionError(
                "the observers do not agree that nothing was sent: "
                + json.dumps(report.as_dict(), indent=2)
            )

        return {
            "beat": "beat2-blocked",
            "live": True,
            "case": case_name,
            "evidence_dir": str(out_dir),
            "status": "blocked",
            "http_status": blocked["status"],
            "request_id": BLOCKED_REQUEST_ID,
            "layer": receipt["layer"],
            "refusing_component": REFUSING_COMPONENT[receipt["layer"]],
            "action_codes": list(receipt["action_codes"]),
            "code_meaning": {code: CODE_MEANING.get(code, "no note recorded")
                             for code in receipt["action_codes"]},
            "block_receipt": receipt,
            "observer_record_count": report.observer_record_count,
            "pcap_hit_count": report.pcap_hit_count,
            "pcap_frame_count": report.pcap_frame_count,
            "agree": report.agree,
            "details": report.details,
            "differences": report.differences,
            "bytes_leaked": False,
            "control": {
                "request_id": CONTROL_REQUEST_ID,
                "purpose": "an approved request on the same observer, the same "
                           "bridge and the same capture, so that the blocked "
                           "request's silence is a measurement and not an absence "
                           "of measurement",
                "http_status": control["status"],
                "approved_payload_hash": control["body"]["approved_payload_hash"],
                "approved_content": control_payload["report_text"],
                "observer_record_count": control_report.observer_record_count,
                "pcap_hit_count": control_report.pcap_hit_count,
                "agree": control_report.agree,
            },
            "policy_mode": beat_support.POLICY_MODE,
            "policy_mode_note": "the deployment mode the audit records in this report carry; the gateway is a local observer and nothing left the host",
            "vacuity_guard": guard,
            "vacuity_guard_holds": True,
            "observer_record_delta": 0,
            "captured_body_delta": 0,
            "capture_readback": environment.capture_readback,
            "capture_readback_exit_status": stopped.returncode,
            "audit_block_event": audit_body,
            "audit_request_id_traceable": audit_body.get("request_id")
            == BLOCKED_REQUEST_ID,
            "planted_identifier_keys": beat_support.planted_identifier_keys(
                json.dumps(blocked_body, ensure_ascii=False)
            ),
        }


def render(report: dict) -> str:
    lines = [
        "=" * 72,
        f"Beat 2 — the blocked path ({report['case']}), observed from outside",
        "=" * 72,
        "",
        f"request id            {report['request_id']}",
        f"HTTP status           {report['http_status']}  (a block receipt, not a "
        f"problem document)",
        f"refused by            {report['refusing_component']}  (layer {report['layer']})",
        f"action codes          {', '.join(report['action_codes'])}",
        "",
        "-- WHY IT WAS REFUSED " + "-" * 48,
    ]
    for code, meaning in report["code_meaning"].items():
        lines += [f"  {code}", f"      {meaning}"]
    lines += [
        "",
        "-- ZERO BYTES AT BOTH OBSERVERS " + "-" * 36,
        f"observer records for this request  {report['observer_record_count']}",
        f"captured request bodies for it     {report['pcap_hit_count']}",
        f"frames in the whole capture        {report['pcap_frame_count']}",
        f"the check agrees                   {report['agree']}",
        "",
    ]
    for detail in report["details"]:
        lines.append(f"  * {detail}")
    lines += [
        "",
        "-- COULD THIS RUN HAVE PROVED IT WITH A BROKEN OBSERVER? " + "-" * 15,
        "no, and these are the four statements that say so:",
        json.dumps(report["vacuity_guard"], indent=2),
        "",
        "the control request, which both observers did see:",
        json.dumps(report["control"], indent=2),
        "",
        "-- THE RECEIPT, AS THE API RETURNED IT " + "-" * 33,
        json.dumps(report["block_receipt"], indent=2, ensure_ascii=False),
        "",
        "-- THE AUDIT RECORD, READ BACK OVER HTTP " + "-" * 32,
        f"GET /v1/audit/records/{report['request_id']} -> "
        f"{report['audit_block_event'].get('final_disposition')}",
        json.dumps(report["audit_block_event"], indent=2, ensure_ascii=False),
        "",
        f"evidence left in      {report['evidence_dir']}",
        "=" * 72,
    ]
    return "\n".join(lines)


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--case", choices=CASES, default="unresolved",
                        help="which corpus case to drive through the boundary")
    parser.add_argument("--json", action="store_true",
                        help="emit the report as JSON, with the input's identifiers masked")
    parser.add_argument("--out", type=Path, default=None,
                        help="where to leave the observer's records and the capture")
    args = parser.parse_args(argv)

    if not beat_support.docker_usable():
        print("beat 2 needs a usable Docker daemon: the observer is a container "
              "and the second observer is a capture of a real bridge. There is no "
              "fixture fallback, because a zero produced by a capture that was "
              "not watching is exactly the false green this beat exists to rule "
              "out.", file=sys.stderr)
        return 2

    out_dir = args.out or Path(tempfile.mkdtemp(prefix=f"medarx-beat2-{args.case}-"))
    report = run(args.case, out_dir)
    if args.json:
        printable = dict(report)
        printable["block_receipt"] = beat_support.mask_tree(report["block_receipt"])
        printable["audit_block_event"] = beat_support.mask_tree(
            report["audit_block_event"]
        )
        print(json.dumps(printable, indent=2, ensure_ascii=False))
    else:
        print(render(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
