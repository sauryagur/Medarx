"""Beat 1 — the approved path, end to end, with the outbound bytes observed twice.

    cd backend && uv run python ../evals/demo_beat1_approved.py
    cd backend && uv run python ../evals/demo_beat1_approved.py --json --out /tmp/beat1

**What this demonstrates.** A report carrying fabricated identifiers and a DICOM
header carrying fabricated identifiers goes in. What comes out the other side of
the boundary is a transformed payload with a policy approval behind it, a reply
from a provider, and — observed from **outside** the Medarx process by two
independent mechanisms — the bytes that actually crossed the network.

**The four artefacts, and where each one came from.** Every one of them is
produced by this run. Nothing here is a recorded capture, a committed fixture, or
a constant: the observer is a container started a few seconds ago and the
capture is a `tcpdump` that was writing while the request went past. The
`artefact_sources` block in the `--json` output says which is which, because a
demonstration that cannot be traced to a run is a story.

    input                      the request body this script posted
    transformed_payload        what component E approved, read out of the kernel
    model_response             what the provider replied
    captured_outbound_request  the bytes the two observers saw

**The two observers, and why there are two.** The observer is a process at the
far end of the socket: it writes down every byte it is given, so it is a record
made by the thing that received the data. The capture is a `tcpdump` on the
Docker bridge, in the host network namespace, so it is a record made by something
that never handled the request at all. Agreement between the two is evidence.
Either one alone is a witness.

**Where the approved payload comes from, which is the whole argument.** The
needle the comparison searches for is the report text of the `StructuredPayload`
component E approved, read out of the kernel in this process. It is not read from
the observer and it is not read from the capture. This project has already built
the version that read it from the gateway's own record of what it sent, and that
version returned the bytes of a *substituted* payload — so the needle matched
and the check certified a leak. An evidence mechanism that cannot fail is worse
than none, so the needle comes from the only party in the arrangement that is not
an observer.

**The input is not the corpus's `known_positive` case, and that is a reported
property rather than a convenience.** That case is **blocked** by the kernel as
it stands: layer D.2 refuses it with `UNSHIFTED_DATE` and
`LEFTOVER_PATTERN_MATCH`, because its `DOB: 1953-04-11` survives layer 1. It
cannot demonstrate the approved path, so this script assembles one from two
corpus cases that can: the `patient_id_label_spelling` report (an identifier in
the free text) and the `dicom_header_identifiers` metadata (identifiers in the
header). Both are the project's own fabricated inventory; no new data is
invented here, and no real data exists anywhere in this tree.

**`--json` masks the identifiers in the request body and nothing else.** The
transformed payload, the reply and the captured bytes are printed exactly as they
were, because a reader seeing the identifiers *absent* is the entire point; the
input is masked because a demonstration's machine-readable output is the part most
likely to be pasted into an issue, and the product spec draws exactly this line
between the two. The default print mode masks nothing, because the data is
fabricated and the before/after diff is the most useful thing on the screen.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

if __package__ in (None, ""):  # run as `python ../evals/demo_beat1_approved.py`
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evals import beat_support
from evals.synthetic_phi import seed_corpus
from infra.capture.agreement import check_agreement

NETWORK = "medarx-beat1"
OBSERVER_IMAGE = "medarx-observer:latest"
CAPTURE_IMAGE = "medarx-capture:latest"
REQUEST_ID = "req-beat1-approved-0001"

#: The two corpus cases this beat's input is assembled from, named here so the
#: report says which ones rather than leaving a reader to diff the body.
REPORT_CASE = "patient_id_label_spelling"
DICOM_CASE = "dicom_header_identifiers"


def build_input() -> dict:
    """The request body, with fabricated identifiers in both surfaces.

    `known_positive` would be the obvious choice and is not usable: the kernel
    blocks it at D.2. These two cases are the corpus's own approved halves — one
    puts an identifier in the free text, the other puts identifiers in the
    header — and the beat shows what happens when both surfaces carry one at
    once, which is the ordinary case and not a special one.
    """
    cases = {case.name: case for case in seed_corpus.ALL_CASES}
    return {
        "function": "Draft",
        "study_context": {
            "study_reference": seed_corpus.identifiers()["study_reference"],
            "modality": "CT",
        },
        "report_text": {
            "text": cases[REPORT_CASE].report_text,
            "source": seed_corpus.REPORT_SOURCE,
        },
        "dicom_metadata": dict(cases[DICOM_CASE].dicom_metadata),
    }


def run(out_dir: Path) -> dict:
    """Run the beat and return its report. Raises rather than returning a red run.

    A demo that returns a report saying `agree: false` and exits 0 has turned
    its own failure into a data point. Every condition below aborts instead, so
    a caller that got a report got a green one.
    """
    body = build_input()
    with beat_support.BeatEnvironment(
        out_dir, NETWORK, OBSERVER_IMAGE, CAPTURE_IMAGE,
    ) as environment:
        if environment.health_before.get("record_count") != 0:
            raise AssertionError(
                f"a fresh observer holds nothing; this one held "
                f"{environment.health_before.get('record_count')!r} records before "
                f"the beat began, so 'zero at the end' would be worth nothing"
            )
        environment.start_capture()
        driven = beat_support.drive(
            out_dir / "kernel.db",
            environment.base_url,
            [beat_support.DrivenRequest(REQUEST_ID, body)],
            scope_study=body["study_context"]["study_reference"],
        )
        stopped = environment.stop_capture()
        environment.collect()

        response = driven.for_request(REQUEST_ID)
        approved = driven.approved_payload(REQUEST_ID)
        captured = beat_support.captured_request_bodies(environment.pcap_text)

        if response["status"] != 200:
            raise AssertionError(
                f"the beat's own request was not approved: HTTP {response['status']} "
                f"with {json.dumps(response['body'])}"
            )
        if not captured:
            raise AssertionError(
                "the capture reassembled no request body at all, so there is "
                "nothing to compare; this is a broken capture, not a result"
            )
        if not approved["claimed_hash_matches_content"]:
            raise AssertionError(
                "the payload's own hash field does not match a hash recomputed "
                "from its content, so the hash the API reports is a claim and "
                "not a fact"
            )

        # The needle is the kernel's approved report text. Not the observer's
        # record, not the capture. See the module docstring for why that
        # distinction is the whole argument.
        report = check_agreement(
            response["body"]["approved_payload_hash"],
            approved["report_text"],
            environment.records,
            environment.pcap_text,
            REQUEST_ID,
            observer_live=True,
        )
        # A capture that saw nothing cannot support any claim about what did
        # not appear in it, and one that lost frames can only support the claim
        # if it demonstrably reassembled this request's whole body. `stop`
        # already says so with its exit status; this is where that becomes a
        # failed beat.
        beat_support.assert_capture_sound(
            stopped, environment.capture_readback,
            control_fully_observed=(report.agree
                                    and report.observer_record_count == 1
                                    and report.pcap_hit_count >= 1),
        )
        watching = environment.control_evidence(approved["report_text"])
        captured_text = captured[0].decode("utf-8", errors="replace")
        # Which inventory values the body this script posted actually carried,
        # named by key rather than by value: a report that listed the values it
        # planted would be publishing them, and the `--json` rendering is the
        # part most likely to be pasted into an issue. Computed from the body
        # rather than declared, so a demo that stopped planting identifiers
        # would report an empty list instead of quietly demonstrating nothing.
        planted = beat_support.planted_identifier_keys(json.dumps(body, ensure_ascii=False))
        survivors = [key for key in planted if beat_support.value_of(key) in captured_text]
        audit = driven.audit_records[0]

        if not report.agree:
            raise AssertionError(
                "the two observers do not agree with the approved payload: "
                + json.dumps(report.as_dict(), indent=2)
            )
        if survivors:
            raise AssertionError(
                "an identifier from the inventory is present in the captured "
                f"outbound bytes: {survivors}"
            )
        if not watching["observer_live"] or watching["pcap_frame_count"] == 0:
            raise AssertionError(
                "this run cannot tell 'nothing was sent' from 'nothing was "
                f"watched': {json.dumps(watching)}"
            )

        return {
            "beat": "beat1-approved",
            "live": True,
            "evidence_dir": str(out_dir),
            "request_id": REQUEST_ID,
            "status": "approved",
            "http_status": response["status"],
            "approved_payload_hash": report.approved_hash,
            "approved_content": approved["report_text"],
            "artefacts": {
                "input": body,
                "transformed_payload": {
                    "approved_by": "component E, via component F's verification",
                    "read_from": "the StructuredPayload object, in this process",
                    "function": approved["function"],
                    "policy_version": approved["policy_version"],
                    "report_text": approved["report_text"],
                    "dicom_fields": approved["dicom_fields"],
                    "payload_hash": approved["approved_payload_hash"],
                    "recomputed_payload_hash": approved["recomputed_payload_hash"],
                    "claimed_hash_matches_content":
                        approved["claimed_hash_matches_content"],
                    "report_text_as_it_reached_the_wire": json.loads(
                        captured[0].decode("utf-8")
                    )["messages"][1]["content"],
                },
                "model_response": {
                    "provider": "the observer container; there is no model in the path",
                    "read_from": "the API's 200 body",
                    "body": response["body"]["draft"],
                },
                "captured_outbound_request": {
                    "read_from": "tcpdump -X readback of the bridge, this run",
                    "body": captured_text,
                },
            },
            "policy_mode": beat_support.POLICY_MODE,
            "policy_mode_note": "the deployment mode the audit records in this report carry; the gateway is a local observer and nothing left the host",
            "artefact_sources": {
                "input": "the request body this script posted",
                "transformed_payload": "the kernel's own approved payload object",
                "model_response": "the API's 200 response body",
                "captured_outbound_request": "the packet capture, reassembled",
                "live": "every artefact above was produced by this run; no "
                        "fixture and no recorded capture is involved",
            },
            "captured_bytes": captured_text,
            "planted_identifier_keys": planted,
            "identifiers_in_captured_bytes": survivors,
            "observer_record_count": report.observer_record_count,
            "pcap_hit_count": report.pcap_hit_count,
            "pcap_frame_count": report.pcap_frame_count,
            "agree": report.agree,
            "details": report.details,
            "differences": report.differences,
            "observers_were_watching": watching,
            "capture_readback": environment.capture_readback,
            "capture_readback_exit_status": stopped.returncode,
            "audit_record": audit["body"],
            "audit_final_disposition": (audit["body"] or {}).get("final_disposition"),
        }


def render(report: dict) -> str:
    artefacts = report["artefacts"]
    lines = [
        "=" * 72,
        "Beat 1 — the approved path, observed from outside the process",
        "=" * 72,
        "",
        f"request id            {report['request_id']}",
        f"HTTP status           {report['http_status']}",
        f"approved payload hash {report['approved_payload_hash']}",
        f"model selected        {artefacts['model_response']['body']['model_id']}",
        "",
        "-- 1. INPUT " + "-" * 60,
        "the request body, with fabricated identifiers in the report text and in",
        "the DICOM metadata. Every value is invented; see",
        "evals/synthetic_phi/identifiers.json.",
        json.dumps(artefacts["input"], indent=2, ensure_ascii=False),
        "",
        "-- 2. TRANSFORMED PAYLOAD " + "-" * 47,
        "what component E approved, read out of the kernel itself. The report",
        "identifier has been replaced and the header identifiers dropped, shifted",
        "or banded; none of them is here.",
        json.dumps(artefacts["transformed_payload"], indent=2, ensure_ascii=False),
        "",
        "-- 3. MODEL RESPONSE " + "-" * 53,
        "what came back through the gateway. There is no model in this path: the",
        "observer is the provider, and it computed this string itself.",
        json.dumps(artefacts["model_response"]["body"], indent=2, ensure_ascii=False),
        "",
        "-- 4. CAPTURED OUTBOUND REQUEST " + "-" * 42,
        "the bytes on the wire, reassembled by tcpdump from a capture running in",
        "the host network namespace. This is what left the environment.",
        artefacts["captured_outbound_request"]["body"],
        "",
        "-- THE TWO OBSERVERS " + "-" * 50,
        f"observer records      {report['observer_record_count']}",
        f"captured request hits {report['pcap_hit_count']}",
        f"frames in the capture {report['pcap_frame_count']}",
        f"they agree            {report['agree']}",
        "",
    ]
    for detail in report["details"]:
        lines.append(f"  * {detail}")
    lines += [
        "",
        "-- WERE THE OBSERVERS WATCHING? " + "-" * 43,
        json.dumps(report["observers_were_watching"], indent=2),
        "",
        "-- AUDIT READBACK " + "-" * 55,
        f"GET /v1/audit/records/{report['request_id']} -> {report['audit_final_disposition']}",
        json.dumps(report["audit_record"], indent=2, ensure_ascii=False),
        "",
        f"evidence left in      {report['evidence_dir']}",
        "=" * 72,
    ]
    return "\n".join(lines)


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", action="store_true",
                        help="emit the report as JSON, with the input's identifiers masked")
    parser.add_argument("--out", type=Path, default=None,
                        help="where to leave the observer's records and the capture")
    args = parser.parse_args(argv)

    if not beat_support.docker_usable():
        print("beat 1 needs a usable Docker daemon: the observer is a container "
              "and the second observer is a capture of a real bridge. There is no "
              "fixture fallback, because a fixture that silently stood in for a "
              "capture is exactly the substitution this beat exists to rule out.",
              file=sys.stderr)
        return 2

    out_dir = args.out or Path(tempfile.mkdtemp(prefix="medarx-beat1-"))
    report = run(out_dir)
    if args.json:
        printable = dict(report)
        printable["artefacts"] = dict(report["artefacts"])
        printable["artefacts"]["input"] = beat_support.mask_tree(report["artefacts"]["input"])
        print(json.dumps(printable, indent=2, ensure_ascii=False))
    else:
        print(render(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
