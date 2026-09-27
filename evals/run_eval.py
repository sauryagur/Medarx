"""Run the evaluation and print the numbers. This is the entry point; the
measurement itself lives in `evals/metrics.py` and `evals/runner.py`.

    cd backend && uv run python ../evals/run_eval.py

**What this is.** A research instrument for this repository. It measures *this
codebase*, over *fabricated text*, and its figures are a claim about neither any
real corpus nor any real patient. No real DICOM sample, no downloaded dataset,
no MIMIC, no TCIA: every value in the corpus is invented, and
`identifiers.json` carries the marker that says so.

**Why synthetic injection and not a dataset.** TCIA is not a detection-recall
oracle. A corpus that has already been stripped of its identifiers cannot say
how many of them a pipeline would have caught in the form they arrived in — the
misses were removed along with the hits. Only a corpus with a known span for
every identifier can produce a denominator, and only a synthetic one can produce
that honestly.

**How the corpus and the metric stay independent.**

* The corpus (`evals/synthetic_phi/`) declares *values*; the scorer
  (`evals/metrics.py`) locates them by searching the rendered text. The corpus
  never hands over a span, so a case whose prose was edited cannot grade
  itself: `locate_planted` raises rather than inventing a truth.
* `metrics` imports no corpus module. It is handed spans and hits and knows
  nothing about radiology.
* Precision is measured on a **different corpus** — identifier-free prose in
  `clean_prose.py` — on which any mask is a false positive by construction, so
  recall and precision share no data, no templates and no fixtures.
* A falsifiability control runs on every invocation: a phantom identifier is
  planted where no detector can reach it and the recall must fall. A benchmark
  that cannot report a worse number is not a benchmark.

**Exit codes.** `0` when nothing regressed and the control moved. `1` when a
figure moved against the recorded baseline, or the falsifiability control
failed to move. `--write-baseline` records the current run as the baseline for
later comparisons; it never widens a threshold on its own.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

if __package__ in (None, ""):  # run as `python ../evals/run_eval.py`
    # `sys.path[0]` is this file's own directory, not the repository root, so
    # `import evals` would fail from the documented command line. The
    # alternative is to require `PYTHONPATH=..` and have every future reader
    # rediscover that; this is one line and it is explicit about why.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evals import metrics, runner
from evals.synthetic_phi import clean_prose, seed_corpus
from medarx.config import Settings
from medarx.pseudonym.mapping_store import MappingStore

__all__ = ["AUDIT_KEY", "BASELINE_PATH", "PROFILES", "RESULTS_PATH", "collect", "main", "render"]

#: Where the recorded figures live. A reviewed artifact, compared against
#: rather than consumed: a number only becomes a gate once someone has looked
#: at it and agreed it is the number this codebase currently produces.
BASELINE_PATH = seed_corpus.CORPUS_DIR / "baseline.json"

#: Where each run writes its measurement record.
RESULTS_PATH = seed_corpus.CORPUS_DIR / "eval_results.json"

#: A synthetic, non-secret audit key. Never a real credential. It is fixed so
#: the date shift and every surrogate are the same on every run: an offset read
#: from the environment would make every figure below a function of the machine
#: it happened to be measured on.
AUDIT_KEY = "medarx-eval-instrument-not-a-credential"  # noqa: S105

#: The files the corpus is made of, hashed by `corpus_fingerprint` in this
#: order. `identifiers.json` and `report_template.txt` decide what is planted
#: and where it is written; `clean_prose.py` is the precision corpus. Changing
#: any of them changes every figure below, so the gate refuses to compare until
#: the baseline is re-recorded.
_CORPUS_SOURCES = ("identifiers.json", "report_template.txt", "clean_prose.py")

#: The two settings profiles every figure is reported under. The kernel has two
#: legitimate configurations here, and quoting one of them without saying which
#: is how a false-positive count of 5/28 became 6/28 and read as a regression.
PROFILES = {"date_order unset": None, "date_order MDY": "MDY"}


def _settings(date_order: str | None) -> Settings:
    return Settings(audit_key=AUDIT_KEY, date_order=date_order)


def _report_text_surface(case) -> tuple:
    """The scanned text of a `report_text` identifier: the report body itself."""
    return case.report_text, "report_text"


def _dicom_prose_surface(case) -> tuple:
    """The scanned text of a `dicom_header` identifier, when there is any.

    Exactly one allowlisted DICOM attribute holds prose — `PriorReportText` —
    and it is the only metadata value redaction layer 2 scans. Every other
    metadata value is a keyword, a date, or an age band, handled structurally.
    A case that carries no prose attribute therefore has no scanned surface at
    all, and this returns empty text so it contributes no hits; the planted
    spans for such a case are counted separately under the structural row.
    """
    value = case.dicom_metadata.get(seed_corpus.DICOM_PROSE_ATTRIBUTE, "")
    return value, f"dicom_header.{seed_corpus.DICOM_PROSE_ATTRIBUTE}"


def collect() -> dict:
    """Every figure this harness reports, as plain data.

    No printing, no thresholds, no exit codes: this is the measurement, and
    keeping it free of judgement is what lets a test consume the same numbers
    the command prints.
    """
    patient_reference = seed_corpus.identifiers()["patient_reference"]
    if runner.PATIENT_REF != patient_reference:
        raise SystemExit(
            f"runner.PATIENT_REF={runner.PATIENT_REF!r} does not match the "
            f"corpus's patient reference {patient_reference!r}; the date shift "
            f"would not be the one the corpus was built under"
        )

    # Detection does not depend on the settings profile: `scan_entities` reads
    # only the score threshold, and layer 2 always passes 0.0. Measured once so
    # the two profiles cannot print two different detection tables.
    report_text = runner.measure_detection(
        seed_corpus.ALL_CASES, "report_text", _report_text_surface
    )
    dicom_prose = runner.measure_detection(
        seed_corpus.ALL_CASES, "dicom_header", _dicom_prose_surface,
        attribute=seed_corpus.DICOM_PROSE_ATTRIBUTE,
    )

    record: dict = {
        "synthetic": True,
        "notice": (
            "A research instrument for this repository. Fabricated input only. "
            "These figures are a measurement of this codebase over invented "
            "text; they are not a claim about any real corpus."
        ),
        "profiles": {},
    }
    with tempfile.TemporaryDirectory() as work:
        for label, order in PROFILES.items():
            settings = _settings(order)
            store = MappingStore(
                f"sqlite:///{Path(work) / f'map-{order}.db'}", AUDIT_KEY
            )
            try:
                end_to_end = runner.measure_end_to_end(
                    seed_corpus.ALL_CASES, store, settings
                )
                unset = runner.measure_clean_corpus(
                    clean_prose.ORDINARY_SENTENCES, store, _settings(None)
                )
                declared = runner.measure_clean_corpus(
                    clean_prose.ORDINARY_SENTENCES, store, _settings("MDY")
                )
                known = runner.measure_clean_corpus(
                    tuple(t[0] for t in clean_prose.KNOWN_FALSE_POSITIVES),
                    store,
                    settings,
                )
            finally:
                store.close()
            record["profiles"][label] = {
                "detection_report_text": _detection_block(report_text),
                "detection_dicom_header": _detection_block(dicom_prose),
                "structural_dicom_header": _structural_surfaces(settings, store),
                "end_to_end": {
                    "checked": end_to_end.checked,
                    "survived": end_to_end.survived,
                    "survivors": [list(s) for s in end_to_end.survivors],
                    "backstopped": [list(b) for b in end_to_end.backstopped],
                    "blocked": list(end_to_end.blocked),
                    "approved": list(end_to_end.approved),
                },
                "clean_corpus": _mask_block(unset, "date_order unset"),
                "clean_corpus_declared": _mask_block(declared, "date_order MDY"),
                "known_false_positives": _mask_block(known, "date_order MDY"),
            }

    record["control"] = {
        source: runner.phantom_control(
            seed_corpus.ALL_CASES, source, surface, attribute=attribute
        )
        for source, surface, attribute in (
            ("report_text", _report_text_surface, None),
            ("dicom_header", _dicom_prose_surface,
             seed_corpus.DICOM_PROSE_ATTRIBUTE),
        )
    }
    record["corpus_fingerprint"] = corpus_fingerprint()
    record["unread_request_fields"] = [
        {"field": name, "reason": runner.REQUEST_FIELD_NOTES.get(name, "")}
        for name in runner.UNREAD_REQUEST_FIELDS
    ]
    record["contract_notes"] = [
        {
            "case": case.name,
            "expressible": case.contract_expressible,
            "note": case.contract_note,
        }
        for case in seed_corpus.ALL_CASES
        if case.contract_note is not None
    ]
    return record


def corpus_fingerprint() -> str:
    """A digest of the three files the corpus is made of.

    The gate compares numerators, which is right — a denominator is fixed by
    the corpus, so a changed denominator means the corpus changed, not that
    the kernel improved. But a corpus edit that *raises* a rate is otherwise
    indistinguishable from a kernel improvement, and nothing would report
    that the ground under the figure had moved. This digest is that report: it
    goes into `baseline.json` and is compared before any rate, and a mismatch
    says "the corpus changed" rather than comparing two numbers taken over
    different questions.

    Hashed by content, not by mtime, and in a fixed order, so an unrelated
    edit elsewhere in the tree cannot move it.
    """
    digest = hashlib.sha256()
    for name in _CORPUS_SOURCES:
        digest.update(name.encode("utf-8"))
        digest.update((seed_corpus.CORPUS_DIR / name).read_bytes())
    return digest.hexdigest()


def _detection_block(report: runner.DetectionReport) -> dict:
    return {
        "planted": report.planted,
        "unscanned": report.unscanned,
        "cases": list(report.cases),
        "by_entity": {
            entity: {
                "tp": tally.tp, "fp": tally.fp, "fn": tally.fn,
                "mislabelled": tally.mislabelled,
                "precision": list(tally.precision), "recall": list(tally.recall),
            }
            for entity, tally in sorted(report.by_key.items())
        },
        "by_surface_and_entity": {
            f"{surface}:{entity}": {
                "tp": tally.tp, "fp": tally.fp, "fn": tally.fn,
                "mislabelled": tally.mislabelled,
            }
            for (entity, surface), tally in sorted(report.by_surface_key.items())
        },
    }


def _mask_block(rate: metrics.MaskRate, label: str) -> dict:
    return {
        "profile": label,
        "masked": rate.masked,
        "shifted": rate.shifted,
        "identical": rate.identical,
        "blocked": rate.blocked,
        "denominator": rate.denominator,
        "examples": [list(pair) for pair in rate.detail],
    }


def _structural_surfaces(settings: Settings, store: MappingStore) -> dict:
    """The DICOM-metadata identifiers the pipeline removes without detecting.

    `PatientID`, `AccessionNumber` and `InstitutionName` are dropped by
    component A; `StudyDate` is shifted by component C; `PatientAge` is banded by
    component A. None of that is a *detection*, and reporting it as a recall
    would be the single most misleading thing this harness could do: a 100%
    figure over a mechanism that cannot fail. So it gets its own row with the
    mechanism named, and the detection table for the same input source prints
    `n/a (0 measured)` because there is no scanned text to measure.
    """
    case = next(
        c for c in seed_corpus.ALL_CASES if c.name == "dicom_header_identifiers"
    )
    outcome = runner.execute(case, store, settings)
    mechanisms = {
        "PatientID": "dropped at layer A (no payload field)",
        "AccessionNumber": "dropped at layer A (no payload field)",
        "InstitutionName": "dropped at layer A (no payload field)",
        "StudyDate": "shifted at component C (patient offset)",
        "PatientAge": "banded at layer A (decade band)",
    }
    carried = dict(outcome.approved_dicom_fields)
    attributes = {
        attribute: {
            "value": case.dicom_metadata[attribute],
            "mechanism": mechanism,
            "in_approved_payload": attribute in carried
            or any(
                case.dicom_metadata[attribute] in value for value in carried.values()
            ),
        }
        for attribute, mechanism in mechanisms.items()
        if attribute in case.dicom_metadata
    }
    return {
        "note": (
            "Structural, not detection: no recognizer runs on these values, so "
            "a recall over them would be a figure for a mechanism that cannot fail"
        ),
        "attributes": attributes,
    }


# -- Presentation --------------------------------------------------------------


def render(record: dict) -> str:
    """The printed table. Every rate is printed as `numerator/denominator`."""
    lines: list[str] = []
    add = lines.append
    add("Medarx evaluation - synthetic PHI corpus")
    add(record["notice"])
    for label, profile in record["profiles"].items():
        add("")
        add(f"=== profile: {label} ===")
        add("1. DETECTION RECALL - did the detector name the planted identifier?")
        add("   counts, not rates; per entity type and per input source")
        for source, block in (
            ("report_text", profile["detection_report_text"]),
            ("dicom_header", profile["detection_dicom_header"]),
        ):
            add(
                f"   source {source}: planted {block['planted']} in "
                f"{len(block['cases'])} case(s) [{', '.join(block['cases']) or 'none'}]"
                f"; {block['unscanned']} more sit on values no recognizer reads"
            )
            if block["planted"] == 0:
                add("     n/a (0 measured) - no scanned text on this source")
            for entity, row in block["by_entity"].items():
                add(
                    f"     {entity:22s} tp={row['tp']} fp={row['fp']} fn={row['fn']}"
                    f" mislabelled={row['mislabelled']}  precision="
                    f"{metrics.format_rate(tuple(row['precision']))}  recall="
                    f"{metrics.format_rate(tuple(row['recall']))}"
                )
        structural = profile["structural_dicom_header"]
        add("")
        add("2. DICOM-METADATA IDENTIFIERS - structural, not detection")
        add(f"   {structural['note']}")
        for attribute, row in structural["attributes"].items():
            state = "LEAKED" if row["in_approved_payload"] else "absent"
            add(f"     {attribute:18s} {row['mechanism']:40s} {state}")
        end = profile["end_to_end"]
        add("")
        add("3. NON-SURVIVAL - the privacy claim, over the whole kernel")
        add(f"     planted identifiers checked: {end['checked']}")
        add(
            f"     reached an approved payload: {end['survived']}/{end['checked']}"
        )
        for survivor in end["survivors"]:
            add(f"       LEAKED {survivor[0]} {survivor[1]} ({survivor[2]})")
        add(
            "     stopped only by layer 3's deterministic re-read: "
            f"{len(end['backstopped'])}"
        )
        for case_name, entity in end["backstopped"]:
            add(f"       {case_name}: {entity}")
        add(
            f"     cases blocked: {len(end['blocked'])}  approved: "
            f"{len(end['approved'])}"
        )
        for name in end["blocked"]:
            add(f"       blocked  {name}")
        for name in end["approved"]:
            add(f"       approved {name}")
        add("")
        add("4. FALSE POSITIVES - prose with no identifier in it")
        for key, title in (
            ("clean_corpus", "ordinary radiology prose, date order unset"),
            ("clean_corpus_declared", "ordinary radiology prose, date order MDY"),
            ("known_false_positives", "the six named false-positive sentences"),
        ):
            block = profile[key]
            add(
                f"     {title} (n={block['denominator']}): "
                f"masked {block['masked']}, date-shifted only {block['shifted']}, "
                f"identical {block['identical']}, blocked {block['blocked']}"
            )
            for sentence, masked in block["examples"]:
                add(f"       {sentence!r}")
                add(f"         -> {masked!r}")
    add("")
    add("=== falsifiability control ===")
    for source, control in record["control"].items():
        before = (
            metrics.format_rate(tuple(control["before"]))
            if control["before"] else "n/a"
        )
        after = (
            metrics.format_rate(tuple(control["after"]))
            if control["after"] else "n/a"
        )
        state = "FELL (good)" if control["fell"] else "DID NOT FALL"
        add(
            f"   {source}: recall {before} -> {after} after planting one "
            f"identifier no detector returned: {state}"
        )
    add("")
    add(f"=== corpus fingerprint: {record['corpus_fingerprint'][:16]}... ===")
    if record["contract_notes"]:
        add("=== contract notes ===")
        for note in record["contract_notes"]:
            state = "expressible" if note["expressible"] else "NOT expressible"
            add(f"   {note['case']} ({state}): {note['note']}")
    if record["unread_request_fields"]:
        add("")
        add("=== request fields the kernel does not read ===")
        for entry in record["unread_request_fields"]:
            add(f"   {entry['field']}: {entry['reason']}")
    return "\n".join(lines)


# -- Baseline comparison -------------------------------------------------------


def _moved(now, then, better: str) -> bool:
    """Whether a numerator moved the wrong way.

    `None` means the rate had no denominator, so there is nothing to compare and
    nothing to have regressed. Serialising a rate as `[null, 0]` rather than as
    `0.0` is what keeps "not measured" from being read as "measured zero", and
    it is why this returns a bool rather than a difference.
    """
    if now is None or then is None:
        return False
    return now < then if better == "up" else now > then


def _regressions(current: dict, baseline: dict) -> list:
    """Every figure that moved in the wrong direction against the baseline.

    Two stages, and the first one can stop it. A corpus that has changed under
    a baseline makes every comparison below meaningless — not because the
    numbers are wrong but because they answer a different question than the
    ones recorded — so a fingerprint mismatch is reported on its own and the
    rate comparison is skipped rather than performed and believed.

    Otherwise only numerators are compared. A denominator is fixed by the
    corpus, and the fingerprint is what establishes that, so a changed
    denominator here means the kernel changed behaviour rather than the
    question.
    """
    worse: list = []
    recorded_fingerprint = baseline.get("corpus_fingerprint")
    if recorded_fingerprint is None:
        worse.append(
            "the baseline records no corpus fingerprint, so nothing here can be "
            "compared: re-record it with --write-baseline"
        )
        return worse
    if recorded_fingerprint != current["corpus_fingerprint"]:
        worse.append(
            f"the corpus changed under the baseline ({', '.join(_CORPUS_SOURCES)}; "
            f"fingerprint {recorded_fingerprint[:16]}... -> "
            f"{current['corpus_fingerprint'][:16]}...), so every figure below is "
            "measured over a different question and none of them is compared"
        )
        return worse
    for label, profile in current["profiles"].items():
        recorded = baseline.get("profiles", {}).get(label)
        if recorded is None:
            worse.append(f"{label}: no baseline recorded for this profile")
            continue
        for key in ("detection_report_text", "detection_dicom_header"):
            was_block = recorded.get(key, {}).get("by_entity", {})
            for entity, row in profile[key]["by_entity"].items():
                was = was_block.get(entity)
                if was is None:
                    worse.append(f"{label}/{key}/{entity}: not in the baseline")
                    continue
                for rate in ("recall", "precision"):
                    if _moved(row[rate][0], was[rate][0], "up"):
                        worse.append(
                            f"{label}/{key}/{entity}: {rate} "
                            f"{was[rate][0]}/{was[rate][1]} -> "
                            f"{row[rate][0]}/{row[rate][1]}"
                        )
        for key in (
            "clean_corpus", "clean_corpus_declared", "known_false_positives",
        ):
            if _moved(profile[key]["masked"], recorded[key]["masked"], "down"):
                worse.append(
                    f"{label}/{key}: masked {recorded[key]['masked']}/"
                    f"{recorded[key]['denominator']} -> "
                    f"{profile[key]['masked']}/{profile[key]['denominator']}"
                )
        end_now, end_was = profile["end_to_end"], recorded["end_to_end"]
        if _moved(end_now["survived"], end_was["survived"], "down"):
            worse.append(
                f"{label}/end_to_end: reached an approved payload "
                f"{end_was['survived']}/{end_was['checked']} -> "
                f"{end_now['survived']}/{end_now['checked']}"
            )
        if _moved(len(end_now["backstopped"]), len(end_was["backstopped"]), "up"):
            worse.append(
                f"{label}/end_to_end: values stopped only by layer 3 "
                f"{len(end_was['backstopped'])} -> {len(end_now['backstopped'])}"
            )
    return worse


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the Medarx synthetic-PHI evaluation.")
    parser.add_argument(
        "--write-baseline", action="store_true",
        help="record this run as the baseline for later comparisons",
    )
    parser.add_argument(
        "--no-gate", action="store_true",
        help="print the table without comparing against the recorded baseline",
    )
    args = parser.parse_args(argv)

    record = collect()
    print(render(record))
    RESULTS_PATH.write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    if args.write_baseline:
        BASELINE_PATH.write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(f"\nBaseline recorded at {BASELINE_PATH}.")
        return 0

    failures: list = [
        f"the recall metric did not fall when an undetectable identifier was "
        f"planted on {source}: the figure for that source is not a measurement"
        for source, control in record["control"].items()
        if not control["fell"]
    ]
    if not args.no_gate and BASELINE_PATH.exists():
        failures.extend(
            _regressions(record, json.loads(BASELINE_PATH.read_text(encoding="utf-8")))
        )
    else:
        print(
            "\nNo baseline recorded, or gating skipped: this run reports figures "
            "but does not compare them."
        )

    if failures:
        print("\nFAILED")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("\nOK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
