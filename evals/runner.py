"""The driver: runs corpus cases through the real kernel and grades them.

`metrics` is the arithmetic; this is the plumbing. The split is the point —
the arithmetic is handed spans and hits and knows nothing about radiology,
while everything project-specific (which function to call, which store to use,
which patient the shift belongs to) lives here and nowhere else.

**What the driver takes from the corpus, and what it does not.** It imports one
name from `seed_corpus`: `INTERNAL_FUNCTION`, the wire-spelling-to-internal
spelling table, which is a *vocabulary* and not a verdict — it says that
`"Draft"` is spelled `draft` internally and nothing about whether a case passes.
Every other thing arrives as an argument: the cases, the store, the settings. In
particular this module never reads `identifiers.json` to decide anything; the
corpus states what it planted and the driver goes and finds it.

**The numbers it produces, and why they are more than one.**

* *Detection recall* — did the detector name this identifier, at the span, with
  the entity type the corpus declared? A claim about one layer.
* *False positives* — over prose with no identifier in it, how many sentences
  came back with a `[REDACTED:...]` mask? The same layer, the other direction,
  measured on a corpus that shares nothing with the planted one.
* *Non-survival* — did any planted value reach an approved payload? The privacy
  claim, and a claim about the *whole* kernel rather than the detector. A value
  can be guaranteed absent purely because every run carrying it blocked, and
  reporting that as a detection would overstate what the recognizers do.
* *Backstops* — which planted values got past the detector and were stopped by
  layer 3's deterministic re-read. This is the number that makes the difference
  between the first and the third a measured number rather than a worry.
"""

from __future__ import annotations

from dataclasses import dataclass

from evals import metrics
from evals.synthetic_phi.seed_corpus import (
    INTERNAL_FUNCTION,
    Case,
    locate_planted,
)
from medarx.config import Settings
from medarx.extraction.payload_extractor import pipeline_for
from medarx.extraction.study_context import StudyContext
from medarx.policy.policy_engine import PolicyEngine
from medarx.pseudonym.mapping_store import MappingStore
from medarx.pseudonym.pseudonymize import pseudonymize_payload
from medarx.redaction.ner import scan_entities
from medarx.redaction.pipeline import run_redaction

__all__ = [
    "CLEAN_METADATA",
    "PATIENT_REF",
    "STUDY_REF",
    "STUDY_UID",
    "DetectionReport",
    "EndToEndReport",
    "build_clean_case",
    "execute",
    "macro_recall",
    "measure_clean_corpus",
    "measure_detection",
    "measure_end_to_end",
    "phantom_control",
]

#: The patient whose surrogate and date shift every corpus case is measured
#: under. Fixed, and checked against the corpus's own inventory by `run_eval`,
#: because an offset read from anywhere else would make every shifted date in
#: the report a different number on every run.
PATIENT_REF = "PAT-0001"

#: The internal study reference the corpus requests carry. Component C
#: substitutes it for a surrogate before anything else happens.
STUDY_REF = "STU-0001"
#: A syntactically valid DICOM UID. It is *not* a `StudyInstanceUID`: the
#: payload carries a surrogate, never this.
STUDY_UID = "1.2.826.0.1.3680043.8.498.1138.100.0.1"


@dataclass(frozen=True)
class DetectionReport:
    """Per-entity-type detection counts over a set of surfaces.

    `by_key` is keyed by entity type alone, which is the row a reader quotes.
    `by_surface_key` keeps the input surface as well, which is the row that
    says *where* the number came from. `unscanned` counts planted identifiers
    on this input source that sit in a field no recognizer reads; they are
    reported, not scored, so a structural keyword drop can never inflate a
    detection rate. Both tables are counts; neither is a rate, because a rate
    cannot be reconstructed from a table of rates and can silently be printed
    with the wrong denominator.
    """

    by_key: dict
    by_surface_key: dict
    planted: int
    cases: tuple
    unscanned: int = 0


#: Metadata held constant across the *clean* corpus. It carries no identifier,
#: so nothing about the false-positive rate depends on it; it is here because a
#: payload with no metadata at all is not a request the kernel sees in practice.
CLEAN_METADATA: dict[str, str] = {
    "Modality": "CT",
    "StudyDate": "20260114",
    "PatientAge": "045Y",
}



@dataclass(frozen=True)
class EndToEndReport:
    """What survived, and what was stopped, across every case."""

    checked: int
    survived: int
    survivors: tuple
    backstopped: tuple
    blocked: tuple
    approved: tuple


def execute(case: Case, store: MappingStore, settings: Settings) -> metrics.Outcome:
    """One case, end to end, through the real layers and the real policy engine.

    Executed through the **published request shape**, not through a
    hand-assembled internal payload: the wire function spelling is translated at
    the boundary, the report text and the keyword-named metadata go into
    `pipeline_for` exactly as `ExecutionRequest` delivers them, and the prior
    references come from `prior_studies`. A harness that built the payload
    itself would be measuring a call no caller can make.
    """
    function = INTERNAL_FUNCTION[case.function]
    study = StudyContext(
        study_uid=STUDY_UID,
        study_ref=STUDY_REF,
        patient_ref=PATIENT_REF,
        function=function,
        prior_study_refs=case.prior_studies,
    )
    source = pipeline_for(
        function,
        study,
        case.report_text,
        dict(case.dicom_metadata),
        settings.policy_version,
    )
    payload = pseudonymize_payload(source, PATIENT_REF, store)
    outcome = run_redaction(
        payload, PATIENT_REF, store, PolicyEngine(settings), settings, source=source
    )
    approved = outcome.approved
    return metrics.Outcome(
        case_name=case.name,
        blocked=outcome.blocked,
        approved_text=None if approved is None else approved.report_text,
        approved_dicom_fields={} if approved is None else dict(approved.dicom_fields),
        dispositions=tuple(outcome.dispositions),
        decision_code=outcome.decision_code,
    )


def _planted_spans(case: Case, source: str) -> list:
    """Every planted identifier on one input source, with a derived span."""
    planted = []
    for truth in case.ground_truth:
        if truth.source != source:
            continue
        surface, start, end = locate_planted(case, truth)
        planted.append(metrics.Planted(
            entity_type=truth.entity_type,
            value=truth.value,
            surface=surface,
            start=start,
            end=end,
        ))
    return planted


def _detections(text: str, surface: str) -> list:
    """The detector's hits on one surface, at the threshold layer 2 uses.

    `min_score=0.0`, which is what redaction layer 2 passes: a candidate the
    scan filtered out could not be blocked downstream, so filtering it here
    would measure a different system from the one that ships.
    """
    return [
        metrics.Detection(h.entity_type, h.start, h.end, surface, h.score)
        for h in scan_entities(text, 0.0)
    ]


def _scan_source(
    cases: tuple, source: str, surface_for, attribute: str | None = None
) -> tuple:
    """`(planted, detected, case_names)` for one input source over the cases.

    Spans and hits are returned **ungraded**, so the phantom control can add a
    planted value and re-grade against exactly the same scan rather than
    against a second, possibly different, one. `attribute` restricts the
    measurement to the one field on the surface a recognizer actually reads;
    see `measure_detection`.
    """
    planted: list = []
    detected: list = []
    used: list = []
    for case in cases:
        if not [g for g in case.ground_truth if g.source == source]:
            continue
        text, surface = surface_for(case)
        spans = [
            span for span in _planted_spans(case, source)
            if attribute is None or span.surface == f"dicom_header.{attribute}"
        ]
        if not spans:
            continue
        planted.extend(spans)
        detected.extend(_detections(text, surface))
        used.append(case.name)
    return planted, detected, used


def _merge(into: dict, fresh: dict) -> dict:
    """Sum per-`(entity_type, surface)` tallies into an accumulating table."""
    for key, tally in fresh.items():
        into[key] = into.get(key, metrics.Tally()).merged(tally)
    return into


def measure_detection(
    cases: tuple, source: str, surface_for, attribute: str | None = None
) -> DetectionReport:
    """Detection recall over the cases, on one input source.

    `surface_for(case)` returns `(text, surface_name)` for the scanned text that
    source reads. `attribute`, when given, names the one field on that surface
    a recognizer can actually read: a `dicom_header` identifier sitting in
    `PatientID` or `StudyDate` is not scanned by anything, so measuring it here
    would score a keyword drop as a detection. Those values are counted in
    `unscanned` and reported on the structural row instead, which keeps the
    recall denominator to the identifiers a detector was ever asked to find.

    **Tallied per case, then merged.** Spans index the text of one case, so
    pooling every case's spans and every case's hits under one surface name
    would let a hit in case A be matched against a planted span in case B. The
    merge happens after each case has been graded on its own.
    """
    by_surface: dict = {}
    planted_count = 0
    unscanned = 0
    used: list[str] = []
    for case in cases:
        if not [g for g in case.ground_truth if g.source == source]:
            continue
        text, surface = surface_for(case)
        if attribute is not None and not text:
            unscanned += len(_planted_spans(case, source))
            continue
        planted = [
            span for span in _planted_spans(case, source)
            if attribute is None or span.surface == f"dicom_header.{attribute}"
        ]
        unscanned += len(_planted_spans(case, source)) - len(planted)
        if not planted:
            continue
        planted_count += len(planted)
        by_surface = _merge(
            by_surface, metrics.tally(planted, _detections(text, surface))
        )
        used.append(case.name)
    by_key: dict = {}
    for (entity_type, _surface), tally in by_surface.items():
        by_key[entity_type] = by_key.get(entity_type, metrics.Tally()).merged(tally)
    return DetectionReport(
        by_key=by_key,
        by_surface_key=by_surface,
        planted=planted_count,
        cases=tuple(used),
        unscanned=unscanned,
    )


def macro_recall(by_surface_key: dict) -> tuple:
    """`(tp, tp + fn)` summed over every key that has a denominator."""
    total = metrics.Tally()
    for tally in by_surface_key.values():
        total = total.merged(tally)
    return total.recall


def phantom_control(
    cases: tuple, source: str, surface_for, attribute: str | None = None
) -> dict:
    """Whether the reported recall **falls** when one identifier is never found.

    The falsifiability guard, run through the same arithmetic that produces the
    table: one extra planted span is added past the end of a real surface, so
    no detection can match it, and the macro recall is recomputed against the
    same scan. If it did not fall, every figure in the report would be a
    property of this code rather than a property of the kernel — the one
    failure a benchmark cannot recover from, because nothing else in the table
    would look wrong.

    The before/after pair is returned rather than a bare boolean so the caller
    can print the movement and a reader can see the guard did something.
    """
    planted, detected, _used = _scan_source(cases, source, surface_for, attribute)
    if not planted:
        return {
            "checked": 0, "before": None, "after": None, "fell": False,
            "note": "nothing is planted on this source, so there is nothing to falsify",
        }
    before = macro_recall(metrics.tally(planted, detected))
    first = planted[0]
    planted.append(
        metrics.Planted(
            entity_type=first.entity_type,
            value="0000000",
            surface=first.surface,
            start=first.end + 1000,
            end=first.end + 1007,
        )
    )
    after = macro_recall(metrics.tally(planted, detected))
    return {
        "checked": len(planted) - 1,
        "before": before,
        "after": after,
        # Compared as a ratio, not as a numerator. Planting a missed identifier
        # leaves the hit count alone and enlarges the denominator, so a
        # numerator-only test would call an unchanged hit count "no movement"
        # while the reported recall had plainly dropped. Cross-multiplied rather
        # than divided so the comparison is exact.
        "fell": bool(
            before[0] is not None
            and after[0] is not None
            and before[0] * after[1] > after[0] * before[1]
        ),
    }


def measure_end_to_end(
    cases: tuple, store: MappingStore, settings: Settings
) -> EndToEndReport:
    """Whether any planted value reached an approved payload, and who stopped it.

    `survived` is the privacy claim: a value present in an approved payload
    would have been transmitted. `backstopped` is the honest footnote — a
    `(case, entity)` pair where layer 3's deterministic re-read fired
    `LEFTOVER_PATTERN_MATCH` means the value was **still in the text** when
    layer 3 read it. A recognizer score of 1.00 and a kernel that refuses to
    emit the value are different claims, and both are reported.
    """
    checked = 0
    survivors: list = []
    backstopped: list = []
    blocked: list[str] = []
    approved: list[str] = []
    for case in cases:
        outcome = execute(case, store, settings)
        (blocked if outcome.blocked else approved).append(case.name)
        haystack = [outcome.approved_text or ""]
        haystack.extend(outcome.approved_dicom_fields.values())
        for truth in case.ground_truth:
            checked += 1
            if any(truth.value in text for text in haystack):
                survivors.append((case.name, truth.entity_type, truth.source))
        for disposition in outcome.dispositions:
            if (
                disposition.action_code == "LEFTOVER_PATTERN_MATCH"
                and disposition.entity is not None
            ):
                pair = (case.name, disposition.entity)
                if pair not in backstopped:
                    backstopped.append(pair)
    return EndToEndReport(
        checked=checked,
        survived=len(survivors),
        survivors=tuple(survivors),
        backstopped=tuple(backstopped),
        blocked=tuple(blocked),
        approved=tuple(approved),
    )


def build_clean_case(text: str) -> Case:
    """A corpus case carrying one identifier-free sentence and nothing else.

    Built here rather than taken from the corpus, so the precision corpus
    shares no case object, no identifier and no template with the planted one.
    The two measurements are independent by construction, not by convention.
    """
    return Case(
        name="clean",
        kind="known_positive",
        report_text=text,
        dicom_metadata=dict(CLEAN_METADATA),
        ground_truth=(),
    )


def measure_clean_corpus(
    sentences: tuple, store: MappingStore, settings: Settings
) -> metrics.MaskRate:
    """False positives over prose that contains no identifier at all.

    Every `[REDACTED:...]` mask in an approved payload over this corpus is by
    construction a false positive, so `masked` is the count of them and
    `denominator` is the sentence count. The four buckets — blocked, masked,
    shifted, identical — are disjoint and sum to the denominator, so a reader
    can tell a corrupted sentence from a correctly date-shifted one instead of
    seeing one number that conflates them.
    """
    masked = 0
    shifted = 0
    identical = 0
    refused = 0
    detail: list = []
    for sentence in sentences:
        outcome = execute(build_clean_case(sentence), store, settings)
        if outcome.blocked:
            refused += 1
            continue
        text = outcome.approved_text or ""
        if text == sentence:
            identical += 1
        elif metrics.NAMED_ENTITY_MASK.search(text):
            masked += 1
            detail.append((sentence, text))
        else:
            # Approved, and the only thing that moved was a date. Not a false
            # positive: it is the transformation the kernel is supposed to make.
            shifted += 1
    return metrics.MaskRate(
        masked=masked,
        shifted=shifted,
        identical=identical,
        blocked=refused,
        denominator=len(sentences),
        detail=tuple(detail),
    )
