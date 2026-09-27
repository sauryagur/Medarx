"""Tests for the synthetic PHI corpus and the evaluation harness.

Three claims, each pinned by at least one test below:

1. **The corpus is what it says it is.** Every planted identifier is
   *derivable from the case text by search*, so a ground-truth entry naming a
   value the case does not contain is an error rather than a silent recall
   deflation, and every case the contract can express is a valid
   `ExecutionRequest` body.
2. **The metric can fail.** An identifier the detector did not find must
   produce a recall below 1.00 through the same arithmetic that produces the
   reported numbers, or the table is decoration.
3. **The corpus and the scorer are separate artifacts.** `evals.metrics` is
   exercised here on inputs built inside this file, so a scorer that had
   learned the answers could not pass.

Every figure asserted below is a **measured** value produced by executing the
real pipeline, and each is written as a count over a named denominator. A rate
without its denominator is not a measurement.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest
import yaml

from evals import metrics, runner
from evals.synthetic_phi import clean_prose, seed_corpus
from medarx.extraction.allowlists import ALLOWED_FIELDS

CONTRACT = Path(__file__).resolve().parents[1] / "contracts" / "openapi.yaml"


def _contract() -> dict:
    return yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))


def _execution_request_validator():
    """A validator for `ExecutionRequest` with the whole document resolvable.

    The schema is a `$ref` into `components/schemas`, so validating the
    subschema alone leaves every reference dangling and the check would report
    a resolution error rather than a verdict. Handing the validator the
    document as its resolution base is what makes this a conformance check on
    the request body instead of a check on the resolver.
    """
    doc = _contract()
    return jsonschema.validators.validator_for(doc)(
        {"$ref": "#/components/schemas/ExecutionRequest", **doc}
    )


def _report_text_surface(case):
    """The scanned text of a `report_text` identifier: the report body."""
    return case.report_text, "report_text"


def _dicom_prose_surface(case):
    """The one allowlisted DICOM attribute whose value is prose."""
    return (
        case.dicom_metadata.get(seed_corpus.DICOM_PROSE_ATTRIBUTE, ""),
        f"dicom_header.{seed_corpus.DICOM_PROSE_ATTRIBUTE}",
    )


# -- The corpus ----------------------------------------------------------------


def test_corpus_is_deterministic(tmp_path):
    a = seed_corpus.write_corpus(tmp_path / "a")
    b = seed_corpus.write_corpus(tmp_path / "b")
    assert a.read_bytes() == b.read_bytes()


def test_three_cases_with_ground_truth():
    assert {c.name for c in seed_corpus.CASES} == {
        "known_positive", "unresolved", "all_phi"
    }
    kp = next(c for c in seed_corpus.CASES if c.name == "known_positive")
    assert {(g.entity_type, g.value) for g in kp.ground_truth} == {
        ("MRN", "4452819"), ("ACCESSION_NUMBER", "ACC0000417"),
        ("PATIENT_ID", "774123"), ("DATE_TIME", "1953-04-11")}


def test_unresolved_case_has_no_ground_truth():
    u = next(c for c in seed_corpus.CASES if c.name == "unresolved")
    assert u.ground_truth == ()


def test_identifiers_json_matches_the_case_text():
    ids = json.loads((seed_corpus.CORPUS_DIR / "identifiers.json").read_text())
    assert ids["mrn"] == "4452819"
    assert ids["accession"] == "ACC0000417"
    assert ids["patient_id"] == "774123"


def test_every_planted_identifier_is_present_in_the_surface_it_is_declared_for():
    """The corpus cannot be graded against a truth it does not contain.

    The scorer locates each planted value by *searching the case text*, so a
    ground-truth entry whose value is absent — a typo, a reworded template, a
    value left behind by an edit to the prose — would silently become a false
    negative and depress recall for an entity the kernel handles perfectly.
    """
    for case in seed_corpus.ALL_CASES:
        for truth in case.ground_truth:
            text, surface = case.surface_for(truth)
            assert truth.value in text, (
                f"{case.name}: {truth.entity_type} {truth.value!r} is declared for "
                f"{surface} but does not occur there"
            )


def test_a_ground_truth_entry_naming_a_value_no_case_contains_is_refused():
    """The counter-case: the check above can fail, so it is not decorative."""
    case = seed_corpus.CASES[0]
    phantom = seed_corpus.GroundTruth("MRN", "0000000", "report_text")
    with pytest.raises(seed_corpus.GroundTruthError, match="0000000"):
        seed_corpus.locate_planted(case, phantom)


def test_a_planted_value_occurring_twice_is_refused_rather_than_graded():
    """An ambiguous value has no single span, and picking one is the failure
    mode this corpus exists to prevent."""
    truth = seed_corpus.GroundTruth("MRN", "4452819", "report_text")
    ambiguous = seed_corpus.Case(
        name="ambiguous",
        kind="known_positive",
        report_text=seed_corpus.CASES[0].report_text + " Prior MRN: 4452819.",
        dicom_metadata={},
        ground_truth=(truth,),
    )
    with pytest.raises(seed_corpus.GroundTruthError, match="occurs 2 times"):
        seed_corpus.locate_planted(ambiguous, truth)


def test_the_written_corpus_records_its_own_synthetic_marker(tmp_path):
    """`corpus.json` is the artifact a reader inspects, so the marker travels
    with it rather than living only in `identifiers.json`."""
    corpus = seed_corpus.write_corpus(tmp_path / "corpus")
    payload = json.loads(corpus.read_text())
    assert payload["synthetic"] is True
    assert payload["identifiers"] == json.loads(
        (seed_corpus.CORPUS_DIR / "identifiers.json").read_text()
    )
    assert (tmp_path / "corpus" / "study.dcm").read_bytes()


# -- The corpus is a contract-shaped request ------------------------------------


@pytest.mark.parametrize(
    "case", seed_corpus.CONTRACT_EXPRESSIBLE_CASES, ids=lambda c: c.name
)
def test_every_contract_expressible_case_is_a_valid_execution_request(case):
    """A corpus case and an API request body are the same object.

    If the fixture were shaped like the kernel's internal call rather than the
    published request, the harness would be measuring a surface no caller can
    reach and every number would be about a fiction.
    """
    _execution_request_validator().validate(case.to_execution_request())


def test_the_function_name_on_every_case_is_the_contracts_spelling():
    """The wire vocabulary and the internal one are disjoint on purpose.

    `ExecutionRequest` carries the contract's spelling (`Draft`); `pipeline_for`
    is called with the internal one (`draft`). A case carrying the internal
    spelling would be a kernel fixture, not a request body, and the harness
    would be measuring a call no caller can make.
    """
    names = set(_contract()["components"]["schemas"]["FunctionName"]["enum"])
    assert not names & set(ALLOWED_FIELDS)
    for case in seed_corpus.ALL_CASES:
        assert case.function in names, case.name
        assert case.function not in ALLOWED_FIELDS, case.name


def test_the_prior_prose_case_is_one_the_contract_cannot_express():
    """The gap, pinned.

    `PriorReportText` is the only allowlisted DICOM attribute whose value layer 2
    scans, and the contract's `AllowlistedDicomMetadata` declares no such
    property — so the one DICOM-metadata input source with a NER surface cannot
    be supplied by a caller today. The case is measured anyway, because the code
    is the truth about what happens to the value and leaving the source
    unmeasured would be the worse error; this test exists so the gap cannot be
    forgotten.
    """
    allowed = set(
        _contract()["components"]["schemas"]["AllowlistedDicomMetadata"]["properties"]
    )
    assert seed_corpus.DICOM_PROSE_ATTRIBUTE not in allowed
    assert seed_corpus.DICOM_PROSE_ATTRIBUTE in __import__(
        "medarx.extraction.payload_extractor", fromlist=["x"]
    ).KNOWN_DICOM_ATTRIBUTES
    gap = next(c for c in seed_corpus.ALL_CASES if not c.contract_expressible)
    assert gap.name == "dicom_header_prose"
    assert seed_corpus.DICOM_PROSE_ATTRIBUTE in gap.dicom_metadata
    with pytest.raises(jsonschema.ValidationError):
        _execution_request_validator().validate(gap.to_execution_request())


# -- The metric ----------------------------------------------------------------


def test_the_metric_measures_a_corpus_it_has_never_seen():
    """Independence, asserted by use rather than by reading the import graph.

    Everything the metric needs is handed to it here, built inside this test
    file. If `evals.metrics` were reading the corpus it would have no way to
    answer this.
    """
    planted = [
        metrics.Planted("MRN", "4452819", "report_text", 0, 7),
        metrics.Planted("MRN", "4452820", "report_text", 9, 16),
    ]
    detected = [
        metrics.Detection("MRN", 0, 7, "report_text", 0.85),
        metrics.Detection("DATE_TIME", 9, 16, "report_text", 0.85),
    ]
    by_key = metrics.tally(planted, detected)
    # The right span with the wrong entity type is a miss *and* a false
    # positive: the MRN was not found as an MRN, and a DATE_TIME was reported
    # where the corpus planted none.
    assert by_key[("MRN", "report_text")] == metrics.Tally(
        tp=1, fp=0, fn=1, mislabelled=1
    )
    assert by_key[("DATE_TIME", "report_text")] == metrics.Tally(tp=0, fp=1, fn=0)


def test_a_detection_is_not_credited_to_two_planted_spans():
    """One-to-one matching: an over-broad hit must not make two misses look
    like two hits."""
    planted = [
        metrics.Planted("MRN", "4452819", "report_text", 0, 7),
        metrics.Planted("MRN", "4452820", "report_text", 3, 10),
    ]
    detected = [metrics.Detection("MRN", 0, 10, "report_text", 0.85)]
    tally = metrics.tally(planted, detected)[("MRN", "report_text")]
    assert (tally.tp, tally.fn) == (1, 1)


def test_the_metric_can_return_a_recall_below_one():
    """The falsifiability guard.

    The same function, on the same code path, with one expected span no
    detector returned. If this could not fail, neither could the number in the
    table, and the table would be the most valuable thing in the repository
    while measuring nothing.
    """
    planted = [metrics.Planted("MRN", "4452819", "report_text", 0, 7)]
    detected = [metrics.Detection("MRN", 0, 7, "report_text", 0.85)]
    assert metrics.tally(planted, detected)[("MRN", "report_text")].recall == (1, 1)
    assert metrics.tally(planted, [])[("MRN", "report_text")].recall == (0, 1)


def test_a_rate_is_never_reported_without_its_denominator():
    tally = metrics.Tally(tp=3, fp=1, fn=1, mislabelled=0)
    assert tally.precision == (3, 4)
    assert tally.recall == (3, 4)
    assert metrics.Tally().precision == (None, 0)
    assert metrics.Tally().recall == (None, 0)


def test_a_rate_over_nothing_never_prints_as_a_rate():
    """A denominator of zero must not be able to read as 1.00 or as 0.00.

    Either would be a claim about a measurement that was never made, and the
    harness has sources with no scanned text at all.
    """
    assert metrics.format_rate((None, 0)) == "n/a (0 measured)"
    assert metrics.format_rate((0, 0)) == "n/a (0 measured)"
    assert metrics.format_rate((3, 4)) == "3/4"


def test_the_dicom_header_source_has_a_named_surface_and_a_denominator():
    """Per input source, not just per report text.

    The `dicom_header` ground truths in `dicom_header_prose` are planted in the
    one allowlisted metadata value that is prose, so they are scanned and the
    source has a real denominator. The four identifiers in
    `dicom_header_identifiers` sit in keyword, date and age fields that no
    recognizer reads; they are counted as `unscanned` and reported on the
    structural row instead, so a keyword drop can never be scored as a hit.
    """
    report = runner.measure_detection(
        seed_corpus.ALL_CASES, "dicom_header", _dicom_prose_surface,
        attribute=seed_corpus.DICOM_PROSE_ATTRIBUTE,
    )
    assert report.planted == 3
    assert report.unscanned == 4
    assert report.cases == ("dicom_header_prose",)
    assert report.by_key["MRN"] == metrics.Tally(tp=1, fp=0, fn=0, mislabelled=0)
    assert report.by_key["ACCESSION_NUMBER"] == metrics.Tally(
        tp=1, fp=0, fn=0, mislabelled=0
    )
    # The canonical spelling again: `Patient ID: 774123` in a metadata value is
    # no more reachable than the same spelling in a report body, and it comes
    # back as a `DATE_TIME` — the same mislabelling, on a second surface.
    assert report.by_key["PATIENT_ID"] == metrics.Tally(
        tp=0, fp=0, fn=1, mislabelled=1
    )
    assert report.by_key["PATIENT_ID"].recall == (0, 1)


def test_detection_recall_by_entity_type_and_input_source():
    """Recall over the planted corpus, per entity type, per input source.

    Counts, not rates. Every denominator is the number of planted instances of
    that entity type on that surface, so a reader can see that `PATIENT_ID` on
    `report_text` is 1 out of **three** planted instances, two of which use a
    spelling the recognizer cannot reach at all.
    """
    by_entity = runner.measure_detection(
        seed_corpus.ALL_CASES, "report_text", _report_text_surface
    ).by_key

    # Executed, not intended: `MRN: 4452819` is detected at 0.85, in both cases
    # that plant one.
    assert by_entity["MRN"] == metrics.Tally(tp=2, fp=0, fn=0, mislabelled=0)
    # `ACC0000417` is detected at 1.00 — the context enhancer adds 0.35 on top
    # of the recognizer's 0.85 floor, because `acc` is a declared context word
    # and appears *inside the value itself*.
    assert by_entity["ACCESSION_NUMBER"] == metrics.Tally(
        tp=2, fp=0, fn=0, mislabelled=0
    )
    # The date of birth is detected and shifted — and the two false positives
    # under `DATE_TIME` are exactly the two patient ids below, each reported as
    # a date. The two numbers are the same fact seen from both sides, which is
    # why both are printed.
    assert by_entity["DATE_TIME"] == metrics.Tally(tp=1, fp=2, fn=0, mislabelled=0)
    # **The finding.** `Patient ID: 774123` is *not* detected as `PATIENT_ID`:
    # `scan_entities` blanks every `ANCHOR_LABELS` entry before the analyser
    # runs, so the label the pattern requires is gone, and the pattern has no
    # bare-value alternative. The value comes back as `DATE_TIME` at 0.85 and
    # is counted as a mislabelled hit. Three instances are planted, across two
    # cases; the one that spells the label `PatientID` with no space is not an
    # anchor label, survives the strip, and matches the pattern's
    # `Patient\s*ID`. One detected out of three.
    assert by_entity["PATIENT_ID"] == metrics.Tally(tp=1, fp=0, fn=2, mislabelled=2)
    assert by_entity["PATIENT_ID"].recall == (1, 3)
    assert by_entity["MRN"].recall == (2, 2)
    assert by_entity["ACCESSION_NUMBER"].recall == (2, 2)
    assert by_entity["DATE_TIME"].recall == (1, 1)
    assert by_entity["DATE_TIME"].precision == (1, 3)




def test_the_planted_patient_id_recognizer_is_unreachable_on_the_canonical_spelling():
    """The mechanism behind the 1/2 above, isolated from the number.

    Every spelling a radiology report actually writes is an `ANCHOR_LABELS`
    entry and is blanked before analysis, and the pattern requires a label, so
    the recognizer is not merely inaccurate — it is unreachable on the canonical
    form. This is a characterisation test and it is meant to go red when the
    defect is fixed.
    """
    from medarx.redaction.ner import scan_entities

    for label in ("Patient ID: 774123.", "PATIENT ID: 774123.", "Pat Id: 774123.",
                  "Patient-ID: 774123.", "PAT: 774123."):
        hits = scan_entities(label, 0.0)
        assert not [h for h in hits if h.entity_type == "PATIENT_ID"], label

    # The one spelling that reaches it: no space, so it is not an anchor label.
    hits = scan_entities("PatientID: 774123.", 0.0)
    assert [h.entity_type for h in hits if h.entity_type == "PATIENT_ID"] == [
        "PATIENT_ID"
    ]


def test_no_planted_identifier_survives_into_an_approved_payload(store, settings):
    """End-to-end non-survival — the privacy claim, at the payload boundary.

    A *different* metric from detection recall, reported separately for that
    reason: a value can fail to be detected by the NER and still be guaranteed
    absent, because a later layer refuses the request instead of passing it.
    Both numbers are needed; neither substitutes for the other.
    """
    measured = runner.measure_end_to_end(seed_corpus.ALL_CASES, store, settings)
    assert measured.checked == 15
    assert measured.survived == 0, measured.survivors


def test_the_values_that_only_layer_3_stops_are_named(store, settings):
    """The honest footnote on the privacy figure.

    `known_positive`, `all_phi` and `dicom_header_prose` all still carry
    `774123` in their text when layer 3 reads it, and `unresolved` still
    carries `ZX-99-ALPHA`; what stops each is layer 3's deterministic re-read,
    not a recognizer. A privacy figure of 0/15 with no note of this would read
    as a detection result, and it is not one.
    """
    measured = runner.measure_end_to_end(seed_corpus.ALL_CASES, store, settings)
    assert measured.backstopped == (
        ("known_positive", "PATIENT_ID"),
        ("unresolved", "AMBIGUOUS_REFERENCE"),
        ("all_phi", "PATIENT_ID"),
        ("dicom_header_prose", "PATIENT_ID"),
    )


def test_false_positives_over_the_clean_corpus(store, settings):
    """Precision, measured on prose that contains no identifier at all.

    Every `[REDACTED:...]` mask in an approved payload over this corpus is by
    construction a false positive: nothing was planted, so anything the
    detector reported is a clinical word it should not have touched. The four
    buckets are disjoint and sum to the denominator, so a reader can tell a
    corrupted sentence from a correctly date-shifted one.
    """
    unset = runner.measure_clean_corpus(
        clean_prose.ORDINARY_SENTENCES, store,
        settings.model_copy(update={"date_order": None}),
    )
    assert (unset.masked, unset.denominator) == (5, 28)
    assert unset.blocked == 4
    assert unset.masked + unset.shifted + unset.identical + unset.blocked == 28

    declared = runner.measure_clean_corpus(
        clean_prose.ORDINARY_SENTENCES, store,
        settings.model_copy(update={"date_order": "MDY"}),
    )
    assert (declared.masked, declared.denominator) == (6, 28)
    assert declared.blocked == 2
    assert (
        declared.masked + declared.shifted + declared.identical + declared.blocked
        == 28
    )


def test_the_known_false_positive_list_carries_its_own_denominator(store, settings):
    """Kept separate from the 28 and never added to them.

    An earlier version of this project's record quoted 7/28 by counting this
    six-sentence list together with the 28 — two distinct lists counted as
    one, producing a number nobody could reproduce from either. They are two
    lists here, with two denominators, and the harness prints two rows.
    """
    sentences = tuple(t[0] for t in clean_prose.KNOWN_FALSE_POSITIVES)
    known = runner.measure_clean_corpus(sentences, store, settings)
    assert (known.masked, known.denominator) == (6, 6)
    assert not set(sentences) & set(clean_prose.ORDINARY_SENTENCES)


def test_the_clean_corpus_shares_no_case_with_the_planted_corpus():
    """Precision and recall are measured over disjoint corpora.

    Not a convention: the clean case is built by the driver from a sentence
    alone and carries no ground truth, so there is nothing for the two
    measurements to share even by accident.
    """
    clean = runner.build_clean_case(clean_prose.ORDINARY_SENTENCES[0])
    assert clean.ground_truth == ()
    assert clean.report_text == clean_prose.ORDINARY_SENTENCES[0]
    assert clean not in seed_corpus.ALL_CASES
    prose = " ".join(clean_prose.ORDINARY_SENTENCES)
    planted = {g.value for case in seed_corpus.ALL_CASES for g in case.ground_truth}
    # `StudyDate` is a fixture value, not a patient identifier, and one of the
    # clean sentences names it; every *identifier* must be absent.
    identifiers_only = planted - {seed_corpus.identifiers()["study_date"]}
    assert not any(value in prose for value in identifiers_only)


# -- The refusal case ----------------------------------------------------------


def test_the_unresolved_case_actually_refuses(store, settings):
    """A case that does not fire is not a test of anything.

    Asserted on the *reason*, not on `blocked`: a run can block for an
    unrelated reason and still look like a working refusal demonstration.
    """
    from medarx.redaction.replacers import has_replacer

    case = next(c for c in seed_corpus.CASES if c.name == "unresolved")
    outcome = runner.execute(case, store, settings)
    assert outcome.blocked
    codes = {d.action_code for d in outcome.dispositions if not d.resolved}
    assert "NER_UNRESOLVED" in codes, codes
    assert "AMBIGUOUS_REFERENCE" in {d.entity for d in outcome.dispositions}
    # The mechanism, verified rather than assumed: the entity is detected *and*
    # has no registered replacer, which is the whole reason it is refused.
    assert not has_replacer("AMBIGUOUS_REFERENCE")


def test_the_unresolved_reference_reaches_the_scan_at_the_recognizer_floor(
    store, settings
):
    """The refusal has to be about the planted value, not about something else.

    The value is detected at the recognizer's floor of 0.30 — below
    `Settings.ner_score_threshold` — and still arrives, because a candidate the
    scan filtered out could not be blocked downstream. Both halves are asserted
    because either alone would be consistent with a broken scan.
    """
    from medarx.redaction.ner import scan_entities

    case = next(c for c in seed_corpus.CASES if c.name == "unresolved")
    reference = seed_corpus.identifiers()["ambiguous_reference"]
    hits = [
        h for h in scan_entities(case.report_text, 0.0)
        if h.entity_type == "AMBIGUOUS_REFERENCE"
    ]
    assert [h.text for h in hits] == [reference]
    assert hits[0].score == pytest.approx(0.30)
    assert hits[0].score < settings.ner_score_threshold
    assert runner.execute(case, store, settings).blocked


def test_the_all_phi_case_is_refused_rather_than_approved_empty(store, settings):
    """What the design asked for, and what actually happens.

    The brief said this case exists "so redaction must not yield an empty
    approved payload". The measured outcome is stronger: the payload is
    refused, with `UNRESOLVED_EMPTY_BODY`, because a body of nothing but field
    labels and identifiers has no clinical content once the labels are
    accounted for. The property the brief wanted holds; the mechanism is a
    refusal, not an approval.
    """
    case = next(c for c in seed_corpus.CASES if c.name == "all_phi")
    outcome = runner.execute(case, store, settings)
    assert outcome.blocked
    assert "UNRESOLVED_EMPTY_BODY" in {d.action_code for d in outcome.dispositions}


def test_every_case_reports_the_verdict_it_measured(store, settings):
    """`kind` is the expectation, the run is the measurement.

    Both are printed, so a case that changes verdict is visible rather than
    inferred from a rate.
    """
    verdicts = {
        case.name: runner.execute(case, store, settings).blocked
        for case in seed_corpus.ALL_CASES
    }
    assert verdicts == {
        "known_positive": True,
        "unresolved": True,
        "all_phi": True,
        "dicom_header_identifiers": False,
        "dicom_header_prose": True,
        "patient_id_label_spelling": False,
    }


# -- Determinism ---------------------------------------------------------------


def test_two_executions_of_the_same_case_agree(store, settings):
    case = seed_corpus.ALL_CASES[0]
    a = runner.execute(case, store, settings)
    b = runner.execute(case, store, settings)
    assert (a.blocked, a.approved_text) == (b.blocked, b.approved_text)
    assert [d.action_code for d in a.dispositions] == [
        d.action_code for d in b.dispositions
    ]
    assert [d.entity for d in a.dispositions] == [d.entity for d in b.dispositions]


def test_the_corpus_contains_no_real_patient_data():
    """Stated as an assertion, because the whole corpus is fabricated.

    Every value is a fixture this project invented and the identifier inventory
    carries an explicit marker saying so. If a real value were ever pasted in,
    the counts the rest of this file asserts would stop matching the case text.
    """
    ids = json.loads((seed_corpus.CORPUS_DIR / "identifiers.json").read_text())
    assert ids["synthetic"] is True
    assert "synthetic" in ids["notice"].lower()
    inventory = {str(value) for value in ids.values() if isinstance(value, str)}
    planted = {g.value for case in seed_corpus.ALL_CASES for g in case.ground_truth}
    assert planted <= inventory, sorted(planted - inventory)
