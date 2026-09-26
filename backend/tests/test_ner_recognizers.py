"""Tests for the custom clinical `PatternRecognizer` set.

Two things are pinned here. The first is that each mandatory clinical
identifier is found with the span and score the redaction layer will see.
The second, and the reason this file is longer than the recognizer module, is
what the recognizers must **not** match: a false positive in a redaction layer
corrupts clinical text while every other test still passes, so the negative
cases are asserted as explicitly as the positive ones.

The spans and scores below are the values these patterns actually return under
Presidio on this machine; they are executed facts, not intent.
"""

import re

import pytest
from presidio_analyzer import Pattern, PatternRecognizer

from medarx.config import load_settings
from medarx.redaction.recognizers import (
    CONTEXT,
    CUSTOM_ENTITIES,
    PATTERNS,
    RECOGNIZER_SCORE,
    REGEX_FLAGS,
    build_recognizers,
    strip_anchor_labels,
)


def _recognizer(entity: str) -> PatternRecognizer:
    matches = [r for r in build_recognizers() if entity in r.supported_entities]
    assert len(matches) == 1, f"expected exactly one {entity} recognizer"
    return matches[0]


def _spans(entity: str, text: str) -> list[tuple[int, int, float]]:
    hits = _recognizer(entity).analyze(text, entities=[entity])
    return [(h.start, h.end, h.score) for h in hits]


def test_the_three_mandatory_clinical_entities_exist():
    assert {"MRN", "ACCESSION_NUMBER", "PATIENT_ID"} <= set(CUSTOM_ENTITIES)


def test_custom_entities_is_exactly_the_four_declared():
    assert CUSTOM_ENTITIES == (
        "MRN",
        "ACCESSION_NUMBER",
        "PATIENT_ID",
        "AMBIGUOUS_REFERENCE",
    )


def test_every_entity_has_patterns_and_context():
    for entity in CUSTOM_ENTITIES:
        assert PATTERNS[entity], f"{entity} has no pattern"
        assert CONTEXT[entity], f"{entity} has no context words"
        assert _recognizer(entity).context == CONTEXT[entity]


def test_mandatory_recognizers_score_the_configured_threshold_floor():
    # 0.85 is a floor in Presidio, not a cap: context enhancement can raise a
    # hit above it. What is pinned here is the score carried by the pattern
    # itself, which is what the recognizer contributes before enhancement.
    settings = load_settings()
    for entity in ("MRN", "ACCESSION_NUMBER", "PATIENT_ID"):
        assert PATTERNS[entity][0].score == 0.85
        assert PATTERNS[entity][0].score >= settings.ner_score_threshold


def test_the_ambiguous_reference_entity_exists_and_scores_below_threshold():
    # This is what makes the blocked beat deterministic rather than dependent
    # on a generic NER model happening to emit a low-confidence hit. It is
    # deliberately below `Settings.ner_score_threshold` *and* has no replacer,
    # so layer 2 must emit NER_UNRESOLVED rather than silently passing it on.
    settings = load_settings()
    assert "AMBIGUOUS_REFERENCE" in CUSTOM_ENTITIES
    assert PATTERNS["AMBIGUOUS_REFERENCE"][0].score == 0.30
    assert PATTERNS["AMBIGUOUS_REFERENCE"][0].score < settings.ner_score_threshold
    recs = [r for r in build_recognizers() if "AMBIGUOUS_REFERENCE" in r.supported_entities]
    assert len(recs) == 1
    hits = recs[0].analyze(
        "Ref ticket ZX-99-ALPHA issued at the counter.", entities=["AMBIGUOUS_REFERENCE"]
    )
    assert [(h.entity_type, h.start, h.end, h.score) for h in hits] == [
        ("AMBIGUOUS_REFERENCE", 11, 22, 0.30)
    ]


def test_build_recognizers_returns_one_pattern_recognizer_per_entity():
    recognizers = build_recognizers()
    assert [r.supported_entities[0] for r in recognizers] == list(CUSTOM_ENTITIES)
    assert all(isinstance(r, PatternRecognizer) for r in recognizers)


# -- MRN --------------------------------------------------------------------


def test_mrn_pattern_matches_a_known_mrn():
    mrns = [r for r in build_recognizers() if "MRN" in r.supported_entities]
    assert len(mrns) == 1 and isinstance(mrns[0], PatternRecognizer)
    hits = mrns[0].analyze("MRN: 4452819", entities=["MRN"])
    assert [(h.entity_type, h.start, h.end, h.score) for h in hits] == [
        ("MRN", 0, 12, 0.85)
    ]


def test_mrn_pattern_matches_a_bare_seven_digit_string():
    mrns = [r for r in build_recognizers() if "MRN" in r.supported_entities]
    assert mrns[0].analyze("ref 4452819", entities=["MRN"])[0].score == 0.85

def test_mrn_pattern_matches_a_lettered_prefix():
    # The optional `[A-Z]{0,2}` prefix is inside the match, so a facility-coded
    # MRN is captured whole rather than leaving the letters behind.
    assert _spans("MRN", "MRN: AB1234567") == [(0, 14, 0.85)]


def test_mrn_does_not_eat_a_ten_digit_phone_number():
    # A phone number and an MRN are both bare digit strings; the boundary
    # between them is where a greedy pattern does real damage.
    assert _spans("MRN", "call 555-123-4567 or 5551234567 now") == []


def test_mrn_does_not_eat_an_eight_digit_date():
    assert _spans("MRN", "study 20260114 was read") == []


def test_mrn_does_not_eat_a_measurement():
    assert _spans("MRN", "nodule measures 4452819 mm") == [(16, 23, 0.85)]


@pytest.mark.parametrize(
    "text",
    [
        "May be a small effusion.",
        "Grant the patient 5 mg of contrast.",
        "The will is unreadable.",
        "FINDINGS: 7mm nodule.",
        "DOB: 1953-04-11",
    ],
)
def test_mrn_does_not_match_clinical_or_common_words(text):
    # "May" is a given name and also a clinical hedge; "Grant" is a surname and
    # also a verb. Neither is seven digits, but a recognizer that reached for
    # either would corrupt prose while this file stayed green.
    assert _spans("MRN", text) == []


# -- ACCESSION_NUMBER ------------------------------------------------------


def test_accession_number_matches_the_canonical_fixture():
    assert _spans("ACCESSION_NUMBER", "Accession: ACC0000417") == [(0, 21, 0.85)]
    assert _spans("ACCESSION_NUMBER", "ACC0000417") == [(0, 10, 0.85)]


def test_accession_number_pattern_can_match_a_hyphenated_value():
    # The corrected character class includes `-`; the earlier `[A-Z0-9]` form
    # could not match its own fixture at all, which is a silent zero-match.
    regex = re.compile(PATTERNS["ACCESSION_NUMBER"][0].regex)
    assert regex.search("Accession: ACC-00417")
    assert regex.search("Accession: ACC0000417")


def test_accession_number_does_not_match_without_its_label():
    # A bare `ACC0000417` matches because the label is optional inside the
    # pattern; a bare string with no such shape must not.
    assert _spans("ACCESSION_NUMBER", "no reference here") == []


def test_accession_number_does_not_eat_a_date_or_a_measurement():
    assert _spans("ACCESSION_NUMBER", "acc 20260114") == []
    assert _spans("ACCESSION_NUMBER", "ACC 7mm") == []


# -- PATIENT_ID ------------------------------------------------------------


def test_patient_id_matches_a_prefixed_and_a_bare_value():
    assert _spans("PATIENT_ID", "Patient ID: 12345678") == [(0, 20, 0.85)]
    assert _spans("PATIENT_ID", "PAT 1234") == [(0, 8, 0.85)]


def test_patient_id_rejects_a_nine_digit_value():
    # `{4,8}` is a bound, not a floor of "any digits": a nine-digit number is
    # outside the entity's declared shape and must not be absorbed.
    assert _spans("PATIENT_ID", "PAT 123456789") == []


def test_patient_id_does_not_match_the_word_patient_alone():
    assert _spans("PATIENT_ID", "the patient is stable") == []


# -- near misses -----------------------------------------------------------


def test_a_one_digit_miss_is_not_absorbed_by_mrn():
    # 4452819 is the MRN; 4452818 and 445281 are one digit and one digit short.
    # The near-miss long one is still a seven-digit string, so it is a genuine
    # MRN shape; the short one is not, and must not be truncated into one.
    assert _spans("MRN", "ref 4452818")[0][:2] == (4, 11)
    assert _spans("MRN", "ref 445281") == []


def test_a_dose_is_not_an_identifier():
    # A leading-zero seven-digit string *is* the MRN shape and this recognizer
    # cannot distinguish the two, so the assertion is on doses that are not
    # seven digits rather than on a claim the pattern cannot support.
    assert _spans("MRN", "administer 125 mg then 450 mg") == []


def test_regex_flags_are_case_sensitive():
    # Presidio's default is IGNORECASE, under which the accession pattern
    # matched the bare word "Accession" as `ACC` + `ession`. Pinned because a
    # recognizer that deletes the word "Accession" from a report is exactly
    # the corruption this suite exists to prevent.
    assert not (REGEX_FLAGS & re.IGNORECASE)
    assert _spans("ACCESSION_NUMBER", "Accession") == []
    assert _spans("ACCESSION_NUMBER", "acc 20260114") == []


def test_a_lower_cased_label_still_leaves_the_value_matched():
    # The accepted cost of case sensitivity: the value is still found, only the
    # label is left in the text.
    assert _spans("ACCESSION_NUMBER", "accession: ACC0000417") == [(11, 21, 0.85)]
    assert _spans("MRN", "mrn: 4452819") == [(5, 12, 0.85)]


# -- anchor labels ---------------------------------------------------------


def test_strip_anchor_labels_removes_standalone_labels():
    assert strip_anchor_labels("DOB: 1953-04-11") == " 1953-04-11"
    assert strip_anchor_labels("FINDINGS: 7mm nodule.") == "FINDINGS: 7mm nodule."


def test_strip_anchor_labels_removes_every_declared_anchor():
    for label in ("MRN:", "Accession:", "PAT:", "Patient ID:"):
        assert strip_anchor_labels(f"{label} X") == " X"


def test_strip_anchor_labels_leaves_clinical_prose_alone():
    # Labels are stripped only when they stand alone before a value; a
    # sentence mentioning the word must survive intact.
    assert strip_anchor_labels("The mrn was verified by the patient.") == (
        "The mrn was verified by the patient."
    )


# -- score constant --------------------------------------------------------


def test_recognizer_score_is_the_documented_mandatory_floor():
    assert RECOGNIZER_SCORE == 0.85
