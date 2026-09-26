"""Tests for the custom clinical `PatternRecognizer` set.

Two things are pinned here. The first is that each mandatory clinical
identifier is found with the span the redaction layer will see. The second, and
the reason this file is longer than the recognizer module, is what the
recognizers must **not** match: a false positive in a redaction layer corrupts
clinical text while every other test still passes, so the negative cases are
asserted as explicitly as the positive ones.

The spans and scores below are the values these patterns actually return under
Presidio on this machine; they are executed facts, not intent.
"""

import re
from datetime import date

import pytest
from presidio_analyzer import Pattern, PatternRecognizer

from medarx.config import load_settings
from medarx.redaction.recognizers import (
    AMBIGUOUS_SCORE,
    CONTEXT,
    CUSTOM_ENTITIES,
    PATTERNS,
    RECOGNIZER_SCORE,
    REGEX_FLAGS,
    UNENHANCEABLE_CONTEXT,
    build_recognizers,
    strip_anchor_labels,
)

from medarx.redaction.ner import EntityHit, build_engine, scan_entities
from medarx.redaction.replacers import (
    REPLACERS,
    ReplacerContext,
    has_replacer,
    replacement_for,
)

# `PatternRecognizer` misses the UserWarning spaCy emits on load for a model
# present in the environment; the assertions here are about entity types and
# spans, not about the warning.
pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")

#: The four patterns as the brief pins them, character for character. Asserted
#: literally so a later task editing a pattern in place fails here rather than
#: leaving this file green with a different recognizer.
BRIEF_PATTERNS = {
    "MRN": r"\b(?:MRN\s*[:#]?\s*)?[A-Z]{0,2}\d{7}\b",
    "ACCESSION_NUMBER": r"\b(?:ACC|Accession)\s*[:#]?\s*[A-Z0-9-]{6,12}\b",
    "PATIENT_ID": r"\b(?:PAT|Patient\s*ID)\s*[:#]?\s*\d{4,8}\b",
    "AMBIGUOUS_REFERENCE": r"\b[A-Z]{2,4}-\d{2}-[A-Z]{4,}\b",
}

#: `PATIENT_ID` is the one deliberate departure from the brief, and the reason
#: is in the module: its value class is digits-only, so a case-insensitive
#: *label* cannot reach a clinical word or a date. Case-sensitive, the pattern
#: matched nothing in "patient id: 12345678" and left a patient identifier in
#: the text the model receives.
BRIEF_PATTERNS_WITH_CASE_INSENSITIVE_LABEL = {
    "PATIENT_ID": r"\b(?i:PAT|Patient\s*ID)\s*[:#]?\s*\d{4,8}\b",
}


def _recognizer(entity: str) -> PatternRecognizer:
    matches = [r for r in build_recognizers() if entity in r.supported_entities]
    assert len(matches) == 1, f"expected exactly one {entity} recognizer"
    return matches[0]


def _hits(entity: str, text: str) -> list[tuple[int, int, float]]:
    return [
        (h.start, h.end, h.score)
        for h in _recognizer(entity).analyze(text, entities=[entity])
    ]


def _spans(entity: str, text: str) -> list[tuple[int, int]]:
    """Spans only, so a score change is never a span-test failure."""
    return [(start, end) for start, end, _ in _hits(entity, text)]


def _scores(entity: str, text: str) -> list[float]:
    return [score for _, _, score in _hits(entity, text)]


def test_the_three_mandatory_clinical_entities_exist():
    assert {"MRN", "ACCESSION_NUMBER", "PATIENT_ID"} <= set(CUSTOM_ENTITIES)


def test_custom_entities_is_exactly_the_four_declared():
    assert CUSTOM_ENTITIES == (
        "MRN",
        "ACCESSION_NUMBER",
        "PATIENT_ID",
        "AMBIGUOUS_REFERENCE",
    )


def test_the_patterns_are_the_ones_the_brief_pins():
    # The single place that would catch a later task editing a pattern in
    # place. `PATIENT_ID` is expected to differ, and only in the documented
    # way; every other pattern must be byte-identical to the brief.
    for entity, regex in BRIEF_PATTERNS.items():
        assert PATTERNS[entity][0].regex == (
            BRIEF_PATTERNS_WITH_CASE_INSENSITIVE_LABEL.get(entity, regex)
        ), f"{entity} no longer matches the pinned pattern"


def test_every_entity_has_patterns_and_context():
    for entity in CUSTOM_ENTITIES:
        assert PATTERNS[entity], f"{entity} has no pattern"
        assert CONTEXT[entity], f"{entity} has no documented context words"


def test_mandatory_recognizers_score_the_configured_threshold_floor():
    # 0.85 is a floor in Presidio, not a cap: context enhancement can raise a
    # hit above it. What is pinned here is the score carried by the pattern
    # itself, which is what the recognizer contributes before enhancement.
    settings = load_settings()
    for entity in ("MRN", "ACCESSION_NUMBER", "PATIENT_ID"):
        assert PATTERNS[entity][0].score == RECOGNIZER_SCORE
        assert RECOGNIZER_SCORE >= settings.ner_score_threshold


def test_the_ambiguous_reference_entity_exists_and_scores_below_threshold():
    # This is what makes the blocked beat deterministic rather than dependent
    # on a generic NER model happening to emit a low-confidence hit. It has no
    # registered replacer, so layer 2 must emit NER_UNRESOLVED rather than
    # silently passing it on.
    settings = load_settings()
    assert "AMBIGUOUS_REFERENCE" in CUSTOM_ENTITIES
    assert PATTERNS["AMBIGUOUS_REFERENCE"][0].score == AMBIGUOUS_SCORE
    assert AMBIGUOUS_SCORE < settings.ner_score_threshold
    recs = [r for r in build_recognizers() if "AMBIGUOUS_REFERENCE" in r.supported_entities]
    assert len(recs) == 1
    hits = recs[0].analyze(
        "Ref ticket ZX-99-ALPHA issued at the counter.", entities=["AMBIGUOUS_REFERENCE"]
    )
    assert [(h.entity_type, h.start, h.end) for h in hits] == [
        ("AMBIGUOUS_REFERENCE", 11, 22)
    ]
    assert [h.score for h in hits] == pytest.approx([AMBIGUOUS_SCORE])


def test_the_ambiguous_reference_cannot_be_lifted_by_context_enhancement():
    # `PatternRecognizer.analyze` does no enhancement, so the unit tests above
    # cannot see this. `AnalyzerEngine._enhance_using_context` does: it adds
    # `context_similarity_factor = 0.35` and floors at 0.4, which takes 0.30 to
    # 0.65 — above `Settings.ner_score_threshold` — because the fixture's own
    # sentence contains `ref`, `ticket` and `issued`. The recognizer is built
    # with an empty context so the enhancer skips it.
    assert CONTEXT["AMBIGUOUS_REFERENCE"], "the documented words should still be recorded"
    assert _recognizer("AMBIGUOUS_REFERENCE").context == []
    assert UNENHANCEABLE_CONTEXT["AMBIGUOUS_REFERENCE"] == []
    # Every other recognizer keeps its real context, or the enhancement fix
    # would have been made by disabling enhancement everywhere.
    for entity in ("MRN", "ACCESSION_NUMBER", "PATIENT_ID"):
        assert _recognizer(entity).context == CONTEXT[entity]


def test_build_recognizers_returns_one_pattern_recognizer_per_entity():
    recognizers = build_recognizers()
    assert [r.supported_entities[0] for r in recognizers] == list(CUSTOM_ENTITIES)
    assert all(isinstance(r, PatternRecognizer) for r in recognizers)


# -- MRN --------------------------------------------------------------------


def test_mrn_pattern_matches_a_known_mrn():
    mrns = [r for r in build_recognizers() if "MRN" in r.supported_entities]
    assert len(mrns) == 1 and isinstance(mrns[0], PatternRecognizer)
    hits = mrns[0].analyze("MRN: 4452819", entities=["MRN"])
    assert [(h.entity_type, h.start, h.end) for h in hits] == [("MRN", 0, 12)]
    assert [h.score for h in hits] == pytest.approx([RECOGNIZER_SCORE])


def test_mrn_pattern_matches_a_bare_seven_digit_string():
    mrns = [r for r in build_recognizers() if "MRN" in r.supported_entities]
    assert mrns[0].analyze("ref 4452819", entities=["MRN"])[0].score == pytest.approx(
        RECOGNIZER_SCORE
    )


def test_mrn_pattern_matches_a_lettered_prefix():
    # The optional `[A-Z]{0,2}` prefix is inside the match, so a facility-coded
    # MRN is captured whole rather than leaving the letters behind.
    assert _spans("MRN", "MRN: AB1234567") == [(0, 14)]


def test_mrn_does_not_eat_a_ten_digit_phone_number():
    # A phone number and an MRN are both bare digit strings; the boundary
    # between them is where a greedy pattern does real damage.
    assert _spans("MRN", "call 555-123-4567 or 5551234567 now") == []


def test_mrn_does_not_eat_an_eight_digit_date():
    assert _spans("MRN", "study 20260114 was read") == []


def test_a_bare_seven_digit_number_is_always_matched_even_outside_its_field():
    # KNOWN FALSE POSITIVE, pinned on purpose. A bare seven-digit number carries
    # no field context, so this recognizer cannot tell an MRN from a room
    # number, a dose or an accession typed without its label. The MRN shape
    # must not be tightened to fix this: requiring a non-zero leading digit
    # would reject real facility-coded MRNs, which is a privacy bug in the
    # other direction. The cases below are recorded so that any future change
    # to `[A-Z]{0,2}\d{7}` is a visible, deliberate decision rather than a
    # silent one.
    assert _spans("MRN", "nodule measures 4452819 mm") == [(16, 23)]
    assert _spans("MRN", "room 4452819 bed") == [(5, 12)]
    assert _spans("MRN", "give 1 mg then 4452819 later") == [(15, 22)]


def test_a_leading_zero_dose_is_matched_because_it_has_the_mrn_shape():
    # KNOWN FALSE POSITIVE, pinned on purpose, and the reason it is not fixed:
    # `0000123` is seven digits. Rejecting it would mean requiring a non-zero
    # leading digit, which rejects genuine leading-zero facility MRNs. Asserted
    # so a future tightening shows up as a failing test with this comment
    # attached, not as a silent behaviour change.
    assert _spans("MRN", "dose 0000123 mg") == [(5, 12)]


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


def test_the_case_insensitive_label_exception_cannot_be_widened_silently():
    # The pin test above compares each pattern against the brief's literal
    # string, with `PATIENT_ID` replaced by the documented `(?i:...)` form. A
    # second entry in that exception dict would make the comparison certify
    # itself: the test would compare the pattern against whatever the exception
    # said, and a drifted pattern would pass. This assertion makes widening the
    # exception a deliberate, visible act — if a future entity genuinely needs
    # a case-folded label, this fails and the reasoning gets written down.
    assert set(BRIEF_PATTERNS_WITH_CASE_INSENSITIVE_LABEL) == {"PATIENT_ID"}


# -- ACCESSION_NUMBER ------------------------------------------------------


def test_accession_number_matches_the_canonical_fixture():
    assert _spans("ACCESSION_NUMBER", "Accession: ACC0000417") == [(0, 21)]
    assert _spans("ACCESSION_NUMBER", "ACC0000417") == [(0, 10)]
    assert _scores("ACCESSION_NUMBER", "Accession: ACC0000417") == pytest.approx(
        [RECOGNIZER_SCORE]
    )


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
    assert _spans("PATIENT_ID", "Patient ID: 12345678") == [(0, 20)]
    assert _spans("PATIENT_ID", "PAT 1234") == [(0, 8)]


@pytest.mark.parametrize(
    "text",
    [
        "patient id: 12345678",
        "Patient ID: 12345678",
        "PATIENT ID 98765432",
        "pat: 1234",
    ],
)
def test_patient_id_matches_a_lower_cased_label(text):
    # A lower-cased label used to match nothing at all, which left a patient
    # identifier in the text the model receives. The label is matched in any
    # case; the value stays digits-only and case-sensitive.
    assert _spans("PATIENT_ID", text), f"lower-cased label missed: {text!r}"


def test_patient_id_rejects_a_nine_digit_value():
    # `{4,8}` is a bound, not a floor of "any digits": a nine-digit number is
    # outside the entity's declared shape and must not be absorbed. This holds
    # with the label case-folded too, which is where a sloppy `(?i:...)` around
    # the whole pattern would have leaked.
    assert _spans("PATIENT_ID", "PAT 123456789") == []
    assert _spans("PATIENT_ID", "patient id: 123456789") == []


def test_patient_id_does_not_match_the_word_patient_alone():
    # A case-insensitive label must not become a case-insensitive value: the
    # value class is `\d{4,8}` and cannot reach prose.
    assert _spans("PATIENT_ID", "the patient is stable") == []
    assert _spans("PATIENT_ID", "patient id unknown") == []


# -- near misses -----------------------------------------------------------


def test_a_one_digit_miss_is_not_absorbed_by_mrn():
    # 4452819 is the MRN; 4452818 is one digit different and 445281 is one
    # digit short. The near-miss long one is still a seven-digit string, so it
    # is a genuine MRN shape; the short one is not, and must not be truncated
    # into one.
    assert _spans("MRN", "ref 4452818") == [(4, 11)]
    assert _spans("MRN", "ref 445281") == []


# -- regex flags -----------------------------------------------------------


def test_regex_flags_are_case_sensitive():
    # Presidio's default is IGNORECASE, under which the accession pattern
    # matched the bare word "Accession" as `ACC` + `ession`. Pinned because a
    # recognizer that deletes the word "Accession" from a report is exactly
    # the corruption this suite exists to prevent.
    assert not (REGEX_FLAGS & re.IGNORECASE)
    assert _spans("ACCESSION_NUMBER", "Accession") == []
    assert _spans("ACCESSION_NUMBER", "acc 20260114") == []


def test_a_lower_cased_label_still_leaves_the_value_matched():
    # The accepted cost of case sensitivity on the labels that are not
    # case-folded: the value is still found, only the label is left in the text.
    assert _spans("ACCESSION_NUMBER", "accession: ACC0000417") == [(11, 21)]
    assert _spans("MRN", "mrn: 4452819") == [(5, 12)]


# -- anchor labels ---------------------------------------------------------


def test_strip_anchor_labels_blanks_standalone_labels_without_changing_length():
    # The output is spaces, not a deletion, and the length is the point. The
    # analyzer cannot see a label either way, but only the length-preserving
    # form keeps every offset downstream valid against the caller's original
    # string. Deleting "DOB:" here would shorten the text by four characters
    # and shift every later span; see `strip_anchor_labels`.
    assert strip_anchor_labels("DOB: 1953-04-11") == "     1953-04-11"
    assert strip_anchor_labels("FINDINGS: 7mm nodule.") == "FINDINGS: 7mm nodule."


def test_strip_anchor_labels_preserves_length_for_every_anchor_and_in_practice():
    # The invariant the offset contract rests on, over every declared anchor
    # and over a note with several of them. The multi-label case is the one
    # that bites: it is what made the third entity's span land eight
    # characters past its value.
    for label in ("MRN:", "ACC:", "Accession:", "PAT:", "Patient ID:", "DOB:",
                  "Date of Birth:"):
        text = f"{label} X"
        assert strip_anchor_labels(text) == " " * len(label) + " X"
        assert len(strip_anchor_labels(text)) == len(text)

    note = "MRN: 4452819 and DOB: 1953-04-11 and PAT 9911"
    assert len(strip_anchor_labels(note)) == len(note)


def test_strip_anchor_labels_blanks_the_label_and_its_separator_only():
    # The separator goes with the label (`MRN:` is four characters, so four
    # spaces); the whitespace after it is not part of the match and is left
    # exactly as it was.
    assert strip_anchor_labels("MRN:  X") == "      X"


def test_strip_anchor_labels_leaves_clinical_prose_alone():
    # Labels are stripped only when they stand alone before a value; a
    # sentence mentioning the word must survive intact.
    assert strip_anchor_labels("The mrn was verified by the patient.") == (
        "The mrn was verified by the patient."
    )


def test_strip_anchor_labels_does_not_strip_inside_a_word():
    # The `(?<![\w])` lookbehind is the only thing preventing a mid-word
    # strip: without it "xMRN: 5" would lose its leading "x" and
    # "ADMISSION NOTE: 5" would lose "ADMISSION". Pinned because the lookbehind
    # is invisible in the output and easy to drop in a refactor.
    assert strip_anchor_labels("xMRN: 5") == "xMRN: 5"
    assert strip_anchor_labels("(MRN): 5") == "(MRN): 5"


# -- score constant --------------------------------------------------------


def test_recognizer_score_is_the_documented_mandatory_floor():
    assert RECOGNIZER_SCORE == 0.85


# -- the engine, the scan, and the replacers (Task 8) -----------------------
#
# Everything above exercises the recognizers directly. `PatternRecognizer.analyze`
# is not the path a redaction layer takes: it performs no context enhancement,
# and it knows nothing about replacers. Everything below goes through the real
# `AnalyzerEngine`, because that is the only place the score a block decision
# would key on is actually produced.


def test_engine_uses_the_spacy_pipeline_dict_shape():
    # `nlp_engine.nlp` is a dict keyed by language code, so `pipe_names` is
    # reached through `nlp["en"]`. `NlpEngine()` is an abstract base and cannot
    # be constructed; the engine comes from `NlpEngineProvider`.
    engine = build_engine()
    assert "ner" in engine.nlp_engine.nlp["en"].pipe_names


def test_the_engine_carries_the_custom_recognizers_among_the_defaults():
    # Registering the custom set must *add* to Presidio's defaults, not replace
    # them: a registry loaded with only the clinical recognizers would still
    # redact an MRN and would leave the phone number beside it in the clear.
    registered = {
        entity
        for recognizer in build_engine().registry.recognizers
        for entity in recognizer.supported_entities
    }
    assert set(CUSTOM_ENTITIES) <= registered
    assert "PHONE_NUMBER" in registered


def test_scan_reuses_one_engine_rather_than_rebuilding_it():
    # `build_engine` builds fresh on purpose; `scan_entities` is on a hot path
    # (one call per text-bearing field) and must not reload spaCy per call.
    # Asserted by identity, not by timing.
    from medarx.redaction import ner

    assert ner._shared_engine() is ner._shared_engine()


def test_mrn_is_detected_as_mrn_and_never_as_a_date():
    # Presidio's own `DATE_TIME` recognizer scores a bare seven-digit MRN at
    # 0.85, which redacts it as though it were a date. The custom recognizer
    # must win the overlap.
    hits = scan_entities("MRN: 4452819", min_score=0.50)
    assert [h.entity_type for h in hits] == ["MRN"]
    assert hits[0].score == pytest.approx(0.85)


def test_accession_and_patient_id_are_detected():
    assert [h.entity_type for h in scan_entities("Accession: ACC0000417", min_score=0.50)] \
        == ["ACCESSION_NUMBER"]
    # `PAT 1234`, not the brief's `Patient ID: 774123`: the scan strips anchor
    # labels before analysing, and `PATIENT_ID`'s pattern is label-anchored,
    # so `Patient ID: 774123` reaches the analyzer as the bare value ` 774123`
    # and comes back as Presidio's `DATE_TIME`. The value is still redacted —
    # under the wrong entity type. The two pinned expectations cannot both
    # hold: stripping is the one that protects the value, because an
    # unstripped `DOB:` is redacted as an `ORGANIZATION` and the date beside
    # it survives in the clear. So the fixture moves to a spelling the anchor
    # strip does not match. Reported in the task-8 report.
    assert [h.entity_type for h in scan_entities("PAT 1234", min_score=0.50)] \
        == ["PATIENT_ID"]


def test_a_bare_patient_id_value_is_still_redacted_even_though_mislabelled():
    # The safety property behind the deviation above: stripping the label costs
    # the entity *type*, never the redaction. `774123` must be covered by some
    # hit whatever the engine calls it.
    hits = scan_entities("Patient ID: 774123", min_score=0.50)
    assert any(h.text == "774123" for h in hits)


def test_common_word_name_not_redacted():
    # "May be a small effusion" is clinical text; a name-shaped word must
    # survive. Asserted on the hit text, so it holds whatever the engine emits.
    hits = scan_entities(
        "FINDINGS: May be a small effusion. Grant appears in the history.",
        min_score=0.50,
    )
    assert all(h.text not in {"May", "Grant"} for h in hits)


def test_phone_number_precision_beats_mrn_pattern():
    # 7 digits = MRN; 10 digits with separators = phone. The longer, more
    # specific match must win so a phone number is not silently mangled into
    # an MRN redaction.
    hits = scan_entities("Call 555-123-4567 to reach the patient.", min_score=0.50)
    assert all(h.entity_type != "MRN" for h in hits)


def test_hits_below_min_score_are_filtered_out():
    # `scan_entities` filters at the supplied `min_score`; layer 2 (Task 9) is
    # what calls it with `min_score=0.0` so that sub-threshold hits are *seen*
    # and can become blocks.
    hits = scan_entities("FINDINGS: 7mm nodule.", min_score=0.99)
    assert hits == []


def test_a_sub_threshold_hit_is_still_visible_and_never_filtered_away():
    # The filter belongs to the caller, and — more to the point — the
    # deliberately-unresolvable reference must arrive *whatever* `min_score`
    # the caller passes, because it is going to become a block and a block
    # cannot be raised for a hit that was filtered out first. No predicate is
    # passed here: this is the default path every future task takes.
    text = "Ref ticket ZX-99-ALPHA issued at the counter."
    for min_score in (0.0, 0.30, load_settings().ner_score_threshold, 0.9, 1.0):
        ambiguous = [
            h for h in scan_entities(text, min_score=min_score)
            if h.entity_type == "AMBIGUOUS_REFERENCE"
        ]
        assert len(ambiguous) == 1, f"dropped at min_score={min_score}"
        assert ambiguous[0].score == pytest.approx(0.30)
        assert ambiguous[0].score < load_settings().ner_score_threshold


def test_the_scan_does_not_apply_the_settings_threshold_itself():
    # `Settings.ner_score_threshold` is the *decision* threshold and belongs to
    # layer 2. If `scan_entities` filtered on it, layer 2 would never see the
    # candidate that has to become a block.
    hits = scan_entities("Ref ticket ZX-99-ALPHA issued at the counter.", min_score=0.0)
    assert any(h.score < load_settings().ner_score_threshold for h in hits)


def test_a_replaceable_hit_is_still_filtered_by_min_score():
    # The control for the test above, and the non-vacuity proof that the score
    # filter still exists: `min_score` is not simply ignored wholesale, and the
    # protection above is not just a filter that was switched off. `ORGANIZATION`
    # has a replacer, so raising `min_score` above its 0.85 does remove it —
    # while the unresolvable `AMBIGUOUS_REFERENCE` on the same span survives.
    text = "Ref ticket ZX-99-ALPHA issued at the counter."
    assert all(h.entity_type == "AMBIGUOUS_REFERENCE"
               for h in scan_entities(text, min_score=0.99))
    assert all(h.entity_type != "ORGANIZATION"
               for h in scan_entities(text, min_score=0.99))


def test_importing_the_replacers_installs_the_scan_safety_rule():
    # The property belongs to the system, not the call site, so it is checked
    # at the registration rather than at a call. `replacers` is imported at the
    # top of this file, which is what put the real predicate in place.
    from medarx.redaction import ner

    assert ner._UNREPLACEABLE is not None
    assert ner._UNREPLACEABLE("AMBIGUOUS_REFERENCE") is True
    assert ner._UNREPLACEABLE("MRN") is False


def test_the_caller_predicate_can_only_widen_the_protection_never_narrow_it():
    # `unreplaceable=` is a hook for protecting *more*, not for overriding the
    # default. A caller that passes "nothing is protected" must not be able to
    # unprotect the ambiguous reference, because that is precisely the
    # pass-through this whole mechanism exists to prevent.
    text = "Ref ticket ZX-99-ALPHA issued at the counter."
    assert any(
        h.entity_type == "AMBIGUOUS_REFERENCE"
        for h in scan_entities(text, min_score=0.0, unreplaceable=lambda e: False)
    )
    # And it can add: a registered type is protected when the caller says so.
    assert any(
        h.entity_type == "AMBIGUOUS_REFERENCE"
        for h in scan_entities(
            text, min_score=0.0, unreplaceable=lambda e: has_replacer(e)
        )
    )


def test_with_no_policy_registered_the_scan_drops_nothing():
    # The state a module that imports `ner` without `replacers` is in. The
    # fallback is fail-closed — every entity is treated as unresolvable, so
    # nothing is filtered and nothing is collapsed — because the alternative
    # default is the one that published documents. The cost is a noisier
    # report in a configuration that no layer-2 caller should be in.
    from medarx.redaction import ner

    registered = ner._UNREPLACEABLE
    ner._UNREPLACEABLE = None
    try:
        hits = scan_entities("MRN: 4452819", min_score=0.99)
    finally:
        ner._UNREPLACEABLE = registered
    assert {h.entity_type for h in hits} >= {"MRN", "DATE_TIME", "US_DRIVER_LICENSE"}


def test_oversized_text_is_truncated_with_a_flag_hit():
    hits = scan_entities("a" * 200_001 + " 4452819", min_score=0.50)
    assert any(h.entity_type == "TRUNCATED_TEXT" for h in hits)


def test_the_truncation_flag_covers_exactly_the_dropped_tail():
    # A silently truncated scan is indistinguishable from a clean one, so the
    # flag must be a real span over the text that was *not* scanned, and there
    # must be exactly one of it.
    text = "a" * 200_001 + " 4452819"
    flags = [h for h in scan_entities(text, min_score=0.50)
             if h.entity_type == "TRUNCATED_TEXT"]
    assert len(flags) == 1
    assert (flags[0].start, flags[0].end) == (load_settings().ner_text_limit, len(text))
    assert flags[0].score == 1.0


def test_text_within_the_limit_carries_no_truncation_flag():
    settings = load_settings()
    hits = scan_entities("a" * settings.ner_text_limit, min_score=0.50)
    assert all(h.entity_type != "TRUNCATED_TEXT" for h in hits)


def test_the_truncation_limit_is_configurable_not_hardcoded():
    # Patched at the module's own seam, so the test proves the *scan* reads
    # `Settings.ner_text_limit` rather than a literal.
    from medarx.redaction import ner

    tight = load_settings().model_copy(update={"ner_text_limit": 10})
    original = ner._settings
    ner._settings = lambda: tight
    try:
        assert any(h.entity_type == "TRUNCATED_TEXT"
                   for h in scan_entities("a" * 11, min_score=0.50))
    finally:
        ner._settings = original


def test_anchor_labels_are_stripped_on_the_scan_path_not_merely_available():
    # `strip_anchor_labels` exists because Presidio scores a bare `DOB` as
    # `ORGANIZATION` at 0.85. If `scan_entities` forgot to apply it, that hit
    # would reach layer 2 and be redacted as an organisation.
    assert [h.entity_type for h in scan_entities("DOB: 1953-04-11", min_score=0.50)] \
        != ["ORGANIZATION"]


def test_hits_are_sorted_by_start_then_end():
    hits = scan_entities("MRN: 4452819 and Accession: ACC0000417 and PAT 9911", min_score=0.50)
    assert [(h.start, h.end) for h in hits] == sorted((h.start, h.end) for h in hits)


def test_overlapping_hits_collapse_to_one_span():
    # A span the engine reports under two entity types must be reported once.
    # A redaction layer that kept both would apply two replacements to the
    # same characters.
    hits = scan_entities("MRN: 4452819", min_score=0.0)
    spans = [(h.start, h.end) for h in hits]
    assert len(spans) == len(set(spans))


def test_an_empty_scan_returns_an_empty_report_and_does_not_raise():
    assert scan_entities("", min_score=0.0) == []


CTX = ReplacerContext(patient_surrogate="medarx-patient-ab12cd34", offset=-30)


def test_a_detected_date_is_shifted_by_the_patient_offset():
    # The replacer shifts the date it was handed. It does not substitute the
    # patient surrogate: one value cannot be the shifted form of every date in
    # a text, and splicing a patient identifier in where a date stood both
    # destroyed the interval and put an identifier into a clinical sentence.
    # CTX's offset is -30, so 2026-01-14 becomes 2025-12-15.
    assert replacement_for(EntityHit("DATE_TIME", 0, 10, 0.9, "2026-01-14"), CTX) \
        == "2025-12-15"
    assert replacement_for(EntityHit("MRN", 0, 7, 0.85, "4452819"), CTX) == "[REDACTED:MRN]"


def test_two_dates_in_one_text_keep_the_interval_between_them():
    # The exact property the substitution destroyed. Before the fix both dates
    # became the same patient identifier, so "on 2026-01-14, unchanged from
    # 2025-12-01" redacted to two copies of one string and the 44-day interval
    # was gone -- a redaction that passes every leak check while destroying the
    # clinical fact the date shift exists to preserve.
    a = replacement_for(EntityHit("DATE_TIME", 0, 10, 0.9, "2026-01-14"), CTX)
    b = replacement_for(EntityHit("DATE_TIME", 0, 10, 0.9, "2025-12-01"), CTX)
    assert a != b, "two different dates collapsed to one value"
    assert (date(2026, 1, 14) - date(2025, 12, 1)).days == 44
    assert (date.fromisoformat(a) - date.fromisoformat(b)).days == 44


def test_a_shifted_date_is_written_back_in_the_format_it_arrived_in():
    # A report mixes DICOM `DA` and ISO dates. Re-rendering every one of them
    # as ISO would silently rewrite the clinical text around it, so the
    # separator style and any time of day survive the shift.
    assert replacement_for(EntityHit("DATE_TIME", 0, 8, 0.9, "20260114"), CTX) == "20251215"
    assert replacement_for(EntityHit("DATE_TIME", 0, 10, 0.9, "2026-01-14"), CTX) \
        == "2025-12-15"
    assert replacement_for(
        EntityHit("DATE_TIME", 0, 16, 0.9, "2026-01-14 10:30"), CTX
    ) == "2025-12-15 10:30"


def test_a_date_the_kernel_cannot_shift_is_refused_rather_than_guessed():
    # `None` means "detected, and no safe replacement" -- the same condition
    # an unregistered entity is in, expressed as a value rather than a
    # missing table entry, so layer 2 has one mechanism and not two. Measured
    # on this machine: Presidio reports the bare patient id "774123" as
    # `DATE_TIME` at 0.85, a relative interval as "6 weeks" at 0.85, and
    # "14 January 2026" at 0.85. Guessing a format for any of them produces a
    # date that is wrong, which is data corruption that reads as a redaction.
    assert replacement_for(EntityHit("DATE_TIME", 0, 6, 0.85, "774123"), CTX) is None
    assert replacement_for(EntityHit("DATE_TIME", 0, 7, 0.85, "6 weeks"), CTX) is None
    assert replacement_for(EntityHit("DATE_TIME", 0, 16, 0.85, "14 January 2026"), CTX) is None
    assert replacement_for(EntityHit("DATE_TIME", 0, 10, 0.85, "2026-02-30"), CTX) is None


def test_replacer_refuses_to_guess_for_an_unregistered_entity():
    # The brief's fixture here was `US_DRIVER_LICENSE`, on the reasoning that a
    # 0.01 hit of that shape is the spurious detection seen on a real MRN. It
    # cannot be used literally: Presidio's default English recognizers emit
    # `US_DRIVER_LICENSE`, and this table registers every default entity, so a
    # driver's licence number in a report is replaced rather than blocked. The
    # property the test exists to pin is the refusal itself, and it is pinned
    # here on an entity that genuinely has no entry. The refusal keys on the
    # *entity*, not the score: even a 0.99 hit is refused.
    with pytest.raises(ValueError):
        replacement_for(EntityHit("AMBIGUOUS_REFERENCE", 0, 3, 0.01, "abc"), CTX)
    with pytest.raises(ValueError):
        replacement_for(EntityHit("AMBIGUOUS_REFERENCE", 0, 3, 0.99, "abc"), CTX)


def test_every_entity_the_engine_can_emit_either_has_a_replacer_or_is_known():
    # The registry is the universe of entity types `scan_entities` can return.
    # Anything Presidio emits that is *not* in `REPLACERS` is a permanent,
    # unconditional block — safe, but worth seeing. This asserts the set is
    # what the table and `AMBIGUOUS_REFERENCE` expect, so a new Presidio
    # recognizer cannot silently start blocking every report.
    emitted = {
        entity
        for recognizer in build_engine().registry.recognizers
        for entity in recognizer.supported_entities
    }
    assert emitted - set(REPLACERS) == {"AMBIGUOUS_REFERENCE"}


def test_an_unreplaceable_hit_survives_the_overlap_collapse_by_default():
    # The failure this guards is silent and total. Measured on this machine,
    # spaCy reports "ZX-99-ALPHA" as `ORGANIZATION` at 0.85 on exactly the same
    # span as `AMBIGUOUS_REFERENCE` at 0.30. Collapsing on score alone keeps
    # the organization, drops the reference, and layer 2 never learns there is
    # anything it cannot replace — the document goes out
    # redacted-as-an-organisation and the blocked beat never fires. No
    # predicate is passed: the registered one already does this.
    text = "Ref ticket ZX-99-ALPHA issued at the counter."
    hits = scan_entities(text, min_score=0.0)
    assert any(h.entity_type == "AMBIGUOUS_REFERENCE" for h in hits)
    assert any(h.entity_type == "ORGANIZATION" for h in hits)
    # And the collapse still does its job where nothing is unresolvable.
    assert [h.entity_type for h in scan_entities("MRN: 4452819", min_score=0.0)] == ["MRN"]


def test_every_hit_splices_back_into_the_callers_own_text():
    # The offset contract, pinned where it protects: every span indexes the
    # string the caller passed, so `text[start:end]` is exactly the detected
    # value. The multi-anchor note is the case that used to break — with the
    # deleting strip, the third hit's span landed eight characters past its
    # value, inside a different field, and `text[start:end]` was `'-11 and '`.
    text = (
        "MRN: 4452819 and DOB: 1953-04-11 and PAT 9911 and "
        "Ref ticket ZX-99-ALPHA issued at the counter."
    )
    hits = scan_entities(text, min_score=0.0)
    assert len(hits) > 1
    for hit in hits:
        if hit.entity_type == "TRUNCATED_TEXT":
            continue
        assert text[hit.start:hit.end] == hit.text, f"{hit} does not splice"

    # Spelled out for the two fields the bug was found in, so a regression
    # names the corruption rather than only failing a loop.
    by_text = {h.text: h for h in hits}
    assert text[by_text["1953-04-11"].start:by_text["1953-04-11"].end] == "1953-04-11"
    assert text[by_text["PAT 9911"].start:by_text["PAT 9911"].end] == "PAT 9911"
    assert text[by_text["4452819"].start:by_text["4452819"].end] == "4452819"


def test_the_ambiguous_reference_has_no_registered_replacer():
    # The standing demonstration, and the thing Beat 2's determinism rests on.
    # Absent on purpose: a detected entity with no deterministic replacement is
    # a block, not a guess.
    assert "AMBIGUOUS_REFERENCE" not in REPLACERS
    assert not has_replacer("AMBIGUOUS_REFERENCE")


def test_the_block_condition_is_expressible_as_an_absent_replacer():
    # The requirement that a block must not rest on a score: the caller has to
    # be able to say "detected, and nothing can replace it" at *any* score.
    # `has_replacer` deliberately consults neither the threshold nor the hit's
    # score — if it ever did, a configuration change could turn a
    # deterministic block into a silent pass-through.
    assert not has_replacer(EntityHit("AMBIGUOUS_REFERENCE", 0, 13, 0.99, "ZX").entity_type)
    detected = scan_entities(
        "Ref ticket ZX-99-ALPHA issued at the counter.",
        min_score=0.0,
    )
    assert any(
        h.entity_type == "AMBIGUOUS_REFERENCE" and not has_replacer(h.entity_type)
        for h in detected
    )


def test_every_registered_replacer_is_reachable_through_the_table():
    for entity in REPLACERS:
        assert has_replacer(entity)
    # `DATE_TIME` is the one replacer that can decline: it needs a date it can
    # shift, so a bare token is the wrong sample for it. A table whose entries
    # are not reachable would let an entity look replaceable and block anyway.
    for entity in REPLACERS:
        sample = "2026-01-14" if entity == "DATE_TIME" else "x"
        assert replacement_for(EntityHit(entity, 0, len(sample), 0.9, sample), CTX)


def test_the_engine_really_does_return_both_labellers_for_one_span():
    # The premise of the tie-break, asserted rather than assumed. If Presidio
    # ever stopped emitting `DATE_TIME` over the MRN, `_rank`'s clinical-first
    # key would become dead code and this test would say so.
    from medarx.redaction.ner import _shared_engine

    raw = _shared_engine().analyze(text="    4452819", language="en")
    by_type = {r.entity_type for r in raw}
    assert {"MRN", "DATE_TIME"} <= by_type
    assert [h.entity_type for h in scan_entities("MRN: 4452819", min_score=0.0)] == ["MRN"]


def test_the_scan_is_stable_across_hash_seeds():
    # Executed in a subprocess because `PYTHONHASHSEED` is fixed at
    # interpreter start. Presidio returns the two same-span, same-score hits
    # above in registry-iteration order, which is not stable across processes:
    # measured on this machine, seed 0 returned `DATE_TIME` and seeds 1 and 2
    # returned `MRN` before the tie-break existed. A redaction kernel that
    # labels an MRN as a date on some runs is not a kernel, so the scan — not
    # only the recognizers — is pinned across seeds here.
    import os
    import subprocess
    import sys

    script = (
        "import warnings; warnings.filterwarnings('ignore');"
        # `replacers` is imported because a real caller always has it: it
        # registers the predicate that lets the collapse run at all. Without
        # it `ner` fails closed and reports all three overlapping hits.
        "import medarx.redaction.replacers;"
        "from medarx.redaction.ner import scan_entities;"
        "print([h.entity_type for h in scan_entities('MRN: 4452819', 0.0)])"
    )
    seen = set()
    for seed in ("0", "1", "2", "42"):
        # `os.environ` is copied into the child so the interpreter can start
        # at all; no configuration is read from it here. `config.py` remains
        # the only module that reads the environment for settings.
        env = {**os.environ, "PYTHONHASHSEED": seed}
        out = subprocess.run(
            [sys.executable, "-c", script], env=env, capture_output=True, text=True,
            check=True,
        )
        seen.add(out.stdout.strip())
    assert seen == {"['MRN']"}, f"scan is not deterministic across hash seeds: {seen}"


def test_scan_rejects_a_non_string_rather_than_iterating_it():
    # `strip_anchor_labels` would otherwise walk the argument and produce a
    # `TypeError` from somewhere inside a regex, which reads like a bug in
    # the recognizers rather than a wrong argument.
    with pytest.raises(TypeError):
        scan_entities(None, min_score=0.0)
