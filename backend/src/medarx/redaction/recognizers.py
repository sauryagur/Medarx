"""The custom clinical `PatternRecognizer` set for the D layer.

Presidio ships no recognizer for MRN, accession number, or patient ID. Worse,
its *generic* recognizers mislabel clinical fields: `DOB` was scored as
`ORGANIZATION` at 0.85 and a seven-digit MRN `4452819` as `DATE_TIME` at 0.85.
Redacting an MRN as though it were a date corrupts the payload instead of
de-identifying it, so these recognizers are a hard requirement of the boundary,
not an enhancement to it.

Two things here are deliberately odd and are load-bearing:

* The recognizer patterns consume their own field label (`MRN: 4452819` is one
  match spanning `(0, 12)`), so the label cannot survive as a dangling `MRN:`
  beside a redacted value. The cost is that the label sits inside the replaced
  span, so the surrounding text reads less like a labelled report.

* `AMBIGUOUS_REFERENCE` scores below `Settings.ner_score_threshold` and has no
  registered replacer. It exists so the blocked beat is deterministic: the
  value is always detected and can never be sanitised, so layer 2 must emit
  `NER_UNRESOLVED`. That determinism rests on the **absent replacer**, not on
  the score: it survives any future change to the score or to the threshold.
  The score is held below the threshold as well, which needs an empty context
  to survive context enhancement — see `UNENHANCEABLE_CONTEXT`.

* `PATIENT_ID` folds the case of its *label* only (`(?i:…)`). Case sensitivity
  there left "patient id: 12345678" matching nothing at all, which is a
  patient identifier left in the text the model receives. The value class is
  digits, so folding the label cannot reach prose. The other entities keep
  case-sensitive labels: their value classes admit letters, and a folded
  `ACC` label matches the date `acc 20260114`.

This module builds recognizers only. The analyzer *engine* belongs to `ner.py`,
which Task 8 owns; constructing it here as well would be the duplication a
reviewer flags.
"""

import re

from presidio_analyzer import Pattern, PatternRecognizer

__all__ = [
    "ANCHOR_LABELS",
    "CONTEXT",
    "CUSTOM_ENTITIES",
    "AMBIGUOUS_SCORE",
    "PATTERNS",
    "RECOGNIZER_SCORE",
    "REGEX_FLAGS",
    "UNENHANCEABLE_CONTEXT",
    "build_recognizers",
    "strip_anchor_labels",
]


#: The score carried by the three mandatory clinical patterns. Presidio treats
#: a recognizer's score as a *minimum*: context enhancement can raise a hit
#: above it, so this is the floor, not a cap.
RECOGNIZER_SCORE = 0.85

#: The score for the deliberately-unresolvable reference. Below
#: `Settings.ner_score_threshold` (0.50) and with no replacer, so the value can
#: be detected and never resolved — which is what makes the blocked beat
#: reproducible rather than a matter of model confidence.
AMBIGUOUS_SCORE = 0.30


#: The entities this module is responsible for. The first three are the
#: design's mandatory clinical recognizers; the fourth is the format-ambiguous
#: reference described above.
CUSTOM_ENTITIES: tuple[str, ...] = (
    "MRN",
    "ACCESSION_NUMBER",
    "PATIENT_ID",
    "AMBIGUOUS_REFERENCE",
)


#: Context words, handed to Presidio's context-aware enhancer. They raise a
#: hit's score when the identifier appears near one of them; they do not
#: participate in matching.
CONTEXT: dict[str, list[str]] = {
    "MRN": ["mrn", "medical record", "record number"],
    "ACCESSION_NUMBER": ["accession", "acc"],
    "PATIENT_ID": ["patient id", "pat id", "mrn"],
    "AMBIGUOUS_REFERENCE": ["ticket", "ref", "issued"],
}

#: Context words for the deliberately-unresolvable reference, kept here as
#: documentation and deliberately NOT attached to the recognizer.
#:
#: WARNING — do not attach these. Presidio's `PatternRecognizer.analyze`
#: performs no enhancement (which is why the unit tests here see exactly 0.30),
#: but `AnalyzerEngine._enhance_using_context` runs
#: `LemmaContextAwareEnhancer`, which adds `context_similarity_factor = 0.35`
#: and then floors at 0.4. On this module's own fixture — "Ref ticket
#: ZX-99-ALPHA issued at the counter." — the words `ref`, `ticket` and `issued`
#: are all in the same sentence, so attaching this context lifts the score from
#: 0.30 to **0.65**, above `Settings.ner_score_threshold` (0.50). Measured
#: through a real engine, not inferred. The recognizer is therefore built with
#: an empty context: `LemmaContextAwareEnhancer.enhance_using_context` skips
#: any recognizer whose `context` is falsy, so 0.30 reaches the engine intact.
#:
#: This protects only the *score*. What makes the blocked beat deterministic is
#: that no replacer is registered for `AMBIGUOUS_REFERENCE`: a detected entity
#: with no safe replacement must be `NER_UNRESOLVED` whatever its confidence.
#: Layer 2 and the policy engine must key on the absent replacer, never on the
#: score.
UNENHANCEABLE_CONTEXT: dict[str, list[str]] = {
    "AMBIGUOUS_REFERENCE": [],
}


#: The patterns, as Presidio `Pattern` objects so the score each one carries is
#: inspectable without building a recognizer.
#:
#: The MRN and accession labels are inside an optional group, so `"MRN: 4452819"`
#: matches as a single span from index 0. The character class in the accession
#: value includes `-`: without it the pattern cannot match a hyphenated
#: accession at all, which fails silently rather than loudly.
PATTERNS: dict[str, list[Pattern]] = {
    "MRN": [
        Pattern(
            name="clinical_mrn",
            regex=r"\b(?:MRN\s*[:#]?\s*)?[A-Z]{0,2}\d{7}\b",
            score=RECOGNIZER_SCORE,
        )
    ],
    "ACCESSION_NUMBER": [
        Pattern(
            name="clinical_accession_number",
            regex=r"\b(?:ACC|Accession)\s*[:#]?\s*[A-Z0-9-]{6,12}\b",
            score=RECOGNIZER_SCORE,
        )
    ],
    "PATIENT_ID": [
        Pattern(
            name="clinical_patient_id",
            # `(?i:...)` scopes case-insensitivity to the *label* only. The
            # label is the part of a field name a human writes in any case; the
            # value class stays digits-only, so folding the label cannot reach a
            # clinical word or a date. Scoped inline flags leave
            # `global_regex_flags` case-sensitive for the other entities, whose
            # value classes admit letters.
            #
            # This is a leak fix, not a preference. Case-sensitive, this
            # pattern matched nothing at all in "patient id: 12345678", leaving
            # a patient identifier in the text the model receives with every
            # test green. A miss here is not a nuisance; it is silent. The
            # unscoped alternative (`(?i:...)` around the whole pattern) is
            # wrong: it re-breaks `acc 20260114` on the accession recognizer.
            regex=r"\b(?i:PAT|Patient\s*ID)\s*[:#]?\s*\d{4,8}\b",
            score=RECOGNIZER_SCORE,
        )
    ],
    "AMBIGUOUS_REFERENCE": [
        Pattern(
            name="ambiguous_reference",
            regex=r"\b[A-Z]{2,4}-\d{2}-[A-Z]{4,}\b",
            score=AMBIGUOUS_SCORE,
        )
    ],
}


#: Standalone clinical field labels. These are stripped from display text so a
#: replaced span does not leave a dangling `MRN:` in front of a surrogate.
ANCHOR_LABELS: tuple[str, ...] = (
    "MRN",
    "ACC",
    "Accession",
    "PAT",
    "Patient ID",
    "DOB",
    "Date of Birth",
)


#: Presidio's `PatternRecognizer` default is
#: `re.DOTALL | re.MULTILINE | re.IGNORECASE`. `IGNORECASE` is wrong for these
#: patterns: the character classes are the *shape* of a clinical identifier
#: (an uppercase `ACC`, an uppercase letter prefix), and case-folding them makes
#: the accessor match text it must not. Executed under the default, the
#: accession pattern matched the bare word "Accession" as `ACC` + `ession` — a
#: redaction that deletes the word "Accession" out of a report — and matched
#: the date `acc 20260114`. These flags are pinned rather than inherited.

#: The accepted cost: a lower-cased *label* is no longer consumed, so
#: `"accession: ACC0000417"` matches the value at `(11, 21)` rather than the
#: whole field, and `"patient id: 12345678"` matches nothing at all — that
#: label has no bare-value alternative. Clinical reports use capitalised field
#: labels; a lower-cased one is a miss, not a corruption, and the choice is
#: deliberate. The bare numeric values are matched in either case.
REGEX_FLAGS = re.DOTALL | re.MULTILINE


def build_recognizers() -> list[PatternRecognizer]:
    """Return one `PatternRecognizer` per entity in `CUSTOM_ENTITIES`.

    `AMBIGUOUS_REFERENCE` is built with an empty context on purpose — see
    `UNENHANCEABLE_CONTEXT`, which explains what breaks if that changes.
    """
    return [
        PatternRecognizer(
            supported_entity=entity,
            name=f"medarx_{entity.lower()}",
            patterns=PATTERNS[entity],
            context=UNENHANCEABLE_CONTEXT.get(entity, CONTEXT[entity]),
            global_regex_flags=REGEX_FLAGS,
        )
        for entity in CUSTOM_ENTITIES
    ]


def _anchor_pattern() -> re.Pattern[str]:
    labels = "|".join(re.escape(label) for label in ANCHOR_LABELS)
    # A label counts as an anchor only when a separator follows it. Requiring
    # the separator is what keeps prose intact: "the mrn was verified" is a
    # sentence, while "MRN: 4452819" is a field.
    return re.compile(rf"(?<![\w])(?:{labels})\s*[:#]", re.IGNORECASE)


_ANCHOR = _anchor_pattern()


def strip_anchor_labels(text: str) -> str:
    """Remove standalone clinical field labels from `text`.

    Only a label standing alone and followed by `:` or `#` is removed, and
    only the label and its separator: the whitespace after it is left in place,
    so offsets elsewhere in the string do not shift. Free-standing clinical
    words (`FINDINGS:`, and a sentence that merely mentions "mrn") are left
    exactly as they are.
    """
    return _ANCHOR.sub("", text)
