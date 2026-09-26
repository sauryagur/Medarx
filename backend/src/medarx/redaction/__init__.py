"""Component D: redaction — deterministic recognizers and their replacers.

The custom recognizers in this package exist because Presidio ships none for
MRN, accession number, or patient ID, and because its generic recognizers
mislabel clinical fields: a seven-digit MRN was classified as `DATE_TIME`,
which would corrupt the payload rather than de-identify it.
"""

from medarx.redaction.recognizers import (
    CONTEXT,
    CUSTOM_ENTITIES,
    PATTERNS,
    RECOGNIZER_SCORE,
    REGEX_FLAGS,
    build_recognizers,
    strip_anchor_labels,
)

__all__ = [
    "CONTEXT",
    "CUSTOM_ENTITIES",
    "PATTERNS",
    "RECOGNIZER_SCORE",
    "REGEX_FLAGS",
    "build_recognizers",
    "strip_anchor_labels",
]
