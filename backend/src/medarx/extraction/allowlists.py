"""The per-function field allowlists.

This module is the only place a field name is blessed. Nothing here widens at
runtime: the table is built once at import time and every consumer reads it
rather than threading field names through any other path.
"""

from __future__ import annotations

__all__ = ["ALLOWED_FIELDS", "REQUIRED_FIELDS"]

ALLOWED_FIELDS: dict[str, frozenset[str]] = {
    "draft": frozenset(
        {"report_text", "patient_age_band", "study_date", "modality"}
    ),
    "prior_summary": frozenset(
        {
            "report_text",
            "patient_age_band",
            "study_date",
            "modality",
            "prior_report_text",
            "prior_study_date",
        }
    ),
    "ask": frozenset(
        {
            "report_text",
            "patient_age_band",
            "study_date",
            "modality",
            "prior_report_text",
            "prior_study_date",
        }
    ),
}

#: The fields a payload for any function cannot do without: what the study is
#: and when it was. `report_text` is absent because it is a required field of
#: `StructuredPayload` itself, and the prior fields are absent because a prior
#: study may genuinely have no narrative or no date.
#:
#: This is the "missing field" half of layer 3's contract check, and it lives
#: here rather than in the redaction layer for the reason this module's own
#: docstring gives: it is the only place a field name is blessed. A second
#: table in the checker would drift from the allowlist and no test would see
#: it.
_STUDY_DESCRIPTORS: frozenset[str] = frozenset(
    {"patient_age_band", "study_date", "modality"}
)

#: Keyed by function so a function added to `ALLOWED_FIELDS` is covered by
#: construction rather than by remembering to add a line here.
REQUIRED_FIELDS: dict[str, frozenset[str]] = {
    function: _STUDY_DESCRIPTORS for function in ALLOWED_FIELDS
}
