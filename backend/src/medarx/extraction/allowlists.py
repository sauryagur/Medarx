"""The per-function field allowlists.

This module is the only place a field name is blessed. Nothing here widens at
runtime: the table is built once at import time and every consumer reads it
rather than threading field names through any other path.
"""

from __future__ import annotations

__all__ = ["ALLOWED_FIELDS"]

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
