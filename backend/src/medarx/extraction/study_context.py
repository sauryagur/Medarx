"""The per-request study context handed to the extractor.

Carries only internal references; no raw DICOM UID or patient identity is
read from it by the extractor.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["StudyContext"]


@dataclass(frozen=True, slots=True)
class StudyContext:
    """Immutable context for one extraction call."""
    study_uid: str
    study_ref: str
    patient_ref: str
    function: str
    #: Prior-study references relevant to this request, in request order.
    #: Carried only by the functions whose allowlist names prior fields.
    prior_study_refs: tuple[str, ...] = ()
