"""Layer A: the structured payload extractor.

This module is the front door of the privacy kernel and a hard boundary. It
never accepts an arbitrary DICOM object or a free-form prompt: it validates
the function, rejects any attribute the known-attribute table does not name,
and copies across only the fields the function's allowlist blesses.

Three refusals, in order:

- an unknown `function` -> `UNKNOWN_FUNCTION`;
- an attribute the known-attribute table does not name, including anything
  under `PixelData` -> `UNKNOWN_DICOM_ATTRIBUTE`;
- a known attribute that maps to a real payload field the function's
  allowlist does not name -> `FIELD_NOT_ALLOWLISTED`. A caller asking for a
  field it may not have is refused, not quietly given less.

Known identifier attributes (`PatientID`, `AccessionNumber`, `PatientName`,
`InstitutionName`) and `StudyInstanceUID` map to no payload field at all and
are dropped; they are never carried, so refusing them would be noise.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

from medarx.errors import ExtractionError
from medarx.extraction.allowlists import ALLOWED_FIELDS
from medarx.extraction.study_context import StudyContext
from medarx.models import ExtractionRequest, StructuredPayload, canonical_hash

__all__ = ["extract", "pipeline_for", "KNOWN_DICOM_ATTRIBUTES"]

LAYER = "A"

#: Every DICOM keyword this boundary will look at. Anything else is refused.
#: `PixelData` is deliberately absent, so any attempt to smuggle a raw element
#: payload through here fails as an unknown attribute.
KNOWN_DICOM_ATTRIBUTES: frozenset[str] = frozenset(
    {
        "Modality",
        "StudyDate",
        "PatientAge",
        "PatientID",
        "AccessionNumber",
        "InstitutionName",
        "PriorReportText",
        "PriorStudyDate",
        "StudyInstanceUID",
        "PatientName",
    }
)

#: DICOM keyword -> canonical snake_case payload field.
_ATTRIBUTE_TO_FIELD: dict[str, str] = {
    "Modality": "modality",
    "StudyDate": "study_date",
    "PatientAge": "patient_age_band",
    "PriorReportText": "prior_report_text",
    "PriorStudyDate": "prior_study_date",
}

#: Field names that make a function a "prior" function: only these functions
#: carry `prior_study_refs` into the payload.
_PRIOR_FIELDS: frozenset[str] = frozenset({"prior_report_text", "prior_study_date"})


_AGE = re.compile(r"^(\d{3})([YMD])$")


def _age_band(value: str) -> str:
    """`045Y` -> `040-049`. Age is a band here, never an exact birth date."""
    m = _AGE.match(value.strip().upper())
    if m is None:
        raise ExtractionError(
            layer=LAYER,
            action_codes=("FIELD_NOT_ALLOWLISTED",),
            message="PatientAge is not a DICOM age string such as 045Y",
        )
    years = int(m.group(1))
    low = years - years % 10
    return f"{low:03d}-{low + 9:03d}"


def pipeline_for(
    function: str,
    study: StudyContext,
    report_text: str,
    dicom_metadata: Mapping[str, str],
    policy_version: str,
) -> StructuredPayload:
    """Build a `StructuredPayload` for `function`, or refuse.

    A pure function of its arguments: `policy_version` is passed in from
    `Settings` at the composition root and configuration is never read here.
    """
    if function not in ALLOWED_FIELDS:
        raise ExtractionError(
            layer=LAYER,
            action_codes=("UNKNOWN_FUNCTION",),
            message=f"{function!r} is not a known function",
        )
    allowed = ALLOWED_FIELDS[function]

    for key in dicom_metadata:
        if key not in KNOWN_DICOM_ATTRIBUTES:
            raise ExtractionError(
                layer=LAYER,
                action_codes=("UNKNOWN_DICOM_ATTRIBUTE",),
                message=f"{key!r} is not a known DICOM attribute",
            )
        field = _ATTRIBUTE_TO_FIELD.get(key)
        if field is not None and field not in allowed:
            # A real field this function may not carry. Refusing is the point:
            # the caller asked for something outside the allowlist.
            raise ExtractionError(
                layer=LAYER,
                action_codes=("FIELD_NOT_ALLOWLISTED",),
                message=f"{field!r} is not allowlisted for function {function!r}",
            )
        # Known attributes with no payload field (the identifier attributes and
        # StudyInstanceUID) are dropped here and never carried.

    dicom_fields: dict[str, str] = {}
    for key, value in dicom_metadata.items():
        field = _ATTRIBUTE_TO_FIELD.get(key)
        if field is None or field not in allowed:
            continue
        dicom_fields[field] = _age_band(value) if key == "PatientAge" else value

    input_hash = canonical_hash(
        {
            "function": function,
            "report_text": report_text,
            "dicom_metadata": dict(dicom_metadata),
            "study_ref": study.study_ref,
            "policy_version": policy_version,
        }
    )

    prior_study_refs = (
        tuple(study.prior_study_refs) if allowed & _PRIOR_FIELDS else ()
    )

    return StructuredPayload(
        function=function,
        report_text=report_text,
        dicom_fields=dicom_fields,
        study_ref=study.study_ref,
        prior_study_refs=prior_study_refs,
        policy_version=policy_version,
        input_hash=input_hash,
        # Pre-redaction provenance only. Redaction layer 3 overwrites this.
        payload_hash=canonical_hash(
            {
                "function": function,
                "report_text": report_text,
                "dicom_fields": dicom_fields,
                "study_ref": study.study_ref,
                "prior_study_refs": prior_study_refs,
                "policy_version": policy_version,
                "input_hash": input_hash,
            }
        ),
    )


def extract(request: ExtractionRequest) -> StructuredPayload:
    """`ExtractionRequest` form of `pipeline_for`; the same boundary."""
    return pipeline_for(
        request.function,
        request.study,
        request.report_text,
        request.dicom_metadata,
        request.policy_version,
    )
