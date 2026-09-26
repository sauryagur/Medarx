"""Layer A: the structured payload extractor.

This module is the front door of the privacy kernel and a hard boundary. It
never accepts an arbitrary DICOM object or a free-form prompt: it validates
the function, rejects any attribute the known-attribute table does not name,
and copies across only the fields the function's allowlist blesses.

The deliberate asymmetry: a *known* attribute that the function's allowlist
does not name is **dropped** (it is not a privacy event); an attribute the
table does not know at all — including anything under `PixelData` — is
**rejected**, because a caller reaching for something outside the table is
signalling an intent this boundary refuses rather than filters.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

from medarx.errors import ExtractionError
from medarx.extraction.allowlists import ALLOWED_FIELDS
from medarx.extraction.study_context import StudyContext
from medarx.models import ExtractionRequest, StructuredPayload, canonical_hash

__all__ = ["pipeline_for", "KNOWN_DICOM_ATTRIBUTES"]

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

#: Never carried into the payload, whatever the allowlist says.
_NEVER_CARRIED: frozenset[str] = frozenset(
    {"PatientID", "AccessionNumber", "PatientName", "InstitutionName"}
)

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

    known_field_names = {field for names in ALLOWED_FIELDS.values() for field in names}

    for key in dicom_metadata:
        if key in _ATTRIBUTE_TO_FIELD or key in KNOWN_DICOM_ATTRIBUTES:
            continue
        # A field name the tables know but this function does not bless is a
        # policy refusal; anything else is an unknown attribute.
        if key in known_field_names:
            raise ExtractionError(
                layer=LAYER,
                action_codes=("FIELD_NOT_ALLOWLISTED",),
                message=f"{key!r} is not allowlisted for function {function!r}",
            )
        raise ExtractionError(
            layer=LAYER,
            action_codes=("UNKNOWN_DICOM_ATTRIBUTE",),
            message=f"{key!r} is not a known DICOM attribute",
        )
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

    return StructuredPayload(
        function=function,
        report_text=report_text,
        dicom_fields=dicom_fields,
        study_ref=study.study_ref,
        prior_study_refs=(),
        policy_version=policy_version,
        input_hash=input_hash,
        payload_hash=canonical_hash(
            {
                "function": function,
                "report_text": report_text,
                "dicom_fields": dicom_fields,
                "study_ref": study.study_ref,
                "prior_study_refs": (),
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
