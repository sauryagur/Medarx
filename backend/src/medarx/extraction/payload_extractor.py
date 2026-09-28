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
from types import MappingProxyType

from medarx.errors import ExtractionError
from medarx.extraction.allowlists import ALLOWED_FIELDS
from medarx.extraction.study_context import StudyContext
from medarx.models import ExtractionRequest, StructuredPayload, canonical_hash

__all__ = ["ATTRIBUTE_TO_FIELD", "extract", "pipeline_for", "KNOWN_DICOM_ATTRIBUTES"]

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

#: DICOM keyword -> canonical snake_case payload field. Published rather than
#: private because the field-action summary has to say which of a caller's
#: attributes reached a payload field and which were dropped, and a private
#: table read through a module attribute would be the same table with worse
#: manners. A keyword absent from it is one this boundary never carries, which
#: is a fact about the boundary and not an error: `PatientID` and
#: `AccessionNumber` are accepted and dropped by design.
ATTRIBUTE_TO_FIELD: Mapping[str, str] = MappingProxyType({
    "Modality": "modality",
    "StudyDate": "study_date",
    "PatientAge": "patient_age_band",
    "PriorReportText": "prior_report_text",
    "PriorStudyDate": "prior_study_date",
})

#: Field names that make a function a "prior" function: only these functions
#: carry `prior_study_refs` into the payload.
_PRIOR_FIELDS: frozenset[str] = frozenset({"prior_report_text", "prior_study_date"})


#: The DICOM `AS` (age string) VR: three digits and one of four units. `W` is
#: in the standard and was missing here, so a perfectly good `010W` was refused
#: as `MALFORMED_METADATA`.
_AGE = re.compile(r"^(\d{3})([DWMY])$")

#: How many months one unit is worth, used to bring every age onto a common
#: scale before it is banded. `M` and `Y` are exact. `D` and `W` are not, and
#: cannot be: an `AS` value carries no calendar, so 365 days and 52 weeks are
#: the conventional year lengths and the conversion is a mean rather than date
#: arithmetic. The measured cost of that: the same real age spelled in days and
#: in the nearest whole weeks lands one month apart for 12 of 1000 day-values,
#: and every one of those 12 is on a band boundary, where the two roundings
#: fall either side. That is inherent to the VR. The alternative is not
#: converting at all, which is how `030D` came to mean a 30-year-old.
_MONTHS_PER_UNIT: dict[str, float] = {"D": 12 / 365, "W": 12 / 52, "M": 1, "Y": 12}

#: The width of an infant band, in months, and the suffix that marks a band as
#: being counted in months rather than years.
_INFANT_BAND_MONTHS = 3
_MONTH_BAND_SUFFIX = "M"

#: Every age from here up shares one band. A de-identification-strength
#: choice, not a compliance claim — Medarx does not assert HIPAA conformance.
#: Grouping is the standard reference implementation for the top of the age
#: range, and what it buys here is stated plainly: ages 90 and over are ten
#: distinguishable values in decade bands and one afterwards. Nothing below the
#: cut changes, because the decade bands are already as coarse as this module
#: goes anywhere.
_OLDEST_BAND_LOW = 90
_OLDEST_BAND = "090+"


def _age_band(value: str) -> str:
    """`045Y` -> `040-049`. Age is a band here, never an exact birth date.

    **The unit is read, not discarded.** `AS` is `ddd[DWMY]`, and an age
    expressed in days, weeks or months is not an age in years: `030D` is a
    30-day-old, and banding it as `030-039` hands every later stage a clinical
    age wrong by thirty years. So the value is first brought onto a common
    scale in months and only then banded.

    **A sub-year age is banded in months, not in years.** `000-009` would put a
    neonate, a 7-month-old and a 9-year-old in one bucket. That is useless to
    anything reading the payload, and it buys nothing in privacy, because
    every other band is already a decade wide — narrowing the top of the range
    to three months is what makes it a *different* band, not a safer one. So
    below one year the band is `_INFANT_BAND_MONTHS` wide and carries a
    trailing `M`, which keeps `003-005M` from being read as three-to-five
    *years*. This is a choice, not a forced one: the alternative is to report
    every age under ten in months, which is finer, and is rejected because it
    makes the under-tens more distinguishable than the adults while leaving
    them no less identifiable to anyone who already knows the age.

    **From one year up the band is a decade of years**, so `018M` — 18 months,
    one year and a half — lands in `000-009` alongside nine-year-olds. That
    coarseness is the trade the band exists to make, and it is the same trade
    `040-049` already makes between a 40-year-old and a 49-year-old.
    """
    m = _AGE.match(value.strip().upper())
    if m is None:
        raise ExtractionError(
            layer=LAYER,
            action_codes=("MALFORMED_METADATA",),
            message="PatientAge is not a DICOM age string such as 045Y",
        )
    magnitude, unit = int(m.group(1)), m.group(2)
    months = round(magnitude * _MONTHS_PER_UNIT[unit])

    if months < 12:
        low = months - months % _INFANT_BAND_MONTHS
        return f"{low:03d}-{low + _INFANT_BAND_MONTHS - 1:03d}{_MONTH_BAND_SUFFIX}"

    years = months // 12
    if years >= _OLDEST_BAND_LOW:
        return _OLDEST_BAND
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
        field = ATTRIBUTE_TO_FIELD.get(key)
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
        field = ATTRIBUTE_TO_FIELD.get(key)
        if field is None or field not in allowed:
            continue
        dicom_fields[field] = _age_band(value) if key == "PatientAge" else value

    # `input_hash` deliberately covers the FULL metadata mapping, including the
    # identifier attributes that are dropped below. It attests to what
    # *arrived* at the boundary, not to what survived: if it covered only the
    # surviving fields, two different inputs that reduced to the same payload
    # would hash identically and the audit trail could no longer tell them
    # apart. The hash is one-way and the raw values never cross the boundary,
    # so including them discloses nothing. Do not narrow this to the carried
    # fields.
    input_hash = canonical_hash(
        {
            "function": function,
            "report_text": report_text,
            "dicom_metadata": dict(dicom_metadata),
            "study_ref": study.study_ref,
            "policy_version": policy_version,
        }
    )

    prior_study_refs = tuple(study.prior_study_refs) if allowed & _PRIOR_FIELDS else ()

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
