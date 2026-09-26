"""Component C applied to a payload: surrogates for references, a shift for dates.

The rule this module exists to keep: **pseudonymization replaces references and
dates. It never touches free text.** `report_text` is carried across
byte-identical — not normalised, not stripped, not reformatted. Rewriting
clinical prose here would alter the report on a rule nobody reviewed, and
finding identifiers inside it is the redaction layers' job (D.1-D.3), not this
one.

Every study reference that leaves this function is a surrogate, including the
prior-study references: a raw prior reference would hand the model a study
identifier the kernel exists to withhold. Every date that leaves is moved by
one offset for the patient, so intervals and order between that patient's
studies survive — except where `shift_date` saturates at the calendar
boundary, which it documents. That single offset is why a patient with no
reference is refused rather than given an invented one.

`payload_hash` is deliberately left exactly as it arrived. It is component A's
pre-redaction provenance value; redaction transforms the payload in place
downstream, so a hash computed here could not agree with it, and layer 3
overwrites it. Do not set it here.

An unparseable date is refused rather than passed through: a value that cannot
be shifted is a value that would reach the model unshifted, and forwarding it
would be a privacy failure dressed as a lenient parse.

One limit is worth stating plainly, because it is a limit and not a guarantee:
this function is a pure function of (payload, patient, store), so running it
twice on the *same* input yields the same output. Chaining it — feeding its own
output back in — keeps the references stable, because a surrogate-shaped
reference is recognised, but shifts the dates a second time, since nothing in
`StructuredPayload` records that a date has already been moved. Callers must
call it once per payload; a second call on an already-pseudonymized payload
is a bug, not an idempotent no-op.
"""

from __future__ import annotations

from datetime import date

from medarx.errors import PseudonymError
from medarx.models import StructuredPayload
from medarx.pseudonym.date_shift import shift_date
from medarx.pseudonym.mapping_store import MappingStore

__all__ = ["DATE_FIELDS", "pseudonymize_payload"]

#: The only payload fields that carry a date, named explicitly rather than
#: matched by a suffix: a rule that shifted anything called `*_date` would
#: quietly rewrite a field no allowlist reviewed, and a date field added later
#: would pass through unshifted instead of being caught here.
DATE_FIELDS = ("study_date", "prior_study_date")

#: The length of a DICOM `DA` value. A longer string is not a date with
#: trailing junk, and truncating it would shift only its prefix and leave the
#: rest of a real date in place.
_DATE_LENGTH = 8

_DATE_FORMAT = "%Y%m%d"

#: The prefix the store gives every study surrogate. A reference already
#: carrying it has been through this component, so it is passed through rather
#: than mapped a second time: re-mapping would mint a surrogate of a surrogate,
#: and the same study would not keep one identity across two passes. The
#: trade-off is explicit — a source reference that already looks like a
#: surrogate is left alone and is never recorded in the store.
_STUDY_SURROGATE_PREFIX = "medarx-study-"


def pseudonymize_payload(
    payload: StructuredPayload,
    patient_ref: str,
    store: MappingStore,
) -> StructuredPayload:
    """Return a copy of `payload` with surrogates and shifted dates.

    `patient_ref` selects the one offset applied to every date. `input_hash` is
    carried through unchanged; `payload_hash` is left as it arrived (see the
    module docstring).

    A study reference already carrying the store's surrogate prefix is passed
    through rather than mapped again (see `_STUDY_SURROGATE_PREFIX`).

    Raises `PseudonymError` with `MISSING_SURROGATE` when the patient or study
    reference is blank, and with `UNSHIFTED_DATE` when a date field holds
    something that is not a DICOM `YYYYMMDD` date. A blank date field is left
    as it is: there is no date there to leak or to shift.
    """
    if not patient_ref.strip():
        raise PseudonymError(
            action_codes=("MISSING_SURROGATE",),
            message="a patient reference is required to choose a date offset",
        )
    if not payload.study_ref.strip():
        raise PseudonymError(
            action_codes=("MISSING_SURROGATE",),
            message="a study reference is required to assign a surrogate",
        )

    offset = store.offset_for_patient(patient_ref)
    fields = {
        key: _shift_field(key, value, offset)
        for key, value in payload.dicom_fields.items()
    }
    return payload.model_copy(
        update={
            "dicom_fields": fields,
            "study_ref": _study_surrogate(payload.study_ref, store),
            "prior_study_refs": tuple(
                _study_surrogate(ref, store) for ref in payload.prior_study_refs
            ),
        }
    )


def _shift_field(key: str, value: str, offset: int) -> str:
    """`value` moved by `offset` days, if `key` is a date field."""
    if key not in DATE_FIELDS:
        return value
    if not value.strip():
        return value
    if len(value) != _DATE_LENGTH:
        raise PseudonymError(
            action_codes=("UNSHIFTED_DATE",),
            message=f"{key!r} is not a DICOM date such as 20260114: {value!r}",
        )
    try:
        parsed = date(int(value[0:4]), int(value[4:6]), int(value[6:8]))
    except ValueError as exc:
        raise PseudonymError(
            action_codes=("UNSHIFTED_DATE",),
            message=f"{key!r} is not a DICOM date such as 20260114: {value!r}",
        ) from exc
    return shift_date(parsed, offset).strftime(_DATE_FORMAT)


def _study_surrogate(study_ref: str, store: MappingStore) -> str:
    """The surrogate for `study_ref`, or `study_ref` itself if it already is one."""
    if study_ref.startswith(_STUDY_SURROGATE_PREFIX):
        return study_ref
    return store.surrogate_for_study(study_ref)
