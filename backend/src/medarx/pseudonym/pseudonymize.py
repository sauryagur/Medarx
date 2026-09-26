"""Component C applied to a payload: surrogates for references, a shift for dates.

The rule this module exists to keep: **pseudonymization replaces references and
dates. It never touches free text.** `report_text` is carried across
byte-identical — not normalised, not stripped, not reformatted. Rewriting
clinical prose here would alter the report on a rule nobody reviewed, and
finding identifiers inside it is the redaction layers' job (D.1-D.3), not this
one.

Every study reference that leaves this function is a surrogate minted and
recorded by the store, including the prior-study references: a raw prior
reference would hand the model a study identifier the kernel exists to
withhold. Every date that leaves is moved by one offset for the patient, so
intervals and order between that patient's studies survive — except where
`shift_date` saturates at the calendar boundary, which it documents. That
single offset is why a patient with no reference is refused rather than given
an invented one.

The patient is recorded too, not only the studies. `store.surrogate_for_patient`
writes the patient's surrogate and the shift offset in force for it in one row,
and it is the only thing that writes that row: the offset this module applies
comes from `offset_for_patient`, which derives the same value and stores
nothing. So the recording is not bookkeeping added here — without the call, the
shift applied to a payload would leave no trace of which shift it was.

`payload_hash` is deliberately left exactly as it arrived. It is component A's
pre-redaction provenance value; redaction transforms the payload in place
downstream, so a hash computed here could not agree with it, and layer 3
overwrites it. Do not set it here.

An unparseable date is refused rather than passed through: a value that cannot
be shifted is a value that would reach the model unshifted, and forwarding it
would be a privacy failure dressed as a lenient parse.

**Call this once per payload.** It is a pure function of (payload, patient,
store), so the same input always gives the same output, but it has no way to
tell whether a date it is handed has already been shifted — nothing in
`StructuredPayload` records that, and the model forbids extra fields. Rather
than resolve that by documentation, it is resolved at runtime: a reference
already shaped like a surrogate is refused (see `SURROGATE_SHAPE`), so a
second application fails loudly instead of double-shifting the dates and
returning a payload whose clinical intervals are silently wrong.
"""

from __future__ import annotations

import re
from datetime import date

from medarx.errors import PseudonymError
from medarx.models import StructuredPayload
from medarx.pseudonym.date_shift import shift_date
from medarx.pseudonym.derivation import SURROGATE_HEX_CHARS
from medarx.pseudonym.mapping_store import MappingStore

__all__ = ["SURROGATE_SHAPE", "pseudonymize_payload", "shift_dicom_date"]

#: The only payload fields that carry a date, named explicitly rather than
#: matched by a suffix: a rule that shifted anything called `*_date` would
#: quietly rewrite a field no allowlist reviewed, and a date field added later
#: would pass through unshifted instead of being caught here.
_DATE_FIELDS = ("study_date", "prior_study_date")

#: The exact shape of a study surrogate: the study domain, then the number of
#: hex characters `derivation.surrogate` keeps. Anchored by `fullmatch` at
#: every call site, so a reference that merely *contains* the domain — a
#: legitimate value such as `STU-medarx-study-1` — is not swept up by it.
#:
#: Public because the redaction layers must recognise exactly this shape when
#: they check a reference, and a second copy of the expression would be free to
#: drift from the one the store mints.
SURROGATE_SHAPE = re.compile(
    rf"medarx-study-[0-9a-f]{{{SURROGATE_HEX_CHARS}}}",
)

#: The length of a DICOM `DA` value. A longer string is not a date with
#: trailing junk, and truncating it would shift only its prefix and leave the
#: rest of a real date in place.
_DATE_LENGTH = 8

_DATE_FORMAT = "%Y%m%d"

#: The code for a reference that already *has* the shape of a surrogate.
#: Deliberately not `MISSING_SURROGATE`, which this module also emits for the
#: genuinely-missing cases (a blank patient or study reference): a receipt
#: carries the code but not the message, so reusing it would leave a receipt
#: unable to tell a missing surrogate from a pre-minted one — opposite
#: conditions under the same layer. The polarity of the name is the point.
_REJECTED_CODE = "SURROGATE_SHAPED_REFERENCE_REJECTED"


def pseudonymize_payload(
    payload: StructuredPayload,
    patient_ref: str,
    store: MappingStore,
) -> StructuredPayload:
    """Return a copy of `payload` with surrogates and shifted dates.

    `patient_ref` selects the one offset applied to every date. `input_hash` is
    carried through unchanged; `payload_hash` is left as it arrived (see the
    module docstring).

    Raises `PseudonymError` with `MISSING_SURROGATE` when the patient, the
    `study_ref`, or any entry in `prior_study_refs` is blank — the refusal
    names the offending index; with
    `SURROGATE_SHAPED_REFERENCE_REJECTED` when
    any study reference already has the shape of a surrogate (a distinct
    condition, not a missing one — see `_REJECTED_CODE`); and with
    `UNSHIFTED_DATE` when a date field holds something that is not a DICOM
    `YYYYMMDD` date. A blank date field is left as it is: there is no date
    there to leak or to shift.

    **The patient is recorded before the offset is applied.** The surrogate for
    `patient_ref` and the offset in force for it are written together, by
    `surrogate_for_patient`, and that row is the only place the shift is
    recorded — `offset_for_patient` is a pure derivation and writes nothing. So
    a payload pseudonymized through this function and nothing else would leave
    `pseudonym_patient` empty, and the "offset recorded so the shift in force
    at a point in time can be explained later" that `PATIENT_TABLE` describes
    would not exist for any of them. Recording first also means a refusal
    later — an unshiftable date, a surrogate-shaped reference — cannot leave a
    payload shifted with nothing to explain it.
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
    _refuse_if_surrogate_shaped(payload.study_ref, "study_ref")
    for position, ref in enumerate(payload.prior_study_refs):
        where = f"prior_study_refs[{position}]"
        if not ref.strip():
            # A prior reference is a study reference, so the same rule applies
            # to it. Checked here rather than left to `surrogate_for_study`,
            # which raises a bare `ValueError`: that carries no layer and no
            # action code, so it cannot become a receipt and reaches the caller
            # as a 500 instead of a 422 block. Whitespace counts as blank —
            # `surrogate_for_study(" ")` would otherwise mint a live surrogate
            # for a reference nobody supplied.
            raise PseudonymError(
                action_codes=("MISSING_SURROGATE",),
                message=f"{where} is {ref!r}, and a prior study reference is required",
            )
        _refuse_if_surrogate_shaped(ref, where)

    # Recorded before it is used, so the row and the applied shift are written
    # by the same call path and cannot disagree.
    store.surrogate_for_patient(patient_ref)
    offset = store.offset_for_patient(patient_ref)
    fields = {
        key: _shift_field(key, value, offset)
        for key, value in payload.dicom_fields.items()
    }
    return payload.model_copy(
        update={
            "dicom_fields": fields,
            "study_ref": store.surrogate_for_study(payload.study_ref),
            "prior_study_refs": tuple(
                store.surrogate_for_study(ref) for ref in payload.prior_study_refs
            ),
        }
    )


def shift_dicom_date(value: str, offset: int) -> str:
    """`value`, a DICOM `DA` date, moved by `offset` days.

    Raises `ValueError` when `value` is not exactly eight digits naming a real
    calendar day, or when the shift runs off the end of the calendar. The
    caller decides what that means: component C reports it as
    `UNSHIFTED_DATE`, and redaction layer 1 reports it as a structured field
    it cannot deterministically replace. One implementation, two reporting
    policies — a second date parser in the redaction layer could disagree with
    this one by a day, and a payload whose free-text dates and structured dates
    disagree is a payload that has been silently corrupted.

    A blank value is returned unchanged: there is no date there to shift, and
    inventing one would put a date into a field the caller left empty.
    """
    if not value.strip():
        return value
    if len(value) != _DATE_LENGTH:
        raise ValueError(f"not a DICOM date such as 20260114: {value!r}")
    try:
        parsed = date(int(value[0:4]), int(value[4:6]), int(value[6:8]))
    except ValueError as exc:
        raise ValueError(f"not a DICOM date such as 20260114: {value!r}") from exc
    return shift_date(parsed, offset).strftime(_DATE_FORMAT)


def _shift_field(key: str, value: str, offset: int) -> str:
    """`value` moved by `offset` days, if `key` is a date field."""
    if key not in _DATE_FIELDS:
        return value
    try:
        return shift_dicom_date(value, offset)
    except ValueError as exc:
        raise PseudonymError(
            action_codes=("UNSHIFTED_DATE",),
            message=f"{key!r} is not a DICOM date such as 20260114: {value!r}",
        ) from exc


def _refuse_if_surrogate_shaped(reference: str, where: str) -> None:
    """Refuse `reference` when it already has the shape of a study surrogate.

    `StudyContext.study_reference` is caller-supplied, so a surrogate-shaped
    string arriving here may be a forged value rather than a real one. Passing
    it through would put an unvalidated, unrecorded string on the model path,
    indistinguishable from a system-minted surrogate and satisfying any check
    that only looks for the domain prefix. Refusing cannot be confused with a
    legitimate reference: the store mints exactly this shape and only this
    shape, and it will mint its own for any other value.
    """
    if not SURROGATE_SHAPE.fullmatch(reference):
        return
    raise PseudonymError(
        action_codes=(_REJECTED_CODE,),
        message=(
            f"{where} is {reference!r}, which already has the shape of a study "
            f"surrogate. The reference must be the original one, and this "
            f"component must be applied once per payload: applying it twice "
            f"would shift the dates twice and misstate the interval between "
            f"this patient's studies."
        ),
    )
