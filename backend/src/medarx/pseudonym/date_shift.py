"""The per-patient date shift.

Every date belonging to one patient moves by the same integer number of days,
so intervals between that patient's studies, and their order, are exactly what
they were before the shift. That is the invariant clinical meaning depends on:
a shift that reordered studies or stretched intervals would misrepresent the
course of a patient's history.

The shift is a plain day count. It deliberately does not preserve the month or
the day of the month, only the distance between dates — preserving the month
too would make the shift a different, re-identifying transformation, and
preserving the weekday would leak a weekend.
"""

from datetime import date, timedelta

from medarx.pseudonym.derivation import audit_digest

__all__ = ["MAX_OFFSET_DAYS", "MIN_OFFSET_DAYS", "patient_offset", "shift_date"]


#: Inclusive bounds on the per-patient shift, in days. One year either way is
#: enough to break a naive date join against the source system without pushing
#: a date out of the representable calendar.
MIN_OFFSET_DAYS = -365
MAX_OFFSET_DAYS = 365

_SPAN = MAX_OFFSET_DAYS - MIN_OFFSET_DAYS + 1


def patient_offset(patient_ref: str, audit_key: str) -> int:
    """The stable day offset for `patient_ref`, in `[-365, 365]`.

    Derived from `HMAC-SHA256(audit_key, "offset:<patient_ref>")` so that the
    shift is reproducible by anyone holding the key and is different for
    different patients — two patients with the same study date do not come out
    with the same study date after the shift.

    Refuses an empty `audit_key`: an unkeyed derivation would be a predictable
    offset table, and knowing a patient's offset against an unshifted date is
    the re-identification the mapping store exists to prevent.
    """
    digest = audit_digest(audit_key, "offset", patient_ref)
    # The first 8 bytes as a big-endian integer, folded into the bound.
    return int.from_bytes(digest[:8], "big") % _SPAN + MIN_OFFSET_DAYS


def shift_date(d: date, offset: int) -> date:
    """Return `d` moved by `offset` days.

    Saturates rather than raising: a date near `date.max` (or `date.min`) plus
    a year's shift overflows the calendar, and a report whose date sits at
    that edge must not be lost to an `OverflowError`. The saturated result
    loses the duration guarantee for that one boundary date, which is the only
    honest option — the alternative is a request that cannot be served.
    """
    try:
        return d + timedelta(days=offset)
    except (OverflowError, ValueError):
        return date.max if offset > 0 else date.min
