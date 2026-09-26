"""The replacer table for redaction layer 2 — the *only* sanctioned way to
replace a detected entity with something.

"Never redact by guessing" is only enforceable if the set of allowed
replacements is a closed, inspectable table. A caller that invents a
replacement at the call site has not been through this module, and no test can
see it. So this module holds:

* `REPLACERS` — an explicit `entity_type -> callable` mapping. An entity that
  is absent has **no** replacer, and the two entry points below
  (`has_replacer`, `replacement_for`) both report that as a refusal rather
  than falling back to a default.

* `AMBIGUOUS_REFERENCE` is deliberately absent, and that absence is the point.
  It is an entity the detectors find and *cannot* resolve — the value's real
  referent is unknowable from the text. Because it is always detected and
  never has a replacer, layer 2's block is deterministic at any score: the
  condition is "detected and no replacer registered", not "scored below
  `Settings.ner_score_threshold`". A future change to the score, to the
  threshold, or to the spaCy model cannot turn that block into a silent
  pass-through. The `ValueError` below is a guard for *direct* callers of
  `replacement_for`; layer 2 consults `has_replacer` first and emits
  `NER_UNRESOLVED` itself.

* A replacer may also return `None`, which is that same refusal expressed as a
  value rather than a missing table entry: the entity was detected, and nothing
  here can produce a safe replacement for *this value*. Only the date replacer
  does it, and only for a date it cannot shift. Layer 2 needs one mechanism for
  "cannot be replaced", not one per reason.

* This module also **installs the scan's own safety rule**. On import it
  registers `lambda entity: not has_replacer(entity)` with `ner`, so that
  `scan_entities` cannot drop an unresolvable hit at *either* of its two
  filters — the `min_score` filter and the overlap collapse — whatever the
  caller passes. Registering the rule here rather than importing this table
  into `ner` keeps the dependency pointing one way and keeps `ner.py` ignorant
  of what a replacement is. The cost is that importing `replacers` is a
  prerequisite for the protection; `ner` fails closed without it (it then
  treats every entity as unresolvable and drops nothing), and a test asserts
  the registration happened.

Two replacement strategies, both deterministic:

* `DATE_TIME` becomes **the same date, shifted by this patient's offset**, in
  the format it was written in — or `None` when it is not a date the kernel can
  shift. This is not a stylistic preference. Substituting the patient surrogate
  was measured to collapse every date in a report onto one string: "on
  2026-01-14, unchanged from 2025-12-01" redacted to two copies of
  `medarx-patient-ab12cd34`, destroying the 44-day interval between the two
  studies, and it put a patient identifier where a date had stood. A shift
  preserves the interval and agrees with the date component C already shifted
  in the structured fields, so both halves of the payload tell the same story
  about when things happened.

* everything else becomes `[REDACTED:<ENTITY_TYPE>]`. The entity type is
  carried into the output deliberately: a reader of the redacted report can
  see *what kind* of thing was removed without seeing the value.
"""

import re
from dataclasses import dataclass
from datetime import date
from typing import Callable, Literal

from medarx.pseudonym.date_shift import shift_date
from medarx.redaction.ner import EntityHit, set_unreplaceable_predicate

__all__ = [
    "REPLACERS",
    "ReplacerContext",
    "has_replacer",
    "is_absolute_date",
    "is_relative_interval",
    "replacement_for",
]


@dataclass(frozen=True)
class ReplacerContext:
    """What a replacer is allowed to know.

    `patient_surrogate` is carried, and no replacer reads it. Deliberately: the
    one replacement that would use it — writing the patient's surrogate where a
    patient identifier stood — is pseudonymisation applied twice, and it
    silently misattributes every identifier in a report that is not this
    patient's to the wrong person. `offset` is the load-bearing field: the date
    replacer moves each date by it, which is what keeps the intervals between
    this patient's dates exactly what they were.

    The shift itself is component C's `shift_date`, imported rather than
    reimplemented. The offset arrives already computed, so this module never
    touches the audit key or the mapping store; sharing one implementation is
    what guarantees a date in free text and the same date in a structured
    field cannot disagree by a day at the edge of the calendar.
    """

    patient_surrogate: str
    offset: int
    #: The deployment's declared day/month order, or `None` when it has not
    #: declared one. Only the numeric date shapes consult it, and with `None`
    #: they are refused rather than guessed — see `Settings.date_order`.
    date_order: Literal["MDY", "DMY"] | None = None


#: The units a relative interval can be counted in. Closed on purpose: an
#: unbounded "word plus a unit-ish suffix" rule is a heuristic, and a heuristic
#: that guesses is the thing this table exists to prevent.
_INTERVAL_UNITS = (
    "seconds?|minutes?|hours?|days?|weeks?|months?|years?|decades?"
)

#: The number words Presidio's relative-date patterns accept, closed. Measured
#: on this machine: the recognizer matches `six weeks` as readily as `6 weeks`,
#: so a digits-only rule would leave every spelled-out interval to be refused.
_NUMBER_WORDS = (
    "one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|"
    "thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|"
    "thirty|forty|fifty|sixty|ninety|hundred|several|few|couple"
)

#: Text that states *when* without stating a date. There is no absolute date in
#: any of it, so there is nothing to shift and nothing to leak: the interval
#: between "now" and "six weeks" is the same for a shifted patient as for an
#: unshifted one. Measured shapes from the engine, each of which it reports as
#: `DATE_TIME` at 0.85: `6 weeks`, `six weeks`, `2 weeks ago`, `6 months`,
#: `2 days`, `1 year`, `24 hours`, `3 o'clock`, `today`.
#:
#: Anything not in this list is **not** passed through. There is no fallthrough
#: where an unrecognised shape becomes a pass; the caller asks this question
#: first precisely so that "I do not recognise it" is an answer of no.
_RELATIVE_INTERVAL = re.compile(
    rf"\A(?:"
    rf"(?:today|yesterday|tomorrow|tonight|now|this\s+(?:morning|afternoon|evening)"
    rf"|last\s+night)"
    rf"|(?:\d+|{_NUMBER_WORDS})\s+(?:{_INTERVAL_UNITS})(?:\s+ago)?"
    rf"|(?:in|within|after)\s+(?:\d+|{_NUMBER_WORDS})\s+(?:{_INTERVAL_UNITS})"
    rf"|\d{{1,2}}\s+o'?clock"
    rf")\Z",
    re.IGNORECASE,
)

#: The month names a date may be written with, mapped to the abbreviated form
#: so a shifted date keeps whichever spelling it arrived in. Closed: a date
#: written in a language the kernel does not parse is refused, not guessed at.
_MONTHS = {
    "january": ("Jan", 1), "jan": ("Jan", 1),
    "february": ("Feb", 2), "feb": ("Feb", 2),
    "march": ("Mar", 3), "mar": ("Mar", 3),
    "april": ("Apr", 4), "apr": ("Apr", 4),
    "may": ("May", 5),
    "june": ("Jun", 6), "jun": ("Jun", 6),
    "july": ("Jul", 7), "jul": ("Jul", 7),
    "august": ("Aug", 8), "aug": ("Aug", 8),
    "september": ("Sep", 9), "sep": ("Sep", 9), "sept": ("Sep", 9),
    "october": ("Oct", 10), "oct": ("Oct", 10),
    "november": ("Nov", 11), "nov": ("Nov", 11),
    "december": ("Dec", 12), "dec": ("Dec", 12),
}

_MONTH_ALTERNATION = "|".join(sorted(_MONTHS, key=len, reverse=True))

#: A time of day, carried through unchanged. The shift is a day count, so the
#: time is not part of what is being protected.
_TIME_OF_DAY = r"[T ]\d{1,2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z)?"

#: The absolute date shapes the kernel shifts, each with its own rendering.
#: Order matters only in that the engine is `fullmatch`ed, so an alternative
#: that could swallow a longer shape must come first.
_DATE_SHAPES: tuple[tuple[re.Pattern[str], str], ...] = (
    # DICOM `DA` and ISO, either followed by a time.
    (re.compile(rf"(?P<y>\d{{4}})-(?P<m>\d{{2}})-(?P<d>\d{{2}})(?P<rest>{_TIME_OF_DAY})?"),
     "iso"),
    (re.compile(rf"(?P<y>\d{{4}})(?P<m>\d{{2}})(?P<d>\d{{2}})(?P<rest>{_TIME_OF_DAY})?"),
     "dicom"),
    # `14 January 2026`, `4 March 2026`, `Jan 14 2026`.
    (re.compile(rf"(?P<d>\d{{1,2}})(?P<ord>st|nd|rd|th)?\s+"
               rf"(?P<mon>{_MONTH_ALTERNATION})\.?,?\s+"
               rf"(?P<y>\d{{4}})(?P<rest>{_TIME_OF_DAY})?", re.IGNORECASE),
     "day-month-name"),
    # `January 14, 2026`, and `Jan 14 2026` without the comma. Whether a
    # comma was written is captured, because adding one to a report that had
    # none is editing text no detector flagged.
    (re.compile(rf"(?P<mon>{_MONTH_ALTERNATION})\.?\s+(?P<d>\d{{1,2}})(?P<ord>st|nd|rd|th)?"
               rf"(?P<comma>,\s*|)\s*"
               rf"(?P<y>\d{{4}})(?P<rest>{_TIME_OF_DAY})?", re.IGNORECASE),
     "month-name-day"),
    # `03/04/2026` — ambiguous, and only readable once the deployment has said
    # which order it writes. With `date_order` unset this shape is not in the
    # list at all, so it is refused rather than read.
    (re.compile(rf"(?P<a>\d{{1,2}})/(?P<b>\d{{1,2}})/(?P<y>\d{{4}})"
                rf"(?P<rest>{_TIME_OF_DAY})?"),
     "numeric"),
)


def is_relative_interval(text: str) -> bool:
    """Whether `text` states a time without stating a date.

    The one shape the kernel passes through untouched, and the answer is a
    closed list rather than a judgement: a count of a named unit, a count with
    "ago", "in"/"within"/"after" plus a count, a bare relative day word, or a
    clock time. Anything else is `False`, and `False` means the text goes on to
    be shifted or refused — never silently kept.

    The condition is the *shape of the text*, not the detector's confidence, so
    it cannot be moved by a threshold. That matters in the same way the
    no-replacer rule matters: a block that is really a parsing gap must not be
    able to become a silent pass by a change to a setting.
    """
    return _RELATIVE_INTERVAL.fullmatch(text.strip()) is not None


def is_absolute_date(text: str) -> bool:
    """Whether `text` is a date the kernel could shift, ignoring the label.

    A date's recognisability is a property of its characters. The engine
    reports `01/14/2026` as `LOCATION` in one sentence and as `DATE_TIME` in
    another, and reports `14 January 2026` as `DATE_TIME`; routing on the label
    would therefore mask a date as a location in one sentence and shift it in
    the next. This predicate lets the caller send *any* hit whose text is a
    date down the date path, so the policy depends on the text and not on which
    recogniser happened to fire.

    The numeric shape is included here even when `date_order` is unset, because
    "unreadable" is not the same as "not a date": the caller must reach the
    refusal rather than mask the digits as something else.
    """
    return _match_date_shape(text) is not None


def _match_date_shape(text: str) -> tuple[re.Match[str], str] | None:
    for pattern, kind in _DATE_SHAPES:
        matched = pattern.fullmatch(text.strip())
        if matched is not None:
            return matched, kind
    return None


def _shifted_date(hit: EntityHit, ctx: ReplacerContext) -> str | None:
    """The detected date, moved by this patient's shift — or `None`.

    `None` is a refusal, not a fallback, and it is the answer for three
    different shapes, each of which the engine really does emit on this
    machine: a date written in a format this table does not parse; a numeric
    date the deployment has not declared an order for; and a month and year
    with no day, where any day would have to be invented and the shifted month
    would depend on which one was picked. Guessing any of them produces a date
    that is wrong, and a report carrying the wrong date is not a redacted
    report, it is a false one.

    A relative interval never reaches here — see `is_relative_interval`, which
    the caller asks first.

    The output keeps the shape it was given: a report that mixes DICOM, ISO and
    month-name dates comes out mixing all three, because rewriting a report's
    date convention is editing clinical text that no detector flagged. A time
    of day is carried through unshifted, for the same reason.

    Calendar edges belong to `shift_date`, which saturates rather than raising.
    A date the *input* cannot express, such as `2026-02-30`, is `None`: it is
    not a date at all.
    """
    found = _match_date_shape(hit.text)
    if found is None:
        return None
    matched, kind = found
    try:
        parsed = _build_date(matched, kind, ctx.date_order)
    except ValueError:
        # A shape this table parses that the calendar does not: `2026-02-30`,
        # or a 31st of a 30-day month. Still not a date.
        return None
    shifted = shift_date(parsed, ctx.offset)
    return _render(shifted, kind, matched.group("rest") or "", hit.text, ctx.date_order)


def _build_date(matched: re.Match[str], kind: str, date_order: str | None) -> date:
    """The calendar date the matched text names, or `ValueError`."""
    if kind == "numeric":
        if date_order is None:
            raise ValueError("no declared date order")
        first, second = int(matched.group("a")), int(matched.group("b"))
        # In `MM/DD/YYYY` the *first* field is the month; in `DD/MM/YYYY` it is
        # the day. Reading it the other way round is the kind of bug that does
        # not raise — the value still parses, it is just a different date.
        day, month = (second, first) if date_order == "MDY" else (first, second)
    elif kind in {"day-month-name", "month-name-day"}:
        _, number = _MONTHS[matched.group("mon").lower().rstrip(".")]
        day, month = int(matched.group("d")), number
    else:
        day, month = int(matched.group("d")), int(matched.group("m"))
    return date(int(matched.group("y")), month, day)


def _render(shifted: date, kind: str, rest: str, written: str,
            date_order: str | None) -> str:
    """`shifted` back into the shape `written` arrived in."""
    if kind == "iso":
        return shifted.strftime("%Y-%m-%d") + rest
    if kind == "dicom":
        return shifted.strftime("%Y%m%d") + rest
    if kind == "numeric":
        first, second = ((shifted.month, shifted.day) if date_order == "MDY"
                         else (shifted.day, shifted.month))
        return f"{first:02d}/{second:02d}/{shifted.year}" + rest
    # `January 14, 2026` and `Jan 14 2026` are one shape written two ways, and
    # `14th January 2026` a third. The comma and the ordinal suffix belong to
    # the sentence that was written, not to the date, so they are reproduced
    # rather than normalised — and the suffix that comes back is the one the new
    # day takes, which is the only part of it that is not a choice.
    if kind == "day-month-name":
        # The month name comes from the *shifted* date and only its spelling
        # comes from the text. Writing `15 January 2025` for a date that is
        # 15 December 2025 would be a silently wrong date, which is the one
        # thing this function exists to avoid.
        ordinal = _ordinal(shifted.day) if _ordinal_written(written) else ""
        return (f"{shifted.day}{ordinal} "
                f"{_month_label(shifted.month, written.split()[1])} "
                f"{shifted.year}") + rest
    separator = ", " if "," in written else " "
    suffix = _ordinal(shifted.day) if _ordinal_written(written) else ""
    return (f"{_month_label(shifted.month, written.split()[0])} {shifted.day}"
            f"{suffix}{separator}{shifted.year}") + rest


#: Month number to the full name, for writing a *shifted* month back out. The
#: abbreviation comes from `_MONTHS`; this is the other direction, and it has
#: to exist because the shifted month is generally not the one that was written.
_MONTH_NAMES = ("January", "February", "March", "April", "May", "June", "July",
                "August", "September", "October", "November", "December")
_MONTH_ABBREVIATIONS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul",
                        "Aug", "Sep", "Oct", "Nov", "Dec")


def _month_label(month: int, written: str) -> str:
    """The shifted month, spelled the way the text spelled its month.

    `Mar` does not become `March` and `JANUARY` does not become `January`:
    rewriting either would edit a word no detector flagged, and the report
    would stop looking like the report that was written. Which of the two forms
    to use is decided by the *original* text, never by the shifted month.
    """
    abbreviated = len(written.rstrip(".")) <= 4
    return _MONTH_ABBREVIATIONS[month - 1] if abbreviated else _MONTH_NAMES[month - 1]


def _ordinal(day: int) -> str:
    """The `st`/`nd`/`rd`/`th` a day of the month takes.

    Applied only to text that wrote one: `14th January` and `14 January` are the
    same date written two ways, and the suffix belongs to the sentence rather
    than to the date, so a report without one does not acquire it. When one was
    written, the suffix that comes back is the one the *shifted* day takes —
    that part is not a choice, since `1st` is the only correct suffix for a
    first and `2nd` for a second.
    """
    if 11 <= (day % 100) <= 13:
        return "th"
    return {1: "st", 2: "nd", 3: "rd"}.get(day % 10, "th")


def _ordinal_written(written: str) -> bool:
    """Whether the text wrote an ordinal suffix on its day of the month."""
    return re.search(r"\d{1,2}(?:st|nd|rd|th)\b", written, re.IGNORECASE) is not None


def _mask(entity_type: str) -> Callable[[EntityHit, ReplacerContext], str]:
    def replacer(hit: EntityHit, ctx: ReplacerContext) -> str:
        return f"[REDACTED:{entity_type}]"

    replacer.__name__ = f"mask_{entity_type.lower()}"
    return replacer


#: Every entity this module will replace, and how. Populated from the entity
#: set Presidio's default English recognizers emit (measured on this machine:
#: 23 types) plus this project's three mandatory clinical entities.
#:
#: `AMBIGUOUS_REFERENCE` is intentionally not here, and its absence is
#: asserted in `tests/test_ner_recognizers.py`. A new entity type is a
#: deliberate addition: without an entry, detection is a block, which is the
#: safe direction to fail, but it is still a visible change to this table.
_MASKED: tuple[str, ...] = (
    "ACCESSION_NUMBER",
    "AGE",
    "CREDIT_CARD",
    "CRYPTO",
    "EMAIL",
    "EMAIL_ADDRESS",
    "IBAN_CODE",
    "ID",
    "IP_ADDRESS",
    "LOCATION",
    "MAC_ADDRESS",
    "MEDICAL_LICENSE",
    "MRN",
    "NRP",
    "ORGANIZATION",
    "PATIENT_ID",
    "PERSON",
    "PHONE_NUMBER",
    "UK_NHS",
    "URL",
    "US_BANK_NUMBER",
    "US_DRIVER_LICENSE",
    "US_ITIN",
    "US_PASSPORT",
    "US_SSN",
)

#: The annotation admits `None` because a replacer can decline a *value*, which
#: is a different refusal from a missing entry and is documented on
#: `replacement_for`.
REPLACERS: dict[str, Callable[[EntityHit, ReplacerContext], str | None]] = {
    "DATE_TIME": _shifted_date,
    **{entity: _mask(entity) for entity in _MASKED},
}


def has_replacer(entity_type: str) -> bool:
    """Whether a deterministic replacement exists for `entity_type`.

    This is the predicate a block decision should be built on. It consults
    only the table: not the hit's score, not `Settings.ner_score_threshold`.
    A caller can therefore ask "can this be replaced?" without first
    conditioning on confidence, which is what keeps the answer stable when the
    score or the threshold moves.

    It says nothing about whether a *particular* value can be replaced; that is
    `replacement_for`'s answer, and the two are asked in sequence.
    """
    return entity_type in REPLACERS


def replacement_for(hit: EntityHit, ctx: ReplacerContext) -> str | None:
    """The replacement text for `hit`, or `None` when there is none.

    Two refusals, deliberately different in kind:

    * An entity with **no registered replacer** raises `ValueError`. That is a
      gap in the table — a defect, not a runtime condition — and the guard is
      for direct callers, who would otherwise substitute something of their
      own. Layer 2 does not arrive here for it: it consults `has_replacer`
      first and emits its own disposition, so an unresolved entity is reported
      as a block rather than as an exception.

    * An entity that **has** a replacer but declines *this value* returns
      `None` — today, a `DATE_TIME` that is not a shiftable date. This is the
      same block condition as the missing entry, reached from the other side,
      and `None` is how layer 2 sees it.
    """
    replacer = REPLACERS.get(hit.entity_type)
    if replacer is None:
        raise ValueError(
            f"no replacer registered for entity {hit.entity_type!r}; "
            f"an unresolvable entity must be blocked, not guessed at"
        )
    return replacer(hit, ctx)


# Install the scan's safety rule now that the table exists. A lambda rather
# than `not has_replacer` so the lookup goes through the public function and
# stays correct if the table is ever extended.
set_unreplaceable_predicate(lambda entity_type: not has_replacer(entity_type))
