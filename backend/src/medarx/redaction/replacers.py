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
from typing import Callable

from medarx.pseudonym.date_shift import shift_date
from medarx.redaction.ner import EntityHit, set_unreplaceable_predicate

__all__ = [
    "REPLACERS",
    "ReplacerContext",
    "has_replacer",
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


#: The date shapes the kernel can shift: DICOM `DA` (`YYYYMMDD`) and ISO
#: (`YYYY-MM-DD`), each optionally followed by a time of day, which is carried
#: through unchanged. Anything else is refused rather than shifted — see
#: `_shifted_date`. The alternation is ordered with the dashed form first; the
#: two shapes cannot both match.
_DATE_TEXT = re.compile(
    r"(?P<date>\d{4}-\d{2}-\d{2}|\d{8})(?P<rest>[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?)?"
)


def _shifted_date(hit: EntityHit, ctx: ReplacerContext) -> str | None:
    """The detected date, moved by this patient's shift — or `None`.

    `None` is a refusal, not a fallback. Whether a detected `DATE_TIME` is a
    date this kernel can shift is a property of the matched text, and three of
    the shapes Presidio actually emits are not. Measured on this machine: the
    bare patient id `774123` at 0.85, the relative interval `6 weeks` at 0.85,
    and `14 January 2026` at 0.85. Guessing a format for any of them produces
    a date that is wrong, and a report carrying the wrong date is not a
    redacted report, it is a false one.

    Both accepted shapes are ones this kernel already writes, and the output
    keeps the shape it was given: a report that mixes DICOM and ISO dates
    comes out mixing both, because rewriting a report's date convention is
    editing clinical text that no detector flagged. A time of day is preserved
    unshifted — the shift is a day count, so the time of day is not what is
    being protected, and dropping or reformatting it would change the text
    around the finding.

    Calendar edges belong to `shift_date`, which saturates rather than raising.
    A date the *input* cannot express, such as `2026-02-30`, is `None`: it is
    not a date at all.
    """
    matched = _DATE_TEXT.fullmatch(hit.text)
    if matched is None:
        return None
    written, rest = matched.group("date", "rest")
    digits = written.replace("-", "")
    try:
        parsed = date(int(digits[0:4]), int(digits[4:6]), int(digits[6:8]))
    except ValueError:
        return None
    fmt = "%Y-%m-%d" if "-" in written else "%Y%m%d"
    # `rest` is optional, and `group` answers None for a group that did not
    # participate in the match.
    return shift_date(parsed, ctx.offset).strftime(fmt) + (rest or "")


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
