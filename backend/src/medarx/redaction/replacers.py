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

* `DATE_TIME` becomes the patient's stable surrogate. The surrogate is the
  already-shifted date, so replacing a date with it keeps the text consistent
  with layer 1 rather than introducing a second, differently-shifted date.

* everything else becomes `[REDACTED:<ENTITY_TYPE>]`. The entity type is
  carried into the output deliberately: a reader of the redacted report can
  see *what kind* of thing was removed without seeing the value.
"""

from dataclasses import dataclass
from typing import Callable

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

    `patient_surrogate` is the stable, already-shifted surrogate for the
    patient, supplied by layer 1 rather than computed here. `offset` is the
    patient's date shift in days, carried alongside it so a replacer that
    ever needs to re-derive a shifted date can; nothing in this module reads
    it today, and it is here because the layer-2 signature pins it.
    """

    patient_surrogate: str
    offset: int


def _surrogate(hit: EntityHit, ctx: ReplacerContext) -> str:
    return ctx.patient_surrogate


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

REPLACERS: dict[str, Callable[[EntityHit, ReplacerContext], str]] = {
    "DATE_TIME": _surrogate,
    **{entity: _mask(entity) for entity in _MASKED},
}


def has_replacer(entity_type: str) -> bool:
    """Whether a deterministic replacement exists for `entity_type`.

    This is the predicate a block decision should be built on. It consults
    only the table: not the hit's score, not `Settings.ner_score_threshold`.
    A caller can therefore ask "can this be replaced?" without first
    conditioning on confidence, which is what keeps the answer stable when the
    score or the threshold moves.
    """
    return entity_type in REPLACERS


def replacement_for(hit: EntityHit, ctx: ReplacerContext) -> str:
    """Return the replacement text for `hit`.

    Raises `ValueError` when the entity has no registered replacer. This is a
    guard for direct callers, not the layer-2 block path: layer 2 calls
    `has_replacer` first and emits its own disposition, so an unresolved
    entity is reported as a block rather than as an exception.
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
