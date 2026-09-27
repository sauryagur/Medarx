"""The measurement primitives. This module is the *instrument*, and an
instrument that has seen the answers is not an instrument.

**It does not import the corpus.** Not `evals.synthetic_phi.seed_corpus`, not
`evals.synthetic_phi.clean_prose`, not `evals.run_eval`. Everything it is given
arrives as an argument: a list of planted spans, a list of detections, a case
object whose methods it calls. There is no lookup table inside it mapping a
value to a verdict and no branch that special-cases a fixture, so a scorer that
had been fitted to the corpus could not be run here at all. That property is
demonstrated by use in `tests`, on inputs built inside the test file.

**What counts as a detection.** A detection is a *hit* from
`medarx.redaction.ner.scan_entities`: an entity type, a span, a score, and the
surface it was found on. A planted value is *detected* when some hit overlaps
its span **and carries the entity type the corpus says is there**. Matching is
one-to-one and greedy in planted document order, so one planted span cannot be
credited twice by two overlapping hits, and the result does not depend on the
order the engine happened to return hits in.

**A mislabelled hit is a miss *and* a false positive, counted once each.** A
planted `MRN` that comes back as `DATE_TIME` has not been found as an MRN, so
recall for `MRN` must fall; and a `DATE_TIME` the corpus never planted has been
reported over ordinary text, so precision for `DATE_TIME` must fall. Both
count, `mislabelled` marks the MRN key so a reader can tell an unreachable
recognizer from a mislabelling one, and it is not double-counted in the total.

**A rate is never a bare float.** `precision` and `recall` return
`(numerator, denominator)` and `format_rate` prints `3/4`. A recall of 1.00 over
three instances and a recall of 1.00 over three hundred are different facts and
this module cannot print one in place of the other. A denominator of zero
returns `(None, 0)` and renders as `n/a (0 measured)` — never as 1.00 and never
as 0.00, because both of those would be claims about measurements that were
never made.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

__all__ = [
    "NAMED_ENTITY_MASK",
    "Detection",
    "MaskRate",
    "Outcome",
    "Planted",
    "Tally",
    "format_rate",
    "tally",
]

#: A named-entity mask standing where an ordinary clinical word was. A date
#: shift is a *correct* transformation of the text and is not counted here:
#: what is measured is the false positive, not every byte that moved.
NAMED_ENTITY_MASK = re.compile(r"\[REDACTED:(\w+)\]")


@dataclass(frozen=True)
class Planted:
    """One identifier the corpus put in a surface, with the span found for it.

    The span is *derived* — by searching the surface for the value — rather
    than declared, so the corpus cannot hand the scorer its own answer key.
    """

    entity_type: str
    value: str
    surface: str
    start: int
    end: int


@dataclass(frozen=True)
class Detection:
    """One hit the detector returned, on the surface it returned it for."""

    entity_type: str
    start: int
    end: int
    surface: str
    score: float = 0.0


@dataclass(frozen=True)
class Tally:
    """Counts, never a rate.

    `tp + fn` is the denominator of recall and `tp + fp` the denominator of
    precision, so either can be reconstructed from these four integers.
    `mislabelled` is a subset of `fn`: a hit that overlapped a planted span
    with the wrong entity type, recorded separately because it is the number
    that separates an unreachable recognizer from a mislabelling one.
    """

    tp: int = 0
    fp: int = 0
    fn: int = 0
    mislabelled: int = 0

    @property
    def precision(self) -> tuple[int | None, int]:
        return (self.tp, self.tp + self.fp) if (self.tp + self.fp) else (None, 0)

    @property
    def recall(self) -> tuple[int | None, int]:
        return (self.tp, self.tp + self.fn) if (self.tp + self.fn) else (None, 0)

    def merged(self, other: Tally) -> Tally:
        return Tally(
            self.tp + other.tp,
            self.fp + other.fp,
            self.fn + other.fn,
            self.mislabelled + other.mislabelled,
        )


@dataclass(frozen=True)
class MaskRate:
    """How each identifier-free sentence came back, in four disjoint buckets.

    `blocked` — the kernel refused it. Neither a pass nor a corruption, and
    counted on its own because a refusal has a different owner from a defect.
    `masked` — approved with a `[REDACTED:...]` mask standing where an ordinary
    clinical word was. By construction a false positive: nothing was planted.
    `shifted` — approved, the text differs, and the only reason is that a date
    moved. A date shift is a *correct* transformation, so it is not a false
    positive, and counting it as one would overstate the defect.
    `identical` — approved and byte-for-byte what went in: what an ideal
    detector returns.

    The four sum to `denominator`, the sentence count, carried as a field
    rather than something a reader has to reconstruct from the corpus.
    """

    masked: int
    shifted: int
    identical: int
    blocked: int
    denominator: int
    detail: tuple = field(default=())


@dataclass(frozen=True)
class Outcome:
    """What one case produced, and why.

    There is deliberately no "text after layer 2" field here. The obvious way
    to answer "did the detector find it" is to inspect the payload between
    layer 2 and layer 3, and the obvious way to get that is to re-run the
    layers by hand inside the harness — which is a second copy of the
    orchestrator's order, free to drift from the one that ships, and the worst
    thing a measuring instrument can be. The same fact is available without
    the copy: layer 3's `LEFTOVER_PATTERN_MATCH` disposition *is* the
    evidence, because it fires only on a value still present in the text when
    layer 3 read it.
    """

    case_name: str
    blocked: bool
    approved_text: str | None
    approved_dicom_fields: dict
    dispositions: tuple
    decision_code: str | None


def format_rate(rate: tuple[int | None, int]) -> str:
    """`3/4` for a rate; `n/a (0 measured)` for a denominator of zero.

    The zero case is the one that matters. A metric computed over nothing must
    not be able to print `0.00`, which reads as a total failure, or `1.00`,
    which reads as a pass. Both would be claims about measurements that were
    never made.
    """
    numerator, denominator = rate
    if numerator is None or denominator == 0:
        return "n/a (0 measured)"
    return f"{numerator}/{denominator}"


def _overlaps(hit: Detection, item: Planted) -> bool:
    return hit.start < item.end and item.start < hit.end


def tally(planted: list, detected: list) -> dict:
    """Counts per `(entity_type, surface)` for one surface's text.

    A key is produced for **every** entity type named on either side, including
    one with no detections at all. A key that is missing and a key with
    `tp=0, fn=2` are different facts — "nothing was measured" versus
    "everything was missed" — so an entity type that was planted always gets a
    key, even when the detector returned nothing for it.
    """
    keys: list[tuple[str, str]] = []
    for source in (planted, detected):
        for item in source:
            key = (item.entity_type, item.surface)
            if key not in keys:
                keys.append(key)
    result: dict[tuple[str, str], Tally] = {key: Tally() for key in keys}
    claimed: set[int] = set()

    for item in planted:
        key = (item.entity_type, item.surface)
        for position, hit in enumerate(detected):
            if position in claimed or hit.surface != item.surface:
                continue
            if hit.entity_type == item.entity_type and _overlaps(hit, item):
                claimed.add(position)
                result[key] = result[key].merged(Tally(tp=1))
                break
        else:
            result[key] = result[key].merged(Tally(fn=1))

    for position, hit in enumerate(detected):
        if position in claimed:
            continue
        overlapping = [p for p in planted if p.surface == hit.surface and _overlaps(hit, p)]
        if overlapping:
            # The planted span already took its `fn` above, under the type the
            # corpus said was there. This hit is a false positive under the type
            # it actually carried, and the planted type is marked so a reader
            # can see *why* it was missed.
            hit_key = (hit.entity_type, hit.surface)
            result.setdefault(hit_key, Tally())
            result[hit_key] = result[hit_key].merged(Tally(fp=1))
            missed_key = (overlapping[0].entity_type, overlapping[0].surface)
            result[missed_key] = result[missed_key].merged(
                Tally(mislabelled=1)
            )
        else:
            hit_key = (hit.entity_type, hit.surface)
            result.setdefault(hit_key, Tally())
            result[hit_key] = result[hit_key].merged(Tally(fp=1))
    return result
