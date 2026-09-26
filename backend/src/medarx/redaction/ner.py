"""The Presidio analyzer engine and the entity scan behind redaction layer 2.

`recognizers.py` builds the clinical patterns; this module runs them. The
distinction matters, because `PatternRecognizer.analyze` is *not* the path a
redaction layer takes: it performs no context enhancement, and it knows
nothing about replacers. The score a block decision would key on is produced
in `AnalyzerEngine.analyze`, and this is the only place that happens.

Six things here are load-bearing, and each is asserted in the tests:

* **The engine is built once.** `build_engine()` constructs a fresh
  `AnalyzerEngine` — spaCy model load included — and `scan_entities` shares a
  single lazily-built one through `_shared_engine`. `scan_entities` runs once
  per text-bearing field, so rebuilding per call would put a multi-second
  model load on the request path.

* **Anchor labels are blanked before the scan**, not merely available to be
  blanked, and blanked to equal-length spaces rather than deleted. Presidio
  scores a bare `DOB` as `ORGANIZATION` at 0.85, so a bare clinical label
  would be redacted as the wrong kind of thing and the value beside it would
  survive; and because the length is preserved, every offset below is an
  index into the caller's own string.

* **Truncation is loud.** Text past `Settings.ner_text_limit` is not scanned,
  and the report says so with a single `TRUNCATED_TEXT` hit spanning exactly
  the dropped tail. A scan that silently dropped a fifth of a report is
  indistinguishable from a clean one, which is the failure this kernel exists
  to make impossible.

* **The scan decides nothing, and drops nothing it must not.** `min_score` is
  the caller's filter and `Settings.ner_score_threshold` is applied nowhere
  in this module; layer 2 calls with `min_score=0.0` so a low-confidence
  candidate is *seen*. But the two filters that do discard hits — the score
  filter and the overlap collapse — may never discard an entity with no
  registered replacer, at any `min_score`. `EntityHit.entity_type` is exposed
  so that condition can be stated as "detected, and nothing can replace it",
  a property of the entity rather than of a score a future setting could move.
  The predicate that enforces it is registered by `replacers` on import; see
  `set_unreplaceable_predicate`.

* **The report is deterministic.** The engine can return two hits with the
  same span *and* the same score — `MRN` and `DATE_TIME` over `(4, 11)` — and
  which one arrives first is not stable across processes. `_rank` breaks that
  tie explicitly instead of inheriting whatever order the engine happened to
  use; see its docstring for the measurement.
"""

import functools
from dataclasses import dataclass
from typing import Callable

from medarx.config import load_settings
from medarx.redaction.recognizers import (
    CUSTOM_ENTITIES,
    build_recognizers,
    strip_anchor_labels,
)

__all__ = [
    "EntityHit",
    "TRUNCATED_TEXT",
    "build_engine",
    "scan_entities",
    "set_unreplaceable_predicate",
]


#: The predicate that decides which entity types `scan_entities` may never
#: drop. `None` means *nobody has said yet* — see `_unreplaceable`.
#:
#: `ner.py` does not know what a replacer is and does not import the module
#: that knows. The owner of the replacement policy injects the decision here,
#: which keeps the dependency pointing one way (`replacers` → `ner`) and keeps
#: this module free of a cycle. `replacers` registers
#: `lambda entity: not has_replacer(entity)` when it is imported, which is why
#: importing it is a prerequisite for the protection, not an optional extra.
_UNREPLACEABLE: Callable[[str], bool] | None = None


def set_unreplaceable_predicate(predicate: Callable[[str], bool]) -> None:
    """Register the predicate `scan_entities` may not drop hits under.

    Called once, at import time, by `medarx.redaction.replacers` — the module
    that actually owns the replacer table. `ner.py` therefore never learns what
    a replacement is; it only learns which entity types must survive the scan.
    """
    global _UNREPLACEABLE
    _UNREPLACEABLE = predicate


def _unreplaceable(extra: Callable[[str], bool] | None) -> Callable[[str], bool]:
    """Combine the registered predicate with a caller's, in the safe order.

    A caller's `extra` can only ever *add* to the protection, never remove it:
    an entity the registered predicate calls unresolvable stays unresolvable
    whatever the caller passes. That is the whole point of the argument — it
    is a widening hook, not a replacement for the default.

    With nothing registered the answer is "everything is unresolvable", so
    the scan reports every hit it saw rather than silently dropping one. That
    is the fail-closed direction: the cost of not having imported `replacers`
    is a noisier report, and the cost of the other default was a published
    document.
    """
    if _UNREPLACEABLE is None and extra is None:
        return lambda entity: True
    if _UNREPLACEABLE is None:
        return extra
    if extra is None:
        return _UNREPLACEABLE
    return lambda entity: _UNREPLACEABLE(entity) or extra(entity)


#: The entity type of the single hit that marks a scan which did not cover
#: the whole input. It is not a Presidio entity and has no recognizer; it is
#: produced by `scan_entities` alone.
TRUNCATED_TEXT = "TRUNCATED_TEXT"

#: The only language this kernel analyses. Presidio requires a language code on
#: every `analyze` call and on the registry load.
LANGUAGE = "en"

#: The single seam through which this module reads configuration. It is a
#: name, not a call, so a test can supply different settings without a
#: `Settings` object having to be constructed from the process environment
#: twice over; `config.py` remains the only module that reads the environment.
_settings = load_settings

_MODEL = "en_core_web_sm"


@dataclass(frozen=True)
class EntityHit:
    """One detected entity.

    `start` and `end` are character offsets **into the string the caller
    passed to `scan_entities`**, not into some intermediate form. That holds
    because `strip_anchor_labels` blanks anchor labels to equal-length spaces
    instead of deleting them, so the analyser's coordinate space is the
    identity. A caller may therefore splice directly:
    `text[hit.start:hit.end] == hit.text`, and `text` is exactly that slice.

    The one exception is `TRUNCATED_TEXT`, whose span is a range of the input
    that was *not* analysed; its `text` is empty by design rather than being
    the slice.
    """

    entity_type: str
    start: int
    end: int
    score: float
    text: str


def build_engine():
    """Construct a fresh `AnalyzerEngine` with the custom recognizers added.

    Presidio's default English recognizers are loaded *as well as* the custom
    clinical set, not instead of them: a registry holding only the clinical
    recognizers would redact an MRN and leave the phone number next to it in
    the clear.

    A fresh engine per call is deliberate for this function, so a caller that
    needs its own recognizer set gets one. For scanning, use
    `scan_entities`, which shares a single engine.
    """
    from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
    from presidio_analyzer.nlp_engine import NlpEngineProvider

    nlp_engine = NlpEngineProvider(
        nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": LANGUAGE, "model_name": _MODEL}],
        }
    ).create_engine()
    registry = RecognizerRegistry()
    registry.load_predefined_recognizers(nlp_engine=nlp_engine, languages=[LANGUAGE])
    for recognizer in build_recognizers():
        registry.add_recognizer(recognizer)
    return AnalyzerEngine(
        nlp_engine=nlp_engine, registry=registry, supported_languages=[LANGUAGE]
    )


@functools.lru_cache(maxsize=1)
def _shared_engine():
    """Return the process-wide engine, building it on first use.

    `lru_cache` rather than a module global so the first call is atomic: two
    threads racing here previously each built an engine and one was discarded,
    costing a redundant ~2.9 s model load and a transiently doubled model
    footprint. It was never a wrong answer — `AnalyzerEngine.analyze` holds no
    mutable scan state — but the race costs one decorator to remove, and the
    property is structural rather than something a timing-based test would
    have to guess at.
    """
    return build_engine()


def _collapse_overlaps(
    hits: list[EntityHit], unreplaceable: Callable[[str], bool]
) -> list[EntityHit]:
    """Keep one hit per overlapping region: the best one under `_rank`.

    The engine reports the same characters under two entity types — the
    seven-digit MRN `4452819` comes back as `MRN` at 0.85 *and* as Presidio's
    `DATE_TIME` at 0.85, over the identical span — and a redaction layer that
    kept both would apply two replacements to one span. Which of the two
    survives is decided by `_rank`, never by the engine's emission order.

    `unreplaceable` stops this filter from swallowing a block. Measured on
    this machine: spaCy reports "ZX-99-ALPHA" as `ORGANIZATION` at 0.85 *on
    exactly the same span* as `AMBIGUOUS_REFERENCE` at 0.30. Collapsing on
    score alone keeps the organization and drops the reference, so layer 2
    would never learn the value is unresolvable and the document would be
    published. A hit the predicate calls unresolvable is therefore never
    discarded here, whatever its score.
    """
    kept: list[EntityHit] = []
    for hit in sorted(hits, key=_rank):
        if unreplaceable(hit.entity_type) or all(
            hit.end <= other.start or other.end <= hit.start for other in kept
        ):
            kept.append(hit)
    return sorted(kept, key=lambda h: (h.start, h.end))


def _rank(hit: EntityHit) -> tuple[float, int, int, str]:
    """Total order over competing hits, best first.

    Score, then the longer span, then **the project's own clinical entity
    first**, then the entity name — so the order is total and reproducible.

    The third key is not cosmetic. Presidio hands back the same span twice
    when a custom recognizer and a default one agree on the characters but not
    the label: "MRN: 4452819", with the anchor label blanked, comes back as
    `MRN` at 0.85 *and* `DATE_TIME` at 0.85 over the identical span `(4, 11)`.
    Presidio returns them in registry-iteration order, and that order is not
    stable across processes — verified here by varying `PYTHONHASHSEED`:
    seed 0 yields `DATE_TIME`, seeds 1 and 2 yield `MRN`. Sorting on score and
    length alone leaves that coin-flip undecided. Preferring the clinical
    entity is also right on the merits: the custom recognizers exist precisely
    because the defaults mislabel these fields.
    """
    return (
        -hit.score,
        -(hit.end - hit.start),
        0 if hit.entity_type in CUSTOM_ENTITIES else 1,
        hit.entity_type,
    )


def scan_entities(
    text: str,
    min_score: float,
    unreplaceable: Callable[[str], bool] | None = None,
) -> list[EntityHit]:
    """Detect entities in `text` and return them sorted by `(start, end)`.

    The pipeline, in order: blank anchor labels, truncate to
    `Settings.ner_text_limit`, run the analyzer, drop hits scoring below
    `min_score`, collapse overlapping hits, append the truncation flag.

    **Offsets index `text` itself.** `strip_anchor_labels` blanks an anchor
    label to equal-length spaces rather than deleting it, so the analyser's
    coordinate space is the identity: `text[hit.start:hit.end] == hit.text` for
    every detected entity, and a caller can splice without a mapping. Under
    the earlier deleting strip, the third hit of a two-label note drifted
    eight characters past its value; see `strip_anchor_labels`.

    **What this function may never drop.** `Settings.ner_score_threshold` is
    applied nowhere here — the decision to block belongs to layer 2, and a
    candidate that is invisible cannot be blocked. `min_score` is the
    caller's filter, and layer 2 calls with `min_score=0.0`.

    Two filters here can drop a hit — the score filter and the overlap
    collapse — and both are governed by the *same* predicate,
    `_unreplaceable`, which combines the one `replacers` registers at import
    time (the real policy, `not has_replacer(entity)`) with anything the
    caller passes. The caller's argument is a widening hook: it can add entity
    types to the protected set and can never remove one. Fixing this at the
    collapse alone would leave the identical failure one filter earlier — a
    caller passing `min_score=Settings.ner_score_threshold` would delete the
    unresolvable candidate at the score filter with the suite still green.

    If the input exceeds the limit, one extra hit of type `TRUNCATED_TEXT` and
    score 1.0 is appended, spanning `[ner_text_limit, len(text))` — the
    characters that were **not** scanned. Its `text` is empty: the dropped tail
    is not retained, so a flag hit cannot become an arbitrarily large string in
    a disposition record. It has no replacer either, so the predicate protects
    it from both filters as well.
    """
    if not isinstance(text, str):
        raise TypeError(f"scan_entities takes str, got {type(text).__name__}")

    protected = _unreplaceable(unreplaceable)
    limit = _settings().ner_text_limit
    # Length-preserving, so `scanned` and `text` share one coordinate space.
    scanned = strip_anchor_labels(text)[:limit]

    hits: list[EntityHit] = []
    if scanned:
        engine = _shared_engine()
        for result in engine.analyze(text=scanned, language=LANGUAGE):
            # Filter 1 of 2. An entity with no deterministic replacement is a
            # block, not a discard, so `min_score` must not be able to hide it:
            # the candidate has to arrive in order to be blocked.
            if result.score < min_score and not protected(result.entity_type):
                continue
            hits.append(
                EntityHit(
                    entity_type=result.entity_type,
                    start=result.start,
                    end=result.end,
                    score=result.score,
                    text=scanned[result.start:result.end],
                )
            )

    if len(text) > limit:
        # The flag goes through the collapse below like any other hit. It
        # cannot be swallowed: it scores 1.0 so `_rank` puts it first, no
        # entity span can overlap it (entity spans end at or before `limit`,
        # the flag starts at `limit`), and it has no replacer, so the predicate
        # keeps it even if a future rank put something else ahead of it.
        hits.append(
            EntityHit(
                entity_type=TRUNCATED_TEXT,
                start=limit,
                end=len(text),
                score=1.0,
                text="",
            )
        )

    # Filter 2 of 2: the overlap collapse. Same predicate, same guarantee.
    return _collapse_overlaps(hits, protected)
