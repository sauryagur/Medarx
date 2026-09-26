"""The Presidio analyzer engine and the entity scan behind redaction layer 2.

`recognizers.py` builds the clinical patterns; this module runs them. The
distinction matters, because `PatternRecognizer.analyze` is *not* the path a
redaction layer takes: it performs no context enhancement, and it knows
nothing about replacers. The score a block decision would key on is produced
in `AnalyzerEngine.analyze`, and this is the only place that happens.

Five things here are load-bearing, and each is asserted in the tests:

* **The engine is built once.** `build_engine()` constructs a fresh
  `AnalyzerEngine` — spaCy model load included — and `scan_entities` shares a
  single lazily-built one through `_shared_engine`. `scan_entities` runs once
  per text-bearing field, so rebuilding per call would put a multi-second
  model load on the request path.

* **Anchor labels are stripped before the scan**, not merely available to be
  stripped. Presidio scores a bare `DOB` as `ORGANIZATION` at 0.85 and a
  seven-digit MRN as `DATE_TIME` at 0.85, so a bare clinical label reaches
  layer 2 mislabelled and is redacted as the wrong kind of thing.

* **Truncation is loud.** Text past `Settings.ner_text_limit` is not scanned,
  and the report says so with a single `TRUNCATED_TEXT` hit spanning exactly
  the dropped tail. A scan that silently dropped a fifth of a report is
  indistinguishable from a clean one, which is the failure this kernel exists
  to make impossible.

* **The scan does not decide anything.** `min_score` is the caller's filter
  and `Settings.ner_score_threshold` is applied nowhere in this module. Layer
  2 calls `scan_entities(..., min_score=0.0)` so a low-confidence candidate
  is *seen*; filtering here would hide the very thing layer 2 has to block.
  `EntityHit.entity_type` is exposed precisely so the block condition can be
  "detected, and no replacer is registered for it" — a property of the entity,
  not of a score that a future setting could move.

* **The report is deterministic.** The engine can return two hits with the
  same span *and* the same score — `MRN` and `DATE_TIME` over `(1, 8)` — and
  which one arrives first is not stable across processes. `_rank` breaks that
  tie explicitly instead of inheriting whatever order the engine happened to
  use; see its docstring for the measurement.
"""

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
]

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

_ENGINE = None


@dataclass(frozen=True)
class EntityHit:
    """One detected entity.

    `start` and `end` are character offsets **into the text the analyzer was
    given**, which is the anchor-stripped text — see `scan_entities`. `text` is
    that same substring, not a slice of the caller's original string.
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


def _shared_engine():
    """Return the process-wide engine, building it on first use.

    Not thread-safe on the first call: two threads racing here may both build
    an engine and one is discarded. That is a wasted load, not a wrong answer,
    and Presidio's `AnalyzerEngine` holds no mutable scan state.
    """
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = build_engine()
    return _ENGINE


def _collapse_overlaps(
    hits: list[EntityHit], unreplaceable: Callable[[str], bool] | None = None
) -> list[EntityHit]:
    """Keep one hit per overlapping region: the best one under `_rank`.

    The engine reports the same characters under two entity types — the
    seven-digit MRN `4452819` comes back as `MRN` at 0.85 *and* as Presidio's
    `DATE_TIME` at 0.85, over the identical span — and a redaction layer that
    kept both would apply two replacements to one span. Which of the two
    survives is decided by `_rank`, never by the engine's emission order.

    `unreplaceable` is the escape hatch that keeps this from swallowing a
    block. Measured on this machine: spaCy reports "ZX-99-ALPHA" as
    `ORGANIZATION` at 0.85 *on exactly the same span* as `AMBIGUOUS_REFERENCE`
    at 0.30. Collapsing on score alone keeps the organization and drops the
    reference, so layer 2 would never learn the value is unresolvable and the
    document would be published. A hit whose entity type the caller says it
    cannot replace is therefore never discarded here, whatever its score.
    `ner.py` deliberately does not know what a replacer is — that policy
    belongs to the caller, which passes the predicate in.
    """
    kept: list[EntityHit] = []
    for hit in sorted(hits, key=_rank):
        unresolvable = unreplaceable is not None and unreplaceable(hit.entity_type)
        if unresolvable or all(
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
    the label: "MRN: 4452819", with the anchor label stripped, comes back as
    `MRN` at 0.85 *and* `DATE_TIME` at 0.85 over the identical span `(1, 8)`.
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

    The pipeline, in order: strip anchor labels, truncate to
    `Settings.ner_text_limit`, run the analyzer, drop hits scoring below
    `min_score`, collapse overlapping hits.

    `min_score` is the caller's filter and nothing else. `min_score=0.0`
    surfaces every hit the engine produced, which is what layer 2 wants: the
    decision to block belongs there, and a candidate that is invisible cannot
    be blocked.

    `unreplaceable` is an entity-type predicate used only by the overlap
    collapse; see `_collapse_overlaps`. A caller that owns a replacer table
    passes `lambda entity: entity not in REPLACERS` (that is, `has_replacer`
    negated) so an unresolvable hit can
    never be hidden behind a higher-scoring neighbour on the same span.

    **Offsets are into the stripped text, not the caller's original string.**
    `strip_anchor_labels` removes the label *and* its separator, so a hit after
    a stripped label is offset by the length of what was removed. A caller
    that splices these offsets into the original text will corrupt it. The
    `text` field is sliced from the same stripped text and is self-consistent
    with `start`/`end`.

    If the input exceeds the limit, one extra hit of type `TRUNCATED_TEXT` and
    score 1.0 is appended, spanning `[ner_text_limit, len(stripped_text))` —
    the characters that were **not** scanned. Its `text` is empty: the dropped
    tail is not retained, so a flag hit cannot itself become a large string.
    """
    if not isinstance(text, str):
        raise TypeError(f"scan_entities takes str, got {type(text).__name__}")

    stripped = strip_anchor_labels(text)
    limit = _settings().ner_text_limit
    scanned = stripped[:limit]

    hits: list[EntityHit] = []
    if scanned:
        engine = _shared_engine()
        for result in engine.analyze(text=scanned, language=LANGUAGE):
            if result.score < min_score:
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

    if len(stripped) > limit:
        hits.append(
            EntityHit(
                entity_type=TRUNCATED_TEXT,
                start=limit,
                end=len(stripped),
                score=1.0,
                text="",
            )
        )

    return _collapse_overlaps(hits, unreplaceable)
