"""Engine-level assertions about context enhancement of the custom recognizers.

The unit tests in `test_ner_recognizers.py` cannot see context enhancement:
`PatternRecognizer.analyze` does none. `AnalyzerEngine._enhance_using_context`
does, via `LemmaContextAwareEnhancer` (+0.35, floored at 0.4), and that is the
only place the score a redaction layer will actually see is produced. These
tests build a real engine to pin it.

Task 8 owns the production engine in `ner.py`. Building one here is deliberate
and local: the point is to observe the enhancer, not to provide an engine.
"""

import pytest

from medarx.config import load_settings
from medarx.redaction.recognizers import (
    AMBIGUOUS_SCORE,
    CUSTOM_ENTITIES,
    build_recognizers,
)

pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")


@pytest.fixture(scope="module")
def engine():
    from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
    from presidio_analyzer.nlp_engine import NlpEngineProvider

    nlp_engine = NlpEngineProvider(
        nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
        }
    ).create_engine()
    registry = RecognizerRegistry()
    registry.load_predefined_recognizers(nlp_engine=nlp_engine, languages=["en"])
    for recognizer in build_recognizers():
        registry.add_recognizer(recognizer)
    return AnalyzerEngine(
        nlp_engine=nlp_engine, registry=registry, supported_languages=["en"]
    )


def _analyze(engine, text):
    return {
        (r.entity_type, r.start, r.end, r.score)
        for r in engine.analyze(text=text, entities=list(CUSTOM_ENTITIES), language="en")
    }


@pytest.mark.parametrize(
    "text",
    [
        # The brief's own fixture, which contains all three of the documented
        # context words in one sentence. With the context attached this is the
        # case that lifts 0.30 to 0.65, above `ner_score_threshold`.
        "Ref ticket ZX-99-ALPHA issued at the counter.",
        # And a case with no context words at all, which must land in exactly
        # the same place: the recognizer is un-enhanceable, so the surrounding
        # prose cannot change its score.
        "no words nearby ZX-99-ALPHA here",
    ],
)
def test_the_ambiguous_reference_reaches_the_engine_unchanged(engine, text):
    # This is the determinism the blocked beat rests on, asserted where it can
    # actually be observed. If this test fails, `UNENHANCEABLE_CONTEXT` has been
    # undone and the entity is reaching the redaction layer as a *confident*
    # detection with no replacer.
    hits = _analyze(engine, text)
    ambiguous = [h for h in hits if h[0] == "AMBIGUOUS_REFERENCE"]
    assert len(ambiguous) == 1
    assert ambiguous[0][3] == pytest.approx(AMBIGUOUS_SCORE)
    assert ambiguous[0][3] < load_settings().ner_score_threshold


def test_context_enhancement_still_lifts_the_mandatory_recognizers(engine):
    # The control for the test above: enhancement is switched off for the
    # ambiguous reference only. If this stops firing, the un-enhanceable
    # context has been applied to every recognizer and the mandatory
    # identifiers have silently lost their context words.
    hits = _analyze(engine, "MRN: 4452819")
    mrn = [h for h in hits if h[0] == "MRN"]
    assert len(mrn) == 1
    assert mrn[0][3] > AMBIGUOUS_SCORE
