import importlib.metadata
import spacy

SPACY_MODEL = "en_core_web_sm"
MODEL_VERSION = "3.8.0"
SPACY_VERSION = "3.8.16"


def test_ner_model_is_installed_at_the_pinned_version():
    assert importlib.metadata.version(SPACY_MODEL) == MODEL_VERSION
    assert importlib.metadata.version("spacy") == SPACY_VERSION


def test_ner_model_loads_and_exposes_the_expected_pipes():
    nlp = spacy.load(SPACY_MODEL)
    assert "ner" in nlp.pipe_names


import os

from medarx.config import load_settings


def test_pinned_defaults_match_the_plan(monkeypatch):
    # The point of this test is that the *defaults* are pinned, so it must not
    # be satisfiable by a stray MEDARX_* variable in the developer's shell.
    # Clearing them makes it a statement about Settings' own defaults.
    for key in list(os.environ):
        if key.startswith("MEDARX_"):
            monkeypatch.delenv(key, raising=False)

    s = load_settings()
    assert s.policy_version == "medarx-policy-1.0.0"
    assert s.ner_score_threshold == 0.50
    assert s.ner_text_limit == 200_000
    assert s.max_body_bytes == 1_048_576
    assert s.gateway_timeout_s == 120.0
    assert s.audit_retention_days == 2555


def test_credential_defaults_are_empty(monkeypatch):
    # A credential must never have a value baked into source: the Phase 1
    # observer needs no authentication, so the defaults are empty and the
    # gateway client omits the Authorization header entirely (Task 16's rule).
    for key in list(os.environ):
        if key.startswith("MEDARX_"):
            monkeypatch.delenv(key, raising=False)

    s = load_settings()
    assert s.audit_key == ""
    assert s.gateway_api_key == ""