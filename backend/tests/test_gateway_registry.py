"""The model registry: the closed set of identifiers component F will send.

The registry is what makes §6 row 7's "unknown model identifier" decidable
locally, before a request body exists. A test that only asserted membership
would not notice a caller bypassing `is_allowed`; these read the set itself
because it is the whole of the boundary.
"""

from medarx.gateway.model_registry import ALLOWED_MODELS, is_allowed


def test_registry_contains_exactly_the_declared_models():
    assert ALLOWED_MODELS == frozenset({"medarx-demo-model", "openrouter/mock-model"})


def test_unknown_model_is_not_allowed():
    assert is_allowed("gpt-9-imaginary") is False
    assert is_allowed("medarx-demo-model") is True


def test_is_allowed_is_exact_and_not_a_prefix_or_substring_match():
    # A registry is a set of whole identifiers. A substring rule would let
    # "medarx-demo-model-and-everything-else" through, which is the same class
    # of hole as a payload check that matches on a prefix.
    assert is_allowed("medarx-demo-model-2") is False
    assert is_allowed("openrouter/mock-model/v2") is False
    assert is_allowed(" medarx-demo-model") is False
    assert is_allowed("") is False


def test_the_default_configured_model_is_in_the_registry():
    # `Settings.gateway_model` is what a deployment with no `model_id` sends, so
    # a default outside the registry would make every such request a block.
    # Checked here rather than in the gateway because it is a property of the
    # two agreeing, and neither owns the other.
    from medarx.config import Settings

    assert is_allowed(Settings().gateway_model)
