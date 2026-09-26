"""The model registry: the closed set of identifiers component F will send.

Design §6 row 7 makes an unknown model identifier a refusal with **no provider
call made**. That is only decidable locally if the set of acceptable
identifiers is fixed in the kernel, which is what this module is. A registry
that could be extended at runtime — read from a directory, fetched from a
provider, taken from the request — would make "unknown" mean "not known yet",
and the refusal would move to a 4xx the provider chose.

Membership is a whole-identifier match, not a prefix, a substring or a
pattern. A prefix rule would admit `medarx-demo-model-anything`, which is the
same class of hole as a payload check that matches on a prefix: the thing
refused is not the thing that was checked.

**What the registry is not.** It does not say which provider serves a name, or
where that provider is, or what the name costs. Those are configuration
(`Settings.gateway_base_url`, `gateway_model`), and the gateway has no
provider branch at all. The registry is only the list of names this kernel is
willing to put on the wire.
"""

from __future__ import annotations

__all__ = ["ALLOWED_MODELS", "is_allowed"]


#: Every model identifier the gateway will send. A member here is the whole of
#: what a model name is checked against; there is no second list elsewhere, and
#: `Settings.gateway_model`'s default is a member of it.
ALLOWED_MODELS: frozenset[str] = frozenset({
    "medarx-demo-model",
    "openrouter/mock-model",
})


def is_allowed(model: str) -> bool:
    """Whether `model` is a registered identifier, as a whole.

    Equality against the set, so an empty string, a padded name, a prefixed
    name and a longer name are all unallowed. Not a normalisation step: a name
    that needed normalising to be recognised is a name the deployment has not
    declared, and admitting it would make the registry advisory.
    """
    return model in ALLOWED_MODELS
