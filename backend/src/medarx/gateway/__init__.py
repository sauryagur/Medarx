"""Component F: the model gateway.

Two modules and nothing else. `model_registry` is the closed set of model
identifiers the gateway will put on the wire, which is what makes design §6
row 7's "unknown model identifier" decidable without asking anyone.
`openai_gateway` is the single egress point: it speaks the OpenAI request and
response wire spec, so one implementation serves a local engine and a cloud
one with no provider branch, and it is the only component in the package that
performs network I/O.
"""

from medarx.gateway.model_registry import ALLOWED_MODELS, is_allowed
from medarx.gateway.openai_gateway import CHAT_COMPLETIONS_PATH, ModelGateway

__all__ = [
    "ALLOWED_MODELS",
    "CHAT_COMPLETIONS_PATH",
    "ModelGateway",
    "is_allowed",
]
