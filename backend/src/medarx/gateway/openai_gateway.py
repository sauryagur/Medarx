"""Component F: the model gateway, the only place a provider is called.

The single property this module is arranged around is the one design §6 row 7
states: **anything other than the exact payload object E approved, or an
unknown model identifier, is an error and no provider call is made.** Two
checks, both before the socket is touched, in this order:

1. `build_body` resolves the model through the registry and refuses an unknown
   one. It is called first in `send` and holds no I/O at all, so an unknown
   model is refused before a request body exists — not after, and not by
   letting a provider return a 4xx about it.
2. `verify_approved_payload` re-derives the approved payload's hash from the
   object itself and refuses unless it equals the hash the policy engine
   approved. It is a separate call because the composition root is what holds
   both the payload and the engine's decision; see its docstring for the
   ordering obligation that implies.

**The bytes are the evidence.** `build_body` produces the body, it is
serialised exactly once, and those bytes are what goes on the wire and what
`last_request_body` returns. Nothing re-encodes, reorders, normalises or
re-serialises them in between, because the whole egress story in design §3 I
is a comparison of the observed bytes against what was approved, and that
comparison is meaningless if the gateway records one encoding and transmits
another. A test in `tests/test_gateway.py` measures the bytes at a loopback
socket and asserts they equal `last_request_body()`.

**Provider-agnostic by construction, not by configuration.** The wire spec is
OpenAI's, and the base URL, model, key and timeout all come from `Settings`.
There is no provider branch in this file, and a test asserts that no provider
is named in it; the same code path serves a local engine and a cloud one.

**Three provider failures, kept apart.** A transport failure, a non-2xx
response and a malformed body are three different conditions with three
different remedies, so they are three exception types and none of them is a
`MedarxError` — design §6 has no row for a provider being down, and giving
one a layer and action codes would render a provider outage as a privacy block.
"""

from __future__ import annotations

import json
import secrets
from typing import Any

import httpx

from medarx.config import Settings
from medarx.errors import (
    GatewayError,
    ProviderResponseError,
    ProviderStatusError,
    ProviderTransportError,
)
from medarx.gateway.model_registry import ALLOWED_MODELS, is_allowed
from medarx.models import ModelRequest, ModelResponse, StructuredPayload, payload_hash_of

__all__ = ["CHAT_COMPLETIONS_PATH", "ModelGateway"]

#: The path, relative to the configured base URL, that the OpenAI chat
#: completions spec puts it at. A constant rather than a literal at the call
#: site, so the one place that knows the path is the one place a reader looks.
CHAT_COMPLETIONS_PATH = "/chat/completions"

# -- Wire codes, declared as module constants so the AST sweep in
# -- tests/test_openapi_contract.py resolves them to the strings they are,
# -- which is what holds them to the contract's ActionCode enum.

_ACTION_CODE_UNKNOWN_MODEL = "UNKNOWN_MODEL"
_ACTION_CODE_PAYLOAD_MISMATCH = "PAYLOAD_MISMATCH"
_ACTION_CODE_HASH_MISMATCH = "HASH_MISMATCH"


def _encode_body(body: dict[str, Any]) -> bytes:
    """The one encoding of a request body, used for the wire and for evidence.

    Compact separators, and `ensure_ascii` left on, so the bytes are ASCII and
    whitespace-free: a body whose encoding could vary is a body that cannot be
    compared against observed bytes later. Key order is the order `build_body`
    wrote, not a sort — nothing reorders a payload between approval and
    transmission.
    """
    return json.dumps(body, separators=(",", ":")).encode("utf-8")


def _content_of(raw: Any) -> str | None:
    """`choices[0].message.content` as a string, or `None` if it is not there.

    Every step is checked rather than assumed, because a body that is JSON and
    is not a completion is a real provider answer (an error envelope sent with
    a 200, a truncated proxy response) and indexing into it would raise
    something unrelated to what actually happened.
    """
    if not isinstance(raw, dict):
        return None
    choices = raw.get("choices")
    if not isinstance(choices, list) or not choices:
        return None
    first = choices[0]
    if not isinstance(first, dict):
        return None
    message = first.get("message")
    if not isinstance(message, dict):
        return None
    content = message.get("content")
    return content if isinstance(content, str) else None


class ModelGateway:
    """The one component permitted to call an inference provider.

    One `httpx.Client`, built from `Settings` and held for the object's life.
    Construction performs no I/O and resolves no provider, so a gateway can be
    constructed in a test with nothing listening anywhere.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._client = httpx.Client(
            base_url=settings.gateway_base_url,
            # Read from configuration, never hard-coded and never lowered here:
            # a cold first inference against a local model measured ~14.6 s
            # against ~1.1 s warm, so a short default is a timeout that fires
            # on the one request a user is waiting for.
            timeout=settings.gateway_timeout_s,
        )
        self._last_request_body: bytes | None = None

    # -- Model resolution --------------------------------------------------

    def model_for(self, registry_name: str | None) -> str:
        """The model identifier to put in the body.

        `registry_name` is what the caller asked for, or `None` to take the
        deployment's configured default — the contract's `model_id` is
        optional and its absence means exactly that. Either way the result is
        checked against the registry, the configured default included: a typo
        in `MEDARX_GATEWAY_MODEL` then fails closed on every request instead
        of sending an identifier no one validated.

        Returns the name unchanged. There is no translation step, because
        translating one provider's naming into another's is the bespoke adapter
        the OpenAI wire spec exists to make unnecessary.

        Raises `GatewayError` carrying `UNKNOWN_MODEL` (design §6 row 7), with
        no request built and no provider call made.
        """
        name = self._settings.gateway_model if registry_name is None else registry_name
        if not is_allowed(name):
            raise GatewayError(
                action_codes=(_ACTION_CODE_UNKNOWN_MODEL,),
                message=(
                    f"model {name!r} is not in the model registry; the registry "
                    f"is {sorted(ALLOWED_MODELS)} and nothing outside it may be "
                    "sent, so no provider call was made"
                ),
            )
        return name

    # -- The body ----------------------------------------------------------

    def build_body(self, request: ModelRequest) -> dict[str, object]:
        """The OpenAI chat-completions body for `request`, or a refusal.

        Public because it is a boundary: a caller that wants to know what
        would go on the wire — the egress check, a log, a test — can ask this
        without sending anything. It performs no I/O, and the model's registry
        check happens here, so **no body exists for an unknown model**.

        Exactly four keys, the four the spec requires and the four
        `ModelRequest` carries. Nothing is defaulted, renamed or dropped: a
        body that quietly supplied a value the caller did not would be a
        reconstruction of the request rather than the request. In particular
        no image or `modalities` parameter is ever added — the local model
        reports capabilities `["completion", "tools"]` and no vision, so
        anything image-shaped on the wire would be a leak by construction.
        """
        model = self.model_for(request.model)
        return {
            "model": model,
            "messages": [dict(message) for message in request.messages],
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
        }

    # -- Row 7: the object E approved -------------------------------------

    def verify_approved_payload(
        self,
        payload: StructuredPayload | None,
        approved_hash: str,
    ) -> None:
        """Refuse unless `payload` is the object the policy engine approved.

        The same substitution §6 row 7 names, checked at the last point before
        transmission. `payload_hash` is a *claim*: any caller can populate it,
        and `model_copy(update=...)` leaves it untouched while replacing
        `report_text` underneath it. So the hash is re-derived from the
        object's own content with `payload_hash_of` — the single definition
        redaction layer 3 and the policy engine share, not a second expression
        here that could drift from the one it is checking against — and the
        claim is only believed when the content agrees with it.

        The refusal carries two contract codes, and both are true of it:

        - `PAYLOAD_MISMATCH` is design §6 row 7's own name for this condition,
          the leading code of the contract's layer-F block example, and the
          code the decision table's row 7 carries;
        - `HASH_MISMATCH` names the check that detected it. The contract has
          carried that member since before this component was written, and it
          was deliberately left unemitted when layer 3's stale example was
          corrected, on the stated ground that the comparison belongs to the
          gateway. Until here nothing emitted it, and an enum member the
          kernel never emits is a claim the contract cannot keep.

        `compare_digest` rather than `==`, so a caller probing this with
        candidate payloads cannot learn the approved hash a byte at a time.

        **Ordering is the caller's obligation.** `send` takes only the model
        request, so nothing here can enforce that this ran first; the
        composition root holds both the payload and the engine's decision, and
        must call this immediately before `send`. Raises `GatewayError`
        (layer `F`); returns `None` when the payload is the approved one.
        """
        if payload is None or not isinstance(approved_hash, str):
            raise GatewayError(
                action_codes=(
                    _ACTION_CODE_PAYLOAD_MISMATCH,
                    _ACTION_CODE_HASH_MISMATCH,
                ),
                message=(
                    "no payload, or no approved hash, was presented for "
                    "transmission; nothing may be sent"
                ),
            )
        claim_matches = isinstance(payload.payload_hash, str) and secrets.compare_digest(
            payload.payload_hash, approved_hash
        )
        content_matches = secrets.compare_digest(payload_hash_of(payload), approved_hash)
        if not (claim_matches and content_matches):
            raise GatewayError(
                action_codes=(
                    _ACTION_CODE_PAYLOAD_MISMATCH,
                    _ACTION_CODE_HASH_MISMATCH,
                ),
                message=(
                    "the payload is not the object the policy engine approved; "
                    "the hash it carries and the hash recomputed from its own "
                    "content do not both equal the approved hash, so nothing "
                    "may be transmitted"
                ),
            )

    # -- Transmission ------------------------------------------------------

    def last_request_body(self) -> bytes | None:
        """The exact bytes of the last request this gateway transmitted.

        `None` until something has been sent. This is the evidence the egress
        check compares against what an observer saw on the wire, so it is
        recorded from the same bytes object that was handed to the transport,
        and a refusal — which sends nothing — leaves it alone rather than
        overwriting the evidence of a request that did happen with a body that
        did not.
        """
        return self._last_request_body

    def send(self, request: ModelRequest) -> ModelResponse:
        """Build the body, transmit it, and parse the provider's reply.

        Order is the guarantee: the body is built (and so the model validated)
        before any I/O, the bytes are recorded before they are sent, and only
        then is the socket touched.

        Three provider failures, three exception types, none of them a privacy
        block — see `medarx.errors.ProviderError`. The success path reads
        `choices[0].message.content` from the OpenAI response shape and keeps
        the whole decoded body in `ModelResponse.raw` for capture and audit.
        """
        body = self.build_body(request)
        payload_bytes = _encode_body(body)
        headers = {"Content-Type": "application/json"}
        api_key = self._settings.gateway_api_key
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        # An empty key sends no Authorization header at all. Sending a bare
        # `Bearer ` would put a credential-shaped header on the wire that
        # authenticates nothing, and the Phase 1 observer requires none.
        #
        # The URL is spelled out rather than left relative to the client's
        # `base_url`, so the request line does not depend on the transport's
        # URL-merge rules.
        url = f"{self._settings.gateway_base_url.rstrip('/')}{CHAT_COMPLETIONS_PATH}"
        self._last_request_body = payload_bytes
        try:
            response = self._client.post(url, content=payload_bytes, headers=headers)
        except httpx.HTTPError as exc:
            raise ProviderTransportError(
                f"the provider at {self._settings.gateway_base_url} could not be "
                f"reached: {type(exc).__name__}"
            ) from exc
        return self._parse(response)

    def _parse(self, response: httpx.Response) -> ModelResponse:
        """One 2xx chat-completion reply, or the failure it turned out to be."""
        if not response.is_success:
            raise ProviderStatusError(response.status_code)
        try:
            raw = response.json()
        except ValueError as exc:
            raise ProviderResponseError(
                "the provider answered 2xx with a body that is not JSON"
            ) from exc
        content = _content_of(raw)
        if content is None:
            raise ProviderResponseError(
                "the provider's body carries no choices[0].message.content string"
            )
        return ModelResponse(model_id=raw.get("model") or "", content=content, raw=raw)
