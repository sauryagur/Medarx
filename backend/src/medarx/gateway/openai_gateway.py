"""Component F: the model gateway, the only place a provider is called.

The single property this module is arranged around is the one design §6 row 7
states: **anything other than the exact payload object E approved, or an
unknown model identifier, is an error and no provider call is made.** Both
checks live in `verify_approved_payload`, in this order, and neither touches a
socket:

1. `build_body` resolves the model through the registry and refuses an unknown
   one. It holds no I/O at all, so an unknown model is refused before a
   request body is serialised — not after, and not by letting a provider
   return a 4xx about it.
2. The payload's hash is re-derived from the object itself and must equal the
   hash the policy engine approved.

**What is verified is what is sent, and that is enforced by a type.**
`verify_approved_payload` returns an `ApprovedSend`; `send` accepts nothing
else. That is not tidiness. When `send` took a bare `ModelRequest` and the
verifier returned `None`, the two were unrelated values with nothing binding
them: a caller could verify the approved payload and then send a request built
from a different one, nothing would object, and `last_request_body` would
return the substituted bytes — so component I's two-observer agreement check
would have **passed and certified the leak**. An evidence mechanism that cannot
fail on the failure it exists to detect is worse than no evidence, because it
manufactures confidence. The token closes all three halves at once: an
unverified send is unrepresentable, the request is bound to the verification
that covered it, and the verification cannot be skipped because `send` has
nothing else to take.

**A frozen dataclass was not enough, and that was found by running the
bypass.** With the sentinel as an ordinary `init` field, `dataclasses.replace`
copied it onto a new instance and a substituted request went on the wire with
`last_request_body` reporting the substituted bytes — the same failure, through
a plain library call and no private name. `copy.copy`, `copy.deepcopy` and
`pickle` each did the same, because all three bypass `__init__`. So the token
is `init=False` plus a private mint path, and all four clone routes raise.
`ApprovedSend` states both what that guarantees and what Python cannot make
guaranteed.

**The bytes are the evidence, and they are fixed at authorisation.** The body
is built and encoded once, inside the verifier, and the resulting `bytes` are
what go on the wire *and* what `last_request_body()` returns. Nothing
re-encodes, reorders, normalises or re-derives them in between, because the
egress story in design §3 I is a comparison of the observed bytes against what
was approved, and that comparison is meaningless if the gateway records one
encoding and transmits another. A test in `tests/test_gateway.py` measures the
bytes at a loopback socket and asserts they equal `last_request_body()`.

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
from collections.abc import Mapping
from dataclasses import dataclass, field
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

__all__ = ["CHAT_COMPLETIONS_PATH", "ApprovedSend", "ModelGateway"]

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


def _model_id_of(raw: Any) -> str:
    """The provider's own name for the model it answered with, or `""`.

    Narrow and checked for the same reason `_content_of` is: a provider that
    answers `"model": null` or `"model": 7` should not reach
    `ModelResponse.model_id`, which is typed `str` and would turn a strange
    answer into a pydantic `ValidationError` — an error about *our* types
    standing in for one about the provider's reply.
    """
    if not isinstance(raw, dict):
        return ""
    model_id = raw.get("model")
    return model_id if isinstance(model_id, str) else ""


#: The only value that lets an `ApprovedSend` be constructed, and the only
#: object `_issue` stamps one with. Module-private.
#:
#: **What that is worth, stated honestly.** Python has no access control, so a
#: determined caller can reach a module-private name. This is the strongest
#: enforcement the language offers, not a guarantee: it is the same standard
#: this package already accepts for `ALLOWED_MODELS` and for the module-level
#: action-code constants, and strictly stronger than a comment. See `_issue`
#: for exactly what it rules out, and `ApprovedSend` for what it does not.

_ISSUED = object()


@dataclass(frozen=True, eq=False)
class ApprovedSend:
    """A request that `verify_approved_payload` has authorised to be sent.

    **What is guaranteed.** `send` transmits exactly the `body_bytes` that the
    verifier built and encoded, and `last_request_body()` returns that same
    object. A request that was not passed to the verifier cannot be sent at
    all, because there is nothing else `send` accepts. A token cannot be
    constructed outside this module, and it cannot be **re-pointed** at a
    different request afterwards: the constructor is closed, and every ordinary
    way of copying a Python object — `dataclasses.replace`, `copy.copy`,
    `copy.deepcopy` and `pickle` — is refused. Those four were not closed by a
    frozen dataclass alone, and I verified that rather than assuming it:
    `dataclasses.replace(token, request=..., body=..., body_bytes=...)`
    succeeded and transmitted a substituted payload, and `copy.copy`,
    `copy.deepcopy` and `pickle.loads(pickle.dumps(...))` each produced a
    working token, because all three bypass `__init__` outright. `_issued` is
    therefore `init=False`, so `replace` cannot pass the sentinel through, and
    the clone hooks below raise instead of letting a copy inherit it.

    **What is not guaranteed, and cannot be in this language.** A caller
    holding a genuine token can rewrite it with
    `object.__setattr__(token, "request", ...)`, which bypasses a frozen
    dataclass's `__setattr__`; Python offers no way to stop that. It is
    measured rather than asserted, in
    `test_only_object_setattr_can_rewrite_a_token`. But the same caller can
    also just call `gw._client.post(...)`, so no in-process object property
    defends against an adversary inside the process; what this class defends
    against is the ordinary mistake, and every plain-library operation that
    could be one.

    The second thing it does not check is that `request` was derived *from*
    the approved payload. No component in this project defines that
    derivation — building the messages from a payload is the orchestrator's
    job — so the gateway binds identity, not provenance, and says so rather
    than implying a check it cannot make.

    `body` and `body_bytes` are the body built and the bytes encoded **during
    verification**, so what goes on the wire is what was authorised rather than
    something re-derived at transmission time.

    It holds `approved_payload_hash` rather than the payload itself: a token
    carrying `report_text` would be a new place that text lives, inside an
    object that is easy to log or attach to an exception. The hash is what the
    rest of the system needs.

    `eq=False`: a token is a capability, not a value. Two tokens for the same
    payload and request are distinct objects that compare unequal and hash by
    identity, so "is this the one that was authorised" is answered by identity
    rather than by a field-by-field comparison that a forged token could
    satisfy.
    """

    request: ModelRequest
    approved_payload_hash: str
    body: Mapping[str, object]
    body_bytes: bytes
    # `init=False` is load-bearing: with the sentinel as a constructor argument
    # and a default, `dataclasses.replace` would copy the live `_ISSUED` onto a
    # new instance and hand out a working token. It is set only by `_issue`,
    # the one place in this module that bypasses `__init__`.
    _issued: object = field(default=None, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._issued is not _ISSUED:
            raise TypeError(
                "ApprovedSend cannot be constructed directly: call "
                "ModelGateway.verify_approved_payload(payload, approved_hash, "
                "request), which is the only thing that can authorise a send"
            )

    def __copy__(self) -> "ApprovedSend":
        raise TypeError(
            "an ApprovedSend cannot be copied: a copy would be a second token "
            "for a request nothing authorised. Re-run verify_approved_payload."
        )

    def __deepcopy__(self, memo: dict) -> "ApprovedSend":
        raise TypeError(
            "an ApprovedSend cannot be deep-copied: the copy would bypass "
            "__init__ and inherit the authorisation. Re-run "
            "verify_approved_payload."
        )

    def __reduce__(self):
        raise TypeError(
            "an ApprovedSend cannot be pickled: an unpickled token would "
            "carry the authorisation of whichever request was verified first. "
            "Re-run verify_approved_payload."
        )

    __reduce_ex__ = __reduce__


def _issue(
    request: ModelRequest,
    approved_payload_hash: str,
    body: Mapping[str, object],
    body_bytes: bytes,
) -> ApprovedSend:
    """Mint an `ApprovedSend`. The only construction path in the package.

    It builds the instance with `__new__` and assigns through
    `object.__setattr__`, deliberately bypassing the constructor that refuses
    — that refusal is the point, and this function is the one exception. It is
    module-private, and `tests/test_gateway.py` asserts by AST sweep that
    `_ISSUED` is referenced nowhere else under `backend/src/medarx/`.

    What that sweep does and does not prove: it proves no other module in the
    package names the sentinel. It does not prove the token is unreachable by
    other means, and it is not claimed to — a caller in this process can reach
    module-private names and, as `ApprovedSend` says, can rewrite a genuine
    token with `object.__setattr__`. What it rules out is a second *component*
    quietly acquiring the authority to authorise a send.
    """
    token = ApprovedSend.__new__(ApprovedSend)
    for name, value in (
        ("request", request),
        ("approved_payload_hash", approved_payload_hash),
        ("body", body),
        ("body_bytes", body_bytes),
    ):
        object.__setattr__(token, name, value)
    object.__setattr__(token, "_issued", _ISSUED)
    return token


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
        request: ModelRequest,
    ) -> ApprovedSend:
        """Check the payload *and* the request, and return the only thing `send` accepts.

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

        **`request` is part of what is being authorised, and that is the
        point.** An earlier version returned `None` and left `send` taking a
        bare `ModelRequest`, which meant the verified payload and the
        transmitted request were two unrelated values with nothing binding
        them: a caller could verify the approved payload and then send a
        request built from a different one, and nothing would object — and
        `last_request_body` would return the substituted bytes, so the
        two-observer agreement check in component I would have *passed* and
        certified the leak. Passing the request here binds it: this is the
        request this verification covers, and `send` transmits that one and no
        other. The body is built and encoded here too, so the exact bytes that
        will go on the wire are fixed at the moment of authorisation.

        What this does **not** do is check that `request` was derived from
        `payload`. No component defines that derivation — it belongs to the
        orchestrator, which builds the messages — so the gateway binds
        identity, not provenance, and §6 row 7 is as far as the kernel can
        carry it on its own.

        The guarantee, stated exactly: `send` transmits the `body_bytes` built
        and encoded *here*, and `last_request_body()` returns that same object,
        so the recorded evidence and the bytes on the wire cannot differ; a
        request that was not passed here cannot be sent at all; and a token
        cannot be re-pointed afterwards by any ordinary library operation.
        What is not guaranteed: that the request was built from the payload at
        all, which is the orchestrator's to construct, and that a caller
        holding a genuine token cannot rewrite it with `object.__setattr__`,
        which Python cannot prevent — see `ApprovedSend`.

        Raises `GatewayError` (layer `F`); returns an `ApprovedSend` when both
        the payload is the approved one and the model is registered.
        """
        body = self.build_body(request)
        approved = self._verify_payload_hash(payload, approved_hash)
        return _issue(
            request=request,
            approved_payload_hash=approved,
            body=body,
            body_bytes=_encode_body(body),
        )

    def _verify_payload_hash(
        self,
        payload: StructuredPayload | None,
        approved_hash: str,
    ) -> str:
        """The approved hash, once the object is proved to be that payload.

        Split out of `verify_approved_payload` so the two refusals — no
        payload presented, and a payload that is not the approved one — are
        each one readable block. Both carry the same two codes, because both
        are the same condition from §6's point of view: the object about to
        leave is not the object E approved.
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
        return approved_hash

    # -- Transmission ------------------------------------------------------

    def last_request_body(self) -> bytes | None:
        """The exact bytes of the last request this gateway handed to a transport.

        `None` until something has been sent. This is the evidence the egress
        check compares against what an observer saw on the wire, so it is the
        same `bytes` object that was passed as `content=`, assigned **before**
        the response is known.

        That ordering is deliberate in both directions. A read timeout means
        the request *did* reach the provider and the provider simply did not
        answer in time, so the bytes were on the wire and this must report
        them. A connect failure is the opposite — nothing was sent — and here
        the value is still populated, because the honest statement of what this
        method reports is "the bytes handed to the transport", not "the bytes a
        provider is known to have received". A caller that needs the difference
        pairs this with the outcome of `send`: a `ProviderTransportError` means
        treat the bytes as unconfirmed, a `ProviderStatusError` or a response
        means they arrived.

        A **refusal** sends nothing and leaves this value alone, so the evidence
        for a request that did happen is not overwritten with a body that did
        not. Refusals no longer reach `send`: an unknown model and a payload
        that is not the approved one are both raised inside
        `verify_approved_payload`, before any token exists, and `send` refuses
        anything that is not a token with a `TypeError` before its assignment.
        """
        return self._last_request_body

    def send(self, approved: ApprovedSend) -> ModelResponse:
        """Transmit the bytes `verify_approved_payload` authorised, and parse the reply.

        The parameter is an `ApprovedSend`, and the check is at runtime rather
        than only in the annotation: a type hint is documentation, and this is
        a boundary. Passing a bare `ModelRequest` raises `TypeError`, because
        an unverified send is not a thing this component will do.

        Nothing is built here. The body was built and encoded during
        verification, so what is transmitted is byte-for-byte what was
        authorised and what `last_request_body()` will return — one encoding,
        one body, no second chance to differ.

        Three provider failures, three exception types, none of them a privacy
        block — see `medarx.errors.ProviderError`. The success path reads
        `choices[0].message.content` from the OpenAI response shape and keeps
        the whole decoded body in `ModelResponse.raw` for capture and audit.
        """
        if not isinstance(approved, ApprovedSend):
            raise TypeError(
                "send() takes an ApprovedSend, which only "
                "verify_approved_payload() can produce; an unverified request "
                f"was passed ({type(approved).__name__}) and nothing was sent"
            )
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
        payload_bytes = approved.body_bytes
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
        return ModelResponse(model_id=_model_id_of(raw), content=content, raw=raw)
