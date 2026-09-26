"""The error taxonomy of the privacy kernel.

Every fail-closed refusal is a `MedarxError`, and both of its payload fields are
validated when it is constructed: `layer` must be a member of the closed set
{"J", "A", "C", "D.1", "D.2", "D.3", "E", "F"} (the `Layer` enum in
`contracts/openapi.yaml`; there is no bare "D"), and `action_codes` must be a
non-empty tuple of classifier-shaped codes — uppercase words joined by single
underscores, with no digits, spaces, or newlines. A code that fails that shape
check is refused, so no error can be built carrying a value in a code.

That is the guarantee, stated at its actual strength: the *shape* of a code is
enforced here, at runtime, on every value. Whether a code is a *member* of the
contract's `ActionCode` enum is enforced at test time by the AST sweep in
`tests/test_openapi_contract.py`, and only over statically declared emission
sites — a code assembled dynamically at runtime is checked for shape and for
nothing else. An error built this way is safe to render into a block receipt
and to log, subject to that one gap.

`AuthzError` is deliberately **not** a `MedarxError`. An authorization failure
returns 403 and a privacy block returns 422, and a caller must be able to tell
them apart by status code alone. Keeping the authorization type outside this
hierarchy means the 422 block handler cannot catch it by accident, and it
carries no `layer` and no `action_codes` to leak into a receipt.

`ProviderError` is not a `MedarxError` for the same reason, and a stronger
one. A provider that is unreachable, that answers 503, or that answers with
something that is not a completion has not refused anything on privacy
grounds: design §6 has no row for it, and the contract answers it with a 500
`ProblemDetail`. A `MedarxError` here would be rendered by the 422 block
handler into a receipt carrying action codes for a refusal the kernel never
made. Its three subclasses keep the three conditions apart by type, so a
caller can tell them apart without reading a message.
"""

from __future__ import annotations

from medarx.models import LAYERS, check_codes

__all__ = [
    "AuthzError",
    "ExtractionError",
    "GatewayError",
    "MedarxError",
    "PolicyError",
    "ProviderError",
    "ProviderResponseError",
    "ProviderStatusError",
    "ProviderTransportError",
    "PseudonymError",
    "RedactionError",
]


class MedarxError(Exception):
    """Base class for a fail-closed refusal raised by a privacy-kernel layer.

    Subclasses fix `LAYER`; the layer that raised the error may pass `layer=`
    only where the layer tag is not fixed (redaction, which spans three).

    Attributes:
        layer: a member of the closed layer set, checked on construction.
        action_codes: non-empty tuple of classifier-shaped codes, also checked
            on construction. This is what makes "safe to log" true at the
            source: an error cannot be built carrying a bare "D" layer or a
            code with a medical record number in it, so nothing downstream has
            to be trusted to re-check what a caller constructed.
    """

    #: Closed-set layer tag for this refusal; see the `Layer` enum.
    LAYER: str

    def __init__(
        self,
        *,
        action_codes: tuple[str, ...],
        message: str = "",
        layer: str | None = None,
    ) -> None:
        if not action_codes:
            raise ValueError("action_codes must not be empty")
        # Same authority as the receipt's `layer` Literal and the same check the
        # receipt runs on its codes — one set, one rule, no second copy.
        check_codes(list(action_codes))
        self.layer = self.LAYER if layer is None else layer
        if self.layer not in LAYERS:
            raise ValueError(
                f"layer {self.layer!r} is not a member of the contract Layer enum "
                f"{LAYERS}; there is no bare 'D' — the redaction layers are D.1, D.2, and D.3"
            )
        self.action_codes = tuple(action_codes)
        self.message = message
        super().__init__(message or f"{self.layer}: {', '.join(self.action_codes)}")


class ExtractionError(MedarxError):
    """Refusal by the structured payload extractor (component A)."""

    LAYER = "A"


class PseudonymError(MedarxError):
    """Refusal by the pseudonymization service (component C).

    A refusal here is attributed to component C, not to redaction: a receipt's
    job is to name the component that refused, and filing C's refusals under
    `D.1` would misattribute them on the wire. `C` is a member of the contract's
    `Layer` enum, which is the closed set every `LAYER` here and the receipt's
    `layer` field draw from, and which
    `tests/test_openapi_contract.py` keeps equal to that enum.
    """

    LAYER = "C"


class RedactionError(MedarxError):
    """Refusal by one of the three layered-redaction layers (component D).

    `layer` is an explicit argument because the raising layer is the whole point
    of the receipt; it defaults to "D.2", where an unresolved NER candidate is
    the common case.
    """

    LAYER = "D.2"


class PolicyError(MedarxError):
    """Refusal by the policy engine (component E). Fails closed in every mode."""

    LAYER = "E"


class GatewayError(MedarxError):
    """Refusal by the model gateway (component F), before any provider call."""

    LAYER = "F"


class AuthzError(Exception):
    """Authorization failure at the API surface: 403, never a 422 block.

    Carries no `layer` and no `action_codes`, so it cannot be rendered as a
    privacy block even if a future handler catches it by mistake.
    """


class ProviderError(Exception):
    """A model provider call failed, for a reason that is not a privacy block.

    Deliberately **not** a `MedarxError`, for the same reason `AuthzError` is
    not one. Design §6 enumerates the conditions that block, and "the provider
    was unreachable", "the provider answered 503" and "the provider answered
    with something that is not a completion" are not among them: no privacy
    refusal was made and no payload was withheld for a privacy reason. Were
    these `MedarxError`s, the API's 422 handler would turn a provider outage
    into a privacy block receipt naming codes for a refusal the kernel never
    made, and the audit log would record a redaction event that never
    happened. The contract's answer for this is `500`, a `ProblemDetail`.

    The three subclasses are the three conditions, kept apart deliberately: a
    transport failure, a non-2xx response and a malformed body are different
    failures with different remedies, and a caller must be able to tell them
    apart by type rather than by parsing a message. None carries a `layer` and
    none carries `action_codes`, so none can be rendered into a block receipt.
    """


class ProviderTransportError(ProviderError):
    """The request never reached the provider: DNS, connect, or timeout."""


class ProviderStatusError(ProviderError):
    """The provider answered, and the answer was not a 2xx.

    `status_code` is the provider's own status. It is a number the provider
    chose; it is not an `action_code` and never reaches a receipt.
    """

    def __init__(self, status_code: int, message: str = "") -> None:
        self.status_code = status_code
        super().__init__(message or f"provider answered {status_code}")


class ProviderResponseError(ProviderError):
    """The provider answered 2xx with a body that is not a completion.

    Raised for a body that is not JSON, and for JSON that does not carry
    `choices[0].message.content` as a string. It is a distinct condition from
    a non-2xx because the call *succeeded* and the answer was unusable, which
    is a different problem with a different fix.
    """
