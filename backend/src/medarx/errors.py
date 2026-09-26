"""The error taxonomy of the privacy kernel.

Every fail-closed refusal is a `MedarxError`: it carries a `layer` drawn from
the closed set {"J", "A", "D.1", "D.2", "D.3", "E", "F"} (the `Layer` enum in
`contracts/openapi.yaml`) and a non-empty tuple of `action_codes` that are
members of the contract's `ActionCode` enum. Codes classify a refusal; they
never carry a raw value, so an error built this way is safe to render into a
block receipt and to log.

`AuthzError` is deliberately **not** a `MedarxError`. An authorization failure
returns 403 and a privacy block returns 422, and a caller must be able to tell
them apart by status code alone. Keeping the authorization type outside this
hierarchy means the 422 block handler cannot catch it by accident, and it
carries no `layer` and no `action_codes` to leak into a receipt.
"""

from __future__ import annotations

__all__ = [
    "AuthzError",
    "ExtractionError",
    "GatewayError",
    "MedarxError",
    "PolicyError",
    "PseudonymError",
    "RedactionError",
]


class MedarxError(Exception):
    """Base class for a fail-closed refusal raised by a privacy-kernel layer.

    Subclasses fix `LAYER`; the layer that raised the error may pass `layer=`
    only where the layer tag is not fixed (redaction, which spans three).

    Attributes:
        layer: closed-set layer tag, a member of the contract `Layer` enum.
        action_codes: non-empty tuple of contract `ActionCode` values.
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
        self.layer = self.LAYER if layer is None else layer
        self.action_codes = tuple(action_codes)
        self.message = message
        super().__init__(message or f"{self.layer}: {', '.join(self.action_codes)}")


class ExtractionError(MedarxError):
    """Refusal by the structured payload extractor (component A)."""

    LAYER = "A"


class PseudonymError(MedarxError):
    """Refusal by the pseudonymization service (component C).

    The contract's `Layer` enum is {"J", "A", "D.1", "D.2", "D.3", "E", "F"}:
    there is no "C", because pseudonymization is not itself a row of the design's
    §6 enforcement table — it performs no block decision. A refusal to replace a
    structured identifier is nevertheless a real refusal, and the tag it must
    carry on a receipt is the one for the deterministic structured-identifier
    replacement it could not complete: `D.1`, redaction layer 1. Emitting "C"
    would put a value off the contract enum onto the wire.
    """

    LAYER = "D.1"


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
