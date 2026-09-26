"""Errors raised by the pseudonymization component itself.

`AuditKeyRequired` is deliberately **not** a `MedarxError`. It is a deployment
misconfiguration, not a refusal about a patient's data: there is nothing to
block, no request to deny, and no layer to attribute. Keeping it outside the
`MedarxError` hierarchy means an `except MedarxError` handler on the request
path cannot mistake it for a privacy block and render a layer and an action
code for it into a receipt or an audit event.

That distinction is not pedantry. The contract's action-code enum does contain a
member that reads plausibly for this situation, and minting it would satisfy the
enum check while asserting something false: a receipt or audit event reading
"component C refused: a surrogate was missing" is a durable, externally-visible
misstatement about a patient's data, produced by a deployment mistake. The
refusals *about* a request's content use `PseudonymError` in `medarx.errors`,
with the rest of the taxonomy, and name an honest code.
"""

__all__ = ["AuditKeyRequired"]


class AuditKeyRequired(ValueError):
    """Raised when pseudonymization is asked to derive anything with no audit key.

    Fail-closed by construction. Surrogates and date shifts are HMACs keyed by
    the audit key; with an empty key the derivation is unkeyed, so anyone who
    knows the construction can invert `medarx-study-<8 hex>` back to its input.
    That turns pseudonymization into a reversible encoding and hands anyone
    holding the output the re-identification key, which is the one thing the
    mapping store exists to withhold. There is no fallback key and no warning:
    the operation is refused.
    """
