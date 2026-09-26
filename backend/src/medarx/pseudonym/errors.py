"""Errors raised by the pseudonymization component itself.

`AuditKeyRequired` is deliberately **not** a `MedarxError`. It reports a
deployment misconfiguration, not a refusal about a patient's data, so it has no
layer and no action code to render, and an `except MedarxError` handler on the
request path cannot catch it and mistake it for a privacy block. Refusals about
a request's content use `PseudonymError` in `medarx.errors`, with the rest of
the taxonomy.
"""


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
