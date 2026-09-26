"""The keyed derivation behind every surrogate and every date shift.

One primitive: an HMAC-SHA256 over a domain-separated reference, keyed by the
audit key. Everything else in this package is a truncation of that digest, so
there is exactly one place where the key is read and one place where its
absence is refused.

**Pseudonymization is not anonymization.** These surrogates are re-identifiable
to anyone who holds the key, and therefore to anyone who holds the mapping
store. That is why the store is a separate, access-controlled database that no
component on the model path may read.
"""

import hashlib
import hmac

from medarx.pseudonym.errors import AuditKeyRequired

__all__ = ["SURROGATE_HEX_CHARS", "audit_digest", "require_audit_key", "surrogate"]


#: Characters of hex kept from a surrogate digest. Eight hex characters is
#: 32 bits: a birthday collision is likely past ~65k references in one scope,
#: so the store's primary key on the original reference — not this truncation —
#: is what guarantees that two originals never share a surrogate.
SURROGATE_HEX_CHARS = 8


def require_audit_key(audit_key: str) -> str:
    """Return `audit_key`, or refuse to proceed on an empty one.

    Refusing is the whole point: an unkeyed HMAC is a plain hash, so the
    surrogate would be a reversible encoding rather than a pseudonym.
    """
    if not audit_key:
        raise AuditKeyRequired(
            "an empty audit key cannot pseudonymize: surrogates and date shifts "
            "would be unkeyed and trivially invertible. Set MEDARX_AUDIT_KEY."
        )
    return audit_key


def audit_digest(audit_key: str, domain: str, reference: str) -> bytes:
    """HMAC-SHA256 over `reference` in `domain`, keyed by the audit key.

    The domain is part of the signed message, so a study reference and a
    patient reference with the same literal value never derive the same digest.
    """
    message = f"{domain}:{reference}".encode()
    return hmac.new(require_audit_key(audit_key).encode(), message, hashlib.sha256).digest()


def surrogate(audit_key: str, domain: str, reference: str) -> str:
    """The stable surrogate for `reference`: `<domain>-<8 hex>`."""
    return f"{domain}-{audit_digest(audit_key, domain, reference).hex()[:SURROGATE_HEX_CHARS]}"
