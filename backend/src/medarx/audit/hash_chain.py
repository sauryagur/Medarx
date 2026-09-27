"""The hash chain: the tamper evidence behind the audit log.

**A relational database alone does not make a log immutable.** Any party that
can write rows can also make those rows agree with each other, so the evidence
has to be in something a writer cannot silently recompute. Two things make it so:

- **Linkage.** Every record carries the hash of the one before it, so a rewritten
  or reordered record breaks the sequence and a deletion in the middle leaves a
  gap. A deletion at the *tail* leaves a chain that still verifies, which is why
  the log also keeps a head anchor written in the same transaction as the append
  (`medarx.audit.audit_log`).
- **The key.** The digest is an HMAC keyed by `Settings.audit_key`, so a party
  that can read and rewrite the rows but does not hold the key cannot produce a
  chain that verifies.

**What the key does not buy.** It is the whole of the protection against a
privileged writer. Anyone holding the key can write a log that verifies
perfectly well, and `tests/test_audit.py` executes exactly that in
`test_a_party_holding_the_key_can_write_a_chain_that_verifies`. The chain is
tamper-*evident* against a reader and against accident, not tamper-*proof*
against someone with the key; the design defers external time-stamping, which
is what closes that gap, to Phase 6.

The encoding is defined rather than merely stable, because the digest is only
evidence if everyone means the same bytes by the same record. `canonical` is
sorted-key, whitespace-free JSON with datetimes as UTC ISO-8601 and `Z`; for any
value holding no datetime it produces byte-for-byte what
`medarx.models.canonical_hash` hashes, so the chain and the content hashes
cannot drift into two encodings.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any, Mapping

from medarx.pseudonym.errors import AuditKeyRequired

__all__ = [
    "GENESIS",
    "ChainReport",
    "anchor_mac",
    "canonical",
    "chain_hash",
    "iso_utc",
    "require_audit_key",
]


#: The previous-hash of the first record. Sixty-four zeros, so a chain that
#: starts anywhere else is a chain whose head has been replaced.
GENESIS = "0" * 64


def iso_utc(value: datetime) -> str:
    """The canonical text of an aware datetime: UTC ISO-8601 with a `Z`.

    The rule the canonical encoding applies to a datetime inside a record,
    exposed on its own because the table stores a bare timestamp as this text.
    A **naive** datetime is refused rather than assumed to be UTC: it has two
    readings, and quietly picking one would bake that guess into the tamper
    evidence.
    """
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(
            "an audit timestamp must carry a UTC offset: a naive datetime has "
            "two readings, and guessing one would change the hash. Use a "
            "timezone-aware datetime."
        )
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class ChainReport:
    """The result of walking the whole chain from `GENESIS`.

    `broken_at_index` is the index, in append order, at which the walk first
    failed, and it distinguishes two failures a caller must act on differently:

    - `broken_at_index < checked` — a surviving record no longer hashes to what
      it claims, or no longer links to its predecessor: something was rewritten,
      reordered, or deleted from the middle.
    - `broken_at_index == checked` — every record that is there verifies, and
      the anchor disagrees with that: the head hash names a record that is not
      present, or the count says there are more. That signature covers **three**
      distinct causes and the report cannot tell them apart — records deleted
      from the tail, records deleted from the tail *and* the anchor repointed at
      a survivor, and `row_count` alone altered with nothing deleted. All three
      are measured (`tests/test_audit.py` exercises each); distinguishing them
      is what the fourth field the design did not add would have bought. A
      caller acting on the report knows the anchor was tampered with; it does
      not know which.
    """

    ok: bool
    broken_at_index: int | None
    checked: int


def _json_default(value: Any) -> Any:
    """Encode the two types the audit record holds that JSON has no shape for.

    Aware datetimes become UTC ISO-8601 with a `Z` suffix, so the same instant
    is the same text whether the deployment is on UTC+5 or UTC-8 — a record
    whose hash changed because of the server's clock setting would be
    indistinguishable from a rewrite.

    A **naive** datetime is refused rather than assumed to be UTC. It has two
    readings, and quietly picking one would bake that guess into the tamper
    evidence. Anything else raises `TypeError`: there is no `default=` fallback
    that stringifies an unknown object, because "what was hashed" and "what was
    meant" would stop being the same question.
    """
    if isinstance(value, datetime):
        return iso_utc(value)
    if isinstance(value, date):
        return value.isoformat()
    raise TypeError(
        f"{type(value).__name__} has no defined canonical JSON encoding, and "
        "this chain has no fallback: an object hashed as its str() would make "
        "the digest evidence about something other than the record"
    )


def canonical(record: Mapping[str, Any]) -> bytes:
    """The canonical bytes a record is hashed as.

    Sorted keys, no whitespace, `None` as `null` — so two records that differ
    only in how they were built hash the same, and a record cannot be reshaped
    by reordering its keys.
    """
    return json.dumps(
        record, sort_keys=True, separators=(",", ":"), default=_json_default
    ).encode("utf-8")


def require_audit_key(audit_key: str) -> str:
    """Return `audit_key`, or refuse to build a chain without one.

    The same guard, and the same exception type, as the mapping store's: an
    unkeyed digest is a plain hash, so a chain written with an empty key is
    re-computable by anyone who can read the rows, which is the one party the
    chain exists to be evidence against.

    It raises `AuditKeyRequired`, a `ValueError` deliberately outside the
    `MedarxError` taxonomy: a missing key is a deployment misconfiguration with
    no layer and no honest action code, and reporting it as a privacy block
    would write a false privacy event into the very log that is meant to be
    trustworthy.
    """
    if not audit_key:
        raise AuditKeyRequired(
            "an empty audit key cannot chain an audit log: the digest is an "
            "HMAC over the record, and with an empty key it is a plain hash that "
            "anyone able to read the rows can recompute. Set MEDARX_AUDIT_KEY."
        )
    return audit_key


def chain_hash(record: Mapping[str, Any], previous_hash: str, key: str) -> str:
    """The keyed digest of `record`, chained to `previous_hash`.

    The record is hashed *with* `previous_hash` folded in, so a digest is a
    function of the whole history rather than of the row it sits on: moving a
    record, or two records with identical content swapping places, changes both
    digests.
    """
    body = {**record, "previous_hash": previous_hash}
    return hmac.new(
        require_audit_key(key).encode("utf-8"), canonical(body), hashlib.sha256
    ).hexdigest()


def anchor_mac(head_hash: str, row_count: int, key: str) -> str:
    """The keyed digest of the chain head, so the anchor cannot be repointed.

    A plain hash chain cannot see deletion at the tail: remove the last records
    and the survivors are still internally consistent. The head anchor is what
    says how far the chain went — and an *unkeyed* anchor is a value the same
    adversary can rewrite, so a repointed anchor would restore a clean
    verification. MACing it with the same key closes that: repointing the head
    now requires the audit key, exactly as re-chaining a record does.

    It does not close the case where the *entire* database is removed: a
    reader with no external copy of the head cannot tell an empty log from a
    deleted one. That is what external time-stamping is for, and the design
    defers it to Phase 6.
    """
    return hmac.new(
        require_audit_key(key).encode("utf-8"),
        canonical({"head_hash": head_hash, "row_count": row_count}),
        hashlib.sha256,
    ).hexdigest()
