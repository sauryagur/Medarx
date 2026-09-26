"""Component G: the audit log — the record of what happened.

Append-only, tamper-evident, and raw-PHI-free by policy. The field-by-field
storage policy is the design's own: hashes, field *names*, and codes are
persisted; values are not, and there is no field here that could hold one. Full
model prompts and responses belong in a restricted, encrypted diagnostic store,
which this component does not implement and does not pretend to.

Tamper evidence is a keyed hash chain plus a head anchor, because a relational
database alone does not make a log immutable: see `medarx.audit.hash_chain` for
what the key buys and, just as importantly, what it does not.
"""

from medarx.audit.audit_log import (
    ALLOWED_AUDIT_FIELDS,
    AUDIT_METADATA,
    EVENT_TABLE,
    HEAD_TABLE,
    AuditLog,
)
from medarx.audit.code_table import CODE_TABLE, PIPELINE_STAGES, STAGE_COMPONENTS, CodeEntry
from medarx.audit.hash_chain import GENESIS, ChainReport, canonical, chain_hash

__all__ = [
    "ALLOWED_AUDIT_FIELDS",
    "AUDIT_METADATA",
    "CODE_TABLE",
    "EVENT_TABLE",
    "GENESIS",
    "HEAD_TABLE",
    "PIPELINE_STAGES",
    "STAGE_COMPONENTS",
    "AuditLog",
    "ChainReport",
    "CodeEntry",
    "canonical",
    "chain_hash",
]
