"""Component G: the audit log — the record of what happened.

Append-only, tamper-evident, and raw-PHI-free by policy. The field-by-field
storage policy is the design's own: hashes, field *names*, classifiers and codes
are persisted; values are not, and every free-form field in a record is held to
a shape, so a value written into a field that should hold a name is refused at
the write. Full model prompts and responses belong in a restricted, encrypted
diagnostic store, which this component does not implement and does not pretend
to.

Tamper evidence is a keyed hash chain, a keyed head anchor, and a retention
purge that re-chains rather than exempts — a relational database alone does not
make a log immutable, and a database a writer can reach does not either. See
`medarx.audit.hash_chain` for what the key buys and, just as importantly, what it
does not.
"""

from medarx.audit.audit_log import (
    ALLOWED_AUDIT_FIELDS,
    AUDIT_METADATA,
    EVENT_TABLE,
    HEAD_TABLE,
    TOMBSTONE_TABLE,
    AuditLog,
)
from medarx.audit.code_table import (
    CODE_TABLE,
    LAYER_STAGE,
    PIPELINE_STAGES,
    STAGE_COMPONENTS,
    CodeEntry,
    stages_reached,
)
from medarx.audit.hash_chain import (
    GENESIS,
    ChainReport,
    anchor_mac,
    canonical,
    chain_hash,
)

__all__ = [
    "ALLOWED_AUDIT_FIELDS",
    "AUDIT_METADATA",
    "CODE_TABLE",
    "EVENT_TABLE",
    "GENESIS",
    "HEAD_TABLE",
    "LAYER_STAGE",
    "PIPELINE_STAGES",
    "STAGE_COMPONENTS",
    "TOMBSTONE_TABLE",
    "AuditLog",
    "ChainReport",
    "CodeEntry",
    "anchor_mac",
    "canonical",
    "chain_hash",
    "stages_reached",
]
