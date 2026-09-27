"""Component G: the audit log — what is stored, and how it is chained.

**The log is not a second PHI store.** The field set is closed and
hand-written, and the free-form fields inside it are shape-checked, so a caller
stuffing a value into a field that should hold a *name* is refused at the write
rather than persisted. The full model prompt and response do not belong here at
all — they belong in a restricted, encrypted diagnostic store, which this
component does not implement and does not pretend to.

**The record speaks the contract's vocabulary, and its stored form is stated
where it differs from the contract's printed one.** `function` is one of the
contract's three `FunctionName` members, spelled as the contract spells it;
`input_hash` and `approved_payload_hash` are the same digest the contract
prints, stored as bare lower-case hex rather than the contract's `sha256:`
prefix, which `append` accepts and strips. Both facts are load-bearing for
anyone comparing a stored record with the contract, and neither is a second
vocabulary: one spelling per value, and a caller writing the contract's own
spelling is not refused for it.

`append` is the only write path. It computes the chain digest inside the same
transaction that inserts the row, and the head is read and advanced under a lock
(see `AuditLog`), so a concurrent append cannot read a stale head and fork the
chain.

**A retention purge is a re-chain, not an exemption.** A purged record is
deleted from `audit_event` and replaced by a row in `audit_tombstone` carrying
its ordinal and its two chain fields; the tombstone's own digest is the keyed
digest of the *blanked* record, so it verifies by exactly the same rule as every
live row, and every record after it is re-chained onto it in the same
transaction. There is no flag anywhere that verification consults and no row
anything is exempt from, which is what stops a writer with database access and
no key from blanking a record and setting a boolean to stop it being checked.

**The head anchor is keyed.** A plain hash chain cannot see deletion at the
tail, and an unkeyed anchor is a value the same adversary can repoint. The
anchor therefore carries an HMAC over its own head and count, so moving it
requires the audit key exactly as re-chaining a record does. It still cannot
distinguish a database whose *entire* contents were deleted from one that was
never written — a reader with no external copy of the head has nothing to
compare against. External time-stamping is what closes that, and the design
defers it to Phase 6.

**Where the schema boundary lies.** Like the mapping store, `AuditLog.__init__`
creates its tables when they are absent. That is a convenience for a single
process, *not* a migration: nothing here upgrades a table that already exists.
Schema ownership for a real database belongs with the compose task, and
`medarx.audit.schema_init` is the one command that builds the whole Phase 1
store. The mapping store's `ProgrammingError` "already exists" guard is dead
code — SQLite raises `OperationalError` there — and it is deliberately neither
copied nor worked around here.
"""

from __future__ import annotations

import json
import re
import secrets
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from sqlalchemy import (
    Column,
    Integer,
    MetaData,
    String,
    Table,
    create_engine,
    delete,
    insert,
    select,
    update,
)
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.pool import NullPool, StaticPool

from medarx.audit.code_table import stages_reached
from medarx.audit.hash_chain import (
    GENESIS,
    ChainReport,
    anchor_mac,
    canonical,
    chain_hash,
    iso_utc,
    require_audit_key,
)
from medarx.models import AuditEvent

__all__ = [
    "ALLOWED_AUDIT_FIELDS",
    "AUDIT_METADATA",
    "EVENT_TABLE",
    "HEAD_TABLE",
    "TOMBSTONE_TABLE",
    "AuditLog",
]


#: The storage policy, written out rather than derived from the event model.
#:
#: It could be `frozenset(AuditEvent.model_fields)`, and that is exactly why it
#: is not: a mirror of the model makes the storage policy a *consequence* of
#: whatever the model happens to carry, and the model is the thing most likely
#: to grow a convenience field. Written out, it is a decision — and now that
#: `layer` has been added, that decision is one the file has already made once.
#: Adding a field to `AuditEvent` makes `append` refuse the record until someone
#: states here whether it may be persisted, which is the question that has to be
#: answered before a value reaches disk.
ALLOWED_AUDIT_FIELDS: frozenset[str] = frozenset(
    {
        "request_id",
        "timestamp",
        "function",
        "selected_model",
        "policy_version",
        "policy_mode",
        "input_hash",
        "approved_payload_hash",
        "redacted_field_names",
        "action_codes",
        "human_approval",
        "final_disposition",
        "layer",
        "chain_hash",
        "previous_hash",
    }
)


AUDIT_METADATA = MetaData()


#: One row per append, in append order, and **never** edited except by a
#: re-chain, which re-authenticates the row it rewrites.
#:
#: `ordinal` is the chain position and the only order that means anything: a log
#: re-sorted by timestamp is a log whose order no longer matches what happened,
#: and the chain is what notices.
#:
#: `timestamp` is stored as its canonical ISO-8601 text rather than as a
#: database timestamp, because the chain is computed over bytes and a datetime
#: round trip through a driver is not guaranteed to give those bytes back —
#: SQLite drops the offset, and a chain that changed on every read would report
#: tampering that never happened.
#:
#: Every column is NOT NULL. A record is removed by a retention purge, not blanked
#: in place, so there is no state in which this table holds a half-record.
EVENT_TABLE = Table(
    "audit_event",
    AUDIT_METADATA,
    Column("ordinal", Integer, primary_key=True, autoincrement=True),
    Column("request_id", String, nullable=False, index=True),
    Column("timestamp", String, nullable=False),
    Column("function", String, nullable=False),
    Column("selected_model", String),
    Column("policy_version", String, nullable=False),
    Column("policy_mode", String),
    Column("input_hash", String, nullable=False),
    Column("approved_payload_hash", String),
    Column("redacted_field_names", String, nullable=False),
    Column("action_codes", String, nullable=False),
    Column("human_approval", String),
    Column("final_disposition", String, nullable=False),
    Column("layer", String),
    Column("chain_hash", String, nullable=False),
    Column("previous_hash", String, nullable=False),
)


#: What a retention purge leaves behind: the record's *position*, and nothing
#: about the record.
#:
#: "This ordinal was purged" is a positive fact in its own row rather than a
#: flag stored on the row it describes, and the row's `chain_hash` is the keyed
#: digest of the blanked record — so a tombstone verifies by the same rule as a
#: live row and cannot be fabricated without the audit key. That is the whole of
#: the answer to "a purge must be authenticated": a keyless writer can delete a
#: record outright, and verification reports the gap; a keyless writer cannot
#: *authorise* the deletion by setting a flag, because nothing reads a flag.
TOMBSTONE_TABLE = Table(
    "audit_tombstone",
    AUDIT_METADATA,
    Column("ordinal", Integer, primary_key=True),
    Column("previous_hash", String, nullable=False),
    Column("chain_hash", String, nullable=False),
    Column("purged_at", String, nullable=False),
    Column("retention_cutoff", String, nullable=False),
)


#: The head of the chain, as a single row: the last digest, the number of
#: records, and an HMAC over those two taken with the audit key.
#:
#: `mac` is what makes this a check rather than a note. Without it, "delete the
#: tail and repoint the head at the surviving last row" restores a clean
#: verification, because the anchor is an ordinary value in the same database
#: the writer already has. Repointing it now costs the audit key.
#:
#: The anchor is tamper-evident, not tamper-proof: a party holding the key can
#: write a consistent forged log from scratch, exactly as it can recompute every
#: digest. See `medarx.audit.hash_chain` for what the key does and does not buy.
HEAD_TABLE = Table(
    "audit_chain_head",
    AUDIT_METADATA,
    Column("id", Integer, primary_key=True),
    Column("head_hash", String, nullable=False),
    Column("row_count", Integer, nullable=False),
    Column("mac", String, nullable=False),
)

#: The single anchor row's identifier. One row, always this one.
_HEAD_ID = 1

#: Columns holding canonical JSON text rather than a scalar.
_JSON_COLUMNS = ("redacted_field_names", "action_codes", "human_approval")

#: Every column the event's own fields are stored in.
_RECORD_COLUMNS = tuple(sorted(ALLOWED_AUDIT_FIELDS))

#: `chain_hash` is the output, not an input; `previous_hash` is both.
_HASHED_FIELDS = tuple(f for f in _RECORD_COLUMNS if f != "chain_hash")

#: The content of a record that has been purged: every field null. What a
#: tombstone's digest is computed over, so a tombstone is a digest anyone can
#: check and nobody can re-point without the key.
BLANKED_RECORD: dict[str, Any] = {name: None for name in _HASHED_FIELDS}


@dataclass(frozen=True)
class Entry:
    """One position in the chain, live or tombstoned, in the form that is hashed.

    `tombstoned` is carried rather than inferred from the record's content,
    because a live record whose every field happens to be null and a tombstone
    are the same bytes and must still be updated in different tables.
    """

    ordinal: int
    previous_hash: str
    chain_hash: str
    record: dict[str, Any]
    tombstoned: bool

# -- What a stored value is allowed to look like --------------------------------
#
# The allowlist says *which fields* may be persisted. These say what a value in
# one may be, which is the other half of "a field that could hold a raw value
# cannot be appended even by a mistake": an allowlisted field with a free-form
# string in it is a door, and the review demonstrated a medical record number
# riding in through `redacted_field_names` on a record that verified perfectly.

#: A payload field *name*: `report_text`, `dicom_metadata.patient_id`. Dotted
#: lower-case path segments, so a sentence — which is what a leaked value is —
#: does not parse as one.
FIELD_PATH = re.compile(r"\A[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*\Z")

#: A bare identifier: `medarx-policy-1.0.0`, `medarx-demo-model`. A space is
#: what separates an identifier from prose, so a name with a space in it is
#: refused — *except* where the contract publishes a spelling that contains
#: one. `function` is that case, and it is not gated by this shape: the contract
#: makes it a closed three-member enum (`Draft` / `Prior Summary` / `Ask`),
#: which `AuditEvent` holds as `FunctionName`. A closed enum is exact where a
#: shape is a guess, and the audit log is a record an auditor reads next to the
#: contract, so it speaks the contract's vocabulary. Translating the contract's
#: `Prior Summary` into `prior_summary` here would put a second spelling of a
#: contract fact into a permanent record *and* still refuse a caller who wrote
#: the contract's spelling. Internal snake_case is the application component's
#: translation, done before the record is written.
IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]*\Z")

#: A canonical digest, and the only two spellings a hash field accepts. Bare
#: lower-case hex is the **stored** form; the contract publishes its own example
#: for `approved_payload_hash` in the prefixed form
#: (`sha256:<64 hex>`, contracts/openapi.yaml `ExecutionResponse`), and the
#: prefix is a defined algorithm label rather than prose. So the prefixed form
#: is accepted on the way in and stripped on the way in — the record, the
#: column and the chain body all carry bare hex, and a reader comparing a
#: stored `2f1a…` with the contract's `sha256:2f1a…` needs this comment to know
#: they are the same value. See `_canonical_digest`.
DIGEST = re.compile(r"\A[0-9a-f]{64}\Z")

#: The contract's hash spelling: the algorithm name, a colon, then the digest.
PREFIXED_DIGEST = re.compile(r"\Asha256:([0-9a-f]{64})\Z")

#: Which stored field is held to which shape, and why each one.
#:
#: `function` is deliberately absent — see the note on `IDENTIFIER`; its gate is
#: the contract's closed enum, which the model applies. `chain_hash` and
#: `previous_hash` are absent because the log computes and overwrites them on
#: every append, so whatever a caller put there is a claim rather than data, and
#: holding them to a shape would only refuse the placeholder an honest caller
#: writes. `selected_model` is deployment configuration — an identifier, not a
#: free string — and `request_id` and `policy_version` are the two the first
#: round of review exercised.
_VALUE_SHAPES: dict[str, re.Pattern[str]] = {
    "request_id": IDENTIFIER,
    "selected_model": IDENTIFIER,
    "policy_version": IDENTIFIER,
    "input_hash": DIGEST,
    "approved_payload_hash": DIGEST,
}

#: The two fields whose value is a hash, and therefore the two the contract is
#: free to publish in its `sha256:` spelling. Written out rather than inferred
#: from `_VALUE_SHAPES` so that adding a shape-gated field does not silently
#: make it a hash field that silently strips a prefix.
_DIGEST_FIELDS = frozenset({"input_hash", "approved_payload_hash"})

#: Held element-wise rather than whole, because the field is a list of names.
_LIST_SHAPES: dict[str, re.Pattern[str]] = {"redacted_field_names": FIELD_PATH}

_MEMORY_POOL_ARGS = {"poolclass": StaticPool, "connect_args": {"timeout": 30}}
_FILE_POOL_ARGS = {"poolclass": NullPool, "connect_args": {"timeout": 30}}
_IN_MEMORY_DATABASES = (None, "", ":memory:")
_MEMORY_DRIVER = "sqlite+memory"

#: Appends are serialised per process. A deferred transaction locks nothing
#: until its first write, and the head is *read* before the insert, so without
#: this two appends can read the same head and fork the chain — which the suite
#: reproduced with twenty records and no error raised. On PostgreSQL the row
#: lock in `_locked_head` covers other processes; SQLite has no row locks,
#: so this is the whole of it there.
_APPEND_LOCK = threading.RLock()


def _url_and_pool(db_url: str) -> tuple[str, dict]:
    """The engine URL and its connection arguments.

    The same reasoning as the mapping store, for the same reason: SQLite's
    driver connection is not safe to share between threads, so a file-backed
    store checks out a connection per operation, and an in-memory database
    keeps one connection for its whole life because every other connection would
    be a different, empty database. `sqlite+memory` is a spelling rather than a
    dialect, so it is normalised to the driver that exists.
    """
    if db_url == _MEMORY_DRIVER:
        db_url = "sqlite://"
    backend, _, database = db_url.partition("://")
    dialect = backend.split("+")[0]
    if dialect == "sqlite" and database in _IN_MEMORY_DATABASES:
        return db_url, dict(_MEMORY_POOL_ARGS)
    if dialect == "sqlite":
        return db_url, dict(_FILE_POOL_ARGS)
    return db_url, {}


def _to_column(name: str, value: Any) -> Any:
    """The stored form of one event field.

    Datetimes and the two lists and the sign-off go to disk as their canonical
    text, so the bytes on the row are the bytes the chain is computed over and
    a read-back re-hashes to the same value.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return iso_utc(value)
    if name in _JSON_COLUMNS:
        return canonical(value).decode("utf-8")
    return value


def _canonical_digest(name: str, value: str | None) -> str | None:
    """`value` in the one form a hash column stores: bare lower-case hex.

    The contract publishes a hash as `sha256:<hex>`; the log stores `<hex>`.
    Both spellings denote the same digest, so the prefixed one is accepted and
    stripped here — *before* the chain digest is computed, not after, so the
    hashed body, the column and the value `append` hands back are one string
    and a read-back re-hashes to the same value. Any other field passes through
    untouched, so this is a no-op for everything that is not a hash.
    """
    if value is None or name not in _DIGEST_FIELDS:
        return value
    prefixed = PREFIXED_DIGEST.match(value)
    return prefixed.group(1) if prefixed else value


def _from_column(name: str, value: Any) -> Any:
    """The event form of one stored column."""
    if name in _JSON_COLUMNS and value is not None:
        return json.loads(value)
    return value


def _record_of(row: Mapping[str, Any]) -> dict[str, Any]:
    """The hashed record for a stored row: every field but the digest itself."""
    return {name: _from_column(name, row[name]) for name in _HASHED_FIELDS}


def _as_utc(value: datetime) -> datetime:
    """`value` in UTC, refusing a naive one rather than assuming where it is."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(
            "an audit timestamp must carry a UTC offset: a naive datetime has "
            "two readings, and the retention cut-off would move with the guess"
        )
    return value.astimezone(timezone.utc)


def _event_of(row: Mapping[str, Any]) -> AuditEvent:
    """Rebuild the event from a stored row.

    The text columns are handed to the model as they were written: a timestamp
    in canonical ISO-8601 parses back to the same instant, and the two list
    columns and the sign-off parse back to the same structures, so a read-back
    re-hashes to the digest the row carries.
    """
    values = {name: _from_column(name, row[name]) for name in _RECORD_COLUMNS}
    return AuditEvent(**values)


class AuditLog:
    """An append-only, tamper-evident log over a database URL.

    Appends are serialised per process by `_APPEND_LOCK` and, on a backend with
    row locks, across processes by the `FOR UPDATE` in `_locked_head`. That is what
    makes "a concurrent append cannot read a stale head" true: without both, the
    head is read and the row written in one transaction, but a deferred
    transaction has taken no lock when the read happens, and two appends can
    legitimately read the same head.
    """

    def __init__(self, db_url: str, key: str) -> None:
        # Refused before any connection is opened: a chain written with an empty
        # key is a plain hash chain that anyone able to read the rows can
        # recompute, which is the one party it exists to be evidence against.
        self._key = require_audit_key(key)
        url, pool = _url_and_pool(db_url)
        self._engine: Engine = create_engine(url, **pool)
        AUDIT_METADATA.create_all(self._engine)

    # -- Writing ------------------------------------------------------------

    def append(self, event: AuditEvent) -> AuditEvent:
        """Store `event`, chained to the current head, and return it stored.

        The returned event carries the `previous_hash` and `chain_hash` the row
        holds; any values the caller supplied for those two fields are replaced,
        because they are the log's to compute and a caller's copy of them is a
        claim rather than a fact.

        A hash written in the contract's `sha256:` spelling is *canonicalised*,
        not refused: the event stored, the column written, the chain body hashed
        and the event returned all carry the bare-hex form, so there is one
        string on disk and the returned record says so. See `_canonical_digest`
        for why that matters to an auditor comparing a row with the contract.
        """
        self._refuse_off_policy(event)
        event = event.model_copy(update={
            name: _canonical_digest(name, getattr(event, name))
            for name in _DIGEST_FIELDS
            if getattr(event, name) is not None
        })
        dumped = event.model_dump()
        body = {name: dumped[name] for name in _HASHED_FIELDS}
        with _APPEND_LOCK, self._engine.begin() as conn:
            head, count, _ = self._locked_head(conn)
            digest = chain_hash(body, head, self._key)
            values = {name: _to_column(name, body[name]) for name in _HASHED_FIELDS}
            values["chain_hash"] = digest
            values["previous_hash"] = head
            conn.execute(EVENT_TABLE.insert().values(**values))
            self._write_head(conn, digest, count + 1)
        return event.model_copy(update={"previous_hash": head, "chain_hash": digest})

    def _refuse_off_policy(self, event: AuditEvent) -> None:
        """Refuse a record the storage policy does not allow, for either reason.

        Two gates, and both are load-bearing:

        - **Field names.** The second gate after `AuditEvent`'s own
          `extra="forbid"`. That one blocks the obvious path; this one blocks the
          path that gets past it — a wider subclass, or a future version of the
          model — and it checks the *declared* fields as well as the ones this
          instance carries, so a field that would be persisted is refused before
          it can be.
        - **Values.** A field being allowlisted does not make a sentence in it
          acceptable. The free-form fields are held to identifier, digest or
          field-path shapes, and `function` is held to the contract's closed
          `FunctionName` enum, so the mistake this policy exists to catch — a
          value written into a field that should hold a name — is refused at
          the write. Hash fields accept the contract's `sha256:` spelling as
          well as bare hex and are stored canonically; that is a normalisation,
          not a widening, because both spellings denote one digest.
        """
        carried = set(event.model_dump()) | set(type(event).model_fields)
        off_policy = sorted(carried - ALLOWED_AUDIT_FIELDS)
        if off_policy:
            raise ValueError(
                f"audit record carries fields outside the storage policy: "
                f"{off_policy}. The audit log is not a place for values; if a "
                f"payload belongs somewhere, it belongs in the restricted "
                f"diagnostic store, not here. Add a field to "
                f"ALLOWED_AUDIT_FIELDS in medarx.audit.audit_log only after "
                f"deciding it cannot hold a value."
            )
        self._refuse_a_value_where_a_name_belongs(event)

    @staticmethod
    def _refuse_a_value_where_a_name_belongs(event: AuditEvent) -> None:
        """Refuse a value in a field that is only ever meant to hold a name."""
        for name, shape in _VALUE_SHAPES.items():
            # A hash field is checked in its canonical form, so the contract's
            # own `sha256:` spelling passes this gate and is stripped by
            # `append` rather than refused here.
            value = _canonical_digest(name, getattr(event, name))
            if value is not None and not shape.match(value):
                expected = (
                    "not a digest: 64 lower-case hex characters, optionally "
                    "written in the contract's 'sha256:' spelling"
                    if name in _DIGEST_FIELDS
                    else f"not an identifier ({shape.pattern})"
                )
                raise ValueError(
                    f"audit field {name!r} holds {getattr(event, name)!r}, which "
                    f"is {expected}. The audit log stores names and codes, "
                    f"never the values they stand for."
                )
        for name, shape in _LIST_SHAPES.items():
            for item in getattr(event, name):
                if not shape.match(item):
                    raise ValueError(
                        f"audit field {name!r} holds {item!r}, which is not a "
                        f"field name ({shape.pattern}). Record the *name* of the "
                        f"field the layer acted on, never what it held."
                    )
        approval = event.human_approval
        if approval is not None and not IDENTIFIER.match(approval.reviewer):
            raise ValueError(
                f"human_approval.reviewer holds {approval.reviewer!r}, which "
                f"is not an identifier ({IDENTIFIER.pattern})."
            )

    # -- Reading ------------------------------------------------------------

    def get(self, request_id: str) -> list[AuditEvent]:
        """Every stored event for `request_id`, in append order.

        A record past its retention window is not here: the purge removed the
        row, and the tombstone that replaced it carries the position and the
        chain fields and nothing else. There is no event to rebuild from it, by
        design.
        """
        with self._engine.begin() as conn:
            rows = conn.execute(
                select(*EVENT_TABLE.c)
                .where(EVENT_TABLE.c.request_id == request_id)
                .order_by(EVENT_TABLE.c.ordinal)
            ).mappings().all()
        return [_event_of(row) for row in rows]

    def stages_for(self, event: AuditEvent) -> tuple[str, ...]:
        """The pipeline stages this record says the request reached.

        Derived at read time from the record's blocking `layer`, not stored: a
        derived value cannot disagree with the record it is computed from, and
        because it is not a field it does not enter the chain body — so a
        record chained before the projection existed still verifies. That is a
        claim about `stages` alone. Adding a *stored* field such as `layer`
        does change the hashed body, and so changed every already-chained
        record's digest when it was added; do not read this sentence as saying
        otherwise.
        """
        return stages_reached(event.layer)

    def verify_chain(self) -> ChainReport:
        """Recompute every digest from `GENESIS` and report the first failure.

        The walk covers live records *and* tombstones, in ordinal order, and
        there is no branch in it for a record that was skipped: a purged record's
        digest is the digest of the blanked record, so it is recomputed by the
        same rule as everything else. Nothing stored here is exempt from being
        checked, which is what makes a purge authenticated rather than asserted.
        """
        with self._engine.begin() as conn:
            entries = self._ordered(conn)
            head, count, mac = self._head(conn)

        if head is None:
            # No anchor at all. An empty database is the only honest reason for
            # that; anything else means the anchor was deleted, and verification
            # fails closed rather than treating "no anchor" as "no records".
            if entries:
                return ChainReport(ok=False, broken_at_index=0, checked=0)
            return ChainReport(ok=True, broken_at_index=None, checked=0)

        if not secrets_equal(mac, anchor_mac(head, count, self._key)):
            # The anchor has been moved. Repointing it is exactly what a writer
            # would do after deleting the tail, and without this it would work.
            return ChainReport(ok=False, broken_at_index=len(entries),
                               checked=len(entries))

        previous = GENESIS
        for index, entry in enumerate(entries):
            if entry.previous_hash != previous:
                return ChainReport(ok=False, broken_at_index=index,
                                   checked=len(entries))
            if chain_hash(entry.record, previous, self._key) != entry.chain_hash:
                return ChainReport(ok=False, broken_at_index=index,
                                   checked=len(entries))
            previous = entry.chain_hash

        if previous != head or len(entries) != count:
            return ChainReport(ok=False, broken_at_index=len(entries),
                               checked=len(entries))
        return ChainReport(ok=True, broken_at_index=None, checked=len(entries))

    @contextmanager
    def connection(self) -> Iterator[Connection]:
        """A committed connection to the same database.

        The hook the tamper tests use to reach past `append` and do the one
        thing an append-only log must not permit, which is the whole point: a
        record's history can be rewritten if someone has the database, and
        verification has to notice.
        """
        with self._engine.begin() as conn:
            yield conn

    # -- Retention ----------------------------------------------------------

    def purge_expired(self, now: datetime, retention_days: int) -> int:
        """Purge every record older than the retention window; return the count.

        A purge is a re-chain, not an edit and not an exemption. Each expired
        record is deleted from `audit_event` and replaced by a tombstone whose
        digest is the keyed digest of the *blanked* record, every record after
        it is re-chained onto that digest, and the anchor is re-MACed — all in
        one transaction. A keyless writer can delete a record outright and
        verification will report the gap; a keyless writer cannot *authorise*
        the deletion, because there is no flag to set and no digest they can
        produce.

        A purged record's content is gone: the chain can no longer say *what* it
        said, only that a record stood there, and this method does not claim
        otherwise.

        A non-positive window is refused rather than honoured — "keep nothing"
        is a configuration mistake, and one that looks like it worked.
        """
        if retention_days <= 0:
            raise ValueError(
                f"retention_days must be positive, got {retention_days!r}: a "
                f"non-positive window would purge the whole log, including the "
                f"chain anchors"
            )
        instant = _as_utc(now)
        cutoff = instant - timedelta(days=retention_days)
        with _APPEND_LOCK, self._engine.begin() as conn:
            rows = conn.execute(
                select(EVENT_TABLE.c.ordinal, EVENT_TABLE.c.timestamp)
            ).mappings().all()
            stale = sorted(
                row["ordinal"] for row in rows
                if _as_utc(datetime.fromisoformat(row["timestamp"])) < cutoff
            )
            if not stale:
                return 0
            first = stale[0]
            # The digest the tombstone at `first` has to chain onto — the one
            # immediately before the oldest expired record.
            chain_before = self._chain_hash_before(conn, first)
            for ordinal in stale:
                conn.execute(delete(EVENT_TABLE).where(
                    EVENT_TABLE.c.ordinal == ordinal))
                # The two chain fields are placeholders for the length of one
                # transaction: `_rechain_suffix` re-derives every position from
                # `chain_before` onwards, tombstones included, and the expired
                # ordinals need not be contiguous for it to do so.
                conn.execute(insert(TOMBSTONE_TABLE).values(
                    ordinal=ordinal,
                    previous_hash=chain_before,
                    chain_hash=chain_before,
                    purged_at=iso_utc(instant),
                    retention_cutoff=iso_utc(cutoff),
                ))
            head = self._rechain_suffix(conn, first, chain_before)
            _, count, _ = self._head(conn)
            self._write_head(conn, head, count)
        return len(stale)

    # -- Lifecycle ----------------------------------------------------------

    def close(self) -> None:
        self._engine.dispose()

    # -- Internals ----------------------------------------------------------

    def _head(self, conn: Connection) -> tuple[str | None, int, str | None]:
        """The stored anchor, or `(None, 0, None)` when there is no anchor row."""
        row = conn.execute(
            select(HEAD_TABLE.c.head_hash, HEAD_TABLE.c.row_count, HEAD_TABLE.c.mac)
            .where(HEAD_TABLE.c.id == _HEAD_ID)
        ).mappings().one_or_none()
        if row is None:
            return None, 0, None
        return row["head_hash"], row["row_count"], row["mac"]

    def _locked_head(self, conn: Connection) -> tuple[str, int, str | None]:
        """The anchor for writing, with the row lock a cross-process append needs.

        `FOR UPDATE` is a no-op on SQLite, which is why the process lock around
        each append exists as well: on SQLite this call is the whole of the
        cross-thread protection, and on PostgreSQL it is the whole of the
        cross-process protection.
        """
        statement = select(
            HEAD_TABLE.c.head_hash, HEAD_TABLE.c.row_count, HEAD_TABLE.c.mac
        ).where(HEAD_TABLE.c.id == _HEAD_ID)
        if conn.dialect.name != "sqlite":
            statement = statement.with_for_update()
        row = conn.execute(statement).mappings().one_or_none()
        if row is None:
            return GENESIS, 0, None
        return row["head_hash"], row["row_count"], row["mac"]

    def _write_head(self, conn: Connection, head_hash: str, row_count: int) -> None:
        """Move the anchor onto the given head, MACed, in the caller's transaction."""
        values = dict(head_hash=head_hash, row_count=row_count,
                      mac=anchor_mac(head_hash, row_count, self._key))
        updated = conn.execute(
            update(HEAD_TABLE).where(HEAD_TABLE.c.id == _HEAD_ID).values(**values)
        )
        if not updated.rowcount:
            conn.execute(insert(HEAD_TABLE).values(id=_HEAD_ID, **values))

    def _ordered(self, conn: Connection) -> list[Entry]:
        """Every record position in the chain, live or tombstoned, in order.

        A position present in neither table has been deleted outright; the
        linkage check finds it, because the next record still chains to the
        digest that was removed with it.
        """
        entries: list[Entry] = []
        for row in conn.execute(select(*EVENT_TABLE.c)).mappings().all():
            entries.append(Entry(row["ordinal"], row["previous_hash"],
                                 row["chain_hash"], _record_of(row), False))
        for row in conn.execute(select(*TOMBSTONE_TABLE.c)).mappings().all():
            entries.append(Entry(row["ordinal"], row["previous_hash"],
                                 row["chain_hash"], dict(BLANKED_RECORD), True))
        entries.sort(key=lambda entry: entry.ordinal)
        return entries

    def _chain_hash_before(self, conn: Connection, ordinal: int) -> str:
        """The digest of the record immediately before `ordinal`."""
        earlier = [e for e in self._ordered(conn) if e.ordinal < ordinal]
        if not earlier:
            return GENESIS
        return earlier[-1].chain_hash

    def _rechain_suffix(self, conn: Connection, first: int, previous: str) -> str:
        """Re-derive the chain from `first` onwards, in place.

        Every record after the purge — live or tombstoned — is re-hashed onto
        its new predecessor, so the chain has no seam where the purge happened.
        Returns the resulting head digest.
        """
        for entry in self._ordered(conn):
            if entry.ordinal < first:
                continue
            digest = chain_hash(entry.record, previous, self._key)
            table = TOMBSTONE_TABLE if entry.tombstoned else EVENT_TABLE
            conn.execute(
                update(table).where(table.c.ordinal == entry.ordinal)
                .values(previous_hash=previous, chain_hash=digest)
            )
            previous = digest
        return previous


def secrets_equal(left: str | None, right: str | None) -> bool:
    """Constant-time-ish equality, so comparing a MAC leaks nothing by timing."""
    if left is None or right is None:
        return left is right
    return secrets.compare_digest(left, right)
