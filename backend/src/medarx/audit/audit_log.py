"""Component G: the audit log — what is stored, and how it is chained.

**The log is not a second PHI store.** The field set is closed and
hand-written: request id and timestamp, function and selected model, policy
version and mode, the input and approved-payload *hashes*, the redacted field
*names*, the action codes, the human approval and the final disposition. There
is no field that can hold a value, and `append` refuses a record carrying one
rather than storing it or dropping it quietly. The full model prompt and
response do not belong here at all — they belong in a restricted, encrypted
diagnostic store, which this component does not implement and does not pretend
to.

`append` is the only write path. It computes the chain hash inside the same
transaction that inserts the row, so a concurrent append cannot read a stale
head and fork the chain.

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
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from sqlalchemy import (
    Boolean,
    Column,
    Integer,
    MetaData,
    String,
    Table,
    create_engine,
    select,
)
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.pool import NullPool, StaticPool

from medarx.audit.hash_chain import (
    GENESIS,
    ChainReport,
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
    "AuditLog",
]


#: The storage policy, written out rather than derived from the event model.
#:
#: It could be `frozenset(AuditEvent.model_fields)`, and that is exactly why it
#: is not: a mirror of the model makes the storage policy a *consequence* of
#: whatever the model happens to carry, and the model is the thing most likely
#: to grow a convenience field. Written out, it is a decision. Adding a field to
#: `AuditEvent` makes `append` refuse the record until someone states here
#: whether that field may be persisted, which is the question that has to be
#: answered before a value reaches disk.
#:
#: Every name here is either an identifier, a hash, a *category*, or a
#: classifier. No field can hold report text, a DICOM attribute value, a prompt,
#: or a response.
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
        "chain_hash",
        "previous_hash",
    }
)


AUDIT_METADATA = MetaData()


#: One row per append, in append order.
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
#: The record columns are nullable *only* because a retention purge blanks them
#: and keeps the chain position; `append` always supplies every one of them.
#: The two chain columns and the ordinal are NOT nullable, because those are
#: the position, and a position cannot be blanked without losing the evidence
#: that something was removed from it.
EVENT_TABLE = Table(
    "audit_event",
    AUDIT_METADATA,
    Column("ordinal", Integer, primary_key=True, autoincrement=True),
    Column("request_id", String, index=True),
    Column("timestamp", String),
    Column("function", String),
    Column("selected_model", String),
    Column("policy_version", String),
    Column("policy_mode", String),
    Column("input_hash", String),
    Column("approved_payload_hash", String),
    Column("redacted_field_names", String),
    Column("action_codes", String),
    Column("human_approval", String),
    Column("final_disposition", String),
    Column("chain_hash", String, nullable=False),
    Column("previous_hash", String, nullable=False),
    Column("purged", Boolean, nullable=False, default=False),
)


#: The head of the chain, as a single row.
#:
#: Without it, deleting the *last* record leaves a chain that still verifies:
#: what remains is internally consistent, and a chain cannot tell "this is
#: everything that happened" from "this is everything someone kept". The anchor
#: carries the last digest and the row count, and it is written in the same
#: transaction as the append, so a chain that is short is a chain whose head
#: disagrees with the log.
#:
#: The anchor is tamper-evident, not tamper-proof: an attacker who holds the
#: audit key can update it to match rewritten rows, exactly as they can
# recompute the digests. See `medarx.audit.hash_chain` for what the key does
#: and does not buy.
HEAD_TABLE = Table(
    "audit_chain_head",
    AUDIT_METADATA,
    Column("id", Integer, primary_key=True),
    Column("head_hash", String, nullable=False),
    Column("row_count", Integer, nullable=False),
)

#: The single anchor row's identifier. One row, always this one.
_HEAD_ID = 1

#: Columns holding canonical JSON text rather than a scalar.
_JSON_COLUMNS = ("redacted_field_names", "action_codes", "human_approval")

#: Every column the event's own fields are stored in.
_RECORD_COLUMNS = tuple(sorted(ALLOWED_AUDIT_FIELDS))

#: `chain_hash` is the output, not an input; `previous_hash` is both.
_HASHED_FIELDS = tuple(f for f in _RECORD_COLUMNS if f != "chain_hash")

#: What a retention purge blanks. The two chain columns are excluded: they are
#: the record's position, and keeping them is what lets a later deletion or a
#: truncation still be seen.
_PURGED_COLUMNS = tuple(f for f in _RECORD_COLUMNS
                        if f not in ("chain_hash", "previous_hash"))

_MEMORY_POOL_ARGS = {"poolclass": StaticPool, "connect_args": {"timeout": 30}}
_FILE_POOL_ARGS = {"poolclass": NullPool, "connect_args": {"timeout": 30}}
_IN_MEMORY_DATABASES = (None, "", ":memory:")
_MEMORY_DRIVER = "sqlite+memory"


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
    if backend.split("+")[0] == "sqlite" and database in _IN_MEMORY_DATABASES:
        return db_url, dict(_MEMORY_POOL_ARGS)
    if backend.split("+")[0] == "sqlite":
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


def _from_column(name: str, value: Any) -> Any:
    """The event form of one stored column."""
    if name in _JSON_COLUMNS and value is not None:
        return json.loads(value)
    return value


def _record_of(row: Mapping[str, Any]) -> dict[str, Any]:
    """The hashed record for a stored row: every field but the digest itself."""
    return {name: _from_column(name, row[name]) for name in _HASHED_FIELDS}


class AuditLog:
    """An append-only, tamper-evident log over a database URL.

    Safe to use from several threads: on SQLite every operation checks out its
    own connection, so none is shared, and the chain head is read and updated
    inside the append's own transaction rather than across two.
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
        """
        self._refuse_off_policy(event)
        # `model_dump` rather than `getattr`, so a nested sign-off arrives as
        # the plain structure the canonical encoding is defined over, and so
        # the record that is hashed is the record that is stored.
        dumped = event.model_dump()
        body = {name: dumped[name] for name in _HASHED_FIELDS}
        with self._engine.begin() as conn:
            head, count = self._head(conn)
            digest = chain_hash(body, head, self._key)
            values = {name: _to_column(name, body[name]) for name in _HASHED_FIELDS}
            values["chain_hash"] = digest
            values["previous_hash"] = head
            values["purged"] = False
            conn.execute(EVENT_TABLE.insert().values(**values))
            self._advance_head(conn, digest, count + 1)
        return event.model_copy(update={"previous_hash": head, "chain_hash": digest})

    def _refuse_off_policy(self, event: AuditEvent) -> None:
        """Refuse a record carrying a field the storage policy does not allow.

        The second gate, after `AuditEvent`'s own `extra="forbid"`. That one
        blocks the obvious path; this one blocks the path that gets past it — a
        wider subclass, or a future version of the model — and it checks the
        *declared* fields as well as the ones this instance carries, so a field
        that would be persisted is refused before it can be.
        """
        carried = set(event.model_dump()) | set(type(event).model_fields)
        off_policy = sorted(carried - ALLOWED_AUDIT_FIELDS)
        if off_policy:
            raise ValueError(
                f"audit record carries fields outside the storage policy: "
                f"{off_policy}. The audit log is not a place for values; if a "
                f"payload belongs somewhere, it belongs in the restricted "
                f"diagnostic store, not here."
            )

    # -- Reading ------------------------------------------------------------

    def get(self, request_id: str) -> list[AuditEvent]:
        """Every stored event for `request_id`, in append order.

        Purged rows are gone by then: a retention purge blanks their content, so
        there is nothing left to reconstruct one from.
        """
        with self._engine.begin() as conn:
            rows = conn.execute(
                select(*EVENT_TABLE.c)
                .where(
                    EVENT_TABLE.c.request_id == request_id,
                    EVENT_TABLE.c.purged.is_(False),
                )
                .order_by(EVENT_TABLE.c.ordinal)
            ).mappings().all()
        return [_event_of(row) for row in rows]

    def verify_chain(self) -> ChainReport:
        """Recompute every digest from `GENESIS` and report the first failure.

        Nothing here is asserted rather than checked: the digests are recomputed
        from the stored content, so a record that was rewritten, or two records
        that were given each other's content, or a record that was deleted from
        the middle, all fail at a specific index. A chain whose rows all verify
        but which ends before the anchor says so has been truncated at the
        tail, which no chain can see without one.
        """
        with self._engine.begin() as conn:
            rows = conn.execute(
                select(*EVENT_TABLE.c).order_by(EVENT_TABLE.c.ordinal)
            ).mappings().all()
            head, count = self._head(conn)

        previous = GENESIS
        for index, row in enumerate(rows):
            if row["previous_hash"] != previous:
                return ChainReport(ok=False, broken_at_index=index, checked=len(rows))
            if not row["purged"]:
                # A purged record's content is gone, so its digest cannot be
                # recomputed — only its position and its link can be checked.
                if chain_hash(_record_of(row), row["previous_hash"], self._key) \
                        != row["chain_hash"]:
                    return ChainReport(ok=False, broken_at_index=index,
                                       checked=len(rows))
            previous = row["chain_hash"]

        if previous != head or len(rows) != count:
            return ChainReport(ok=False, broken_at_index=len(rows), checked=len(rows))
        return ChainReport(ok=True, broken_at_index=None, checked=len(rows))

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
        """Blank every record older than the retention window; return the count.

        A purged record keeps its ordinal, its previous hash and its own digest,
        so the positions after it stay linked and a later deletion is still
        visible. Its content is gone: the chain can no longer say *what* the
        record said, only that a record stood there, and this method does not
        claim otherwise.

        A non-positive window is refused rather than honoured — "keep nothing"
        is a configuration mistake, and one that looks like it worked.
        """
        if retention_days <= 0:
            raise ValueError(
                f"retention_days must be positive, got {retention_days!r}: a "
                f"non-positive window would purge the whole log, including the "
                f"chain anchors"
            )
        cutoff = _as_utc(now) - timedelta(days=retention_days)
        with self._engine.begin() as conn:
            rows = conn.execute(
                select(EVENT_TABLE.c.ordinal, EVENT_TABLE.c.timestamp)
                .where(EVENT_TABLE.c.purged.is_(False))
            ).all()
            stale = [row.ordinal for row in rows
                     if _as_utc(datetime.fromisoformat(row.timestamp)) < cutoff]
            for ordinal in stale:
                conn.execute(
                    EVENT_TABLE.update()
                    .where(EVENT_TABLE.c.ordinal == ordinal)
                    .values(purged=True,
                            **{name: None for name in _PURGED_COLUMNS})
                )
        return len(stale)

    # -- Lifecycle ----------------------------------------------------------

    def close(self) -> None:
        self._engine.dispose()

    # -- Internals ----------------------------------------------------------

    def _head(self, conn: Connection) -> tuple[str, int]:
        """The current head digest and row count, or genesis and zero."""
        row = conn.execute(
            select(HEAD_TABLE.c.head_hash, HEAD_TABLE.c.row_count)
            .where(HEAD_TABLE.c.id == _HEAD_ID)
        ).one_or_none()
        if row is None:
            return GENESIS, 0
        return row.head_hash, row.row_count

    def _advance_head(self, conn: Connection, digest: str, count: int) -> None:
        """Move the anchor onto the row just written, in the caller's transaction."""
        updated = conn.execute(
            HEAD_TABLE.update()
            .where(HEAD_TABLE.c.id == _HEAD_ID)
            .values(head_hash=digest, row_count=count)
        )
        if not updated.rowcount:
            conn.execute(
                HEAD_TABLE.insert().values(id=_HEAD_ID, head_hash=digest, row_count=count)
            )


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
