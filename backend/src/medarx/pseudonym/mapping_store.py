"""The pseudonym mapping store: the re-identification key, held apart.

**Pseudonymized data is not anonymized.** It stays re-identifiable to anyone
holding this store, which is why the store is a separate, access-controlled
database and why nothing on the model path may read it. Component C is the only
component that talks to it; the model gateway and every stage after C work on
surrogates alone. The store therefore exposes no connection, no query, and no
generic accessor: it hands out surrogates and nothing else.

The store exists to make assignment *sticky* and *auditable*, not to compute
anything: a surrogate is a pure keyed derivation, so a row can always be
recomputed, and a missing row can be filled in without changing what any
existing caller sees. What the rows add is the pair of constraints below.
"""

import time

from sqlalchemy import (
    Column,
    DateTime,
    Integer,
    MetaData,
    String,
    Table,
    create_engine,
    func,
    make_url,
    select,
)
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError, ProgrammingError
from sqlalchemy.pool import NullPool, StaticPool

from medarx.pseudonym.date_shift import patient_offset
from medarx.pseudonym.derivation import require_audit_key, surrogate

__all__ = ["PATIENT_TABLE", "STUDY_TABLE", "MappingStore"]


METADATA = MetaData()

#: One row per study reference ever pseudonymized.
#:
#: The two constraints guard two different properties, and the difference is
#: load-bearing: the PRIMARY KEY gives one row per original (the same original
#: is never assigned twice), while UNIQUE on `surrogate` is what stops two
#: *different* originals from ending up with the same surrogate. Only the
#: second one is the collision guarantee — a primary key on `study_ref` says
#: nothing about the surrogate column. Dropping `unique=True` here would let a
#: 8-hex truncation collision (likely past ~65k references in one scope) hand
#: one live surrogate to a second original, so
#: `tests/test_pseudonym.py::test_a_surrogate_collision_is_refused` pins it.
STUDY_TABLE = Table(
    "pseudonym_study",
    METADATA,
    Column("study_ref", String, primary_key=True),
    Column("surrogate", String, nullable=False, unique=True),
    Column("created_at", DateTime, nullable=False, server_default=func.now()),
)

#: One row per patient: the surrogate, and the date shift applied to that
#: patient's dates, recorded so the shift in force at a point in time can be
#: explained later without recomputing against a changed derivation. Same two
#: constraints, same reasons, as `STUDY_TABLE`.
PATIENT_TABLE = Table(
    "pseudonym_patient",
    METADATA,
    Column("patient_ref", String, primary_key=True),
    Column("surrogate", String, nullable=False, unique=True),
    Column("shift_offset", Integer, nullable=False),
    Column("created_at", DateTime, nullable=False, server_default=func.now()),
)

_STUDY_DOMAIN = "medarx-study"
_PATIENT_DOMAIN = "medarx-patient"

#: Pool per dialect. SQLite's driver connection is not safe to share between
#: threads, so file-backed SQLite uses `NullPool`: every operation checks out
#: its own connection and none is ever shared. PostgreSQL is left on the
#: driver's default pool — it *is* thread-safe, and surrogate assignment is per
#: study, so discarding its pool would cost a TCP connect and a full
#: authentication on every assignment. In-memory SQLite must keep one
#: connection for its whole life, since each new connection would be a
#: different, empty database.
_POOL_ARGS = {
    "sqlite": {"poolclass": NullPool, "connect_args": {"timeout": 30}},
    "sqlite+memory": {"poolclass": StaticPool, "connect_args": {"timeout": 30}},
}

#: Attempts when a concurrent writer holds the row. The unique constraint, not
#: the surrogate derivation, is what makes the loser converge on the winner's
#: value; the retry only gives that winner time to commit.
_ASSIGN_ATTEMPTS = 5
_RETRY_DELAY_S = 0.02


def _pool_args(db_url: str) -> dict:
    """Connection arguments for `db_url`.

    A SQLite URL gets the SQLite-appropriate pool: `NullPool` for a file, and
    a single pinned connection for `:memory:`, where every new connection
    would otherwise be a different, empty database. Any other backend is left
    entirely on its driver's defaults.
    """
    url = make_url(db_url)
    if url.get_backend_name() == "sqlite":
        if (url.database or "") in (None, "", ":memory:"):
            return dict(_POOL_ARGS["sqlite+memory"])
        return dict(_POOL_ARGS["sqlite"])
    return {}


def _create_tables(engine: Engine) -> None:
    """Create the mapping tables if they are absent.

    `create_all` checks for existence and then emits a bare `CREATE TABLE`, so
    two workers starting together can both see the table missing and one of them
    can fail on "already exists". That is a real startup race on PostgreSQL and
    an invisible one under SQLite, so the race is absorbed here: only *this*
    error is swallowed, and any other failure still propagates. This is a
    convenience for a single process, not a schema migration — a deployment that
    wants versioned DDL should run it as one.
    """
    try:
        METADATA.create_all(engine)
    except ProgrammingError as exc:
        message = str(exc).lower()
        if "already exists" not in message:
            raise
        # Another creator won; the tables this process needs are present.


class MappingStore:
    """Stable surrogate assignment over a database URL.

    The store is safe to use from several threads: on SQLite every operation
    checks out its own connection, so none is shared, and a racing insert is
    resolved by re-reading the committed row. On PostgreSQL, where a conflicting
    insert blocks until the winner commits, the same re-read is guaranteed to
    see the winning row.
    """

    def __init__(self, db_url: str, audit_key: str) -> None:
        # Refused before any connection is opened: a store built on an empty
        # key would issue unkeyed, invertible surrogates.
        require_audit_key(audit_key)
        self._audit_key = audit_key
        self._engine = create_engine(db_url, **_pool_args(db_url))
        _create_tables(self._engine)

    # -- Surrogates --------------------------------------------------------

    def surrogate_for_study(self, study_ref: str) -> str:
        """The stable surrogate for `study_ref`; idempotent.

        Refuses an empty reference: there is no stable surrogate for "nothing",
        and inventing one would let unlabelled studies share an identity.
        """
        if not study_ref:
            raise ValueError("a study reference is required to assign a surrogate")
        return self._assign(
            table=STUDY_TABLE,
            key="study_ref",
            ref=study_ref,
            value=surrogate(self._audit_key, _STUDY_DOMAIN, study_ref),
        )

    def surrogate_for_patient(self, patient_ref: str) -> str:
        """The stable surrogate for `patient_ref`; idempotent."""
        if not patient_ref:
            raise ValueError("a patient reference is required to assign a surrogate")
        return self._assign(
            table=PATIENT_TABLE,
            key="patient_ref",
            ref=patient_ref,
            value=surrogate(self._audit_key, _PATIENT_DOMAIN, patient_ref),
            extra={"shift_offset": patient_offset(patient_ref, self._audit_key)},
        )

    def offset_for_patient(self, patient_ref: str) -> int:
        """The day offset applied to `patient_ref`'s dates, in `[-365, 365]`."""
        return patient_offset(patient_ref, self._audit_key)

    # -- Lifecycle ---------------------------------------------------------

    def close(self) -> None:
        """Release the engine's connections. The rows persist."""
        self._engine.dispose()

    # -- Assignment --------------------------------------------------------

    def _assign(self, table: Table, key: str, ref: str, value: str, extra: dict | None = None) -> str:
        """Insert `ref -> value` if absent, else return the committed value."""
        row = {key: ref, "surrogate": value, **(extra or {})}
        for attempt in range(_ASSIGN_ATTEMPTS):
            try:
                with self._engine.begin() as conn:
                    conn.execute(table.insert().values(**row))
                return value
            except IntegrityError:
                # Either this reference already has a row (someone else won the
                # race, on either the primary key or the unique surrogate) or a
                # surrogate is already bound to a *different* reference. The
                # latter is a real collision: `existing` stays None, the insert
                # keeps failing, and the error propagates rather than silently
                # re-binding a live surrogate to a second original.
                existing = self._read(table, key, ref)
                if existing is not None:
                    return existing
                if attempt + 1 == _ASSIGN_ATTEMPTS:
                    raise
                time.sleep(_RETRY_DELAY_S)
        raise AssertionError("unreachable")  # pragma: no cover

    def _read(self, table: Table, key: str, ref: str) -> str | None:
        with self._engine.connect() as conn:
            return conn.execute(
                select(table.c.surrogate).where(table.c[key] == ref)
            ).scalar_one_or_none()
