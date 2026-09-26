"""The pseudonym mapping store: the re-identification key, held apart.

**Pseudonymized data is not anonymized.** It stays re-identifiable to anyone
holding this store, which is why the store is a separate, access-controlled
database and why nothing on the model path may read it. Component C is the only
component that talks to it; the model gateway and every stage after C work on
surrogates alone.

The store exists to make assignment *sticky* and *auditable*, not to compute
anything: a surrogate is a pure keyed derivation, so a row can always be
recomputed, and a missing row can be filled in without changing what any
existing caller sees. What the rows add is the primary key on the original
reference, which is what makes two distinct originals unable to share a
surrogate even if their 8-hex truncations ever collided.
"""

import time
from contextlib import contextmanager

from sqlalchemy import (
    Column,
    DateTime,
    Integer,
    MetaData,
    String,
    Table,
    create_engine,
    func,
    select,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.pool import NullPool

from medarx.pseudonym.date_shift import patient_offset
from medarx.pseudonym.derivation import require_audit_key, surrogate

__all__ = ["PATIENT_TABLE", "STUDY_TABLE", "MappingStore"]


METADATA = MetaData()

#: One row per study reference ever pseudonymized. `surrogate` is unique, so a
#: surrogate is never handed to two different originals.
STUDY_TABLE = Table(
    "pseudonym_study",
    METADATA,
    Column("study_ref", String, primary_key=True),
    Column("surrogate", String, nullable=False, unique=True),
    Column("created_at", DateTime, nullable=False, server_default=func.now()),
)

#: One row per patient: the surrogate, and the date shift applied to that
#: patient's dates, recorded so the shift in force at a point in time can be
#: explained later without recomputing against a changed derivation.
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

#: Attempts when a concurrent writer holds the row. The unique constraint, not
#: the surrogate derivation, is what makes the loser converge on the winner's
#: value; the retry only gives that winner time to commit.
_ASSIGN_ATTEMPTS = 5
_RETRY_DELAY_S = 0.02


class MappingStore:
    """Stable surrogate assignment over a database URL.

    The store is safe to use from several threads: every operation opens its own
    connection (`NullPool`), so no connection is shared across threads, and a
    racing insert is resolved by re-reading the committed row.
    """

    def __init__(self, db_url: str, audit_key: str) -> None:
        # Refused before any connection is opened: a store built on an empty
        # key would issue unkeyed, invertible surrogates.
        require_audit_key(audit_key)
        self._audit_key = audit_key
        self._engine = create_engine(
            db_url,
            poolclass=NullPool,
            connect_args={"timeout": 30} if db_url.startswith("sqlite") else {},
        )
        METADATA.create_all(self._engine)

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

    @contextmanager
    def connect(self):
        """A read-only connection, for inspecting the mapping rows."""
        with self._engine.connect() as conn:
            yield conn

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
                # race) or a surrogate is already bound to another reference.
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
