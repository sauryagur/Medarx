"""The one schema-init command for the whole Phase 1 store.

Phase 1 has two stores — the audit log (G) and the pseudonym mapping store (C) —
and two places that create their own tables when they are missing. This command
is what a deployment runs, so there is one thing to run and one thing to point
at a database: it creates `audit_event`, `audit_tombstone`, `audit_chain_head`,
`pseudonym_study` and `pseudonym_patient`, in whichever database URL it is
given, and it is idempotent.

**What it is not.** It is not a migration. It creates what is missing and
leaves every existing table exactly as it is, so the versioned-DDL story for a
real database belongs to the compose task, not here. Schema ownership is
recorded rather than assumed: `AuditLog.__init__` and `MappingStore.__init__`
both create their own tables as a convenience for a single process, and this
command is the deployment path.

**No environment.** Only `medarx.config` may read `os.environ`, so the database
URL is an argument. There is no default: a command that silently picked one
would create tables in whatever database it happened to find.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from sqlalchemy import MetaData, create_engine
from sqlalchemy.engine import Engine

from medarx.audit.audit_log import AUDIT_METADATA
from medarx.pseudonym.mapping_store import METADATA as MAPPING_METADATA

__all__ = ["main", "store_metadata"]


def store_metadata() -> MetaData:
    """Every table Phase 1 persists, in one `MetaData`.

    The two stores each own their own `MetaData` — neither should have to
    import the other's tables to describe itself. Copying both into a fresh one
    here is what keeps that separation while still giving the deployment a
    single command that builds the whole schema.
    """
    combined = MetaData()
    for source in (AUDIT_METADATA, MAPPING_METADATA):
        for table in source.sorted_tables:
            table.to_metadata(combined)
    return combined


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="medarx.audit.schema_init",
        description=(
            "Create the Phase 1 Medarx store (audit log and pseudonym mapping "
            "tables) in the given database. Idempotent; not a migration."
        ),
    )
    parser.add_argument(
        "--db-url",
        required=True,
        help=(
            "SQLAlchemy database URL, e.g. postgresql+psycopg://medarx@host/"
            "medarx or sqlite:////var/lib/medarx/audit.db. Required: only "
            "medarx.config may read the environment, so there is no default to "
            "fall back on."
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Create the store. Returns a process exit status."""
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:  # argparse already reported the problem
        return 0 if exc.code is None else int(exc.code)

    engine: Engine = create_engine(args.db_url)
    try:
        store_metadata().create_all(engine)
    finally:
        engine.dispose()
    return 0


if __name__ == "__main__":  # pragma: no cover - the process entry point
    raise SystemExit(main())
