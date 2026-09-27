"""Fixtures for the evaluation harness's own tests.

Separate from `backend/tests/conftest.py` on purpose. The backend suite must be
runnable without the evaluation package, and the evaluation tests need their
own `store` and `settings` so a change to the kernel's shared fixtures cannot
silently move a figure in this harness's report.
"""

from __future__ import annotations

import pytest

from medarx.config import Settings
from medarx.pseudonym.mapping_store import MappingStore

#: A synthetic, non-secret audit key. Never a real credential, and fixed so
#: every date shift and surrogate the harness reports is reproducible by
#: anyone who runs it.
KEY = "medarx-eval-instrument-not-a-credential"  # noqa: S105


@pytest.fixture
def settings() -> Settings:
    return Settings(audit_key=KEY)


@pytest.fixture
def store(tmp_path) -> MappingStore:
    """A throwaway mapping store, so every run derives the same offset from
    the same key rather than from whatever a previous run left behind."""
    store = MappingStore(f"sqlite:///{tmp_path / 'eval-map.db'}", KEY)
    try:
        yield store
    finally:
        store.close()
