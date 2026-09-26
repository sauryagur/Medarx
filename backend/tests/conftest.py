"""Shared fixtures for the backend suite.

The audit key and the `settings` / `store` fixtures live here, in one place, so
that a second definition elsewhere cannot shadow them. Test modules import
`KEY` from here and take `store` as a fixture argument.
"""

import pytest

from medarx.config import Settings
from medarx.pseudonym.mapping_store import MappingStore

#: A synthetic, non-secret audit key. Test-only; never a real credential.
KEY = "test-audit-key"


@pytest.fixture
def settings() -> Settings:
    """Settings built explicitly, so no test depends on the process environment."""
    return Settings(audit_key=KEY)


@pytest.fixture
def store(tmp_path) -> MappingStore:
    """A `MappingStore` over a throwaway SQLite file, closed on teardown."""
    s = MappingStore(f"sqlite:///{tmp_path / 'map.db'}", KEY)
    try:
        yield s
    finally:
        s.close()
