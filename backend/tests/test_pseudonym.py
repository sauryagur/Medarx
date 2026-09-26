"""Tests for component C: stable surrogates and the per-patient date shift.

These assert the component's two invariants — the same original maps to the
same surrogate within scope, and the shift preserves sequence and duration —
plus the fail-closed behaviour on an empty audit key.
"""

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import date

import pytest
from conftest import KEY  # noqa: F401  (the shared `store` fixture comes from conftest)
from sqlalchemy import select

from medarx.errors import MedarxError
from medarx.pseudonym.date_shift import patient_offset, shift_date
from medarx.pseudonym.errors import AuditKeyRequired
from medarx.pseudonym.mapping_store import PATIENT_TABLE, MappingStore


def test_same_original_maps_to_the_same_surrogate(store):
    a = store.surrogate_for_study("STU-0001")
    assert a == store.surrogate_for_study("STU-0001")
    assert a.startswith("medarx-study-")


def test_different_originals_do_not_collide(store):
    assert store.surrogate_for_study("STU-0001") != store.surrogate_for_study("STU-0002")


def test_offset_is_stable_and_bounded():
    o = patient_offset("PAT-0001", KEY)
    assert o == patient_offset("PAT-0001", KEY)
    assert -365 <= o <= 365


def test_offset_depends_on_both_the_patient_and_the_key():
    assert patient_offset("PAT-0001", KEY) != patient_offset("PAT-0002", KEY)
    assert patient_offset("PAT-0001", KEY) != patient_offset("PAT-0001", "another-key")


def test_surrogate_shape_is_eight_hex_characters(store):
    surrogates = (store.surrogate_for_study("STU-0001"), store.surrogate_for_patient("PAT-0001"))
    for surrogate in surrogates:
        _, _, digest = surrogate.rpartition("-")
        assert len(digest) == 8
        int(digest, 16)  # raises unless it is hex


def test_study_and_patient_namespaces_are_separate(store):
    # The same literal reference in the two tables must not produce the same
    # surrogate: the domains are separated, so neither maps into the other.
    assert store.surrogate_for_patient("REF-1").startswith("medarx-patient-")
    assert store.surrogate_for_study("REF-1") != store.surrogate_for_patient("REF-1")


def test_shift_preserves_order_and_duration_across_ten_years():
    ds = [date(2015, 3, 1), date(2016, 6, 1), date(2026, 1, 1)]
    off = patient_offset("PAT-0001", KEY)
    s = [shift_date(d, off) for d in ds]
    assert s[0] < s[1] < s[2]
    assert (s[1] - s[0]).days == (ds[1] - ds[0]).days
    assert (s[2] - s[1]).days == (ds[2] - ds[1]).days


def test_leap_day_shift_preserves_order_and_duration():
    ds = [date(2024, 2, 29), date(2024, 9, 1), date(2025, 3, 1)]
    off = patient_offset("PAT-0002", KEY)
    s = [shift_date(d, off) for d in ds]
    assert s[0] < s[1] < s[2]
    assert (s[1] - s[0]).days == (ds[1] - ds[0]).days


@pytest.mark.parametrize("offset", [-365, -1, 0, 1, 365])
def test_shift_is_exactly_the_offset_in_days(offset):
    d = date(2024, 7, 15)
    assert (shift_date(d, offset) - d).days == offset


def test_shift_crosses_month_and_year_boundaries():
    assert shift_date(date(2024, 1, 31), 1) == date(2024, 2, 1)
    assert shift_date(date(2024, 12, 31), 1) == date(2025, 1, 1)
    assert shift_date(date(2025, 1, 1), -1) == date(2024, 12, 31)


def test_shift_never_raises_on_invalid_calendar_results():
    for d in (date(2024, 2, 29), date(2100, 1, 1), date(1970, 1, 1)):
        assert isinstance(shift_date(d, 365), date)


def test_shift_saturates_at_the_calendar_boundaries():
    # date.max and date.min cannot absorb a year's shift; the component
    # saturates rather than raising.
    assert shift_date(date.max, 365) == date.max
    assert shift_date(date.min, -365) == date.min


def test_zero_offset_is_the_identity():
    d = date(2024, 2, 29)
    assert shift_date(d, 0) == d


def test_surrogate_is_stable_across_store_reopen(tmp_path):
    url = f"sqlite:///{tmp_path / 'map.db'}"
    first = MappingStore(url, KEY).surrogate_for_study("STU-0001")
    second = MappingStore(url, KEY).surrogate_for_study("STU-0001")
    assert first == second


def test_patient_offset_is_stable_and_persisted_across_store_reopen(tmp_path):
    url = f"sqlite:///{tmp_path / 'map.db'}"
    with _open(url) as first_store:
        first_store.surrogate_for_patient("PAT-0007")
        first = first_store.offset_for_patient("PAT-0007")
    with _open(url) as second_store:
        assert second_store.offset_for_patient("PAT-0007") == first
        with second_store.connect() as conn:
            persisted = conn.execute(
                select(PATIENT_TABLE.c.shift_offset).where(
                    PATIENT_TABLE.c.patient_ref == "PAT-0007"
                )
            ).scalar_one()
        # The offset stored beside the surrogate is the one served back.
        assert persisted == first


def test_concurrent_assignment_yields_one_surrogate(tmp_path):
    url = f"sqlite:///{tmp_path / 'map.db'}"
    results, errors = [], []
    stores = [MappingStore(url, KEY) for _ in range(4)]

    def assign(i):
        try:
            results.append(stores[i].surrogate_for_study("STU-RACE"))
        except Exception as exc:  # pragma: no cover - failure path
            errors.append(exc)

    ts = [threading.Thread(target=assign, args=(i,)) for i in range(4)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    for s in stores:
        s.close()
    assert errors == []
    assert len(set(results)) == 1


def test_empty_audit_key_is_refused_by_the_offset_derivation():
    with pytest.raises(AuditKeyRequired):
        patient_offset("PAT-0001", "")


def test_empty_audit_key_is_refused_by_the_mapping_store(tmp_path):
    path = tmp_path / "map.db"
    with pytest.raises(AuditKeyRequired):
        MappingStore(f"sqlite:///{path}", "")
    # Refused before a connection is opened, so no mapping store is created.
    assert not path.exists()


def test_audit_key_required_is_not_a_privacy_layer_error():
    # It must not be catchable as a MedarxError: there is no layer and no
    # action code that could reach a block receipt.
    assert not issubclass(AuditKeyRequired, MedarxError)


@contextmanager
def _open(url: str) -> Iterator[MappingStore]:
    store = MappingStore(url, KEY)
    try:
        yield store
    finally:
        store.close()
