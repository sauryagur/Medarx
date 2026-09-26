"""Tests for component C: stable surrogates and the per-patient date shift.

These assert the component's two invariants — the same original maps to the
same surrogate within scope, and the shift preserves sequence and duration —
plus the fail-closed behaviour on an empty audit key.
"""

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import date, timedelta
from pathlib import Path

import pytest
from conftest import KEY  # noqa: F401  (the shared `store` fixture comes from conftest)
from sqlalchemy import create_engine, insert, select
from sqlalchemy.exc import IntegrityError

from medarx.errors import MedarxError, PseudonymError
from medarx.models import BlockReceipt, StructuredPayload
from medarx.pseudonym.date_shift import patient_offset, shift_date
from medarx.pseudonym.derivation import audit_digest, surrogate
from medarx.pseudonym.errors import AuditKeyRequired
from medarx.pseudonym.mapping_store import (
    PATIENT_TABLE,
    STUDY_TABLE,
    MappingStore,
    _FILE_POOL_ARGS,
    _pool_args,
)
from medarx.pseudonym.pseudonymize import pseudonymize_payload

STUDY_DOMAIN = "medarx-study"
PATIENT_DOMAIN = "medarx-patient"


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


def test_domains_are_separated_in_the_signed_message():
    # Compared as digests, not as prefixed surrogates: the prefixes alone would
    # make any two surrogates differ, so comparing the strings could not tell
    # whether the domain is actually signed in.
    assert audit_digest(KEY, STUDY_DOMAIN, "REF-1") != audit_digest(KEY, PATIENT_DOMAIN, "REF-1")


def test_study_and_patient_surrogates_do_not_share_a_digest(store):
    study = store.surrogate_for_study("REF-1").removeprefix(STUDY_DOMAIN + "-")
    patient = store.surrogate_for_patient("REF-1").removeprefix(PATIENT_DOMAIN + "-")
    assert study != patient


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
        # Read straight from the database rather than through the store: the
        # mapping store deliberately exposes no connection or query, and the
        # offset persisted beside the surrogate is the one served back.
        with create_engine(url).connect() as conn:
            persisted = conn.execute(
                select(PATIENT_TABLE.c.shift_offset).where(
                    PATIENT_TABLE.c.patient_ref == "PAT-0007"
                )
            ).scalar_one()
        assert persisted == first


def test_a_surrogate_collision_is_refused(tmp_path):
    # A surrogate already bound to one original must never be handed to a
    # second. The UNIQUE constraint on `surrogate` is what refuses it: the
    # primary key on `study_ref` would not, because the colliding original is a
    # different row entirely. The collision is seeded directly rather than
    # brute-forced, by binding `STU-0001`'s would-be surrogate to another
    # reference first.
    url = f"sqlite:///{tmp_path / 'map.db'}"
    contested = surrogate(KEY, STUDY_DOMAIN, "STU-0001")
    engine = create_engine(url)
    MappingStore(url, KEY).close()  # create the schema
    with engine.begin() as conn:
        conn.execute(insert(STUDY_TABLE).values(study_ref="STU-COLLIDE", surrogate=contested))
    with _open(url) as colliding:
        with pytest.raises(IntegrityError):
            colliding.surrogate_for_study("STU-0001")

    # The contested surrogate is still bound to the reference it was issued to,
    # and the refused assignment left no row behind.
    with engine.connect() as conn:
        rows = conn.execute(select(STUDY_TABLE.c.study_ref, STUDY_TABLE.c.surrogate)).all()
    assert rows == [("STU-COLLIDE", contested)]


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


@pytest.mark.parametrize(
    "url",
    [
        "sqlite:///:memory:",
        # `sqlite+memory` is a spelling, not a dialect SQLAlchemy can load. The
        # store accepts it and normalises it, so the obvious way to ask for an
        # in-memory store is the working one rather than a silent pool mismatch.
        "sqlite+memory://",
    ],
)
def test_in_memory_urls_are_usable(url):
    # Every in-memory connection is a separate empty database, so such a store
    # must pin one connection; otherwise the schema created at construction
    # would be gone by the first assignment.
    with _open(url) as memory_store:
        a = memory_store.surrogate_for_study("STU-0001")
        assert memory_store.surrogate_for_study("STU-0001") == a


def test_file_backed_url_keeps_the_null_pool(tmp_path):
    # The counterpart: a file-backed store must not pin a single connection, or
    # the concurrency guarantee would rest on SQLite serializing writes rather
    # than on the unique constraint.
    url = f"sqlite:///{tmp_path / 'map.db'}"
    assert _pool_args(url) == _FILE_POOL_ARGS


BASE = StructuredPayload(
    function="draft",
    report_text="FINDINGS: 7mm nodule. Patient 4452819.",
    dicom_fields={
        "modality": "CT",
        "study_date": "20260114",
        "patient_age_band": "040-049",
    },
    study_ref="STU-0001",
    prior_study_refs=("STU-0000",),
    policy_version="medarx-policy-1.0.0",
    input_hash="h0",
    payload_hash=None,
)


def test_references_become_surrogates_and_dates_shift(store):
    out = pseudonymize_payload(BASE, "PAT-0001", store)
    assert out.study_ref.startswith(STUDY_DOMAIN + "-")
    assert all(r.startswith(STUDY_DOMAIN + "-") for r in out.prior_study_refs)
    assert out.dicom_fields["study_date"] != "20260114"
    assert out.dicom_fields["patient_age_band"] == "040-049"


def test_no_raw_reference_survives_anywhere_in_the_payload(store):
    out = pseudonymize_payload(BASE, "PAT-0001", store)
    assert "STU-0001" not in out.study_ref
    assert "STU-0000" not in out.prior_study_refs


def test_surrogates_are_the_stores_own_for_those_references(store):
    out = pseudonymize_payload(BASE, "PAT-0001", store)
    assert out.study_ref == store.surrogate_for_study("STU-0001")
    assert out.prior_study_refs == (store.surrogate_for_study("STU-0000"),)


def test_dates_shift_by_exactly_the_patient_offset(store):
    out = pseudonymize_payload(BASE, "PAT-0001", store)
    offset = store.offset_for_patient("PAT-0001")
    expected = (date(2026, 1, 14) + timedelta(days=offset)).strftime("%Y%m%d")
    assert out.dicom_fields["study_date"] == expected


def test_both_date_fields_shift_by_the_same_offset(store):
    payload = BASE.model_copy(
        update={
            "dicom_fields": {
                "study_date": "20260114",
                "prior_study_date": "20250901",
            }
        }
    )
    out = pseudonymize_payload(payload, "PAT-0001", store)
    before = (date(2026, 1, 14) - date(2025, 9, 1)).days
    after = (
        _as_date(out.dicom_fields["study_date"])
        - _as_date(out.dicom_fields["prior_study_date"])
    ).days
    assert before == after, "the interval between a patient's two studies must survive"


def test_free_text_passes_through_byte_identical(store):
    out = pseudonymize_payload(BASE, "PAT-0001", store)
    assert out.report_text == BASE.report_text
    assert out.report_text.encode("utf-8") == BASE.report_text.encode("utf-8")


def test_free_text_is_untouched_even_when_it_looks_like_a_reference(store):
    # The composition is not a text scanner: a reference or a date inside the
    # report is layer D's problem, and rewriting it here would alter clinical
    # text on a rule nobody reviewed.
    payload = BASE.model_copy(update={"report_text": "  Compared with 20260114 STU-0000.  "})
    out = pseudonymize_payload(payload, "PAT-0001", store)
    assert out.report_text == "  Compared with 20260114 STU-0000.  "


def test_input_payload_is_not_mutated(store):
    before = BASE.model_dump()
    pseudonymize_payload(BASE, "PAT-0001", store)
    assert BASE.model_dump() == before


def test_result_does_not_alias_the_input_field_mapping(store):
    out = pseudonymize_payload(BASE, "PAT-0001", store)
    assert out.dicom_fields is not BASE.dicom_fields


def test_input_hash_is_carried_through_and_payload_hash_is_left_alone(store):
    payload = BASE.model_copy(update={"payload_hash": "pre-redaction"})
    out = pseudonymize_payload(payload, "PAT-0001", store)
    assert out.input_hash == payload.input_hash
    # The pre-redaction hash is component A's provenance value; layer 3
    # overwrites it. Recomputing it here could not agree with it.
    assert out.payload_hash == "pre-redaction"


def test_the_same_payload_and_patient_always_give_the_same_result(store):
    once = pseudonymize_payload(BASE, "PAT-0001", store)
    twice = pseudonymize_payload(BASE, "PAT-0001", store)
    assert once.study_ref == twice.study_ref
    assert once.prior_study_refs == twice.prior_study_refs
    assert once.dicom_fields == twice.dicom_fields



@pytest.mark.parametrize(
    "reference",
    [
        "medarx-study-deadbeef",
        "medarx-study-00000000",
        "medarx-study-abcdef12",
    ],
)
def test_a_caller_supplied_surrogate_shaped_reference_is_refused(store, reference):
    # The reference arrives from the caller, so one shaped like a surrogate may
    # be a forged value. Passing it through would put an unvalidated, unrecorded
    # string on the model path that is indistinguishable from a real one — and
    # it would satisfy any check that only looks for the domain prefix.
    with pytest.raises(PseudonymError) as ei:
        pseudonymize_payload(
            BASE.model_copy(update={"study_ref": reference}), "PAT-0001", store
        )
    assert ei.value.action_codes == ("SURROGATE_SHAPED_REFERENCE_REJECTED",)


def test_a_surrogate_shaped_prior_reference_is_refused(store):
    payload = BASE.model_copy(update={"prior_study_refs": ("STU-0000", "medarx-study-deadbeef")})
    with pytest.raises(PseudonymError) as ei:
        pseudonymize_payload(payload, "PAT-0001", store)
    assert ei.value.action_codes == ("SURROGATE_SHAPED_REFERENCE_REJECTED",)


def test_the_refusal_says_which_reference_and_why(store):
    payload = BASE.model_copy(update={"prior_study_refs": ("medarx-study-deadbeef",)})
    with pytest.raises(PseudonymError) as ei:
        pseudonymize_payload(payload, "PAT-0001", store)
    assert "prior_study_refs[0]" in ei.value.message
    assert "medarx-study-deadbeef" in ei.value.message
    assert "once per payload" in ei.value.message


def test_applying_this_twice_raises_instead_of_double_shifting_the_dates(store):
    # A second application would move every date again and return a payload
    # whose intervals are silently wrong. It must fail loudly instead.
    once = pseudonymize_payload(BASE, "PAT-0001", store)
    with pytest.raises(PseudonymError) as ei:
        pseudonymize_payload(once, "PAT-0001", store)
    assert ei.value.action_codes == ("SURROGATE_SHAPED_REFERENCE_REJECTED",)


def _receipt_from(error: PseudonymError) -> BlockReceipt:
    return BlockReceipt(
        request_id="req-1",
        layer=error.layer,
        action_codes=list(error.action_codes),
        policy_version="medarx-policy-1.0.0",
    )


def test_a_receipt_from_the_refusal_carries_the_rejection_code(store):
    with pytest.raises(PseudonymError) as ei:
        pseudonymize_payload(
            BASE.model_copy(update={"study_ref": "medarx-study-deadbeef"}), "PAT-0001", store
        )
    receipt = _receipt_from(ei.value)
    assert receipt.action_codes == ["SURROGATE_SHAPED_REFERENCE_REJECTED"]
    assert receipt.layer == "C"


@pytest.mark.parametrize(
    "payload, patient_ref",
    [
        (BASE, ""),
        (BASE.model_copy(update={"study_ref": ""}), "PAT-0001"),
    ],
)
def test_a_receipt_can_tell_a_missing_surrogate_from_a_rejected_one(
    store, payload, patient_ref
):
    # The two conditions are opposites and both live in layer C, so they must
    # not share a code: a receipt carries the code and not the message, and it
    # is a persistent audit record.
    with pytest.raises(PseudonymError) as missing:
        pseudonymize_payload(payload, patient_ref, store)
    missing_receipt = _receipt_from(missing.value)
    assert missing_receipt.action_codes == ["MISSING_SURROGATE"]

    with pytest.raises(PseudonymError) as rejected:
        pseudonymize_payload(
            BASE.model_copy(update={"study_ref": "medarx-study-deadbeef"}), "PAT-0001", store
        )
    rejected_receipt = _receipt_from(rejected.value)
    assert rejected_receipt.action_codes == ["SURROGATE_SHAPED_REFERENCE_REJECTED"]
    assert missing_receipt.layer == rejected_receipt.layer == "C"
    assert missing_receipt.action_codes != rejected_receipt.action_codes


@pytest.mark.parametrize(
    "reference",
    [
        "STU-medarx-study-1",
        "medarx-study",
        "medarx-study-",
        "medarx-study-ZZZZ",
        "medarx-study-attacker-chosen-value",
        "medarx-study-1234567",
        "medarx-study-deadbeef-extra",
        "medarx-study-DEADBEEF",
    ],
)
def test_a_reference_only_containing_the_domain_is_still_processed(store, reference):
    # The check must not be so broad that it refuses legitimate references.
    out = pseudonymize_payload(
        BASE.model_copy(update={"study_ref": reference}), "PAT-0001", store
    )
    assert out.study_ref == store.surrogate_for_study(reference)
    assert out.study_ref != reference


def test_a_new_reference_maps_to_exactly_one_surrogate(store):
    reference = "STU-NEW-9"
    first = pseudonymize_payload(
        BASE.model_copy(update={"study_ref": reference}), "PAT-0001", store
    )
    again = pseudonymize_payload(
        BASE.model_copy(update={"study_ref": reference}), "PAT-0001", store
    )
    minted = store.surrogate_for_study(reference)
    assert first.study_ref == again.study_ref == minted


def test_pseudonymization_reads_no_environment():
    import medarx.pseudonym.pseudonymize as module

    source = Path(module.__file__).read_text(encoding="utf-8")
    assert "os.environ" not in source and "getenv" not in source


def test_different_patients_get_different_dates_for_the_same_payload(store):
    a = pseudonymize_payload(BASE, "PAT-0001", store)
    b = pseudonymize_payload(BASE, "PAT-0002", store)
    assert a.dicom_fields["study_date"] != b.dicom_fields["study_date"]


@pytest.mark.parametrize("patient_ref", ["", " "])
def test_empty_patient_ref_is_a_pseudonym_error(store, patient_ref):
    with pytest.raises(PseudonymError) as ei:
        pseudonymize_payload(BASE, patient_ref, store)
    assert ei.value.action_codes == ("MISSING_SURROGATE",)
    assert ei.value.layer == "C"


def test_a_study_ref_that_cannot_be_surrogated_is_a_pseudonym_error(store):
    with pytest.raises(PseudonymError) as ei:
        pseudonymize_payload(BASE.model_copy(update={"study_ref": ""}), "PAT-0001", store)
    assert ei.value.action_codes == ("MISSING_SURROGATE",)


def test_a_date_that_cannot_be_shifted_is_refused_rather_than_passed_through(store):
    payload = BASE.model_copy(update={"dicom_fields": {"study_date": "not-a-date"}})
    with pytest.raises(PseudonymError) as ei:
        pseudonymize_payload(payload, "PAT-0001", store)
    assert ei.value.action_codes == ("UNSHIFTED_DATE",)


def test_an_impossible_calendar_date_is_refused_rather_than_shifted(store):
    payload = BASE.model_copy(update={"dicom_fields": {"study_date": "20260230"}})
    with pytest.raises(PseudonymError):
        pseudonymize_payload(payload, "PAT-0001", store)


def test_a_blank_date_field_is_left_alone(store):
    # There is no date here, so there is none to leak and none to shift.
    payload = BASE.model_copy(update={"dicom_fields": {"study_date": ""}})
    out = pseudonymize_payload(payload, "PAT-0001", store)
    assert out.dicom_fields["study_date"] == ""


def test_a_non_date_field_that_looks_like_a_date_is_not_shifted(store):
    payload = BASE.model_copy(
        update={"dicom_fields": {"study_date": "20260114", "patient_age_band": "040-049"}}
    )
    out = pseudonymize_payload(payload, "PAT-0001", store)
    assert out.dicom_fields["patient_age_band"] == "040-049"


def _as_date(value: str) -> date:
    return date(int(value[:4]), int(value[4:6]), int(value[6:8]))


@contextmanager
def _open(url: str) -> Iterator[MappingStore]:
    store = MappingStore(url, KEY)
    try:
        yield store
    finally:
        store.close()
