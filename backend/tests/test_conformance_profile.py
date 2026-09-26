import pytest
from pydicom.dataset import Dataset, FileDataset
from pydicom.sequence import Sequence

from medarx.config import load_settings
from medarx.deident.dicom_deidentifier import deidentify, make_uid
from medarx.deident.profiles import (
    CLEAN_PIXEL_DATA_IMPLEMENTED,
    IMPLEMENTED_OPTIONS,
    PROFILE,
)
from evals.synthetic_phi.gen_dcm import make_synthetic_dataset

ROOT = load_settings().dicom_uid_root


def test_patient_identity_attributes_are_removed_or_emptied():
    ds = make_synthetic_dataset()
    out, actions = deidentify(ds, ROOT)
    assert "PatientName" not in out
    assert out.PatientID == ""
    assert out.AccessionNumber == ""
    assert out.InstitutionName == ""
    assert out.ReferringPhysicianName == ""
    assert out.PatientBirthDate in ("", None)
    assert {a.tag for a in actions} >= {"PatientName", "PatientID", "AccessionNumber"}


def test_study_instance_uid_is_replaced_under_the_org_root():
    out, _ = deidentify(make_synthetic_dataset(), ROOT)
    assert out.StudyInstanceUID.startswith("1.2.826.0.1.3680043.10.1338.")
    assert out.StudyInstanceUID != make_synthetic_dataset().StudyInstanceUID


def test_clinical_content_survives_untouched():
    out, _ = deidentify(make_synthetic_dataset(), ROOT)
    assert out.Modality == "CT"
    assert out.SeriesDescription == "AXIAL 3MM"
    assert out.PatientAge == "045Y"
    assert out.StudyDate == "20260114"


def test_clean_pixel_data_option_is_not_claimed():
    assert CLEAN_PIXEL_DATA_IMPLEMENTED is False
    assert "CleanPixelData" not in PROFILE

    # An exact-set assertion, not a membership check: the Basic Profile is the
    # base profile rather than an option, and nothing is layered on top of it.
    # If this ever fails, an option was implemented — update the set and the
    # conformance claims deliberately rather than by accident.
    assert IMPLEMENTED_OPTIONS == frozenset()
    assert "CleanPixelData" not in IMPLEMENTED_OPTIONS


def test_deidentification_is_idempotent():
    once, _ = deidentify(make_synthetic_dataset(), ROOT)
    twice, _ = deidentify(once, ROOT)
    assert once == twice


def test_the_input_dataset_is_never_mutated():
    ds = make_synthetic_dataset()
    original_name = str(ds.PatientName)
    original_uid = ds.StudyInstanceUID
    original_pixels = ds.PixelData
    deidentify(ds, ROOT)
    assert str(ds.PatientName) == original_name
    assert ds.StudyInstanceUID == original_uid
    assert ds.PixelData == original_pixels
    assert ds.PatientID == "SYN-000042"


def test_the_defined_subset_covers_the_uids_and_never_pixel_data():
    defined = set(PROFILE)
    assert "PixelData" not in defined
    assert {"StudyInstanceUID", "SeriesInstanceUID", "SOPInstanceUID"} <= defined
    assert all(rule.action in {"replace_uid", "empty", "remove"} for rule in PROFILE.values())


def test_pixel_data_bytes_are_carried_through_unchanged():
    out, _ = deidentify(make_synthetic_dataset(), ROOT)
    assert out.PixelData == make_synthetic_dataset().PixelData


def _dataset_with_nested_phi() -> FileDataset:
    """A synthetic instance with PHI buried inside a sequence the profile
    does not name: the case that passes straight through if the de-identifier
    only ever looks at the top level."""
    ds = make_synthetic_dataset()
    item = Dataset()
    item.PatientName = "NESTED^PHI"
    item.PatientID = "NESTED-0001"
    item.StudyInstanceUID = "1.2.826.0.1.3680043.8.498.1138.100.9.1"
    # A second level, so a walk that only descends one level is caught too.
    inner = Dataset()
    inner.ReferringPhysicianName = "DEEP^PHI"
    item.ReferencedImageSequence = Sequence([inner])
    ds.RequestAttributesSequence = Sequence([item])
    return ds


def test_phi_nested_in_a_sequence_is_de_identified_not_passed_through():
    ds = _dataset_with_nested_phi()
    out, _ = deidentify(ds, ROOT)

    item = out.RequestAttributesSequence[0]
    assert "PatientName" not in item
    assert item.PatientID == ""
    assert item.ReferencedImageSequence[0].ReferringPhysicianName == ""
    assert item.StudyInstanceUID.startswith(ROOT)

    # Nothing that looked like the nested values may survive anywhere in the
    # output; this is the assertion that fails if the walk ever stops working.
    dumped = out.to_json()
    for leaked in ("NESTED^PHI", "NESTED-0001", "DEEP^PHI"):
        assert leaked not in dumped

    # And the input is still the caller's: the nested item keeps its values.
    assert str(ds.RequestAttributesSequence[0].PatientName) == "NESTED^PHI"
    assert str(ds.RequestAttributesSequence[0].ReferencedImageSequence[0].ReferringPhysicianName) == "DEEP^PHI"


def test_a_profile_named_sequence_is_emptied_and_its_items_do_not_survive():
    ds = make_synthetic_dataset()
    item = Dataset()
    item.PatientName = "NESTED^PHI"
    ds.PatientInsurancePlanCodeSequence = Sequence([item])
    out, _ = deidentify(ds, ROOT)
    assert len(out.PatientInsurancePlanCodeSequence) == 0


def test_surrogate_uids_are_deterministic_and_within_the_ps35_length_limit():
    first = make_uid("StudyInstanceUID:1.2.3.4", ROOT)
    assert first == make_uid("StudyInstanceUID:1.2.3.4", ROOT)
    assert first != make_uid("StudyInstanceUID:1.2.3.5", ROOT)
    assert first.startswith(ROOT)
    assert not first.startswith("2.25.")
    assert len(first) <= 64


def _nested_dataset(levels_below_top: int) -> Dataset:
    """A dataset nesting `levels_below_top` sequence levels, innermost empty.

    Built by wrapping upward from the innermost item, so it terminates: every
    level is a distinct `Dataset` and no level points back at another, so there
    is no cycle for the walk to chase.
    """
    node = Dataset()
    for _ in range(levels_below_top):
        wrapper = Dataset()
        wrapper.ReferencedImageSequence = Sequence([node])
        node = wrapper
    return node


def test_nesting_at_the_depth_limit_is_walked():
    # The cap counts levels *below* the top-level dataset: 32 nested levels are
    # walked, and the item reached at depth 33 is the first one refused. This
    # test is what pins that reading of the constant.
    out, _ = deidentify(_nested_dataset(32), ROOT)
    assert out is not None


def test_nesting_past_the_depth_limit_is_refused_rather_than_recursed():
    with pytest.raises(ValueError, match="refusing rather than"):
        deidentify(_nested_dataset(33), ROOT)
