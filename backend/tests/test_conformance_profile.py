from medarx.config import load_settings
from medarx.deident.dicom_deidentifier import deidentify, make_uid
from medarx.deident.profiles import CLEAN_PIXEL_DATA_IMPLEMENTED, PROFILE
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


def test_defined_and_implemented_only_reflect_the_basic_profile():
    defined = set(PROFILE)
    assert "PixelData" not in defined
    assert {"StudyInstanceUID", "SeriesInstanceUID", "SOPInstanceUID"} <= defined
    assert all(rule.action in {"replace_uid", "empty", "remove"} for rule in PROFILE.values())


def test_pixel_data_bytes_are_carried_through_unchanged():
    out, _ = deidentify(make_synthetic_dataset(), ROOT)
    assert out.PixelData == make_synthetic_dataset().PixelData


def test_surrogate_uids_are_deterministic_and_within_the_ps35_length_limit():
    first = make_uid("StudyInstanceUID:1.2.3.4", ROOT)
    assert first == make_uid("StudyInstanceUID:1.2.3.4", ROOT)
    assert first != make_uid("StudyInstanceUID:1.2.3.5", ROOT)
    assert first.startswith(ROOT)
    assert not first.startswith("2.25.")
    assert len(first) <= 64
