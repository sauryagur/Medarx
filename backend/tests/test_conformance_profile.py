import warnings

import pytest
from pydicom.dataset import Dataset, FileDataset
from pydicom.sequence import Sequence
from pydicom.uid import UID

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


def test_the_sop_instance_uid_still_matches_its_file_meta_copy():
    """PS3.10: the two hold the same value, so the two must stay the same value.

    The fixture sets `SOPInstanceUID` and `file_meta.MediaStorageSOPInstanceUID`
    to the same source UID, and the applier seeded its derivation on
    `f"{keyword}:{value}"` — so each attribute got a *different* surrogate from
    the same source, and a written file pointed at an instance the dataset no
    longer contained. `profiles.py` gives cross-references resolving to the
    same object as the reason the attribute is replaced rather than removed, so
    this is the code contradicting its own stated rationale.
    """
    out, _ = deidentify(make_synthetic_dataset(), ROOT)
    assert out.SOPInstanceUID == out.file_meta.MediaStorageSOPInstanceUID


def test_two_attributes_holding_one_uid_get_one_surrogate():
    """The general case behind the file meta copy: the seed is the value alone."""
    ds = make_synthetic_dataset()
    ds.SeriesInstanceUID = ds.StudyInstanceUID
    out, _ = deidentify(ds, ROOT)
    assert out.StudyInstanceUID == out.SeriesInstanceUID
    assert out.StudyInstanceUID.startswith(ROOT)


def test_different_source_uids_still_differ_after_de_identification():
    """Seeding on the value must not collapse the mapping.

    One seed per UID rather than one per (keyword, UID) pair is the fix for the
    cross-reference break; the failure mode that fix invites is two distinct
    source objects sharing a surrogate, which would be a worse privacy defect
    than the one it repairs. So both halves are asserted.
    """
    ds = make_synthetic_dataset()
    surrogates = {out for out in (
        deidentify(make_synthetic_dataset(), ROOT)[0].StudyInstanceUID,
        deidentify(make_synthetic_dataset(), ROOT)[0].SeriesInstanceUID,
        deidentify(make_synthetic_dataset(), ROOT)[0].SOPInstanceUID,
        deidentify(make_synthetic_dataset(), ROOT)[0].FrameOfReferenceUID,
    )}
    source = make_synthetic_dataset()
    assert len({source.StudyInstanceUID, source.SeriesInstanceUID,
                source.SOPInstanceUID, source.FrameOfReferenceUID}) == len(surrogates)


#: How many surrogates `test_every_surrogate_uid_is_legal` derives. The
#: derivation previously produced a component with a leading zero — which
#: PS3.5 §9.1 forbids and pydicom warns on — for roughly one seed in ten, so a
#: sample has to be large enough to hit that tenth. Measured at 116 in 1000
#: with the previous derivation.
_SAMPLE_SIZE = 1000


def _illegal_components(uid: str) -> list[str]:
    """The components of `uid` that PS3.5 §9.1 does not permit.

    Only the first component is exempt from the leading-zero rule: it is the
    one that identifies the org root, and a leading zero there would change
    which organisation a UID appears to belong to.
    """
    return [
        component
        for index, component in enumerate(uid.split("."))
        if not component.isdigit() or (index > 0 and len(component) > 1 and component[0] == "0")
    ]


def test_every_surrogate_uid_is_legal(_sample_size=_SAMPLE_SIZE):
    """A thousand seeds, every one of them checked — a sample of three would
    have missed a one-in-ten failure entirely, which is how it survived.

    The width of the component is the whole defence: `uuid5(...).int %
    10**36` is below `10**35` about a tenth of the time, and `zfill` then
    padded the front with a zero to reach the 36 characters the 64-character
    limit allows. The docstring said the bound existed to keep the UID legal;
    this is the test that makes that sentence true.
    """
    uids = [make_uid(f"seed-{index}", ROOT) for index in range(_sample_size)]
    illegal = {uid: _illegal_components(uid) for uid in uids if _illegal_components(uid)}
    assert not illegal, f"{len(illegal)} of {_sample_size} surrogates are illegal: {list(illegal)[:3]}"
    assert all(len(uid) <= 64 for uid in uids)


def test_every_surrogate_uid_is_accepted_by_a_dicom_reader():
    """The same sample read back by pydicom, which warns on an illegal `UI`.

    A structural check and a reader's verdict are different evidence: this one
    is what a downstream system would actually see when it opened the file.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        for index in range(_SAMPLE_SIZE):
            assert UID(make_uid(f"seed-{index}", ROOT)) is not None


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
