"""A fabricated DICOM dataset for the conformance tests.

Every value in here is invented. There is no real patient data in this file and
none may be added to it: the identifiers below name a synthetic subject
(`SYN-*`) and use a private test OID arc, not any real institution's root. The
point of the fixture is to give the de-identifier something with a realistic
*shape* — a populated identity block, a set of UIDs, and one pixel data element
— so the profile can be exercised without touching real PHI.
"""

from __future__ import annotations

import pydicom
from pydicom.dataset import Dataset, FileDataset, FileMetaDataset
from pydicom.uid import ExplicitVRLittleEndian

__all__ = ["make_synthetic_dataset"]

#: Explicit VR Little Endian, the transfer syntax the fixture is written in.
TRANSFER_SYNTAX_UID = ExplicitVRLittleEndian

#: A private test arc, deliberately *not* the org root
#: (`Settings.dicom_uid_root`) so that a de-identified UID is always visibly
#: different from the source.
_SYNTHETIC_UID_ROOT = "1.2.826.0.1.3680043.8.498.1138.100."


def make_synthetic_dataset() -> FileDataset:
    """Build a fresh synthetic dataset.

    A new object on every call: the de-identifier must never mutate its input,
    and a shared fixture would hide a mutation between tests.
    """
    file_meta = FileMetaDataset()
    file_meta.TransferSyntaxUID = TRANSFER_SYNTAX_UID
    file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"  # CT Image Storage
    file_meta.MediaStorageSOPInstanceUID = f"{_SYNTHETIC_UID_ROOT}3.1"
    file_meta.ImplementationClassUID = f"{_SYNTHETIC_UID_ROOT}1.1"

    # The VR flags go in the constructor rather than being assigned afterwards:
    # setting them as attributes is deprecated in pydicom 3.x, and a fixture
    # that warns on every call drowns the suite's output.
    ds = FileDataset(
        "synthetic.dcm",
        Dataset(),
        preamble=b"\0" * 128,
        file_meta=file_meta,
        is_implicit_VR=False,
        is_little_endian=True,
    )

    # -- Identity block: every one of these is in the Basic Profile's scope.
    ds.PatientName = "SYNTHETIC^TESTONLY"
    ds.PatientID = "SYN-000042"
    ds.PatientBirthDate = "19800401"
    ds.PatientSex = "F"
    ds.PatientAge = "045Y"
    ds.PatientAddress = "1 Fabricated Way"
    ds.PatientTelephoneNumbers = "+1-000-000-0000"
    ds.OtherPatientIDs = "SYN-ALT-0007"
    ds.OtherPatientNames = "ALTSYNTHETIC^TESTONLY"
    ds.AccessionNumber = "ACC-SYN-0001"
    ds.InstitutionName = "Synthetic Imaging Centre"
    ds.InstitutionAddress = "2 Fabricated Way"
    ds.ReferringPhysicianName = "REFERRER^SYNTHETIC"
    ds.PerformingPhysicianName = "OPERATOR^SYNTHETIC"
    ds.OperatorsName = "OPERATOR^SYNTHETIC"

    # -- Study / series: the clinical content that must survive untouched.
    ds.StudyDate = "20260114"
    ds.StudyDescription = "CHEST CT SYNTHETIC"
    ds.SeriesDescription = "AXIAL 3MM"
    ds.Modality = "CT"
    ds.StudyInstanceUID = f"{_SYNTHETIC_UID_ROOT}1.1"
    ds.SeriesInstanceUID = f"{_SYNTHETIC_UID_ROOT}2.1"
    ds.SOPInstanceUID = f"{_SYNTHETIC_UID_ROOT}3.1"
    ds.FrameOfReferenceUID = f"{_SYNTHETIC_UID_ROOT}4.1"

    # -- One tiny 4x4 8-bit image. Present so the profile can be shown to
    # leave it alone; the Clean Pixel Data option is NOT implemented and
    # nothing in the de-identifier may touch these bytes.
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.Rows = 4
    ds.Columns = 4
    ds.BitsAllocated = 8
    ds.BitsStored = 8
    ds.HighBit = 7
    ds.PixelRepresentation = 0
    ds.PixelData = bytes(range(16))

    return ds
