"""Seed Orthanc with a synthetic study, over DICOMweb, for the viewer demo.

**Everything in the objects this writes is fabricated.** There is no real
patient data here and none may be added: the identity block names a synthetic
subject, the UIDs come from the same private test arc `evals/synthetic_phi/
gen_dcm.py` uses, and every pixel is computed from a formula in this file. The
study description carries a `SYNTHETIC` marker so that a screenshot of the
viewer is self-identifying as fabricated data (product spec §10).

The image is a **phantom**, not a scan. It exists so that the viewport has
something whose appearance actually responds to a window/level change — a flat
grey rectangle would render in any viewer and would prove nothing about the
tools. It is a disc of "dense" material on a soft-tissue background with a
linear ramp along one axis, so window/level, zoom and the basic display
presets visibly do something to it.

## STOW-RS, and the header that has to be exactly right

`POST /dicom-web/studies` answers **415** unless the request carries

    Content-Type: multipart/related; type="application/dicom"; boundary=...

The `type` parameter and the boundary are both required; a bare
`multipart/related`, and — the mistake that costs the most time — a
`Content-Type: application/dicom` on a body that is a multipart envelope, both
fail. `infra/orthanc/orthanc.json` records the same three gotchas next to the
file they cost somebody an afternoon.

## Reading it back

The script finishes by reading `/dicom-web/studies/{uid}/metadata` and
printing the instance count. `GET /dicom-web/studies/{uid}` with
`Accept: application/dicom+json` returns **400** on Orthanc 1.10.1; the
`/metadata` form is the one that works.

This script talks to the archive and nothing else. It is a **display** seed: it
puts images where the OHIF viewport can display them and it does not put them
anywhere near Medarx. No component of the privacy kernel reads pixels, and
nothing this writes is ever read by the Medarx API.

    backend/.venv/bin/python viewer/ohif/seed_study.py
    backend/.venv/bin/python viewer/ohif/seed_study.py --slices 7
    backend/.venv/bin/python viewer/ohif/seed_study.py --orthanc-url http://127.0.0.1:9999
"""

from __future__ import annotations

import argparse
import json
from io import BytesIO
import struct
import sys
import urllib.error
import urllib.request
import uuid

import pydicom
from pydicom.dataset import Dataset, FileDataset, FileMetaDataset
from pydicom.uid import ExplicitVRLittleEndian

__all__ = ["build_study", "stow", "main"]

#: The same private test arc `evals/synthetic_phi/gen_dcm.py` uses. Deliberately
#: not any institution's root, so a UID here can never collide with a real one.
UID_ROOT = "1.2.826.0.1.3680043.8.498.1138.900."

#: CT Image Storage. A transfer syntax the browser's decoder already handles
#: (explicit VR little endian, uncompressed) — the point of this fixture is
#: the mount, not the codec.
SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.1.2"

ROWS = COLUMNS = 256
BODY_RADIUS = 0.42
DISC_RADIUS = 0.13


def _phantom_slice(index: int, total: int) -> bytes:
    """One computed axial slice, as 16-bit little-endian MONOCHROME2 pixels.

    A soft-tissue background, a denser disc that moves with the slice index, a
    ramp along the horizontal axis so window/level has something to act on, and
    a soft vignette so the corners of a windowed image are visibly not uniform.
    Every value is a function of the pixel coordinate: no image was downloaded,
    decoded or traced.
    """
    import math

    # The disc walks down the phantom over the series, which is what makes the
    # series scroll in the viewport do something a person can see.
    disc_cy = 0.5 + 0.16 * math.sin(2 * math.pi * index / max(total, 1))

    pixels = bytearray(ROWS * COLUMNS * 2)
    offset = 0
    for y in range(ROWS):
        fy = (y + 0.5) / ROWS - 0.5
        for x in range(COLUMNS):
            fx = (x + 0.5) / COLUMNS - 0.5

            value = 320.0  # soft tissue
            r = math.hypot(fx, fy)
            if r > BODY_RADIUS:
                value = 40.0  # air outside the phantom
            else:
                value += 120.0 * (1.0 - r / BODY_RADIUS)  # denser toward the middle
                if math.hypot(fx, fy - disc_cy) < DISC_RADIUS:
                    value = 1150.0  # the "lesion"
            value += 180.0 * (x / COLUMNS - 0.5)  # the ramp
            value -= 400.0 * (r / (BODY_RADIUS * 1.6)) ** 3  # the vignette

            pixels[offset : offset + 2] = struct.pack("<H", max(0, min(4095, int(value))))
            offset += 2
    return bytes(pixels)


def _instance(index: int, total: int) -> FileDataset:
    file_meta = FileMetaDataset()
    file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
    file_meta.MediaStorageSOPClassUID = SOP_CLASS_UID
    file_meta.MediaStorageSOPInstanceUID = f"{UID_ROOT}3.{index + 1}"
    file_meta.ImplementationClassUID = f"{UID_ROOT}1.1"

    ds = FileDataset(
        f"synthetic-ct-{index + 1:03d}.dcm",
        Dataset(),
        preamble=b"\0" * 128,
        file_meta=file_meta,
        is_implicit_VR=False,
        is_little_endian=True,
    )

    # -- Identity block. Every value invented; the `SYN-` prefix and the
    #    `SYNTHETIC` descriptions are the marker.
    ds.PatientName = "SYNTHETIC^PHANTOM"
    ds.PatientID = "SYN-PHANTOM-0001"
    ds.PatientBirthDate = "19800101"
    ds.PatientSex = "O"
    ds.PatientAge = "046Y"
    ds.StudyDate = "20260928"
    ds.StudyTime = "120000"
    ds.AccessionNumber = "SYN-ACC-9001"
    ds.ReferringPhysicianName = "SYNTHETIC^REFERRER"
    ds.InstitutionName = "Synthetic Imaging Centre (fabricated data)"

    # -- Study / series
    #
    # `SOPClassUID` is in the **dataset**, not only in the file meta, and its
    # absence is a `400` from STOW-RS with the log line "STOW-RS: Missing a
    # mandatory tag in incoming DICOM file" and nothing else to say which tag.
    # The plugin requires StudyInstanceUID, SeriesInstanceUID, SOPClassUID and
    # SOPInstanceUID to be present *and* to be JSON strings.
    ds.SOPClassUID = SOP_CLASS_UID
    ds.StudyInstanceUID = f"{UID_ROOT}1.1"
    ds.SeriesInstanceUID = f"{UID_ROOT}2.1"
    ds.SOPInstanceUID = f"{UID_ROOT}3.{index + 1}"
    ds.FrameOfReferenceUID = f"{UID_ROOT}4.1"
    ds.StudyDescription = "SYNTHETIC PHANTOM - NOT PATIENT DATA"
    ds.SeriesDescription = "SYNTHETIC AXIAL 256X256"
    ds.Modality = "CT"
    ds.Manufacturer = "Medarx synthetic fixture generator"
    ds.SeriesNumber = 1
    ds.InstanceNumber = index + 1

    # -- Geometry and acquisition, enough for a CT image to display
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.Rows = ROWS
    ds.Columns = COLUMNS
    ds.BitsAllocated = 16
    ds.BitsStored = 16
    ds.HighBit = 15
    ds.PixelRepresentation = 0
    ds.PixelSpacing = [0.7, 0.7]
    ds.SliceThickness = 2.5
    ds.ImagePositionPatient = [0.0, 0.0, -2.5 * index]
    ds.ImageOrientationPatient = [1, 0, 0, 0, 1, 0]
    ds.RescaleIntercept = 0.0
    ds.RescaleSlope = 1.0
    ds.WindowCenter = 300
    ds.WindowWidth = 900
    ds.PixelData = _phantom_slice(index, total)

    return ds


def build_study(slices: int) -> list[FileDataset]:
    """The synthetic series: `slices` instances in one study, one series."""
    return [_instance(i, slices) for i in range(slices)]


def _multipart_body(instances: list[FileDataset]) -> tuple[bytes, str]:
    """The DICOM multipart envelope STOW-RS takes, built by hand.

    `dcmwrite` wants a file, so each dataset goes through an in-memory buffer
    rather than to disk: the object exists only in this process and in the
    request body.
    """
    boundary = f"----medarx-{uuid.uuid4().hex}"
    chunks: list[bytes] = []
    for ds in instances:
        buffer = BytesIO()
        pydicom.dcmwrite(buffer, ds, enforce_file_format=True)
        chunks.append(f"--{boundary}\r\n".encode())
        chunks.append(b"Content-Type: application/dicom\r\n\r\n")
        chunks.append(buffer.getvalue())
        chunks.append(b"\r\n")
    chunks.append(f"--{boundary}--\r\n".encode())
    return b"".join(chunks), boundary


def stow(base_url: str, instances: list[FileDataset], timeout: float = 30.0) -> str:
    """POST the instances to `/dicom-web/studies`. Returns the study UID.

    The 1.7 plugin answers with the DICOM JSON of the **first stored instance**,
    not with the `{"0008,1155": {"vr": "UI", "InlineBinary": ...}}` envelope a
    later version returns, so the study UID is read out of the dataset itself
    with the response's own `ReferencedURL` as the fallback. Getting this
    wrong raises `KeyError` *after* the instances are safely stored, which
    reads like a failed upload that is in fact a successful one.
    """
    body, boundary = _multipart_body(instances)
    # The exact header the DICOM standard requires and Orthanc enforces. The
    # `type` parameter is not decoration: without it this is a 415.
    content_type = f'multipart/related; type="application/dicom"; boundary={boundary}'
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/dicom-web/studies",
        data=body,
        method="POST",
        headers={"Content-Type": content_type, "Accept": "application/dicom+json"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode())

    for tag in ("0020000D", "0020,000D"):
        if tag in payload:
            return payload[tag]["Value"][0]

    for tag in ("00081190", "0008,1190"):
        if tag in payload:
            # .../dicom-web/studies/{uid}
            return payload[tag]["Value"][0].rstrip("/").rsplit("/", 1)[-1]

    # Last resort, and the honest one: the UID the instances were built with.
    return str(instances[0].StudyInstanceUID)


def read_back(base_url: str, study_uid: str, timeout: float = 30.0) -> dict:
    """`/metadata`, not the study itself — see the module docstring."""
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/dicom-web/studies/{study_uid}/metadata",
        headers={"Accept": "application/dicom+json"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--orthanc-url",
        default="http://127.0.0.1:8042",
        help="the archive's base URL (the loopback forwarder's published port)",
    )
    parser.add_argument("--slices", type=int, default=5, help="instances in the synthetic series")
    args = parser.parse_args(argv)

    instances = build_study(args.slices)
    print(f"built {len(instances)} synthetic instances ({ROWS}x{COLUMNS}, 16-bit)")

    try:
        study_uid = stow(args.orthanc_url, instances)
    except urllib.error.HTTPError as exc:
        print(f"STOW-RS failed: HTTP {exc.code} {exc.reason}", file=sys.stderr)
        print(exc.read().decode(errors="replace")[:500], file=sys.stderr)
        return 1
    except urllib.error.URLError as exc:
        print(f"STOW-RS could not reach {args.orthanc_url}: {exc.reason}", file=sys.stderr)
        return 1

    print(f"STOW-RS accepted. StudyInstanceUID: {study_uid}")

    metadata = read_back(args.orthanc_url, study_uid)
    print(f"read back {len(metadata)} instance(s) from /dicom-web/studies/{{uid}}/metadata")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
