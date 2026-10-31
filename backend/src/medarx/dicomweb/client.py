"""The DICOMweb metadata client: the only path by which Medarx reads from Orthanc.

One request shape exists here and it is the only one the module can build:
``GET /dicom-web/studies/{StudyInstanceUID}/metadata``. The study UID is checked
against the DICOM UID grammar before any request is made, so no caller can reach
``/frames``, ``/rendered``, ``/thumbnail``, ``/bulkdata`` or an instance path by
passing a crafted identifier. Pixel data is therefore never requested.

The response is DICOM JSON. Only the eight keywords of
``AllowlistedDicomMetadata`` are read, and every other element is dropped
without being inspected for its value. A keyword no instance carries is reported
missing; a keyword the instances disagree on is reported conflicting. Neither is
filled with a guess.

Not wired into the pipeline or any route: Phase 2 does not require one.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

import httpx

__all__ = [
    "ALLOWLIST",
    "DEFAULT_ORTHANC_URL",
    "DicomwebError",
    "DicomwebResponseError",
    "DicomwebStatusError",
    "DicomwebTransportError",
    "InvalidStudyUid",
    "ORTHANC_URL_ENV",
    "StudyMetadata",
    "fetch_study_metadata",
]

ORTHANC_URL_ENV = "MEDARX_ORTHANC_URL"
DEFAULT_ORTHANC_URL = "http://127.0.0.1:8042"

TIMEOUT_S = 10.0

#: The eight keywords of ``AllowlistedDicomMetadata``, each mapped to the DICOM
#: tag Orthanc keys it under in DICOM JSON. ``None`` marks a keyword that is not
#: a DICOM element, so no instance can carry it and it is always reported missing.
ALLOWLIST: dict[str, str | None] = {
    "PatientID": "00100020",
    "AccessionNumber": "00080050",
    "InstitutionName": "00080080",
    "StudyDate": "00080020",
    "PatientAge": "00101010",
    "Modality": "00080060",
    "PriorReportText": None,
    "PriorStudyDate": None,
}

# DICOM UID grammar (PS3.5 §9.1): dot-separated numeric components, no leading
# zeros, at most 64 characters.
_DICOM_UID = re.compile(r"(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*))*")
_MAX_UID_LEN = 64


class DicomwebError(Exception):
    """Base of every failure this client raises.

    None of these carries a response body or a study identifier in its message,
    because the message reaches logs and a DICOM server's log is itself an
    identifier store.
    """


class InvalidStudyUid(DicomwebError):
    """The study identifier is not a DICOM UID. Raised before any request is made."""


class DicomwebTransportError(DicomwebError):
    """The request never produced an HTTP response: DNS, connect, or timeout."""


class DicomwebStatusError(DicomwebError):
    """Orthanc answered, and the answer was not 200. ``status_code`` is Orthanc's."""

    def __init__(self, status_code: int) -> None:
        self.status_code = status_code
        super().__init__(f"Orthanc answered {status_code} to the metadata request")


class DicomwebResponseError(DicomwebError):
    """Orthanc answered 200 with a body that is not DICOM JSON metadata."""


@dataclass(frozen=True)
class StudyMetadata:
    """One study's allowlisted metadata.

    ``values`` holds only keywords on which every instance that carries them
    agrees. ``missing`` and ``conflicting`` name the other allowlisted keywords;
    no value is supplied for either.
    """

    study_uid: str
    values: dict[str, str]
    missing: tuple[str, ...]
    conflicting: tuple[str, ...]


def _checked_uid(study_uid: str) -> str:
    if len(study_uid) > _MAX_UID_LEN or not _DICOM_UID.fullmatch(study_uid):
        raise InvalidStudyUid("the study identifier is not a dotted-numeric DICOM UID")
    return study_uid


def _root() -> str:
    base = os.environ.get(ORTHANC_URL_ENV) or DEFAULT_ORTHANC_URL
    return base.rstrip("/") + "/dicom-web"


def _element_value(element: object, keyword: str) -> str | None:
    """The string value of one DICOM JSON element, or ``None`` if it is empty."""
    if element is None:
        return None
    if not isinstance(element, dict):
        raise DicomwebResponseError(f"{keyword} is not a DICOM JSON element")
    raw = element.get("Value", [])
    if not isinstance(raw, list) or not all(isinstance(v, str) for v in raw):
        raise DicomwebResponseError(f"{keyword} carries a value that is not a string")
    # DICOM's own multi-value separator. An empty element yields "", i.e. missing.
    return "\\".join(raw) or None


def _reduce(study_uid: str, instances: object) -> StudyMetadata:
    if not isinstance(instances, list) or not all(isinstance(i, dict) for i in instances):
        raise DicomwebResponseError("the metadata body is not a list of DICOM JSON objects")
    found: dict[str, set[str]] = {keyword: set() for keyword in ALLOWLIST}
    for instance in instances:
        for keyword, tag in ALLOWLIST.items():
            if tag is None:
                continue
            value = _element_value(instance.get(tag), keyword)
            if value is not None:
                found[keyword].add(value)
    values: dict[str, str] = {}
    missing: list[str] = []
    conflicting: list[str] = []
    for keyword, seen in found.items():
        if not seen:
            missing.append(keyword)
        elif len(seen) > 1:
            conflicting.append(keyword)
        else:
            values[keyword] = seen.pop()
    return StudyMetadata(study_uid, values, tuple(missing), tuple(conflicting))


def fetch_study_metadata(
    study_uid: str, *, transport: httpx.BaseTransport | None = None
) -> StudyMetadata:
    """Fetch one study's allowlisted metadata with a single GET.

    ``transport`` is injectable so a test can answer without a network. Without
    it, the request goes to ``MEDARX_ORTHANC_URL`` (default ``127.0.0.1:8042``).
    """
    uid = _checked_uid(study_uid)
    url = f"{_root()}/studies/{uid}/metadata"
    # trust_env=False: a proxy named in the environment must not carry study
    # identifiers off-host.
    with httpx.Client(transport=transport, timeout=TIMEOUT_S, trust_env=False) as client:
        try:
            response = client.get(url, headers={"Accept": "application/dicom+json"})
        except httpx.HTTPError as exc:
            raise DicomwebTransportError(
                f"Orthanc could not be reached: {type(exc).__name__}"
            ) from exc
    if response.status_code != 200:
        raise DicomwebStatusError(response.status_code)
    try:
        instances = response.json()
    except ValueError as exc:
        raise DicomwebResponseError("the metadata body is not JSON") from exc
    return _reduce(uid, instances)
