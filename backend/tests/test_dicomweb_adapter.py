"""The DICOMweb metadata client: one request shape, allowlisted output, typed failures.

Every test answers through an injected ``httpx.MockTransport``; nothing opens a
socket. The assertions are about what can go wrong: a request to a path other
than ``/metadata``, a non-allowlisted element reaching the output, a malformed
UID reaching the network, a guessed value for a missing keyword, and a response
body echoed into an error message.
"""

from __future__ import annotations

import httpx
import pytest

from medarx.api.schemas import AllowlistedDicomMetadata
from medarx.dicomweb import (
    ALLOWLIST,
    DicomwebResponseError,
    DicomwebStatusError,
    DicomwebTransportError,
    InvalidStudyUid,
    fetch_study_metadata,
)

STUDY = "1.2.826.0.1.3680043.8.498.11111111111111111111111111111111"
SECRET = "SYN^PATIENT-DO-NOT-ECHO"


def _el(vr: str, *values: str) -> dict:
    return {"vr": vr, "Value": list(values)}


def _instances() -> list[dict]:
    """Two instances of one study. Carries a non-allowlisted name and pixel-data reference."""
    common = {
        "00100020": _el("LO", "SYN-PAT-0001"),
        "00080050": _el("SH", "SYN-ACC-7"),
        "00080080": _el("LO", "SYNTHETIC HOSPITAL"),
        "00080020": _el("DA", "20260315"),
        "00101010": _el("AS", "063Y"),
        "00100010": _el("PN", SECRET),
        "7FE00010": {"vr": "OW", "BulkDataURI": "http://orthanc.test/pixels"},
    }
    first = {**common, "00080060": _el("CS", "CT")}
    second = {**common, "00080060": _el("CS", "CT")}
    return [first, second]


def _transport(status: int = 200, *, json_body: object = None, text: str | None = None):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if text is not None:
            return httpx.Response(status, text=text)
        return httpx.Response(status, json=json_body)

    return httpx.MockTransport(handler), seen


def test_one_get_to_metadata_path_and_nothing_else(monkeypatch):
    monkeypatch.delenv("MEDARX_ORTHANC_URL", raising=False)
    transport, seen = _transport(json_body=_instances())

    fetch_study_metadata(STUDY, transport=transport)

    assert len(seen) == 1
    request = seen[0]
    assert request.method == "GET"
    assert request.url.path == f"/dicom-web/studies/{STUDY}/metadata"
    assert request.url.query == b""
    assert str(request.url) == f"http://127.0.0.1:8042/dicom-web/studies/{STUDY}/metadata"


def test_base_url_comes_from_environment(monkeypatch):
    monkeypatch.setenv("MEDARX_ORTHANC_URL", "http://orthanc.test:9000/")
    transport, seen = _transport(json_body=_instances())

    fetch_study_metadata(STUDY, transport=transport)

    assert str(seen[0].url) == f"http://orthanc.test:9000/dicom-web/studies/{STUDY}/metadata"


def test_only_allowlisted_keywords_reach_the_output(monkeypatch):
    monkeypatch.delenv("MEDARX_ORTHANC_URL", raising=False)
    transport, _ = _transport(json_body=_instances())

    result = fetch_study_metadata(STUDY, transport=transport)

    assert set(result.values) <= set(ALLOWLIST)
    assert set(result.values) == {
        "PatientID",
        "AccessionNumber",
        "InstitutionName",
        "StudyDate",
        "PatientAge",
        "Modality",
    }
    assert result.values["PatientID"] == "SYN-PAT-0001"
    assert result.values["Modality"] == "CT"
    rendered = repr(result)
    assert SECRET not in rendered
    assert "BulkDataURI" not in rendered
    assert "orthanc.test/pixels" not in rendered


@pytest.mark.parametrize(
    "bad_uid",
    [
        "",
        "1..2",
        ".1.2",
        "1.2.",
        "1.2.03",
        "1.2.a",
        "1.2.3 ",
        " 1.2.3",
        "1.2.3\n",
        "1.2.3?x=1",
        "1.2.3/frames",
        "1.2.3/rendered",
        "1.2.3/../../system",
        "1.2.3/instances/4.5/frames/1",
        "1." + "2" * 63,
    ],
)
def test_malformed_uid_raises_before_any_request(bad_uid):
    transport, seen = _transport(json_body=_instances())

    with pytest.raises(InvalidStudyUid):
        fetch_study_metadata(bad_uid, transport=transport)

    assert seen == []


@pytest.mark.parametrize("good_uid", ["0", "1.0", "1." + "2" * 62])
def test_valid_dicom_uid_shapes_are_accepted(good_uid):
    transport, seen = _transport(json_body=[])

    fetch_study_metadata(good_uid, transport=transport)

    assert len(seen) == 1


def test_absent_keyword_is_reported_missing_not_filled(monkeypatch):
    monkeypatch.delenv("MEDARX_ORTHANC_URL", raising=False)
    instances = _instances()
    for instance in instances:
        del instance["00101010"]  # PatientAge
        instance["00080060"] = {"vr": "CS"}  # Modality present but empty
    transport, _ = _transport(json_body=instances)

    result = fetch_study_metadata(STUDY, transport=transport)

    assert "PatientAge" not in result.values
    assert "Modality" not in result.values
    assert "PatientAge" in result.missing
    assert "Modality" in result.missing
    # Not DICOM elements, so no instance can supply them.
    assert "PriorReportText" in result.missing
    assert "PriorStudyDate" in result.missing


def test_disagreeing_instances_are_reported_conflicting_not_picked(monkeypatch):
    monkeypatch.delenv("MEDARX_ORTHANC_URL", raising=False)
    instances = _instances()
    instances[1]["00080060"] = _el("CS", "PR")  # a second series with another modality
    transport, _ = _transport(json_body=instances)

    result = fetch_study_metadata(STUDY, transport=transport)

    assert "Modality" not in result.values
    assert result.conflicting == ("Modality",)


def test_keyword_set_matches_the_contract_schema():
    assert set(ALLOWLIST) == set(AllowlistedDicomMetadata.model_fields)


@pytest.mark.parametrize("status", [404, 500, 302])
def test_non_200_raises_typed_error_without_body(status):
    transport, _ = _transport(status, text=f"<html>{SECRET} Modality CT</html>")

    with pytest.raises(DicomwebStatusError) as info:
        fetch_study_metadata(STUDY, transport=transport)

    assert info.value.status_code == status
    assert SECRET not in str(info.value)
    assert "Modality" not in str(info.value)


def test_non_json_200_body_is_a_response_error_without_body():
    transport, _ = _transport(200, text=f"not json {SECRET}")

    with pytest.raises(DicomwebResponseError) as info:
        fetch_study_metadata(STUDY, transport=transport)

    assert SECRET not in str(info.value)


def test_non_list_json_is_a_response_error():
    transport, _ = _transport(json_body={"00100020": _el("LO", "SYN-PAT-0001")})

    with pytest.raises(DicomwebResponseError):
        fetch_study_metadata(STUDY, transport=transport)


def test_connection_failure_is_a_transport_error_without_study_uid():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    with pytest.raises(DicomwebTransportError) as info:
        fetch_study_metadata(STUDY, transport=httpx.MockTransport(handler))

    assert STUDY not in str(info.value)
