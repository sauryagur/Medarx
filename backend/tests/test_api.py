"""Component J: the HTTP surface, exercised as a caller exercises it.

**Every assertion here is about the wire.** A test that drove the pipeline
directly would pass against a route that skipped every check; these go through
`POST /v1/functions/{name}/executions` and read the response.

The load-bearing claims in this file:

- a caller can tell a privacy block from an authorization failure **by status
  code alone** (422 against 403), which is the design's own §6 requirement and
  the reason `AuthzError` sits outside the `MedarxError` taxonomy;
- a request refused for its shape never enters the pipeline, asserted by
  watching the pipeline's own entry point rather than by reading a status;
- a 422 means **nothing was sent**, asserted against the loopback stub's record
  of what reached a socket rather than against a mock's call log;
- the served OpenAPI document *is* the tracked contract, compared after parsing
  rather than by eye.
"""

from __future__ import annotations

import json
import logging
from io import StringIO
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from conftest import (
    EXEC_URL,
    KEY,
    KNOWN_POSITIVE_BODY,
    SCOPE,
    SCOPE_HEADERS,
    StubProvider,
    body_with,
    body_with_dicom,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
CONTRACT = REPO_ROOT / "contracts" / "openapi.yaml"

#: A body the kernel refuses at component C: `20260230` matches the contract's
#: `DicomDate` pattern (eight digits) and is not a real calendar day, so it gets
#: past the schema and is refused where the shift happens.
UNSHIFTABLE_DATE_BODY = body_with_dicom(StudyDate="20260230")


# -- The approved path --------------------------------------------------------


def test_approved_request_returns_200_with_request_id_and_draft(client):
    r = client.post(EXEC_URL, json=KNOWN_POSITIVE_BODY, headers=SCOPE_HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "approved"
    assert body["request_id"]
    assert body["approved_payload_hash"].startswith("sha256:")
    assert body["draft"]["content"]
    assert body["policy_version"] == "medarx-policy-1.0.0"
    assert body["selected_model"] == "medarx-demo-model"


def test_the_approved_response_validates_as_the_contract_execution_response(client):
    """Key for key, so a field the contract does not declare cannot ride along."""
    from medarx.api.schemas import ExecutionResponse

    r = client.post(EXEC_URL, json=KNOWN_POSITIVE_BODY, headers=SCOPE_HEADERS)
    assert r.status_code == 200
    ExecutionResponse.model_validate(r.json())


def test_the_response_stores_the_contract_spelling_of_the_function(client):
    """`Draft` on the wire and in the record; `draft` only inside the kernel.

    One fact, one spelling, in the artefact a human reads next to the contract.
    """
    from medarx.extraction.allowlists import ALLOWED_FIELDS

    r = client.post(EXEC_URL, json=body_with(function="Draft"), headers=SCOPE_HEADERS)
    assert r.status_code == 200
    assert r.json()["function"] == "Draft"
    record = client.get(f"/v1/audit/records/{r.json()['request_id']}",
                        headers=SCOPE_HEADERS).json()
    assert record["function"] == "Draft"
    # Two spellings of one fact, and the record carries the contract's. The
    # kernel's own table is the other one, so the two are read from their
    # sources rather than written out here.
    assert "draft" in ALLOWED_FIELDS
    assert "Draft" not in ALLOWED_FIELDS


def test_nothing_planted_in_the_request_reaches_the_wire(client, provider):
    """The synthetic MRN and accession are in the request and absent from the bytes."""
    before = len(provider.requests)
    r = client.post(EXEC_URL, json=KNOWN_POSITIVE_BODY, headers=SCOPE_HEADERS)
    assert r.status_code == 200
    assert len(provider.requests) == before + 1
    sent = provider.requests[-1].body
    assert b"4452819" not in sent
    assert b"ACC0000417" not in sent
    assert json.loads(sent)["model"] == "medarx-demo-model"


def test_the_bytes_the_gateway_records_are_the_bytes_the_stub_received(client, provider,
                                                                      pipeline):
    """Two observers, and they agree: the gateway's record and the socket's."""
    client.post(EXEC_URL, json=KNOWN_POSITIVE_BODY, headers=SCOPE_HEADERS)
    assert pipeline.gateway.last_request_body() == provider.requests[-1].body


def test_the_approved_payload_hash_is_a_digest_of_the_approved_payload(client, pipeline):
    """`sha256:`-prefixed on the wire, because the contract publishes that form."""
    from medarx.audit.audit_log import DIGEST, PREFIXED_DIGEST

    r = client.post(EXEC_URL, json=KNOWN_POSITIVE_BODY, headers=SCOPE_HEADERS)
    wire = r.json()["approved_payload_hash"]
    assert PREFIXED_DIGEST.fullmatch(wire), wire
    stored = pipeline.audit.get(r.json()["request_id"])[0].approved_payload_hash
    assert DIGEST.fullmatch(stored) and wire == f"sha256:{stored}"


# -- The request id header ----------------------------------------------------


def test_a_supplied_request_id_is_honoured_and_echoed(client):
    r = client.post(EXEC_URL, json=KNOWN_POSITIVE_BODY,
                    headers={**SCOPE_HEADERS, "X-Request-Id": "req-fixed-0001"})
    assert r.status_code == 200
    assert r.json()["request_id"] == "req-fixed-0001"
    assert r.headers["X-Request-Id"] == "req-fixed-0001"
    assert client.get("/v1/audit/records/req-fixed-0001",
                      headers=SCOPE_HEADERS).status_code == 200


def test_an_absent_request_id_is_generated_once_per_request(client):
    first = client.post(EXEC_URL, json=KNOWN_POSITIVE_BODY, headers=SCOPE_HEADERS)
    second = client.post(EXEC_URL, json=KNOWN_POSITIVE_BODY, headers=SCOPE_HEADERS)
    assert first.json()["request_id"] != second.json()["request_id"]
    for response in (first, second):
        assert response.headers["X-Request-Id"] == response.json()["request_id"]


def test_the_request_id_is_present_on_a_block_too(client):
    r = client.post(EXEC_URL, json=UNSHIFTABLE_DATE_BODY,
                    headers={**SCOPE_HEADERS, "X-Request-Id": "req-block-0001"})
    assert r.status_code == 422
    assert r.json()["request_id"] == "req-block-0001"
    assert r.headers["X-Request-Id"] == "req-block-0001"


def test_the_request_id_is_present_on_a_malformed_request_too(client):
    """A header still reaches the surface when the body is unusable."""
    r = client.post(EXEC_URL, content=b"{not json",
                    headers={**SCOPE_HEADERS, "X-Request-Id": "req-bad-0001",
                             "Content-Type": "application/json"})
    assert r.status_code == 400
    assert r.json()["request_id"] == "req-bad-0001"


def test_a_request_id_the_audit_log_could_not_hold_is_refused_not_stored(client):
    """A space in the request ID would be a `ValueError` at the audit write.

    Caught at the boundary it is a 400 with a problem document; uncaught it is a
    500 that reads as a server fault. The audit log holds request IDs to
    `medarx.audit.audit_log.IDENTIFIER`, and a caller naming one the log cannot
    carry is told so.
    """
    r = client.post(EXEC_URL, json=KNOWN_POSITIVE_BODY,
                    headers={**SCOPE_HEADERS, "X-Request-Id": "req with a space"})
    assert r.status_code == 400
    assert r.json()["type"].startswith("https://medarx.invalid/problems/")


# -- Authorization: 403, never 422 ------------------------------------------


def test_out_of_scope_study_returns_403_not_422(client):
    r = client.post(EXEC_URL, json=KNOWN_POSITIVE_BODY,
                    headers={"X-Scope": "scope:study:STUDY-SYN-999999,"
                                        "scope:function:Draft"})
    assert r.status_code == 403
    assert r.json()["type"].endswith("/study-scope-unauthorized")


def test_unpermitted_function_returns_403(client):
    r = client.post("/v1/functions/Ask/executions", json=KNOWN_POSITIVE_BODY,
                    headers={"X-Scope": "scope:study:STUDY-SYN-000041,"
                                        "scope:function:Draft"})
    assert r.status_code == 403
    assert r.json()["type"].endswith("/function-not-permitted")


def test_an_absent_scope_header_grants_nothing(client):
    """The header names the scopes the caller holds; naming none means it holds none."""
    assert client.post(EXEC_URL, json=KNOWN_POSITIVE_BODY).status_code == 403


def test_an_empty_scope_header_grants_nothing(client):
    assert client.post(EXEC_URL, json=KNOWN_POSITIVE_BODY,
                       headers={"X-Scope": ""}).status_code == 403


def test_a_scope_token_the_grammar_does_not_recognise_grants_nothing(client):
    """Fail closed on an unreadable header rather than guessing at what it meant."""
    assert client.post(EXEC_URL, json=KNOWN_POSITIVE_BODY,
                       headers={"X-Scope": "scope:draft-only"}).status_code == 403


def test_a_caller_can_tell_403_from_422_by_status_code_alone(client, provider):
    before = len(provider.requests)
    blocked = client.post(EXEC_URL, json=UNSHIFTABLE_DATE_BODY,
                          headers=SCOPE_HEADERS).status_code
    scope = client.post(EXEC_URL, json=KNOWN_POSITIVE_BODY).status_code
    assert (blocked, scope) == (422, 403)
    assert len(provider.requests) == before, "a 422 and a 403 must send nothing"


def test_a_refused_scope_is_recorded_as_an_authorization_refusal(client):
    r = client.post(EXEC_URL, json=KNOWN_POSITIVE_BODY, headers={"X-Scope": ""})
    record = client.get(f"/v1/audit/records/{r.headers['X-Request-Id']}",
                        headers=SCOPE_HEADERS).json()
    assert record["final_disposition"] == "blocked"
    assert record["layer"] == "J"
    assert record["action_codes"] == ["UNAUTHORIZED_SCOPE"]
    # No pipeline stage was ever behind this request, which is what layer `J`
    # means in the contract's `Layer` enum: the surface refused before the
    # pipeline started. A reader of this record is therefore not looking at a
    # privacy block that happened late — at a refusal that happened first.
    assert record["stages"] == []


def test_a_refused_function_is_recorded_with_its_own_code(client):
    r = client.post("/v1/functions/Ask/executions", json=KNOWN_POSITIVE_BODY,
                    headers={"X-Scope": "scope:study:STUDY-SYN-000041,"
                                        "scope:function:Draft"})
    record = client.get(f"/v1/audit/records/{r.headers['X-Request-Id']}",
                        headers=SCOPE_HEADERS).json()
    assert record["action_codes"] == ["FUNCTION_NOT_PERMITTED"]


# -- The surface refuses shapes it cannot express ----------------------------


def test_free_form_prompt_is_rejected_as_malformed(client, entered):
    r = client.post(EXEC_URL, json=body_with(prompt="summarize this in French"),
                    headers=SCOPE_HEADERS)
    assert r.status_code == 400
    assert r.json()["type"].startswith("https://medarx.invalid/problems/")
    assert any(e["field"] == "body.prompt" for e in r.json()["errors"])
    assert entered == [], "the pipeline was entered for a body it cannot express"


def test_arbitrary_dicom_object_property_is_rejected_as_malformed(client, entered):
    r = client.post(EXEC_URL, json=body_with(dicom_object={"PixelData": "AAAA"}),
                    headers=SCOPE_HEADERS)
    assert r.status_code == 400
    assert any(e["field"] == "body.dicom_object" for e in r.json()["errors"])
    assert entered == []


def test_raw_pixel_data_property_is_rejected_as_malformed(client, entered):
    r = client.post(EXEC_URL, json=body_with(pixel_data="AAAA"), headers=SCOPE_HEADERS)
    assert r.status_code == 400
    assert entered == []


def test_a_request_cannot_select_its_own_policy_mode(client, entered):
    r = client.post(EXEC_URL, json=body_with(policy_mode="authorized_local"),
                    headers=SCOPE_HEADERS)
    assert r.status_code == 400
    assert any(e["field"] == "body.policy_mode" for e in r.json()["errors"])
    assert entered == []


def test_a_dicom_field_outside_the_closed_set_is_rejected_as_malformed(client):
    """`AllowlistedDicomMetadata` is closed: an unknown keyword is a 400.

    This is the structural expression of "no arbitrary DICOM object", and it is
    a 400 rather than a 422 block because the body never matched the request
    schema — the contract's `ExecutionRequest` description says so by name.
    """
    r = client.post(EXEC_URL, json=body_with_dicom(PatientName="DOE^JANE"),
                    headers=SCOPE_HEADERS)
    assert r.status_code == 400


def test_a_dicom_date_that_is_not_a_dicom_date_is_rejected_as_malformed(client):
    """The contract's `DicomDate` pattern states the shape; the body must match it."""
    r = client.post(EXEC_URL, json=body_with_dicom(StudyDate="2026-01-14"),
                    headers=SCOPE_HEADERS)
    assert r.status_code == 400


def test_an_oversized_body_is_rejected_400(client, pipeline):
    big = body_with_dicom(InstitutionName="x" * (pipeline.settings.max_body_bytes + 1))
    r = client.post(EXEC_URL, json=big, headers=SCOPE_HEADERS)
    assert r.status_code == 400
    assert r.json()["type"].endswith("/malformed-request")


def test_an_oversized_body_is_rejected_even_without_a_content_length(client, pipeline):
    """The header check is early; the measured length is the one that cannot lie.

    A chunked request carries no `Content-Length`, so a guard reading only the
    header would pass an oversized body straight through. Both are checked, and
    this is the one that fails when only the header is read.
    """
    payload = body_with_dicom(InstitutionName="x" * (pipeline.settings.max_body_bytes + 1))
    r = client.post(EXEC_URL, content=_chunked(payload), headers={
        **SCOPE_HEADERS, "Content-Type": "application/json",
    })
    assert r.status_code == 400


def _chunked(payload: dict):
    """A generator body, sent chunked, so no `Content-Length` is sent."""
    text = json.dumps(payload)

    def chunks():
        for start in range(0, len(text), 64_000):
            yield text[start:start + 64_000].encode()

    return chunks()


def test_an_unparseable_body_is_a_problem_detail(client):
    r = client.post(EXEC_URL, content=b"{not json",
                    headers={**SCOPE_HEADERS, "Content-Type": "application/json"})
    assert r.status_code == 400
    assert r.json()["type"].endswith("/malformed-request")


def test_a_non_json_content_type_is_415(client):
    r = client.post(EXEC_URL, content=b"report text",
                    headers={**SCOPE_HEADERS, "Content-Type": "text/plain"})
    assert r.status_code == 415


def test_an_unknown_function_name_in_the_path_is_404(client, entered):
    r = client.post("/v1/functions/Summarize/executions",
                    json=KNOWN_POSITIVE_BODY, headers=SCOPE_HEADERS)
    assert r.status_code == 404
    assert r.json()["type"].endswith("/function-not-found")
    assert entered == []


def test_a_shape_refusal_names_the_smuggle_it_refused(client):
    """The two action codes the contract's row-1 example advertises are emitted.

    They land on the audit record, because the response to a schema violation is
    a `ProblemDetail` and the contract's `ExecutionRequest` description calls
    that a `400`. The codes are not the response's business; the record's is.
    """
    r = client.post(EXEC_URL, json=body_with(dicom_object={"PixelData": "AAAA"},
                                             prompt="translate this"),
                    headers=SCOPE_HEADERS)
    assert r.status_code == 400
    record = client.get(f"/v1/audit/records/{r.headers['X-Request-Id']}",
                        headers=SCOPE_HEADERS).json()
    assert record["action_codes"] == ["ARBITRARY_DICOM_OBJECT_REJECTED",
                                      "FREE_FORM_PROMPT_REJECTED"]
    assert record["layer"] == "J"


# -- Policy inspection -------------------------------------------------------


def test_policy_route_matches_the_contract(client):
    pol = client.get("/v1/policy").json()
    assert pol["policy_mode"] == "cloud"
    assert pol["policy_version"] == "medarx-policy-1.0.0"
    assert set(pol["implemented_modes"]) == {"strict_local", "cloud"}
    assert pol["fail_closed"] is True
    assert pol["extensions"][0]["name"] == "authorized_local"
    assert pol["extensions"][0]["implemented"] is False


def test_the_policy_mode_is_the_deployments_and_not_the_callers(client, pipeline):
    """Two requests cannot move the mode, and the surface reports the deployed one.

    `Settings` is frozen and `PolicyEngine.decide` takes no mode parameter, so
    asserting the response equals the engine's own reading is what makes "per
    deployment, fixed" an observed fact rather than a comment.
    """
    assert client.get("/v1/policy").json()["policy_mode"] == pipeline.policy.mode


def test_the_policy_route_needs_no_scope(client):
    """The contract declares no 403 on `/v1/policy`, and none is returned.

    Declared-but-unreachable responses are drift; this asserts the surface does
    not invent one the contract did not ask for.
    """
    assert client.get("/v1/policy").status_code == 200


# -- Audit readback ----------------------------------------------------------


def test_audit_readback_never_contains_the_raw_identifier(client):
    r = client.post(EXEC_URL, json=KNOWN_POSITIVE_BODY, headers=SCOPE_HEADERS)
    rec = client.get(f"/v1/audit/records/{r.json()['request_id']}",
                     headers=SCOPE_HEADERS)
    assert rec.status_code == 200
    assert rec.json()["final_disposition"] == "pending_human_approval"
    assert rec.json()["chain_verified"] is True
    assert "4452819" not in rec.text
    assert "ACC0000417" not in rec.text


def test_the_audit_record_never_carries_a_field_the_storage_policy_forbids(client):
    from medarx.audit.audit_log import ALLOWED_AUDIT_FIELDS

    r = client.post(EXEC_URL, json=KNOWN_POSITIVE_BODY, headers=SCOPE_HEADERS)
    record = client.get(f"/v1/audit/records/{r.json()['request_id']}",
                        headers=SCOPE_HEADERS).json()
    derived_on_read = {"chain_verified", "stages"}
    assert set(record) - derived_on_read <= ALLOWED_AUDIT_FIELDS


def test_stages_are_derived_from_the_layer_and_not_stored(client):
    r = client.post(EXEC_URL, json=UNSHIFTABLE_DATE_BODY, headers=SCOPE_HEADERS)
    record = client.get(f"/v1/audit/records/{r.json()['request_id']}",
                        headers=SCOPE_HEADERS).json()
    assert record["layer"] == "C"
    assert record["stages"] == ["Fields selected", "Pseudonymized"]


def test_an_approved_record_reached_every_stage(client):
    r = client.post(EXEC_URL, json=KNOWN_POSITIVE_BODY, headers=SCOPE_HEADERS)
    record = client.get(f"/v1/audit/records/{r.json()['request_id']}",
                        headers=SCOPE_HEADERS).json()
    assert record["layer"] is None
    assert record["stages"] == ["Fields selected", "Pseudonymized", "Text screened",
                                "Payload validated", "Policy decision", "Model request"]


def test_audit_collection_filters_by_request_id(client):
    r = client.post(EXEC_URL, json=KNOWN_POSITIVE_BODY, headers=SCOPE_HEADERS)
    rid = r.json()["request_id"]
    coll = client.get("/v1/audit/records", params={"request_id": rid},
                      headers=SCOPE_HEADERS).json()
    assert {rec["request_id"] for rec in coll["records"]} == {rid}
    assert coll["count"] == len(coll["records"])
    assert coll["chain_verified"] is True


def test_audit_collection_filters_by_function_and_disposition(client):
    r = client.post(EXEC_URL, json=KNOWN_POSITIVE_BODY, headers=SCOPE_HEADERS)
    rid = r.json()["request_id"]
    by_function = client.get("/v1/audit/records", params={"function": "Draft"},
                             headers=SCOPE_HEADERS).json()
    assert rid in {rec["request_id"] for rec in by_function["records"]}
    by_disposition = client.get(
        "/v1/audit/records", params={"disposition": "pending_human_approval"},
        headers=SCOPE_HEADERS).json()
    assert rid in {rec["request_id"] for rec in by_disposition["records"]}


def test_an_audit_filter_outside_its_closed_enum_is_400_not_an_empty_page(client):
    """A typo in a query must not look like a request with no records.

    `draft` is the kernel's internal spelling, and the readback speaks the
    contract's vocabulary: one spelling per fact, even when the caller has to be
    told which one.
    """
    r = client.get("/v1/audit/records", params={"function": "draft"},
                   headers=SCOPE_HEADERS)
    assert r.status_code == 400
    assert "Draft" in r.json()["detail"]


def test_a_limit_outside_the_contract_range_is_400(client):
    assert client.get("/v1/audit/records", params={"limit": 0},
                      headers=SCOPE_HEADERS).status_code == 400
    assert client.get("/v1/audit/records", params={"limit": 501},
                      headers=SCOPE_HEADERS).status_code == 400


def test_an_unknown_audit_record_is_404(client):
    r = client.get("/v1/audit/records/req-does-not-exist", headers=SCOPE_HEADERS)
    assert r.status_code == 404
    assert r.json()["type"].endswith("/audit-record-not-found")


def test_the_audit_readback_is_behind_the_authorization_surface(client):
    assert client.get("/v1/audit/records").status_code == 403
    assert client.get("/v1/audit/records/anything").status_code == 403
    assert client.get("/v1/audit/records", headers=SCOPE_HEADERS).status_code == 200


def test_an_undeclared_audit_filter_is_refused_rather_than_ignored(client):
    """A caller who believes they scoped a readback have not.

    Silently dropping `?study_reference=` would return the **whole** page — a
    wider result than was asked for — and the response body has no field that
    says the filter was dropped. So an undeclared parameter is a `400`, the same
    answer an out-of-enum value gets.
    """
    from medarx.api.routes_audit import ALLOWED_QUERY_PARAMETERS

    client.post(EXEC_URL, json=KNOWN_POSITIVE_BODY, headers=SCOPE_HEADERS)
    for name, value in (("study_reference", "STUDY-SYN-000041"),
                        ("patient_reference", "PAT-0001"),
                        ("requeste_id", "typo")):
        response = client.get("/v1/audit/records", params={name: value},
                              headers=SCOPE_HEADERS)
        assert response.status_code == 400, name
        assert name in response.json()["detail"]
    assert "study_reference" not in ALLOWED_QUERY_PARAMETERS


def test_the_audit_readback_cannot_filter_by_study_because_the_record_cannot_carry_one(
    client,
):
    """The limitation, asserted so it cannot be mistaken for a missing feature.

    A study-scoped readback is not implemented in Phase 1, and the reason is a
    privacy decision rather than an omission: the storage policy has no study
    field to filter on, the contract's `AuditRecord` is closed and has none
    either, and adding one would put a study identifier into a log that is
    required never to hold one.
    """
    from medarx.api.schemas import AuditRecord
    from medarx.audit.audit_log import ALLOWED_AUDIT_FIELDS
    from medarx.models import AuditEvent

    assert not {"study_reference", "study_ref"} & set(ALLOWED_AUDIT_FIELDS)
    assert "study_reference" not in AuditEvent.model_fields
    assert "study_reference" not in AuditRecord.model_fields
    served = client.get("/openapi.json").json()["paths"]["/v1/audit/records"]["get"]
    assert "not study-scoped" in served["description"]
    declared = {
        q["$ref"].rsplit("/", 1)[-1] if "$ref" in q else q["name"]
        for q in served["parameters"]
    }
    assert declared == {
        "ScopeHeader", "RequestIdQueryParam", "FunctionQueryParam",
        "DispositionQueryParam", "SinceQueryParam", "LimitQueryParam",
    }


# -- The per-patient date shift, measured on the wire ------------------------


def _outbound_study_date(provider):
    """The `study_date` the provider actually received on the last request."""
    body = json.loads(provider.requests[-1].body)
    user = [m for m in body["messages"] if m["role"] == "user"][0]["content"]
    for line in user.splitlines():
        if line.startswith("Allowlisted metadata:"):
            return json.loads(line.split(": ", 1)[1])["study_date"]
    raise AssertionError("no study_date reached the provider")


def _wire_interval(after, before):
    from datetime import date

    def as_date(value):
        return date(int(value[0:4]), int(value[4:6]), int(value[6:8]))

    return (as_date(after) - as_date(before)).days


def test_two_studies_of_one_patient_keep_their_interval(client, provider):
    """Design §3 C: "the date shift preserves sequence and duration".

    Measured at the socket, across two requests for two studies of one patient
    seven days apart. **Before `StudyContext.patient_reference` existed this was
    213 days** — two unrelated per-study offsets of opposite sign, which is a
    guarantee that inverts rather than one that weakens. A caller who says which
    patient they mean gets the design's invariant; a caller who says nothing
    gets a documented degradation, and neither gets a silent one.
    """
    first, second = "STUDY-SYN-000041", "STUDY-SYN-000042"
    outbound = []
    for study, sent in ((first, "20260114"), (second, "20260121")):
        response = client.post(EXEC_URL, json={
            "study_context": {"study_reference": study,
                              "patient_reference": "PAT-SYN-000041"},
            "report_text": {"text": "FINDINGS: 7 mm nodule."},
            "dicom_metadata": {"Modality": "CT", "StudyDate": sent},
        }, headers={"X-Scope": f"scope:study:{study},scope:function:Draft"})
        assert response.status_code == 200, response.text
        outbound.append(_outbound_study_date(provider))
    assert _wire_interval(outbound[1], outbound[0]) == 7


def test_a_shared_patient_id_also_preserves_the_interval(client, provider):
    """The second source, so neither of the two fallbacks is decorative."""
    outbound = []
    for study in ("STUDY-SYN-000041", "STUDY-SYN-000042"):
        response = client.post(EXEC_URL, json={
            "study_context": {"study_reference": study},
            "report_text": {"text": "FINDINGS: 7 mm nodule."},
            "dicom_metadata": {"Modality": "CT", "StudyDate": "20260114",
                               "PatientID": "PAT-SYN-000041"},
        }, headers={"X-Scope": f"scope:study:{study},scope:function:Draft"})
        assert response.status_code == 200, response.text
        outbound.append(_outbound_study_date(provider))
    assert _wire_interval(outbound[1], outbound[0]) == 0


def test_the_patient_reference_is_never_carried_to_the_provider(client, provider):
    """A pseudonymization key: used to choose a shift, then nowhere else."""
    before = len(provider.requests)
    response = client.post(EXEC_URL, json={
        "study_context": {"study_reference": "STUDY-SYN-000041",
                          "patient_reference": "PAT-SYN-000041"},
        "report_text": {"text": "FINDINGS: 7 mm nodule."},
        "dicom_metadata": {"Modality": "CT", "StudyDate": "20260114"},
    }, headers=SCOPE_HEADERS)
    assert response.status_code == 200
    sent = provider.requests[-1].body
    assert b"PAT-SYN-000041" not in sent
    assert "PAT-SYN-000041" not in client.get(
        f"/v1/audit/records/{response.json()['request_id']}",
        headers=SCOPE_HEADERS).text


def test_the_patient_reference_is_never_recorded_in_the_audit_log(client):
    """The audit store has no field for a subject reference, and must not gain one."""
    from medarx.audit.audit_log import ALLOWED_AUDIT_FIELDS

    assert not {"patient_reference", "patient_ref", "subject"} & set(
        ALLOWED_AUDIT_FIELDS)
    response = client.post(EXEC_URL, json={
        "study_context": {"study_reference": "STUDY-SYN-000041",
                          "patient_reference": "PAT-SYN-000041"},
        "report_text": {"text": "FINDINGS: 7 mm nodule."},
        "dicom_metadata": {"Modality": "CT", "StudyDate": "20260114"},
    }, headers=SCOPE_HEADERS)
    assert response.status_code == 200
    assert "PAT-SYN-000041" not in client.get(
        f"/v1/audit/records/{response.json()['request_id']}",
        headers=SCOPE_HEADERS).text


# -- Human approval ----------------------------------------------------------


def test_human_approval_is_recorded_and_never_automatic(client):
    r = client.post(EXEC_URL, json=KNOWN_POSITIVE_BODY, headers=SCOPE_HEADERS)
    rid = r.json()["request_id"]
    before = client.get(f"/v1/audit/records/{rid}", headers=SCOPE_HEADERS).json()
    assert before["human_approval"] is None
    approval = client.post(f"/v1/executions/{rid}/approval",
                           json={"decision": "approved",
                                 "reviewer": "synthetic-reviewer-01"},
                           headers=SCOPE_HEADERS)
    assert approval.status_code == 200
    assert approval.json()["request_id"] == rid
    assert approval.json()["final_disposition"] == "approved_by_human"
    after = client.get(f"/v1/audit/records/{rid}", headers=SCOPE_HEADERS).json()
    assert after["human_approval"]["decision"] == "approved"
    assert after["human_approval"]["reviewer"] == "synthetic-reviewer-01"
    assert after["final_disposition"] == "approved_by_human"


def test_a_second_decision_is_409_because_the_log_is_append_only(client):
    r = client.post(EXEC_URL, json=KNOWN_POSITIVE_BODY, headers=SCOPE_HEADERS)
    rid = r.json()["request_id"]
    assert client.post(f"/v1/executions/{rid}/approval",
                       json={"decision": "approved", "reviewer": "rev-01"},
                       headers=SCOPE_HEADERS).status_code == 200
    second = client.post(f"/v1/executions/{rid}/approval",
                         json={"decision": "rejected", "reviewer": "rev-01"},
                         headers=SCOPE_HEADERS)
    assert second.status_code == 409


def test_a_rejection_is_recorded_as_a_final_disposition_not_a_deletion(client):
    r = client.post(EXEC_URL, json=KNOWN_POSITIVE_BODY, headers=SCOPE_HEADERS)
    rid = r.json()["request_id"]
    client.post(f"/v1/executions/{rid}/approval",
                json={"decision": "rejected", "reviewer": "rev-01"},
                headers=SCOPE_HEADERS)
    record = client.get(f"/v1/audit/records/{rid}", headers=SCOPE_HEADERS).json()
    assert record["final_disposition"] == "rejected_by_human"
    assert record["human_approval"]["decision"] == "rejected"


def test_approving_an_unknown_request_id_is_404(client):
    r = client.post("/v1/executions/req-nope/approval",
                    json={"decision": "approved", "reviewer": "rev-01"},
                    headers=SCOPE_HEADERS)
    assert r.status_code == 404
    assert r.json()["type"].endswith("/execution-not-found")


def test_an_approval_accepts_no_draft_content(client):
    """The endpoint records a judgement; it does not edit or resubmit a draft."""
    r = client.post(EXEC_URL, json=KNOWN_POSITIVE_BODY, headers=SCOPE_HEADERS)
    rid = r.json()["request_id"]
    bad = client.post(f"/v1/executions/{rid}/approval",
                      json={"decision": "approved", "reviewer": "rev-01",
                            "content": "a rewritten draft"},
                      headers=SCOPE_HEADERS)
    assert bad.status_code == 400


def test_a_reviewer_note_reaches_a_filtered_log_surface_and_not_the_audit_store(client,
                                                                                pipeline):
    """The contract's note has nowhere in the audit schema to go, and says so.

    `HumanApprovalState` is closed and has no `note`, and the storage policy has
    no field for one. So the note goes where the contract's own description
    sends it — "subject to the same sensitive-data filtering as every other log
    surface" — and the audit record proves it was not stored there.
    """
    r = client.post(EXEC_URL, json=KNOWN_POSITIVE_BODY, headers=SCOPE_HEADERS)
    rid = r.json()["request_id"]
    approved = client.post(f"/v1/executions/{rid}/approval",
                           json={"decision": "approved", "reviewer": "rev-01",
                                 "note": "MRN 4452819 checked against the ward list."},
                           headers=SCOPE_HEADERS)
    assert approved.status_code == 200
    record = client.get(f"/v1/audit/records/{rid}", headers=SCOPE_HEADERS)
    assert "4452819" not in record.text
    assert "note" not in record.json()["human_approval"]


def test_approving_a_blocked_request_is_404(client):
    """A refused request has no draft, so there is nothing to sign off."""
    r = client.post(EXEC_URL, json=UNSHIFTABLE_DATE_BODY, headers=SCOPE_HEADERS)
    assert r.status_code == 422
    rid = r.json()["request_id"]
    assert client.post(f"/v1/executions/{rid}/approval",
                       json={"decision": "approved", "reviewer": "rev-01"},
                       headers=SCOPE_HEADERS).status_code == 404


# -- Provider failures are availability, not privacy -------------------------


def test_a_provider_outage_is_500_and_leaves_no_privacy_block(tmp_path):
    """A provider being down is not a block, so it is not recorded as one.

    Built as its own application over its own stub, because the shared stub
    answers 200 and a failure must not leak into another test.
    """
    from medarx.api.app import create_app
    from medarx.config import Settings

    with StubProvider(status=503, body=b'{"error":"down"}') as down:
        app = create_app(
            Settings(audit_key=KEY, date_order="MDY", gateway_base_url=down.base_url),
            f"sqlite:///{tmp_path / 'outage.db'}",
        )
        c = TestClient(app)
        assert c.post(EXEC_URL, json=KNOWN_POSITIVE_BODY,
                      headers=SCOPE_HEADERS).status_code == 500
        # The request reached the socket and nothing came back: that is what
        # distinguishes a provider outage from a privacy block, which sends
        # nothing at all.
        assert len(down.requests) == 1
        assert c.get("/v1/audit/records", headers=SCOPE_HEADERS).json()["records"] == []


def test_an_unexpected_server_failure_is_a_problem_detail_not_a_traceback(client,
                                                                        pipeline):
    def explode(*args, **kwargs):
        raise RuntimeError("boom")

    pipeline.run = explode
    r = client.post(EXEC_URL, json=KNOWN_POSITIVE_BODY, headers=SCOPE_HEADERS)
    assert r.status_code == 500
    assert r.json()["type"].endswith("/internal-error")
    assert "boom" not in r.text
    assert "Traceback" not in r.text


# -- The served contract -----------------------------------------------------


def test_the_served_openapi_document_is_the_tracked_contract(client):
    served = client.get("/openapi.json").json()
    with CONTRACT.open(encoding="utf-8") as fh:
        tracked = yaml.safe_load(fh)
    assert served == tracked


def test_the_served_document_declares_no_authentication(client):
    """`security: []` is the honest representation of Phase 1 scope."""
    served = client.get("/openapi.json").json()
    assert served["security"] == []
    assert served["components"]["securitySchemes"] == {}


# -- The log filter reaches this application's own loggers -------------------


@pytest.mark.parametrize("name", [
    "medarx.api",
    "medarx.api.approval",
    "medarx.api.errors",
    "uvicorn",
    "uvicorn.error",
    "uvicorn.access",
])
def test_every_application_logger_carries_the_installed_filter(client, name):
    """`install_filter` covers the root logger and the SDK loggers, not these.

    A logger filter is not inherited, so this application's own records are
    covered only because `create_app` attached the filter to each name in
    `APPLICATION_LOGGERS`. The list is asserted against that constant rather than
    against a hard-coded copy, so a logger added to one and forgotten in the other
    fails here. A logger created after `install_filter` and not named there is
    **not** covered, and nothing in this package claims otherwise.
    """
    from medarx.api.app import APPLICATION_LOGGERS
    from medarx.logging_filter import SensitiveDataFilter

    assert name in APPLICATION_LOGGERS
    logger = logging.getLogger(name)
    assert any(isinstance(f, SensitiveDataFilter) for f in logger.filters)
    assert logger.filters[-1] is client.app.state.sensitive_filter


def test_the_api_logger_scrubs_a_planted_identifier(client):
    logger = logging.getLogger("medarx.api")
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    logger.addHandler(handler)
    previous = logger.level
    logger.setLevel(logging.INFO)
    try:
        logger.info("admitting MRN %s now", "4452819")
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous)
    assert "4452819" not in stream.getvalue()
    assert "redacted:MRN" in stream.getvalue()


# -- Startup guard -----------------------------------------------------------


def test_an_undeclared_numeric_date_order_stops_the_application_being_built(tmp_path,
                                                                          provider):
    """`require_date_order` gets the caller it was written for.

    A deployment that has not said whether its reports are MDY or DMY cannot
    read `01/14/2026`, and the kernel's answer to that is a per-request block.
    Failing at startup instead makes the gap a configuration decision someone
    has to make once, rather than a receipt an auditor has to interpret.
    """
    from medarx.api.app import create_app
    from medarx.config import Settings

    with pytest.raises(ValueError, match="MEDARX_DATE_ORDER"):
        create_app(
            Settings(audit_key=KEY, date_order=None,
                     gateway_base_url=provider.base_url),
            f"sqlite:///{tmp_path / 'no-order.db'}",
        )


def test_the_shipped_scope_vocabulary_is_the_one_the_tests_use(client):
    """The synthetic scope grammar and this file's `SCOPE` constant agree.

    Without this the 403 tests would pass for the wrong reason: a scope the
    authoriser does not recognise grants nothing, so every request would be
    refused and every 403 assertion would still hold.
    """
    from medarx.api.authz import SCOPE_FUNCTION_PREFIX, SCOPE_STUDY_PREFIX

    assert SCOPE == (f"{SCOPE_STUDY_PREFIX}STUDY-SYN-000041"
                     f",{SCOPE_FUNCTION_PREFIX}Draft")
    assert client.post(EXEC_URL, json=KNOWN_POSITIVE_BODY,
                       headers=SCOPE_HEADERS).status_code == 200


# -- What the scope header is not --------------------------------------------


def test_the_scope_header_is_not_an_authentication_mechanism(client):
    """Measured, not asserted from a comment: anyone may present any scope.

    Phase 1 declares no authentication scheme, and this is what that looks like
    from outside. The test is the evidence, so that no future reader mistakes
    the header for a security control.
    """
    assert client.post(EXEC_URL, json=KNOWN_POSITIVE_BODY,
                       headers={"X-Scope": SCOPE}).status_code == 200
    served = client.get("/openapi.json").json()
    assert served["security"] == []
    assert served["components"]["securitySchemes"] == {}


# -- The approved bytes and the hash the response claims ---------------------


def test_the_approved_payload_hash_is_a_digest_and_the_stored_form_is_bare_hex(client,
                                                                             pipeline):
    """`sha256:`-prefixed on the wire, bare hex in the record: one value, two forms.

    The contract publishes the prefixed spelling for `approved_payload_hash` and
    the storage policy canonicalises a prefixed digest to bare hex on the way in.
    A reader comparing the two needs to know they are the same value, so this
    asserts the relationship rather than either spelling alone.
    """
    from medarx.audit.audit_log import DIGEST, PREFIXED_DIGEST

    r = client.post(EXEC_URL, json=KNOWN_POSITIVE_BODY, headers=SCOPE_HEADERS)
    wire = r.json()["approved_payload_hash"]
    assert PREFIXED_DIGEST.fullmatch(wire), wire
    stored = pipeline.audit.get(r.json()["request_id"])[0].approved_payload_hash
    assert DIGEST.fullmatch(stored)
    assert wire == f"sha256:{stored}"


# -- Every refusal at this surface leaves a trace ----------------------------


@pytest.mark.parametrize("label,path,kwargs,expected", [
    ("wrong media type", EXEC_URL, {"content": b"text", "headers":
     {**SCOPE_HEADERS, "Content-Type": "text/plain"}}, 415),
    ("unparseable body", EXEC_URL, {"content": b"{not json", "headers":
     {**SCOPE_HEADERS, "Content-Type": "application/json"}}, 400),
    ("undeclared property", EXEC_URL, {"json": body_with(prompt="x")}, 400),
    ("no scope", EXEC_URL, {"json": KNOWN_POSITIVE_BODY, "headers": {}}, 403),
])
def test_every_surface_refusal_leaves_a_record(client, label, path, kwargs,
                                               expected):
    """A refusal with no trace is not evidence.

    Each of these used to answer and file nothing, so a probe sweep with
    malformed requests left no record at all. The assertion is on the *record*,
    not the status: the status was already right, and a test that only checked
    it would pass against a surface that remembered nothing.
    """
    kwargs = dict(kwargs)
    if "headers" not in kwargs:
        kwargs["headers"] = SCOPE_HEADERS
    response = client.post(path, **kwargs)
    assert response.status_code == expected, label
    record = client.get(f"/v1/audit/records/{response.headers['X-Request-Id']}",
                        headers=SCOPE_HEADERS)
    assert record.status_code == 200, label
    body = record.json()
    assert body["layer"] == "J", label
    assert body["final_disposition"] == "blocked", label
    assert body["stages"] == [], label


def test_an_oversized_body_leaves_a_record_too(client, pipeline):
    """Sent chunked, so the *route* measures it rather than the middleware.

    The middleware refuses an oversized `Content-Length` before the body is read
    — the right place for it, so an oversized request costs a header rather than
    a megabyte — and it is the second refusal that cannot be recorded, because it
    runs before the application exists to record it. Both are stated rather than
    worked around; this sends the same body without a `Content-Length` so the
    route's measured check is the one under test, and the assertion is that it
    *files* the refusal.
    """
    from conftest import body_with_dicom

    payload = body_with_dicom(InstitutionName="x" * (pipeline.settings.max_body_bytes + 1))
    response = client.post(EXEC_URL, content=_chunked(payload), headers={
        **SCOPE_HEADERS, "Content-Type": "application/json"})
    assert response.status_code == 400
    record = client.get(f"/v1/audit/records/{response.headers['X-Request-Id']}",
                        headers=SCOPE_HEADERS)
    assert record.status_code == 200
    assert record.json()["layer"] == "J"


def test_the_body_cap_the_middleware_applies_is_the_one_refusal_it_cannot_record(client,
                                                                                 pipeline):
    """Two refusals cannot be recorded, both for a stated structural reason.

    The 404 for an unknown function has no truthful `AuditRecord.function`, and
    the header-level body cap is answered before the application exists. Both
    still carry the request ID, so a caller can correlate them, and both are
    pinned here so neither is a surprise found later.
    """
    from conftest import body_with_dicom

    payload = body_with_dicom(InstitutionName="x" * (pipeline.settings.max_body_bytes + 1))
    response = client.post(EXEC_URL, json=payload, headers=SCOPE_HEADERS)
    assert response.status_code == 400
    assert response.headers["X-Request-Id"]
    assert client.get(f"/v1/audit/records/{response.headers['X-Request-Id']}",
                      headers=SCOPE_HEADERS).status_code == 404


def test_an_unknown_function_in_the_path_is_the_one_refusal_it_cannot_record(client):
    """Why, and stated rather than worked around.

    `AuditEvent.function` is required and is the contract's closed
    `FunctionName` enum. A request naming a function that does not exist has no
    truthful value to file it under, and filing it under a sibling would be a
    false record. The response still carries the request ID, and the contract
    would have to let `AuditRecord.function` be null to close this.
    """
    response = client.post("/v1/functions/Summarize/executions",
                           json=KNOWN_POSITIVE_BODY, headers=SCOPE_HEADERS)
    assert response.status_code == 404
    assert response.headers["X-Request-Id"]
    assert client.get(f"/v1/audit/records/{response.headers['X-Request-Id']}",
                      headers=SCOPE_HEADERS).status_code == 404
