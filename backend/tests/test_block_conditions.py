"""Design §6 driven **through the HTTP surface**, one request body per condition.

An engine-level test leaves the route unproven: a route that skipped every check
would pass it. Everything here is a real `POST` and a real response, and two
things are asserted of every block receipt:

- the `layer` names the component that **actually** refused, not a plausible one;
- the `action_codes` are that component's codes — a D.2 block must not report a
  policy code, and a policy refusal must not report a redaction code.

The receipt has exactly five fields and `extra="forbid"`, so there is nowhere for
a message to go: the codes are all an auditor gets, and a wrong one is a false
record.

**Reachability is measured, not assumed.** Two of the design's seven rows cannot
be reached by any request a caller may legally make, and the tests at the bottom
say so with the evidence rather than leaving the table looking complete.
"""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path

import pytest

from medarx.config import Settings

from conftest import EXEC_URL, KEY, KNOWN_POSITIVE_BODY, SCOPE_HEADERS, body_with_dicom

RECEIPT_KEYS = {"status", "request_id", "layer", "action_codes", "policy_version"}

#: The codes layer E owns, and the codes the redaction layers own. A receipt that
#: mixes the two halves is the specific falsehood this file exists to catch, so
#: the halves are named here rather than spelled inline.
POLICY_CODES = {"UNKNOWN_POLICY_VERSION", "POLICY_CONFIG_ERROR", "UNAPPROVED_PAYLOAD"}
REDACTION_CODES = {
    "NER_UNRESOLVED", "LOW_CONFIDENCE_NER_UNRESOLVED", "UNRESOLVED_EMPTY_BODY",
    "DETERMINISTIC_REPLACEMENT_FAILED", "LEFTOVER_PATTERN_MATCH",
    "CONTRACT_VIOLATION", "MISSING_SURROGATE", "UNSHIFTED_DATE",
    "FIELD_NOT_ALLOWLISTED", "UNKNOWN_FUNCTION",
}
GATEWAY_CODES = {"UNKNOWN_MODEL", "PAYLOAD_MISMATCH", "HASH_MISMATCH"}
PSEUDONYM_CODES = {"MISSING_SURROGATE", "SURROGATE_SHAPED_REFERENCE_REJECTED",
                   "UNSHIFTED_DATE"}
SURFACE_CODES = {"ARBITRARY_DICOM_OBJECT_REJECTED", "FREE_FORM_PROMPT_REJECTED",
                 "UNAUTHORIZED_SCOPE", "FUNCTION_NOT_PERMITTED"}

#: A report the NER pass cannot resolve. `AMBIGUOUS_REFERENCE` has no registered
#: replacer, so the block does not depend on the score: the value is always
#: detected and can never be sanitised, which is what makes this the
#: reproducible beat rather than a matter of model confidence.
UNRESOLVABLE_REPORT = {
    "text": "FINDINGS: 7 mm nodule. Ticket ZX-99-ALPHA issued at the counter.",
    "source": "synthetic_corpus",
}


def _receipt(response):
    """The block receipt, after asserting that it is one."""
    assert response.status_code == 422, response.text
    body = response.json()
    assert set(body) == RECEIPT_KEYS, body
    assert body["status"] == "blocked"
    assert body["policy_version"] == "medarx-policy-1.0.0"
    assert body["action_codes"]
    assert body["action_codes"] == list(dict.fromkeys(body["action_codes"]))
    return body


def _unresolved_body(**dicom_overrides):
    """The known-positive body with the unresolvable report text substituted in."""
    body = body_with_dicom(**dicom_overrides)
    body["report_text"] = dict(UNRESOLVABLE_REPORT)
    return body


# -- Row 1: the application API --------------------------------------------


def test_row1_unauthorized_scope_is_403_and_names_no_privacy_code(client, provider):
    before = len(provider.requests)
    r = client.post(EXEC_URL, json=KNOWN_POSITIVE_BODY,
                    headers={"X-Scope": "scope:study:STUDY-SYN-999999,"
                                        "scope:function:Draft"})
    assert r.status_code == 403
    assert r.json()["type"].endswith("/study-scope-unauthorized")
    assert len(provider.requests) == before


def test_row1_unpermitted_function_is_403(client, provider):
    before = len(provider.requests)
    r = client.post("/v1/functions/Ask/executions", json=KNOWN_POSITIVE_BODY,
                    headers={"X-Scope": "scope:study:STUDY-SYN-000041,"
                                        "scope:function:Draft"})
    assert r.status_code == 403
    assert r.json()["type"].endswith("/function-not-permitted")
    assert len(provider.requests) == before


@pytest.mark.parametrize("extra,code", [
    ({"dicom_object": {"PixelData": "AAAA"}}, "ARBITRARY_DICOM_OBJECT_REJECTED"),
    ({"pixel_data": "AAAA"}, "ARBITRARY_DICOM_OBJECT_REJECTED"),
    ({"prompt": "summarize this in French"}, "FREE_FORM_PROMPT_REJECTED"),
])
def test_row1_a_shape_it_cannot_express_is_400_and_names_the_smuggle(client, provider,
                                                                     entered, extra,
                                                                     code):
    """The contract's `ExecutionRequest` description names these three as `400`.

    The response is a `ProblemDetail`; the code lands on the audit record, which
    is where a non-raw disposition code belongs. Nothing entered the pipeline and
    nothing reached a socket.
    """
    before = len(provider.requests)
    r = client.post(EXEC_URL, json={**KNOWN_POSITIVE_BODY, **extra},
                    headers=SCOPE_HEADERS)
    assert r.status_code == 400
    assert len(provider.requests) == before
    assert entered == []
    record = client.get(f"/v1/audit/records/{r.headers['X-Request-Id']}",
                        headers=SCOPE_HEADERS).json()
    assert record["layer"] == "J"
    assert record["action_codes"] == [code]
    assert set(record["action_codes"]) <= SURFACE_CODES


# -- Row 2: the structured payload extractor --------------------------------


def test_row2_a_field_outside_the_function_allowlist_is_a_layer_a_block(client, provider):
    before = len(provider.requests)
    r = client.post(EXEC_URL, json=body_with_dicom(PriorReportText="Prior: 6 mm."),
                    headers=SCOPE_HEADERS)
    body = _receipt(r)
    assert body["layer"] == "A"
    assert body["action_codes"] == ["FIELD_NOT_ALLOWLISTED"]
    assert not set(body["action_codes"]) & POLICY_CODES
    assert len(provider.requests) == before


def test_row2_an_unknown_function_in_the_body_is_a_layer_a_block(client, provider):
    """The path is valid; the body names a function the contract does not have.

    The contract's `FunctionNotFound` response says this case is reported as a
    422 with `layer: A` and `UNKNOWN_FUNCTION`, unlike the same condition in the
    path segment, which is a 404.
    """
    before = len(provider.requests)
    r = client.post(EXEC_URL, json={**KNOWN_POSITIVE_BODY, "function": "Summarize"},
                    headers=SCOPE_HEADERS)
    body = _receipt(r)
    assert body["layer"] == "A"
    assert body["action_codes"] == ["UNKNOWN_FUNCTION"]
    assert len(provider.requests) == before


# -- Component C -------------------------------------------------------------


def test_a_date_that_cannot_be_shifted_is_a_layer_c_block(client, provider):
    """`20260230` matches the contract's `DicomDate` pattern and is not a day.

    So the schema accepts it, component C refuses it, and the receipt names C
    rather than a redaction layer that never looked at it.
    """
    before = len(provider.requests)
    r = client.post(EXEC_URL, json=body_with_dicom(StudyDate="20260230"),
                    headers=SCOPE_HEADERS)
    body = _receipt(r)
    assert body["layer"] == "C"
    assert body["action_codes"] == ["UNSHIFTED_DATE"]
    assert set(body["action_codes"]) <= PSEUDONYM_CODES
    assert len(provider.requests) == before


def test_a_blank_prior_study_reference_is_a_layer_c_block(client):
    """The blank-reference refusal, through a body that can reach it.

    A blank *study* reference cannot: the authoriser matches the study scope
    against the reference the body names, and a blank one is not in any scope, so
    that request is a `403` before the kernel runs. A prior-study reference is
    not scope-checked, so a blank one reaches component C — which is where the
    `MISSING_SURROGATE` refusal belongs, under layer C rather than under J.
    """
    body = {
        **KNOWN_POSITIVE_BODY,
        "prior_studies": [{"prior_study_reference": "   "}],
    }
    r = client.post("/v1/functions/Prior Summary/executions", json=body,
                    headers={"X-Scope": "scope:study:STUDY-SYN-000041,"
                                        "scope:function:Prior Summary"})
    receipt = _receipt(r)
    assert receipt["layer"] == "C"
    assert receipt["action_codes"] == ["MISSING_SURROGATE"]


def test_a_blank_study_reference_is_refused_by_the_authorizer_first(client):
    """The 403 that keeps a blank study reference out of the kernel at all."""
    r = client.post(EXEC_URL, json={**KNOWN_POSITIVE_BODY,
                                    "study_context": {"study_reference": "   "}},
                    headers=SCOPE_HEADERS)
    assert r.status_code == 403


def test_a_reference_already_shaped_like_a_surrogate_is_a_layer_c_block(client):
    from medarx.pseudonym.derivation import SURROGATE_HEX_CHARS

    forged = f"medarx-study-{'a' * SURROGATE_HEX_CHARS}"
    r = client.post(EXEC_URL, json={**KNOWN_POSITIVE_BODY,
                                    "study_context": {"study_reference": forged}},
                    headers={"X-Scope": f"scope:study:{forged},scope:function:Draft"})
    body = _receipt(r)
    assert body["layer"] == "C"
    assert body["action_codes"] == ["SURROGATE_SHAPED_REFERENCE_REJECTED"]


# -- Rows 4 and 5: redaction layers 2 and 3 ---------------------------------


def test_row4_an_unresolvable_ner_candidate_is_a_d2_block(client, provider):
    before = list(_sends_seen_by(provider))
    r = client.post(EXEC_URL, json=_unresolved_body(), headers=SCOPE_HEADERS)
    body = _receipt(r)
    assert body["layer"] == "D.2"
    assert body["action_codes"][0] == "NER_UNRESOLVED"
    assert not set(body["action_codes"]) & (POLICY_CODES | GATEWAY_CODES
                                            | PSEUDONYM_CODES | SURFACE_CODES)
    assert list(_sends_seen_by(provider)) == before


def _sends_seen_by(provider) -> list:
    """Every request the stub has ever received. Read, not counted, so a
    regression that sends *one extra* request cannot pass by comparing a length
    to itself."""
    return provider.requests


def test_row4_a_422_sends_nothing(client, provider):
    before = list(_sends_seen_by(provider))
    _receipt(client.post(EXEC_URL, json=_unresolved_body(), headers=SCOPE_HEADERS))
    assert list(_sends_seen_by(provider)) == before


def test_a_d2_block_reports_no_policy_code_even_though_e_also_refused(client):
    """The distinction the design asks for, asserted on a real receipt.

    Component E did block — an unresolved disposition is one of its §6 row 6
    conditions — and the receipt still names D.2 and carries D's codes only. A
    receipt reporting `UNKNOWN_POLICY_VERSION` here would tell an auditor the
    deployment was misconfigured, which it is not.
    """
    body = _receipt(client.post(EXEC_URL, json=_unresolved_body(),
                                headers=SCOPE_HEADERS))
    assert body["layer"] == "D.2"
    assert not set(body["action_codes"]) & POLICY_CODES


def test_row5_a_pattern_surviving_redaction_is_reported_by_layer_three(client):
    """Layer 3's leftover scan fires, and the receipt says so honestly.

    The scan and the NER pass read the *same* pattern table, so a pattern that
    survives redaction is one layer 2 could not resolve. The receipt therefore
    names D.2 — the first layer that flagged anything — and carries D.3's code
    alongside D.2's. Both are redaction codes; neither is a policy code, which
    is the distinction this test exists for.
    """
    body = _receipt(client.post(EXEC_URL, json=_unresolved_body(),
                                headers=SCOPE_HEADERS))
    assert "LEFTOVER_PATTERN_MATCH" in body["action_codes"]
    assert body["action_codes"][0] == "NER_UNRESOLVED"
    assert not set(body["action_codes"]) & POLICY_CODES


# -- Row 7: the model gateway ------------------------------------------------


def test_row7_an_unknown_model_is_a_layer_f_block_with_no_provider_call(client, provider):
    before = list(_sends_seen_by(provider))
    r = client.post(EXEC_URL, json={**KNOWN_POSITIVE_BODY, "model_id": "no-such-model"},
                    headers=SCOPE_HEADERS)
    body = _receipt(r)
    assert body["layer"] == "F"
    assert body["action_codes"] == ["UNKNOWN_MODEL"]
    assert not set(body["action_codes"]) & (REDACTION_CODES | POLICY_CODES)
    assert list(_sends_seen_by(provider)) == before


# -- Every block records what it did and nothing more ------------------------


def test_every_block_records_a_layer_and_a_code_in_the_audit_log(client):
    r = client.post(EXEC_URL, json=body_with_dicom(StudyDate="20260230"),
                    headers=SCOPE_HEADERS)
    receipt = _receipt(r)
    record = client.get(f"/v1/audit/records/{receipt['request_id']}",
                        headers=SCOPE_HEADERS).json()
    assert record["layer"] == receipt["layer"]
    assert record["action_codes"] == receipt["action_codes"]
    assert record["final_disposition"] == "blocked"
    assert record["approved_payload_hash"] is None
    assert record["selected_model"] is None


# -- The two rows this surface cannot reach ----------------------------------


def test_the_five_reachable_rows_are_reachable(client):
    """What a caller can cause, one request each, asserted as a whole.

    Kept as a single test so that the set cannot quietly shrink: an empty or
    partial sweep would pass a per-condition assertion that had stopped running.
    """
    reached = {
        "J": client.post(EXEC_URL, json={**KNOWN_POSITIVE_BODY, "prompt": "do a thing"},
                         headers=SCOPE_HEADERS).status_code,
        "A": _receipt(client.post(EXEC_URL, json=body_with_dicom(
            PriorReportText="Prior: 6 mm."), headers=SCOPE_HEADERS))["layer"],
        "C": _receipt(client.post(EXEC_URL, json=body_with_dicom(StudyDate="20260230"),
                                  headers=SCOPE_HEADERS))["layer"],
        "D.2": _receipt(client.post(EXEC_URL, json=_unresolved_body(),
                                    headers=SCOPE_HEADERS))["layer"],
        "F": _receipt(client.post(EXEC_URL, json={**KNOWN_POSITIVE_BODY,
                                                  "model_id": "no-such-model"},
                                  headers=SCOPE_HEADERS))["layer"],
    }
    assert reached == {"J": 400, "A": "A", "C": "C", "D.2": "D.2", "F": "F"}


def _direct_run(pipeline, request_id: str, report_text: str):
    """The pipeline's own entry point, with the same request the route builds.

    Used only for the two claims about rows that *cannot* be reached through the
    surface: a claim about an unreachable condition cannot be demonstrated by a
    request that cannot make it, so the run is made directly and its dispositions
    read. Everything about what a caller can reach is driven over HTTP above.
    """
    from medarx.api.schemas import ExecutionRequest as ExecutionRequestBody
    from medarx.api.wiring import execution_request_from_body

    body = ExecutionRequestBody.model_validate({
        "study_context": {"study_reference": "STUDY-SYN-000041"},
        "report_text": {"text": report_text, "source": "synthetic_corpus"},
        "dicom_metadata": {"Modality": "CT", "StudyDate": "20260114"},
    })
    request = execution_request_from_body(body, "Draft", "0" * 64)
    return pipeline.run(request_id, request)


def test_row3_layer_d1_cannot_be_reached_because_component_c_shifts_first(pipeline):
    """The evidence for the row-3 claim, executed rather than argued.

    `layer1_deterministic` shifts a date only when it still equals the value
    component C was given, and component C always shifts it first or refuses the
    request outright. So no D.1 disposition is produced on any run the API can
    drive, and `DETERMINISTIC_REPLACEMENT_FAILED` is unreachable from here.

    Asserted against the pipeline's own dispositions, which is what the audit
    record's codes are built from.
    """
    result = _direct_run(pipeline, "req-d1-probe", UNRESOLVABLE_REPORT["text"])
    assert result.approved is False, "the probe text is deliberately unresolvable"
    assert [d for d in result.dispositions if d.layer == "D.1"] == []

    clean = _direct_run(pipeline, "req-d1-probe-2",
                        "FINDINGS: 7 mm nodule in the right upper lobe.")
    assert clean.approved is True
    assert [d for d in clean.dispositions if d.layer == "D.1"] == []


def test_row6_layer_e_cannot_be_reached_by_a_caller(pipeline):
    """The evidence for the row-6 claim, executed rather than argued.

    Every condition `PolicyEngine.decide` can fail on is either a misconfiguration
    the `Settings` types forbid, or a state the orchestrator cannot be in. An
    unresolved disposition does block, and the orchestrator attributes it to the
    layer that raised the disposition rather than to E — deliberately, so one
    refusal cannot produce two different receipts depending on who asked.
    """
    from medarx.policy.policy_engine import IMPLEMENTED_MODES, PolicyEngine

    with pytest.raises(Exception):
        Settings(policy_mode="authorized_local")  # type: ignore[arg-type]
    assert "authorized_local" not in IMPLEMENTED_MODES

    # An engine built over a policy version the orchestrator does not present is
    # the one way E can refuse, and the orchestrator then attributes the block to
    # E with the engine's own wire code.
    from medarx.redaction.pipeline import run_privacy_kernel

    mismatched = PolicyEngine(Settings(audit_key=KEY, date_order="MDY",
                                       policy_version="some-other-policy"))
    approved = _approved_payload_for(mismatched)
    from medarx.errors import RedactionError

    with pytest.raises(RedactionError) as caught:
        run_privacy_kernel(approved.payload, approved.patient, approved.store,
                           mismatched, approved.settings, source=approved.source)
    assert caught.value.layer == "E"
    assert caught.value.action_codes == ("UNKNOWN_POLICY_VERSION",)

    # And the reachable attribution, for contrast: a disposition block names the
    # layer that raised it.
    result = _direct_run(pipeline, "req-e-probe", UNRESOLVABLE_REPORT["text"])
    assert result.block_receipt is not None
    assert result.block_receipt.layer == "D.2"


def _approved_payload_for(engine):
    """A clean, pseudonymized payload, plus what the kernel needs to judge it.

    Built directly rather than through the API, because the point of the test
    that uses it is a *configuration* mismatch between the engine and the
    settings it is handed — something a request cannot express, because the
    contract forbids a request from naming a policy version at all.
    """
    from medarx.extraction.payload_extractor import pipeline_for
    from medarx.extraction.study_context import StudyContext
    from medarx.pseudonym.mapping_store import MappingStore
    from medarx.pseudonym.pseudonymize import pseudonymize_payload

    settings = Settings(audit_key=KEY, date_order="MDY",
                        policy_version="medarx-policy-1.0.0")
    store = MappingStore(f"sqlite:///{Path(tempfile.mkdtemp()) / 'm.db'}", KEY)
    study = StudyContext(study_uid="S", study_ref="STUDY-SYN-000041",
                         patient_ref="PAT-0001", function="draft", prior_study_refs=())
    a = pipeline_for("draft", study, "FINDINGS: 7 mm nodule in the right lobe.",
                     {"Modality": "CT", "StudyDate": "20260114"},
                     settings.policy_version)
    c = pseudonymize_payload(a, "PAT-0001", store)
    return _Approved(payload=c, patient="PAT-0001", store=store, settings=settings,
                     source=a)


@dataclass(frozen=True)
class _Approved:
    payload: object
    patient: str
    store: object
    settings: object
    source: object
