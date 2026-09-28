"""The validate-then-send pair, driven through the real HTTP surface.

Everything here is a real `POST` against the real application, against a loopback
provider that records the bytes it actually receives. Nothing is mocked at the
gateway and no assertion is made about a private method on the pipeline, because
the property this pair of operations exists to provide is a property of what
reaches the wire.

**The central claim, and how it is checked.** A preflight publishes a payload
and a send must transmit *that* payload. The check is the byte comparison: the
`messages` the stub received are parsed and searched for the exact `report_text`
and `study_ref` the preflight published, and for nothing else. A send that
re-derived the payload, a send that sent a different one, and a send that sent the
caller's unredacted text all fail that comparison — and so does a send that sends
nothing, which is why the control is in the same test.

**The zeros are measured against the transport, not inferred.** "The preflight
did not transmit" is `len(provider.requests) == before` where `provider.requests`
is a list the receiving HTTP server appends to in its request handler. Nothing
between the kernel and that list can be the reason a byte is missing.

**And every zero is paired with a positive.** A test that only ever observes
silence would also pass if the gateway were simply broken. Each of the three
transmission tests ends by doing a send and asserting the count went **up**, so a
gateway that never fired would be visible in the same run rather than in a
different one someone might forget to run.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

from medarx.audit.code_table import (
    GATEWAY_LAYER,
    PIPELINE_STAGES,
    preflight_stages,
)
from medarx.audit.code_table import STAGE_COMPONENTS
from medarx.models import LAYERS
from medarx.policy.policy_engine import PolicyEngine
from conftest import KEY, KNOWN_POSITIVE_BODY, SCOPE_HEADERS, body_with

REPO_ROOT = Path(__file__).resolve().parents[2]
CONTRACT = REPO_ROOT / "contracts" / "openapi.yaml"

PREFLIGHT_URL = "/v1/functions/Draft/executions/preflight"

#: The report the corpus plants identifiers in, and the one an NER pass cannot
#: sanitise: `AMBIGUOUS_REFERENCE` has no registered replacer, so the block does
#: not depend on a score.
UNRESOLVABLE = (
    "FINDINGS: 7 mm nodule. Ticket ZX-99-ALPHA issued at the counter."
)

def _contract() -> dict:
    with CONTRACT.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _validator(name: str) -> Draft202012Validator:
    doc = _contract()
    return Draft202012Validator({
        "$ref": f"#/__target__",
        "__target__": doc["components"]["schemas"][name],
        "components": doc["components"],
    })


# -- Helpers ------------------------------------------------------------------


def _preflight(client, body=None, **kwargs):
    """A preflight, scoped unless the caller passes its own `headers`."""
    kwargs.setdefault("headers", SCOPE_HEADERS)
    return client.post(PREFLIGHT_URL, json=body or KNOWN_POSITIVE_BODY, **kwargs)


def _send(client, request_id, **kwargs):
    """A send, scoped unless the caller passes its own `headers`."""
    kwargs.setdefault("headers", SCOPE_HEADERS)
    return client.post(f"/v1/executions/{request_id}/send", **kwargs)


def _sent_bodies(provider) -> list[bytes]:
    return [recorded.body for recorded in provider.requests]


def _user_message(recorded) -> str:
    body = json.loads(recorded.body)
    return next(m["content"] for m in body["messages"] if m["role"] == "user")


def _pending(pipeline, request_id):
    return pipeline.pending_for(request_id)


# -- The stages a preflight reports -------------------------------------------


def test_the_gateway_layer_is_the_one_that_owns_the_model_request_stage():
    """The cut in `preflight_stages` is derived, so pin what it is derived from."""
    assert GATEWAY_LAYER in LAYERS
    assert GATEWAY_LAYER in STAGE_COMPONENTS["Model request"]


def test_a_preflight_reports_five_stages_and_never_the_model_request(client):
    """The list is the pipeline's, and `Model request` is not in it.

    Six would be the worse defect: a client rendering a six-stage timeline from a
    preflight would be telling a reader a provider was contacted, and no provider
    was.
    """
    body = _preflight(client).json()
    assert body["stages"] == list(preflight_stages())
    assert body["stages"] == list(PIPELINE_STAGES[:5])
    assert "Model request" not in body["stages"]
    assert set(body["stages"]) == {
        "Fields selected", "Pseudonymized", "Text screened",
        "Payload validated", "Policy decision",
    }


def test_the_preflight_stage_cut_leaves_no_layer_unaccounted_for():
    """Completeness: every layer a preflight runs is inside a stage it reports.

    A cut derived by dropping stages that mention `F` would be correct today and
    silently wrong if a stage were added that `preflight_stages` then dropped for
    a reason nobody noticed. This is the check that makes the derivation total.
    """
    covered = {layer for stage in preflight_stages()
               for layer in STAGE_COMPONENTS[stage]}
    # `J` is the request surface, which is behind the request but never behind a
    # stage; `F` is the one component a preflight stops before.
    assert covered == set(LAYERS) - {"J", GATEWAY_LAYER}


# -- The payload the preflight publishes --------------------------------------


def test_the_preflight_response_is_the_contract_schemas_preflight_response(client):
    body = _preflight(client).json()
    _validator("PreflightResponse").validate(body)
    _validator("PayloadPreview").validate(body["payload"])


def test_a_preflight_publishes_the_transformed_payload_and_nothing_else(client):
    """The preview is the payload, not a description of one.

    Every payload member is present — including both hashes, which are two
    different values over two different things — so a client cannot be tempted to
    reconstruct an object it was given.
    """
    payload = _preflight(client).json()["payload"]
    assert set(payload) == {
        "function", "report_text", "dicom_fields", "study_ref", "prior_study_refs",
        "policy_version", "input_hash", "payload_hash",
    }
    assert payload["function"] == "draft"
    assert payload["policy_version"] == "medarx-policy-1.0.0"
    assert payload["payload_hash"]
    assert payload["input_hash"] != payload["payload_hash"]


def test_nothing_the_caller_supplied_as_an_identifier_reaches_the_preview(client):
    """The preview is the payload, so the payload's guarantees are its guarantees."""
    payload = _preflight(client).json()["payload"]
    body = json.dumps(payload)
    for planted in ("4452819", "ACC0000417", "STUDY-SYN-000041"):
        assert planted not in body, f"{planted} reached the preview"
    assert "PatientID" not in payload["dicom_fields"]
    assert "AccessionNumber" not in payload["dicom_fields"]


def test_the_study_reference_in_the_preview_is_the_surrogate_not_the_caller_s(client):
    payload = _preflight(client).json()["payload"]
    assert payload["study_ref"] != KNOWN_POSITIVE_BODY["study_context"]["study_reference"]


def test_the_report_text_in_the_preview_is_redacted_not_the_callers(client):
    payload = _preflight(client).json()["payload"]
    assert payload["report_text"] != KNOWN_POSITIVE_BODY["report_text"]["text"]
    assert "4452819" not in payload["report_text"]


# -- The field-action summary -------------------------------------------------


def test_the_field_action_summary_names_every_field_of_the_payload(client):
    """Completeness, both ways.

    Every payload member appears, and every entry that is not `excluded` names
    something the payload actually carries. A summary that omitted a field would
    leave a caller unable to see what went, and one that named a field the payload
    does not have would be reporting a transformation that did not happen.
    """
    body = _preflight(client).json()
    actions = {a["field"]: a["state"] for a in body["field_actions"]}
    payload = body["payload"]
    for member in ("function", "report_text", "study_ref", "prior_study_refs",
                   "policy_version", "input_hash", "payload_hash"):
        assert member in actions, f"{member} is in the payload and not in the summary"
    for name in payload["dicom_fields"]:
        assert f"dicom_fields.{name}" in actions
    carried = {
        name for name, state in actions.items()
        if state in ("included", "transformed")
    }
    assert carried <= set(payload) | {
        f"dicom_fields.{name}" for name in payload["dicom_fields"]
    }
    assert {a["state"] for a in body["field_actions"]} <= {
        "included", "transformed", "excluded"
    }


def test_the_summary_marks_the_dropped_identifier_attributes_as_excluded(client):
    actions = {a["field"]: a["state"] for a in _preflight(client).json()[
        "field_actions"]}
    assert actions["dicom_metadata.PatientID"] == "excluded"
    assert actions["dicom_metadata.AccessionNumber"] == "excluded"
    assert actions["dicom_fields.modality"] in ("included", "transformed")


def test_the_summary_marks_the_study_references_nothing_carries_as_excluded(client):
    """`patient_reference` and `modality` reach nothing on the request path.

    A caller who sets `modality` on the study context and not on `dicom_metadata`
    gets no payload field, because component A reads modality from the DICOM
    attribute. Saying so is the whole point of the summary; silently dropping it
    is the defect it prevents.
    """
    body = body_with(study_context={
        "study_reference": "STUDY-SYN-000041",
        "patient_reference": "PAT-SYN-000041",
        "modality": "CT",
    })
    actions = {a["field"]: a["state"] for a in _preflight(client, body).json()[
        "field_actions"]}
    assert actions["study_context.patient_reference"] == "excluded"
    assert actions["study_context.modality"] == "excluded"
    assert actions["report_text.source"] == "excluded"


def test_no_field_action_carries_a_value(client):
    """A summary that quoted the dropped value would be a leak in the answer."""
    for action in _preflight(client).json()["field_actions"]:
        assert set(action) == {"field", "state"}


# -- The preflight transmits nothing ------------------------------------------


def test_an_approved_preflight_transmits_nothing_and_the_check_can_fail(client,
                                                                        provider):
    """The zero, and its positive control, in one test.

    The second half is the point. A stub that recorded nothing because the
    gateway was broken would satisfy the first half alone; sending afterwards and
    watching the same counter go up is what makes the first half a measurement of
    the preflight rather than of the transport.
    """
    before = len(_sent_bodies(provider))
    body = _preflight(client)
    assert body.status_code == 200
    assert body.json()["status"] == "needs_review"
    assert len(_sent_bodies(provider)) == before, (
        "a preflight opened a socket: it runs A, C, D and E and stops before F"
    )

    # The control. The same preflight's send does reach the transport.
    sent = _send(client, body.json()["request_id"])
    assert sent.status_code == 200
    assert len(_sent_bodies(provider)) == before + 1


def test_a_blocked_preflight_returns_the_receipt_and_transmits_nothing(client,
                                                                       provider):
    """The `422`, and a zero measured the same way as the approved case's."""
    before = len(_sent_bodies(provider))
    response = _preflight(client, body_with(report_text={
        "text": UNRESOLVABLE, "source": "synthetic_corpus",
    }))
    assert response.status_code == 422
    receipt = response.json()
    assert receipt["status"] == "blocked"
    assert receipt["action_codes"]
    assert receipt["layer"] in LAYERS
    _validator("BlockReceipt").validate(receipt)
    assert len(_sent_bodies(provider)) == before

    # The control: the transport is live and this stub does record sends.
    assert _preflight(client).status_code == 200
    _send(client, _preflight(client).json()["request_id"])
    assert len(_sent_bodies(provider)) == before + 1


def test_a_blocked_preflight_leaves_the_audit_record_a_blocked_execution_does(client,
                                                                              provider):
    """The evidence for a refusal is the same whichever route produced it."""
    from test_block_conditions import _unresolved_body

    request_id = _preflight(
        client, _unresolved_body()
    ).json()["request_id"]
    record = client.get(f"/v1/audit/records/{request_id}",
                        headers=SCOPE_HEADERS).json()
    assert record["final_disposition"] == "blocked"
    assert record["layer"] == "D.2"
    assert record["stages"] == list(PIPELINE_STAGES[:3])


def test_a_validated_preflight_leaves_no_audit_record_until_it_is_sent(client):
    """Nothing was refused and nothing was transmitted, so nothing is filed.

    A record here would derive `stages` from a `layer` of `null`, which means
    "reached all six" — a claim that a provider was called.
    """
    request_id = _preflight(client).json()["request_id"]
    assert client.get(f"/v1/audit/records/{request_id}",
                      headers=SCOPE_HEADERS).status_code == 404
    _send(client, request_id)
    record = client.get(f"/v1/audit/records/{request_id}",
                        headers=SCOPE_HEADERS)
    assert record.status_code == 200
    body = record.json()
    assert body["final_disposition"] == "pending_human_approval"
    assert body["human_approval"] is None
    assert body["stages"] == list(PIPELINE_STAGES)


# -- The send transmits what the preflight published ---------------------------


def test_the_send_transmits_exactly_the_payload_the_preflight_published(client,
                                                                       provider):
    """The central claim, checked against the bytes the stub received.

    Not "the response is 200" and not "the hash matches itself": the `user`
    message the provider actually got must contain the exact transformed
    `report_text` and the exact surrogate `study_ref` the preflight published, and
    must not contain the caller's own values.
    """
    before = len(_sent_bodies(provider))
    preview = _preflight(client).json()
    payload = preview["payload"]

    assert _send(client, preview["request_id"]).status_code == 200
    assert len(_sent_bodies(provider)) == before + 1
    user = _user_message(provider.requests[-1])

    assert payload["report_text"] in user
    assert payload["study_ref"] in user
    assert "4452819" not in user
    assert "STUDY-SYN-000041" not in user
    for name, value in payload["dicom_fields"].items():
        assert value in user, f"the approved {name} did not reach the wire"


def test_the_hash_the_preflight_published_is_the_hash_the_send_reports(client):
    preview = _preflight(client).json()
    sent = _send(client, preview["request_id"]).json()
    assert sent["status"] == "approved"
    assert sent["approved_payload_hash"] == preview["approved_payload_hash"]
    assert sent["draft"]["content"]
    assert sent["function"] == preview["function"] == "Draft"


def test_the_send_is_bound_to_the_payload_and_refuses_a_substituted_one(client,
                                                                        provider,
                                                                        pipeline):
    """The guard, and proof it can fail.

    The token the preflight minted is swapped for one minted over a *different*
    payload — which is the substitution design §6 row 7 exists to stop, and the
    only way the two objects in a pending approval can disagree. The send must
    refuse before any byte moves.
    """
    from medarx.gateway.openai_gateway import ModelGateway
    from medarx.models import ModelRequest, payload_hash_of

    request_id = _preflight(client).json()["request_id"]
    approval = _pending(pipeline, request_id)
    assert approval is not None

    # A genuinely different payload, and a genuinely valid token over it. Built
    # through the gateway's own verifier, so nothing here is a forgery — the
    # point is that a *real* token for the *wrong* payload is still refused.
    other = approval.payload.model_copy(
        update={"report_text": "FINDINGS: a different finding entirely."}
    )
    other_hash = payload_hash_of(other)
    other = other.model_copy(update={"payload_hash": other_hash})
    gateway: ModelGateway = pipeline.gateway
    other_token = gateway.verify_approved_payload(other, other_hash, ModelRequest(
        model=approval.selected_model, messages=[{"role": "user", "content": "x"}],
        temperature=0.0, max_tokens=1,
    ))
    assert other_token.approved_payload_hash != approval.approved_payload_hash
    pipeline._pending[request_id] = type(approval)(
        **{**{f: getattr(approval, f) for f in approval.__dataclass_fields__},
           "approved_send": other_token}
    )

    before = len(_sent_bodies(provider))
    response = _send(client, request_id)
    assert response.status_code == 422
    receipt = response.json()
    assert receipt["layer"] == "F"
    assert set(receipt["action_codes"]) == {"PAYLOAD_MISMATCH", "HASH_MISMATCH"}
    assert len(_sent_bodies(provider)) == before


def test_a_send_for_an_unknown_request_id_is_404_and_transmits_nothing(client,
                                                                      provider):
    before = len(_sent_bodies(provider))
    response = _send(client, "no-such-request-id")
    assert response.status_code == 404
    assert response.json()["type"].endswith("/execution-not-found")
    assert len(_sent_bodies(provider)) == before
    # The control: this transport does record a send when there is one to make.
    _send(client, _preflight(client).json()["request_id"])
    assert len(_sent_bodies(provider)) == before + 1


def test_a_send_after_the_policy_version_moved_is_blocked_and_sends_nothing(client,
                                                                            provider,
                                                                            pipeline):
    """§6 row 6, at the moment the bytes would move.

    `Settings` is frozen, so the deployment's configuration cannot change inside
    a process; the observable form of "the policy version moved" is the engine no
    longer holding the version the approval was made under, which is what this
    swaps. That is the one way the check is reachable, and a check that cannot
    fire is not a check.
    """
    from medarx.config import Settings

    request_id = _preflight(client).json()["request_id"]
    pipeline.policy = PolicyEngine(Settings(
        audit_key=KEY, policy_version="medarx-policy-9.9.9", date_order="MDY",
    ))
    before = len(_sent_bodies(provider))
    response = _send(client, request_id)
    assert response.status_code == 422
    receipt = response.json()
    assert receipt["layer"] == "E"
    assert receipt["action_codes"] == ["UNKNOWN_POLICY_VERSION"]
    assert len(_sent_bodies(provider)) == before


def test_an_approval_is_consumed_by_one_send(client, provider):
    """One authorisation, one transmission, one record.

    A second send of the same bytes under one request ID would file two records
    the append-only log cannot tell apart, so the second attempt is a `404` and
    nothing is transmitted.
    """
    request_id = _preflight(client).json()["request_id"]
    assert _send(client, request_id).status_code == 200
    before = len(_sent_bodies(provider))
    second = _send(client, request_id)
    assert second.status_code == 404
    assert len(_sent_bodies(provider)) == before


def test_a_send_does_not_re_run_the_pipeline(client, pipeline, monkeypatch):
    """Nothing is re-derived. The pipeline's `run` is not reachable from a send.

    Re-running the pipeline at send time is how a caller ends up transmitting a
    payload nobody previewed, so the assertion is that the composition root's own
    one-shot path is not called at all.
    """
    request_id = _preflight(client).json()["request_id"]

    def explode(*_args, **_kwargs):  # pragma: no cover - the point is it is not called
        raise AssertionError("a send re-ran the pipeline")

    monkeypatch.setattr(pipeline, "run", explode)
    monkeypatch.setattr(pipeline, "preflight", explode)
    assert _send(client, request_id).status_code == 200


# -- Authorization ------------------------------------------------------------


def test_a_preflight_without_a_scope_is_403_and_sends_nothing(client, provider):
    before = len(_sent_bodies(provider))
    assert _preflight(client, headers={}).status_code == 403
    assert len(_sent_bodies(provider)) == before


def test_a_send_without_a_scope_is_403_and_sends_nothing(client, provider):
    """And the refused send does not consume the approval it was refused on."""
    request_id = _preflight(client).json()["request_id"]
    before = len(_sent_bodies(provider))
    assert _send(client, request_id, headers={}).status_code == 403
    assert len(_sent_bodies(provider)) == before
    assert _send(client, request_id).status_code == 200
    assert len(_sent_bodies(provider)) == before + 1


# -- The route control is display-only ----------------------------------------


def test_a_preflight_cannot_choose_its_own_policy_mode(client, provider):
    """`400`, and nothing transmitted.

    A request that names a mode is asking the boundary to move. The schema is
    closed, so the answer is a refusal at the surface rather than a policy
    decision — and it is the same answer the atomic path gives, because the
    preflight takes the same request body.
    """
    before = len(_sent_bodies(provider))
    response = _preflight(client, body_with(policy_mode="strict_local"))
    assert response.status_code == 400
    assert len(_sent_bodies(provider)) == before


def test_the_policy_mode_in_the_preflight_is_the_deployments(client, pipeline):
    """Reported, not chosen: it is the engine's own reading, read-only."""
    assert _preflight(client).json()["policy_mode"] == pipeline.policy.mode
    assert pipeline.settings.policy_mode == "cloud"


# -- The contract declares what the surface enforces --------------------------


#: Every operation the contract declares, with the request that reaches it and
#: whether the code behind it requires a scope. The `requires_scope` column is
#: the claim under test; it is not read from the contract, so a document that
#: stopped declaring the header would fail against the code and a code that
#: stopped enforcing it would fail against the document.
OPERATIONS = [
    ("/v1/functions/{function_name}/executions", "post", True,
     lambda c: c.post("/v1/functions/Draft/executions", json=KNOWN_POSITIVE_BODY,
                      headers={})),
    ("/v1/functions/{function_name}/executions/preflight", "post", True,
     lambda c: c.post(PREFLIGHT_URL, json=KNOWN_POSITIVE_BODY, headers={})),
    ("/v1/executions/{request_id}/send", "post", True,
     lambda c: c.post("/v1/executions/unknown-request-id/send", headers={})),
    ("/v1/executions/{request_id}/approval", "post", True,
     lambda c: c.post("/v1/executions/unknown-request-id/approval",
                      json={"decision": "approved", "reviewer": "rev-01"},
                      headers={})),
    ("/v1/audit/records", "get", True, lambda c: c.get("/v1/audit/records",
                                                       headers={})),
    ("/v1/audit/records/{request_id}", "get", True,
     lambda c: c.get("/v1/audit/records/unknown-request-id", headers={})),
    ("/v1/policy", "get", False, lambda c: c.get("/v1/policy", headers={})),
]


@pytest.mark.parametrize("path,method,requires_scope,call", OPERATIONS,
                         ids=[f"{m} {p}" for p, m, _, _ in OPERATIONS])
def test_every_operation_refuses_a_caller_with_no_scope_exactly_where_it_declares_one(
    path, method, requires_scope, call, client
):
    """The code and the document, held to each other by running the code.

    A generated client reads the document, so the document has to say what the
    server does. Both directions are checked: an operation the code refuses and
    the document does not declare is a client that sends nothing and gets `403`,
    and an operation the document declares and the code does not enforce is a
    declared control that does not exist.
    """
    declared = _declared_scope_refs(path, method)
    assert ("ScopeHeader" in declared) is requires_scope, (
        f"{method} {path}: the contract declares the scope header as "
        f"{'required' if 'ScopeHeader' in declared else 'absent'}, but the "
        "code enforces it as "
        f"{'required' if requires_scope else 'not required'}"
    )
    response = call(client)
    assert response.status_code == (403 if requires_scope else 200)


def _declared_scope_refs(path: str, method: str) -> set[str]:
    operation = _contract()["paths"][path][method]
    return {
        parameter.get("$ref", parameter.get("name", "")).rsplit("/", 1)[-1]
        for parameter in operation.get("parameters", [])
    }


def test_the_scope_header_parameter_says_it_is_not_authentication():
    """The description is the only place a client author will read the warning.

    A header called `X-Scope` on an API with no security schemes looks like a
    credential to anyone who has not read the design. The sentence is asserted
    because the whole of D and C's honesty lives in it.
    """
    parameter = _contract()["components"]["parameters"]["ScopeHeader"]
    assert parameter["name"] == "X-Scope"
    assert parameter["in"] == "header"
    assert parameter["required"] is True
    text = parameter["description"].lower()
    assert "not an authentication mechanism" in text
    assert "not a defence against an attacker" in text


def test_the_policy_operation_states_that_its_mode_is_display_only():
    """A UI author reads the operation description, not the code."""
    text = _contract()["paths"]["/v1/policy"]["get"]["description"]
    assert "read-only" in text.lower()
    assert "must not offer a control that changes it" in text
    assert "requires no `X-Scope`" in text


def test_the_contract_publishes_no_way_to_choose_a_policy_mode():
    """One search, over the whole document, for the thing a route control needs."""
    text = CONTRACT.read_text(encoding="utf-8")
    assert "policy_mode" in text  # it is reported, and refused
    request = _contract()["components"]["schemas"]["ExecutionRequest"]
    assert "policy_mode" not in request["properties"]
    assert request["additionalProperties"] is False


# -- The additive claim -------------------------------------------------------


def test_the_contract_is_additive_against_the_pre_phase2_document():
    """Every member the contract gained is a gain: nothing was removed or changed.

    The reference is the file as it stood at the last Phase 1 commit, read from
    git rather than from a copy kept beside this test, so the comparison cannot
    drift away from what the repository actually published.
    """
    import subprocess

    before = subprocess.run(
        ["git", "show", "eb4070c:contracts/openapi.yaml"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    ).stdout
    old = yaml.safe_load(before)
    new = _contract()

    assert set(old["paths"]) <= set(new["paths"]), (
        "a Phase 1 path disappeared"
    )
    for path, item in old["paths"].items():
        for method, operation in item.items():
            assert method in new["paths"][path], f"{method} {path} disappeared"
            for status in operation["responses"]:
                assert status in new["paths"][path][method]["responses"], (
                    f"{status} was removed from {method} {path}"
                )
    for name, schema in old["components"]["schemas"].items():
        assert name in new["components"]["schemas"], f"schema {name} disappeared"
        for member in schema.get("properties", {}):
            assert member in new["components"]["schemas"][name]["properties"], (
                f"{name}.{member} was removed"
            )
        for member in schema.get("enum", []):
            assert member in new["components"]["schemas"][name].get("enum", []), (
                f"{name} lost the enum member {member}"
            )
    assert set(old["components"]["schemas"]["Layer"]["enum"]) <= set(
        new["components"]["schemas"]["Layer"]["enum"]
    )
    assert set(old["components"]["schemas"]["ActionCode"]["enum"]) <= set(
        new["components"]["schemas"]["ActionCode"]["enum"]
    )
    # The third state is a transport status, not a new audit disposition: the
    # vocabulary the audit log stores is unchanged, which is what stops a
    # parallel one growing beside it.
    assert set(old["components"]["schemas"]["FinalDisposition"]["enum"]) == set(
        new["components"]["schemas"]["FinalDisposition"]["enum"]
    )
