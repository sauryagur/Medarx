"""The viewer's request set, driven against the real observer.

`viewer/src/api/client.ts` makes exactly four calls: policy, preflight, send,
and audit readback. These tests issue those calls and nothing else, so the
observer is the only judge of whether bytes left the kernel.
"""

from __future__ import annotations

import re

from conftest import EXEC_URL, SCOPE_HEADERS, body_with, body_with_dicom
from test_observer_service import _observer_backed_client, observer  # noqa: F401
from test_preflight import UNRESOLVABLE, _validator

#: The four calls `client.ts` makes, as (method, path template).
VIEWER_CALLS = {
    ("GET", "/v1/policy"),
    ("POST", "/v1/functions/Draft/executions/preflight"),
    ("POST", "/v1/executions/{request_id}/send"),
    ("GET", "/v1/audit/records/{request_id}"),
}

APPROVED_BODY = body_with_dicom(StudyDate="20260114")
BLOCKED_BODY = body_with(report_text={"text": UNRESOLVABLE, "source": "synthetic_corpus"})


def _policy(client):
    return client.get("/v1/policy")


def _preflight(client, body):
    return client.post(f"{EXEC_URL}/preflight", json=body, headers=SCOPE_HEADERS)


def _send(client, request_id):
    return client.post(f"/v1/executions/{request_id}/send", headers=SCOPE_HEADERS)


def _audit(client, request_id):
    return client.get(f"/v1/audit/records/{request_id}", headers=SCOPE_HEADERS)


def _template(method: str, path: str) -> tuple[str, str]:
    path = re.sub(r"^/v1/executions/[^/]+/send$", "/v1/executions/{request_id}/send", path)
    path = re.sub(r"^/v1/audit/records/[^/]+$", "/v1/audit/records/{request_id}", path)
    return method, path


def test_approved_path_transmits_exactly_once_and_only_on_send(observer, tmp_path):
    client = _observer_backed_client(observer, tmp_path)
    assert observer.health()["record_count"] == 0

    preflight = _preflight(client, APPROVED_BODY)
    assert preflight.status_code == 200, preflight.text
    validated = preflight.json()
    assert validated["status"] == "needs_review"
    _validator("PreflightResponse").validate(validated)
    assert observer.health()["record_count"] == 0, "a validated preflight must not transmit"

    sent = _send(client, validated["request_id"])
    assert sent.status_code == 200, sent.text
    approved = sent.json()
    assert approved["status"] == "approved"
    assert approved["request_id"] == validated["request_id"]
    _validator("ExecutionResponse").validate(approved)
    assert observer.health()["record_count"] == 1, "the send is the one transmission"


def test_blocked_path_refuses_and_its_send_transmits_nothing(observer, tmp_path):
    client = _observer_backed_client(observer, tmp_path)

    blocked = _preflight(client, BLOCKED_BODY)
    assert blocked.status_code == 422, blocked.text
    receipt = blocked.json()
    assert receipt["status"] == "blocked"
    _validator("BlockReceipt").validate(receipt)
    assert receipt["action_codes"], "a block names at least one disposition code"
    assert observer.health()["status"] == "ok", "the observer must be live for zero to mean anything"

    refused = _send(client, receipt["request_id"])
    assert refused.status_code == 404, refused.text
    assert "draft" not in refused.text
    assert observer.health()["record_count"] == 0
    assert observer.index() == [], "a blocked request must leave no record"


def test_validated_but_unsent_transmits_nothing_and_has_no_audit_record(observer, tmp_path):
    client = _observer_backed_client(observer, tmp_path)

    validated = _preflight(client, APPROVED_BODY).json()
    assert validated["status"] == "needs_review"
    assert observer.health()["record_count"] == 0
    assert observer.index() == []
    assert _audit(client, validated["request_id"]).status_code == 404

    # Positive control: the same request id is live, so the send is what transmits.
    assert _send(client, validated["request_id"]).status_code == 200
    assert observer.health()["record_count"] == 1
    assert _audit(client, validated["request_id"]).status_code == 200


def test_the_viewer_makes_only_its_four_calls_with_the_scope_it_declares(observer, tmp_path):
    client = _observer_backed_client(observer, tmp_path)
    seen = []
    client.event_hooks["request"].append(seen.append)

    assert _policy(client).status_code == 200
    approved = _preflight(client, APPROVED_BODY).json()
    assert _send(client, approved["request_id"]).status_code == 200
    assert _audit(client, approved["request_id"]).status_code == 200
    blocked = _preflight(client, BLOCKED_BODY).json()
    assert blocked["status"] == "blocked"
    assert _audit(client, blocked["request_id"]).status_code == 200

    templates = {_template(request.method, request.url.path) for request in seen}
    assert templates == VIEWER_CALLS, templates

    for request in seen:
        is_policy = request.url.path == "/v1/policy"
        assert ("x-scope" in request.headers) != is_policy, request.url.path
        if request.url.path.endswith("/send"):
            assert "content-type" not in request.headers, "send carries no body"
