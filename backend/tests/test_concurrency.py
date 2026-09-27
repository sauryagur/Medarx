"""Four callers at once: one surrogate, one hash, an intact chain.

The review focus for this task was a race, so this is the test for it. Four
identical requests arrive simultaneously and the invariants that must survive
are the ones the pseudonymization store and the audit log's hash chain each
promise on their own:

- the same study maps to one surrogate, so all four approved payloads carry the
  same `study_ref` and therefore the same `approved_payload_hash`;
- the chain still verifies afterwards, so no append forked it;
- every one of the four is readable back with `chain_verified` true.

The point of running it through the HTTP surface rather than against the
pipeline is the same as everywhere else in this task: the app holds a single
`MappingStore` and a single `AuditLog`, and only an API-level test exercises
that sharing the way the server will.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from conftest import EXEC_URL, KNOWN_POSITIVE_BODY, SCOPE_HEADERS

CALLERS = 4


def test_concurrent_requests_share_one_payload_and_the_chain_still_verifies(client,
                                                                            pipeline):
    with ThreadPoolExecutor(max_workers=CALLERS) as pool:
        results = list(pool.map(
            lambda _: client.post(EXEC_URL, json=KNOWN_POSITIVE_BODY,
                                  headers=SCOPE_HEADERS),
            range(CALLERS),
        ))

    assert {r.status_code for r in results} == {200}
    assert len({r.json()["approved_payload_hash"] for r in results}) == 1
    assert len({r.json()["request_id"] for r in results}) == CALLERS
    assert pipeline.audit.verify_chain().ok is True

    for response in results:
        record = client.get(f"/v1/audit/records/{response.json()['request_id']}",
                            headers=SCOPE_HEADERS)
        assert record.status_code == 200
        assert record.json()["chain_verified"] is True


def test_concurrent_approvals_all_append_and_the_chain_still_verifies(client, pipeline):
    """A 409 race would be a lost decision, not a lost write: the log is
    append-only, so two approvals of the same request must not both land."""
    approved = client.post(EXEC_URL, json=KNOWN_POSITIVE_BODY, headers=SCOPE_HEADERS)
    request_id = approved.json()["request_id"]

    with ThreadPoolExecutor(max_workers=CALLERS) as pool:
        results = list(pool.map(
            lambda i: client.post(
                f"/v1/executions/{request_id}/approval",
                json={"decision": "approved", "reviewer": f"rev-{i:02d}"},
                headers=SCOPE_HEADERS,
            ),
            range(CALLERS),
        ))

    statuses = sorted(r.status_code for r in results)
    assert statuses[0] == 200
    assert set(statuses[1:]) == {409}
    assert pipeline.audit.verify_chain().ok is True

    decisions = [e for e in pipeline.audit.get(request_id) if e.human_approval is not None]
    assert len(decisions) == 1, "a 409 must mean the decision was already recorded"
