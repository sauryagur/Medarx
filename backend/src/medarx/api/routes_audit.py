"""`GET /v1/audit/records` and `GET /v1/audit/records/{request_id}` — component G.

**What a reader is shown is the record, and the record is the storage policy.**
Both routes return exactly the fields component G persists, plus the two answers
that are computed on read: `chain_verified` (the walk's verdict, so no rewrite
can make a record claim it about itself) and `stages` (the pipeline prefix
derived from the record's blocking `layer`, so a stored copy could never disagree
with the record it was computed from). There is no raw-PHI field to omit,
redact or leak, because the log never stores one.

**The single-record route merges; the collection does not.** The contract says of
the first that "a request ID that produced both processing events and a final
disposition returns the merged record", and says nothing of the second — so the
second returns the stored records, one row per append, which is what an auditor
reading a chain position needs to see. Two endpoints answering the same question
with two different shapes would be the sort of thing a reader has to notice.

**An unrecognised filter is a `400`, not a wider page.** `medarx.audit.queries`
enforces the closed enums and the page size, and this route refuses both a value
outside an enum and a parameter the operation does not declare at all. The
second is the sharper edge: this readback is not study-scoped (see the contract's
own operation description), so a caller who writes `?study_reference=…` and is
silently ignored receives **every** record rather than the one study they asked
for, and the response body — `{records, count, chain_verified, input_source}` —
has no field that says the filter was dropped. Refusing is the only answer that
cannot mislead.

**This readback is authorized and unfiltered, and the limit is a privacy
decision.** A study-scoped readback cannot be implemented on this storage
policy: the record has no study field, and the policy forbids adding one, since
the log is required never to hold a study identifier. What the routes do instead
is require the caller to present a scope at all — see
`medarx.api.authz.Authorizer.require_any_scope`.
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from medarx.api.authz import SCOPE_HEADER, parse_scopes
from medarx.api.schemas import (
    AuditRecord,
    AuditRecordCollection,
    HumanApprovalState,
)
from medarx.api.wiring import (
    PROBLEM_AUDIT_RECORD_NOT_FOUND,
    PROBLEM_MALFORMED_REQUEST,
    PROBLEM_UNAUTHORIZED_SCOPE,
    json_response,
    problem,
    problem_response,
)
from medarx.audit.queries import DEFAULT_LIMIT, chain_status, events_for_request, \
    search_records
from medarx.audit.code_table import stages_reached
from medarx.errors import AuthzError
from medarx.models import AuditEvent

__all__ = ["ALLOWED_QUERY_PARAMETERS", "router", "record_view", "merged_view"]

router = APIRouter(tags=["audit"])

#: The query parameters this collection declares, exactly. Anything else is
#: refused rather than ignored, and the reason is a disclosure surface rather
#: than tidiness: a caller who writes `?study_reference=…` and is silently
#: ignored receives the **whole** page instead of the one study they asked for,
#: with nothing in the response saying the filter was dropped. The contract
#: already declares every parameter below, and `400 MalformedRequest` is the
#: answer it gives for a request it cannot interpret.
ALLOWED_QUERY_PARAMETERS: frozenset[str] = frozenset(
    {"request_id", "function", "disposition", "since", "limit"}
)


@router.get("/v1/audit/records")
async def list_audit_records(request: Request) -> JSONResponse:
    """A page of stored audit records, oldest first."""
    pipeline = request.app.state.pipeline
    denied = _authorize(request, "list")
    if denied is not None:
        return denied

    query = request.query_params
    unknown = sorted(set(query) - ALLOWED_QUERY_PARAMETERS)
    if unknown:
        return problem_response(problem(
            PROBLEM_MALFORMED_REQUEST, status=400,
            detail=(f"undeclared query parameter(s): {', '.join(unknown)}. This "
                    "operation accepts only "
                    f"{', '.join(sorted(ALLOWED_QUERY_PARAMETERS))}. An "
                    "unrecognised parameter is refused rather than ignored: "
                    "ignoring it would return a wider page than the caller "
                    "asked for, and nothing in the response would say so"),
            request_id=request.state.request_id))
    try:
        since = _parse_since(query.get("since"))
        limit = _parse_limit(query.get("limit"))
        events = search_records(
            pipeline.audit,
            request_id=query.get("request_id"),
            function=query.get("function"),
            disposition=query.get("disposition"),
            since=since,
            limit=limit,
        )
    except ValueError as exc:
        return problem_response(problem(
            PROBLEM_MALFORMED_REQUEST, status=400, detail=str(exc),
            request_id=request.state.request_id))

    verified = bool(chain_status(pipeline.audit)["chain_verified"])
    collection = AuditRecordCollection(
        records=[record_view(event, chain_verified=verified) for event in events],
        count=len(events),
        chain_verified=verified,
    )
    return json_response(200, collection.model_dump(mode="json"),
                         request.state.request_id)


@router.get("/v1/audit/records/{request_id}")
async def get_audit_record(request: Request) -> JSONResponse:
    """The merged record for one request ID, or `404`."""
    pipeline = request.app.state.pipeline
    denied = _authorize(request, "read")
    if denied is not None:
        return denied

    request_id = request.path_params["request_id"]
    events = events_for_request(pipeline.audit, request_id)
    if not events:
        return problem_response(problem(
            PROBLEM_AUDIT_RECORD_NOT_FOUND, status=404,
            detail=f"no audit record exists for request {request_id!r}",
            request_id=request.state.request_id))

    verified = bool(chain_status(pipeline.audit)["chain_verified"])
    return json_response(200, merged_view(events, chain_verified=verified),
                         request.state.request_id)


# -- Views --------------------------------------------------------------------


def record_view(event: AuditEvent, *, chain_verified: bool) -> AuditRecord:
    """One stored record, as the contract's `AuditRecord`."""
    approval = event.human_approval
    return AuditRecord(
        request_id=event.request_id,
        timestamp=event.timestamp,
        function=event.function,
        policy_version=event.policy_version,
        final_disposition=event.final_disposition,
        selected_model=event.selected_model,
        policy_mode=event.policy_mode,
        input_hash=event.input_hash,
        approved_payload_hash=event.approved_payload_hash,
        redacted_field_names=list(event.redacted_field_names),
        action_codes=list(event.action_codes),
        human_approval=(
            None if approval is None else
            HumanApprovalState(decision=approval.decision,
                               recorded_at=approval.recorded_at,
                               reviewer=approval.reviewer)
        ),
        layer=event.layer,
        chain_verified=chain_verified,
        stages=list(stages_reached(event.layer)),
    )


def merged_view(events: "list[AuditEvent]", *, chain_verified: bool) -> dict:
    """One request's records as the single record the contract describes.

    The first record carries the identity of the request — its function, hashes
    and the layer that refused it, if anything did — and the **last** decision
    recorded against it carries the disposition. Merged, not summarised: no
    field is dropped and no count is invented, and the audit log still holds
    every append separately for anyone reading the chain.
    """
    first = record_view(events[0], chain_verified=chain_verified)
    approvals = [e for e in events if e.human_approval is not None]
    if approvals:
        latest = approvals[-1]
        merged = first.model_copy(update={
            "human_approval": record_view(latest, chain_verified=chain_verified
                                           ).human_approval,
            "final_disposition": latest.final_disposition,
        })
    else:
        merged = first
    return merged.model_dump(mode="json")


# -- Query parameters ---------------------------------------------------------


def _parse_since(raw: str | None) -> datetime | None:
    """The `since` parameter as an aware RFC 3339 instant, or `None`.

    A naive value is refused rather than assumed: a bare local time has two
    readings and which one bounds the page would be a guess made silently.
    `search_records` raises on a naive instant too; this only turns the parse
    itself into the same `400`.
    """
    if raw is None or not raw.strip():
        return None
    try:
        value = datetime.fromisoformat(raw.strip())
    except ValueError as exc:
        raise ValueError(
            f"since={raw!r} is not an RFC 3339 instant such as "
            "2026-01-14T09:30:00Z"
        ) from exc
    if value.tzinfo is None:
        raise ValueError(
            f"since={raw!r} carries no UTC offset: a naive instant has two "
            "readings, and which one is the page's boundary would be a guess "
            "made silently. RFC 3339 puts the offset on the value."
        )
    return value


def _parse_limit(raw: str | None) -> int:
    """The `limit` parameter, or the contract's default.

    The bounds are the parameter's own, and they are enforced in
    `medarx.audit.queries`; this only turns a non-integer into the same `400`
    rather than letting a `ValueError` escape as a `500`.
    """
    if raw is None or not raw.strip():
        return DEFAULT_LIMIT
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"limit={raw!r} is not an integer") from exc


def _authorize(request: Request, action: str) -> JSONResponse | None:
    """The `403` document, or `None` when the caller presented a scope."""
    try:
        request.app.state.authorizer.require_any_scope(
            request.state.request_id,
            parse_scopes(request.headers.get(SCOPE_HEADER)),
        )
    except AuthzError as exc:
        return problem_response(problem(
            PROBLEM_UNAUTHORIZED_SCOPE, status=403,
            detail=(f"reading the audit log requires a presented scope ({action}). "
                    "X-Scope is an authorization boundary this Phase 1 API models "
                    "and enforces; it is not authentication, and the contract "
                    "declares no security scheme"),
            request_id=request.state.request_id))
    return None
