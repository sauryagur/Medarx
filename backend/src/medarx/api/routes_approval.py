"""`POST /v1/executions/{request_id}/approval` — the human sign-off, and only that.

**This endpoint records a judgement and does nothing else.** It does not publish
the draft, submit it to a clinical system, or trigger any downstream clinical
action. The design gives Medarx no autonomous clinical write-back, and this is
where that promise is kept: there is no code path from this handler to a
transmission of any kind, and the only thing it appends is an audit record.

**It accepts no draft content.** The caller approves or rejects by request ID
and cannot edit or resubmit anything, because `HumanApprovalRequest` is closed
and carries no content field. Editing a draft requires a new execution, which
re-runs the whole privacy pipeline — which is the only way a changed draft could
ever have been approved by the policy that approves payloads.

**A decision is immutable.** The audit log is append-only, so a second decision
is `409` and not an update. A changed mind requires a new execution, and the
contract says so in the words of the `409` response itself.

**`404` for a request that never produced a draft.** A blocked request has an
audit record and no execution, and the contract's `ExecutionNotFound` is exactly
"no execution exists for the supplied request ID". Approving a refusal would be
approving nothing.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError as PydanticValidationError

from medarx.api.authz import SCOPE_HEADER, parse_scopes
from medarx.api.schemas import HumanApprovalRequest, HumanApprovalResponse
from medarx.api.wiring import (
    PROBLEM_DECISION_ALREADY_RECORDED,
    PROBLEM_EXECUTION_NOT_FOUND,
    PROBLEM_MALFORMED_REQUEST,
    PROBLEM_UNAUTHORIZED_SCOPE,
    PROBLEM_UNSUPPORTED_MEDIA_TYPE,
    decode_json,
    json_response,
    problem,
    problem_response,
    validation_errors,
)
from medarx.errors import AuthzError

__all__ = ["router"]

router = APIRouter(tags=["approval"])


@router.post("/v1/executions/{request_id}/approval")
async def record_human_approval(request: Request) -> JSONResponse:
    """Record an explicit human approval or rejection of a drafted response."""
    pipeline = request.app.state.pipeline
    settings = request.app.state.settings
    request_id = request.state.request_id
    execution_id = request.path_params["request_id"]

    try:
        request.app.state.authorizer.require_any_scope(
            request_id, parse_scopes(request.headers.get(SCOPE_HEADER))
        )
    except AuthzError:
        return problem_response(problem(
            PROBLEM_UNAUTHORIZED_SCOPE, status=403,
            detail=("recording a decision requires a presented scope. X-Scope is "
                    "an authorization boundary this Phase 1 API models and "
                    "enforces; it is not authentication, and the contract "
                    "declares no security scheme"),
            request_id=request_id))

    media_type = (request.headers.get("content-type") or "").split(";")[0].strip()
    if media_type.lower() != "application/json":
        return problem_response(problem(
            PROBLEM_UNSUPPORTED_MEDIA_TYPE, status=415,
            detail="this API accepts structured JSON only",
            request_id=request_id))

    raw = await request.body()
    if len(raw) > settings.max_body_bytes:
        return problem_response(problem(
            PROBLEM_MALFORMED_REQUEST, status=400,
            detail=(f"the request body is larger than the {settings.max_body_bytes} "
                    "bytes this deployment accepts"),
            request_id=request_id))

    try:
        body = HumanApprovalRequest.model_validate(decode_json(raw))
    except PydanticValidationError as exc:
        return problem_response(problem(
            PROBLEM_MALFORMED_REQUEST, status=400,
            detail=("the request does not match the human approval schema. This "
                    "endpoint accepts no draft content: a draft is approved or "
                    "rejected by request ID and never edited here"),
            request_id=request_id,
            errors=validation_errors(exc)))
    except (ValueError, UnicodeDecodeError):
        return problem_response(problem(
            PROBLEM_MALFORMED_REQUEST, status=400,
            detail="the request body is not valid JSON", request_id=request_id))

    try:
        event = pipeline.record_approval(
            execution_id, body.decision, body.reviewer, body.note
        )
    except LookupError:
        return problem_response(problem(
            PROBLEM_EXECUTION_NOT_FOUND, status=404,
            detail=(f"no execution exists for request {execution_id!r}; a request "
                    "that was refused has a record and no draft to sign off"),
            request_id=request_id))
    except FileExistsError as exc:
        return problem_response(problem(
            PROBLEM_DECISION_ALREADY_RECORDED, status=409, detail=str(exc),
            request_id=request_id))
    except ValueError as exc:
        return problem_response(problem(
            PROBLEM_MALFORMED_REQUEST, status=400, detail=str(exc),
            request_id=request_id))

    return json_response(
        200,
        HumanApprovalResponse(
            request_id=execution_id,
            decision=body.decision,
            recorded_at=event.timestamp,
            final_disposition=event.final_disposition,
        ).model_dump(mode="json"),
        request_id,
    )
