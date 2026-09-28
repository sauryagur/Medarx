"""The validate-then-send pair: preflight, and the send bound to it.

Two operations, and the whole of their design is the sentence between them:
**a preflight publishes the payload, and a send transmits that payload and no
other.**

**Why they exist.** `POST /v1/functions/{function_name}/executions` is atomic —
it validates, transforms, decides, calls the provider and answers, so `approved`
and `sent` are the same instant and there is no moment at which a human is
reviewing anything. A client cannot enable a *send* control on a validation it
cannot see, nor disable it on a decision it has not been told, and a payload
preview has to come from the server: a client-side rendering of "what it would
probably send" is a different algorithm from the server's and will disagree with
it. Splitting the two operations is what makes the `Needs review` state a state
the system evaluated rather than one a client asserted.

**The binding is the payload's identity, not a stored copy's goodness.** The
preflight mints component F's own `ApprovedSend` — the frozen token `send`
accepts and nothing else accepts — over the approved payload and the wire body
built from it, and holds it. The send hands that token to `send` and touches
nothing else: no component is re-run, no payload is re-derived, and the bytes
that go on the wire are the bytes that were built at authorisation. So a
preview and a transmission cannot disagree, because there is no second
computation for them to disagree about. Three things still refuse a send before
any byte moves:

- **no pending approval** — `404`. An unknown, already-sent, restarted or
  evicted request ID. Never re-derived, because re-running the pipeline is how a
  caller ends up sending a payload nobody previewed.
- **the policy version moved** — `422`, layer `E`. The approval was made under
  one policy and component E has another in force; design §6 row 6 makes that a
  fail-closed block.
- **the token is not the one the approval recorded** — `422`, layer `F`. A
  substitution, refused with the two codes row 7 names.

**An approval is one-shot.** It is consumed by the first send, before either
check runs, so a double-clicked control cannot transmit twice and cannot file
two records under one request ID. A later send is the same `404` as one that
never existed. A preflight is not durable: the pending payload lives in this
process, in memory, bounded, and is never written to the audit log — whose
storage policy admits no field that could hold a value. A restart loses every
pending approval, and the contract says so rather than smoothing it over.

**A validated preflight writes no audit record.** Nothing was refused and
nothing was transmitted; the record is written by the send, or by the block. A
`GET /v1/audit/records/{request_id}` for a validated-but-unsent preflight is
therefore `404`, and the contract states it.

**This endpoint cannot choose a policy mode.** It takes the same closed
`ExecutionRequest` as the atomic path, which has no `policy_mode` property and
is `additionalProperties: false`; a request that supplies one is a `400`. The
mode in force is *displayed* in the response so a client can render it, and it
is read from the deployment through component E, exactly as `GET /v1/policy`
reports it. A client that offered a mode selector would be a second, unaudited
way to choose the boundary, which is the thing the policy-mode design forbids.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from medarx.api import intake, surface, wiring
from medarx.api.authz import SCOPE_HEADER, parse_scopes
from medarx.api.wiring import (
    PROBLEM_EXECUTION_NOT_FOUND,
    PROBLEM_UNAUTHORIZED_SCOPE,
    problem,
    problem_response,
)
from medarx.errors import AuthzError

__all__ = ["router"]

router = APIRouter(tags=["preflight"])

#: The detail for a send with no approval to send. Named so the two `404`s this
#: surface can produce — an unknown function and an unknown request ID — cannot
#: be worded identically, and so a client branching on the problem type still
#: gets a sentence a human can act on.
_NO_PENDING_APPROVAL = (
    "no pending preflight approval exists for this request ID. An approval is "
    "consumed by the first send and is held in this process only, so a request "
    "ID that was never preflighted, has already been sent, was evicted, or "
    "belongs to a process that has restarted has none. Run the preflight again "
    "to get a new one; nothing is re-derived here on your behalf."
)


@router.post("/v1/functions/{function_name}/executions/preflight")
async def preflight_function_execution(request: Request) -> JSONResponse:
    """Validate a request, publish the payload it would send, and stop."""
    accepted = await intake.accept_execution(
        request, operation="the preflight endpoint"
    )
    if isinstance(accepted, JSONResponse):
        return accepted
    result = request.app.state.pipeline.preflight(
        request.state.request_id, accepted.execution
    )
    if not result.needs_review:
        # A block, on the same terms as the atomic path: a `422` and a
        # `BlockReceipt`, never a problem document, and never a payload.
        return wiring.block_response(result.block_receipt)
    return wiring.json_response(
        200,
        wiring.preflight_response_body(result, accepted.addressed_function),
        request.state.request_id,
    )


@router.post("/v1/executions/{request_id}/send")
async def send_preflighted_execution(request: Request) -> JSONResponse:
    """Transmit exactly the payload a preflight approved.

    **No body, and no content of any kind.** The draft cannot be edited,
    substituted or smuggled through this path: the caller names a request ID and
    the server transmits the bytes component F authorised for it. The human
    sign-off is a different endpoint with a different job — it records a
    judgement about a draft that already exists, and this one is the
    transmission gate in front of the first one.

    **Two refusals here leave no audit record, and both are the same reason.**
    `AuditEvent.function` is required and is the contract's closed `FunctionName`
    enum, and a request ID with no preflight behind it has no truthful value to
    file a record under — the same reasoning the unknown-function `404` on the
    execution path uses. A `403` *with* a pending approval behind it *is*
    recorded, and the peek that names the function consumes nothing.
    """
    pipeline = request.app.state.pipeline
    settings = request.app.state.settings
    request_id = request.state.request_id
    supplied = request.path_params["request_id"]

    # Authorization is `any scope`, not a function or a study check: the request
    # ID names a preflight, not a study, and there is no study to check a study
    # scope against. The audit record behind a preflight carries no study
    # property at all — the storage policy forbids one — so a study-scoped check
    # here would have nothing to compare and would pass for every caller holding
    # any scope, which is the kind of guard that reads as a control and is not
    # one.
    pending = pipeline.pending_for(supplied)
    try:
        request.app.state.authorizer.require_any_scope(
            supplied, parse_scopes(request.headers.get(SCOPE_HEADER))
        )
    except AuthzError:
        if pending is not None:
            surface.record_surface_refusal(
                pipeline.audit,
                request_id=supplied,
                function=pending.addressed_function,
                input_hash=pending.input_hash,
                policy_version=settings.policy_version,
                policy_mode=settings.policy_mode,
                reason=surface.reason_for_authz("unauthorized_scope"),
            )
        return problem_response(problem(
            PROBLEM_UNAUTHORIZED_SCOPE, status=403,
            detail=("X-Scope is an authorization boundary this Phase 1 API "
                    "models and enforces; it is not authentication, and the "
                    "contract declares no security scheme"),
            request_id=request_id))

    try:
        result = pipeline.send_approved(supplied)
    except LookupError:
        return problem_response(problem(
            PROBLEM_EXECUTION_NOT_FOUND, status=404,
            detail=_NO_PENDING_APPROVAL, request_id=supplied))

    if not result.approved:
        return wiring.block_response(result.block_receipt)
    return wiring.json_response(
        200, wiring.execution_response_body(result, result.addressed_function),
        supplied)
