"""`POST /v1/functions/{function_name}/executions` — component J's front door.

The order of the checks below is the order the design's §6 row 1 implies, and
each step is a place where a request stops having any further effect:

1. **request identity** — resolved by the middleware, before the body is read, so
   a refusal is still reportable against a request ID the caller chose;
2. **media type** — `415` for anything but `application/json`. This surface
   accepts structured JSON and does not accept DICOM multipart payloads, so
   `multipart/related` and `application/dicom` are refused by design;
3. **body size** — `400` past `Settings.max_body_bytes`, measured on the bytes
   actually received rather than only on the declared `Content-Length`;
4. **shape** — the body must match the contract's `ExecutionRequest` or it is a
   `400` listing the offending fields. This is where an arbitrary DICOM object or
   a free-form prompt is refused, and it happens *before* anything is parsed into
   a domain object, let alone run;
5. **authorization** — `403` for an out-of-scope study or an unpermitted
   function. Deliberately after the shape check, so the body has to be
   structurally valid before the pipeline learns anything about it, and
   deliberately a different status from every refusal below;
6. **the pipeline** — which returns a result rather than raising, so a privacy
   block is a `422` with a `BlockReceipt` and a provider outage is a `500`.

**Nothing here constructs a component.** Every one of them came from
`app.state.pipeline`, which `create_app` built once, so a test and the server
exercise the same wiring.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError as PydanticValidationError

from medarx.api import surface, wiring
from medarx.api.authz import SCOPE_HEADER, parse_scopes
from medarx.api.schemas import ExecutionRequest as ExecutionRequestBody
from medarx.api.wiring import (
    PROBLEM_FUNCTION_NOT_FOUND,
    PROBLEM_FUNCTION_NOT_PERMITTED,
    PROBLEM_MALFORMED_REQUEST,
    PROBLEM_REQUEST_VALIDATION,
    PROBLEM_STUDY_SCOPE_UNAUTHORIZED,
    PROBLEM_UNAUTHORIZED_SCOPE,
    PROBLEM_UNSUPPORTED_MEDIA_TYPE,
    block_response,
    problem,
    problem_response,
)
from medarx.errors import AuthzError
from medarx.pipeline import FUNCTION_WIRE_TO_INTERNAL

__all__ = ["router"]

router = APIRouter(tags=["execution"])


@router.post("/v1/functions/{function_name}/executions")
async def create_function_execution(request: Request) -> JSONResponse:
    """Execute a named function over clinician-supplied report text."""
    pipeline = request.app.state.pipeline
    settings = request.app.state.settings
    authorizer = request.app.state.authorizer
    request_id = request.state.request_id

    # 2. Media type. Checked before the body is touched, because a body this
    #    surface will not accept is not worth reading.
    media_type = (request.headers.get("content-type") or "").split(";")[0].strip()
    if media_type.lower() != "application/json":
        return problem_response(problem(
            PROBLEM_UNSUPPORTED_MEDIA_TYPE,
            status=415,
            detail=("this API accepts structured JSON only; it does not accept "
                    "DICOM multipart payloads"),
            request_id=request_id,
        ))

    # 3. Body size, measured. The middleware has already refused an oversized
    #    `Content-Length` before the body was read; this is the half a chunked
    #    request cannot avoid, and a guard reading only the header would pass an
    #    oversized body straight through.
    raw = await request.body()
    if len(raw) > settings.max_body_bytes:
        return problem_response(problem(
            PROBLEM_MALFORMED_REQUEST,
            status=400,
            detail=(f"the request body is larger than the {settings.max_body_bytes} "
                    "bytes this deployment accepts"),
            request_id=request_id,
        ))

    # 4. The path names one of the three closed functions, or it names none.
    wire_function = request.path_params["function_name"]
    if wire_function not in FUNCTION_WIRE_TO_INTERNAL:
        return problem_response(problem(
            PROBLEM_FUNCTION_NOT_FOUND,
            status=404,
            detail=("the function set is closed: Draft, Prior Summary and Ask. "
                    f"{wire_function!r} is not one of them, and a request naming "
                    "an unknown function never enters the pipeline"),
            request_id=request_id,
        ))

    input_hash = wiring.hash_of_bytes(raw)
    try:
        body = ExecutionRequestBody.model_validate(wiring.decode_json(raw))
    except PydanticValidationError as exc:
        # First, because pydantic's `ValidationError` is a `ValueError` and a
        # schema violation is not the same condition as unparseable JSON: one
        # names properties, the other names no property at all.
        offending = wiring.offending_properties(exc)
        surface.record_surface_refusal(
            pipeline.audit,
            request_id=request_id,
            function=wire_function,
            input_hash=input_hash,
            policy_version=settings.policy_version,
            policy_mode=settings.policy_mode,
            reason=surface.reason_for_shape(offending),
        )
        detail = ("Unrecognized or disallowed properties present: "
                  f"{', '.join(offending)}. " if offending else "")
        return problem_response(problem(
            PROBLEM_REQUEST_VALIDATION,
            status=400,
            detail=(detail + "Medarx does not accept arbitrary DICOM objects or "
                    "free-form prompts at this surface."),
            request_id=request_id,
            errors=wiring.validation_errors(exc),
        ))
    except (ValueError, UnicodeDecodeError):
        # Unparseable JSON: no property to name, so no shape code either.
        return problem_response(problem(
            PROBLEM_MALFORMED_REQUEST,
            status=400,
            detail="the request body is not valid JSON",
            request_id=request_id,
        ))

    try:
        wiring.resolve_function(body.function, wire_function)
    except ValueError as exc:
        return problem_response(problem(
            PROBLEM_REQUEST_VALIDATION,
            status=400,
            detail=str(exc),
            request_id=request_id,
        ))

    # 5. Authorization. The path's function is what is checked, because it is the
    #    one the caller addressed; a body naming a function the contract does not
    #    have is component A's refusal, and it is reached only once the request
    #    has been found permitted to be made at all.
    grants = parse_scopes(request.headers.get(SCOPE_HEADER))
    try:
        authorizer.require(
            request_id, wire_function, body.study_context.study_reference, grants
        )
    except AuthzError as exc:
        surface.record_surface_refusal(
            pipeline.audit,
            request_id=request_id,
            function=wire_function,
            input_hash=input_hash,
            policy_version=settings.policy_version,
            policy_mode=settings.policy_mode,
            reason=surface.reason_for_authz(getattr(exc, "reason", "")),
        )
        return problem_response(_authz_problem(exc, request_id))

    # 6. The pipeline. It *returns* for a privacy block — a `422` with a
    #    `BlockReceipt` — and *raises* for a provider outage, which is a
    #    different condition in the design's own terms and is rendered by
    #    `Boundary`, the one place in the application that turns an exception
    #    into a response. A `ProviderError` caught here as well would be two
    #    handlers for one condition, and the second would never run.
    execution = wiring.execution_request_from_body(body, wire_function, input_hash)
    result = pipeline.run(request_id, execution)
    if not result.approved:
        return block_response(result.block_receipt)
    return wiring.json_response(
        200, wiring.execution_response_body(result, wire_function), request_id)


def _authz_problem(exc: AuthzError, request_id: str):
    """The `403` document, split by cause.

    Two causes the contract names, so two problem types: a caller can tell "you
    may not run that function here" from "that study is not yours" without
    reading the detail, and both are `403` — never `422`, because a request that
    was not permitted in the first place is a different condition from one that
    was permitted and then refused by the privacy pipeline.
    """
    reason = getattr(exc, "reason", "")
    if reason == "function_not_permitted":
        return problem(
            PROBLEM_FUNCTION_NOT_PERMITTED, status=403,
            detail="the requested function is not permitted in the caller's scope",
            request_id=request_id)
    if reason == "study_scope_unauthorized":
        return problem(
            PROBLEM_STUDY_SCOPE_UNAUTHORIZED, status=403,
            detail=("the requested study is not within the caller's authorized "
                    "scope"),
            request_id=request_id)
    return problem(
        PROBLEM_UNAUTHORIZED_SCOPE, status=403,
        detail=("no scope was presented. X-Scope is an authorization boundary "
                "this Phase 1 API models and enforces; it is not authentication, "
                "and the contract declares no security scheme"),
        request_id=request_id)
