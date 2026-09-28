"""The six ordered checks every `ExecutionRequest` passes before the kernel sees it.

The order is the design's §6 row 1, and each step is a place a request stops
having any further effect:

1. **function identity** — the path names one of the three closed functions, or
   it names none. Checked before the body is touched, because the function set
   is closed and this is the cheapest statement of that, and because every
   refusal below it can then be recorded against a function the audit log can
   actually hold;
2. **media type** — `415` for anything but `application/json`. This surface
   accepts structured JSON and does not accept DICOM multipart payloads, so
   `multipart/related` and `application/dicom` are refused by design;
3. **body size** — `400` past `Settings.max_body_bytes`, measured on the bytes
   actually received rather than only on the declared `Content-Length`;
4. **shape** — the body must match the contract's `ExecutionRequest` or it is a
   `400` listing the offending fields. This is where an arbitrary DICOM object
   or a free-form prompt is refused, and it happens *before* anything is parsed
   into a domain object, let alone run;
5. **authorization** — `403` for an out-of-scope study or an unpermitted
   function. Deliberately after the shape check, so the body has to be
   structurally valid before the pipeline learns anything about it, and
   deliberately a different status from every refusal below;
6. the kernel, which the route calls.

**Why this is a module and not a route.** Two routes accept an
`ExecutionRequest` — the atomic execution and the preflight — and they must
apply the identical six. A copy in each would be a second implementation of the
boundary, and the failure mode of that is not a crash: it is a preflight that
accepts a body the execution route would have refused, which is exactly the
kind of disagreement a validate-then-send split is supposed to make impossible.

**The one refusal that leaves no record.** An unknown function in the path
cannot be filed, because `AuditEvent.function` is required and is the contract's
closed `FunctionName` enum, and a request naming a function that does not exist
has no truthful value to file it under. It is described in full where it is
decided, in `routes_functions.NOT_A_FUNCTION_NOTE`, so the two routes cannot
word it differently.

Every refusal that is a document returns it; the caller sends it unchanged.
Nothing here constructs a component: every one of them came from
`app.state.pipeline`, which `create_app` built once.
"""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import ValidationError as PydanticValidationError

from medarx.api import surface, wiring
from medarx.api.authz import SCOPE_HEADER, parse_scopes
from medarx.api.schemas import ExecutionRequest as ExecutionRequestBody
from medarx.api.wiring import (
    PROBLEM_FUNCTION_NOT_PERMITTED,
    PROBLEM_FUNCTION_NOT_FOUND,
    PROBLEM_MALFORMED_REQUEST,
    PROBLEM_REQUEST_VALIDATION,
    PROBLEM_STUDY_SCOPE_UNAUTHORIZED,
    PROBLEM_UNAUTHORIZED_SCOPE,
    PROBLEM_UNSUPPORTED_MEDIA_TYPE,
    problem,
    problem_response,
)
from medarx.errors import AuthzError
from medarx.models import FunctionName
from medarx.pipeline import FUNCTION_WIRE_TO_INTERNAL, ExecutionRequest

__all__ = ["Accepted", "NOT_A_FUNCTION_NOTE", "accept_execution"]


#: The detail text for a path naming a function outside the closed set. One
#: string, used by both routes, so the two cannot word the same refusal
#: differently — and a caller that reads one of them has read the other.
NOT_A_FUNCTION_NOTE = (
    "the function set is closed: Draft, Prior Summary and Ask. "
    "{name!r} is not one of them, and a request naming an unknown function "
    "never enters the pipeline"
)


@dataclass(frozen=True)
class Accepted:
    """A request that passed all six checks, and the kernel's form of it."""

    addressed_function: FunctionName
    execution: ExecutionRequest


async def accept_execution(request, *, operation: str):
    """Run the six checks. `Accepted`, or the `JSONResponse` that answers them.

    `operation` names the contract operation in the `400` and `415` details,
    because the two routes refuse the same shapes for different reasons — a
    preflight that is malformed is malformed *as a preflight* — and a caller
    reading the detail should be able to tell which call they made.

    The return is a union rather than a raised exception on purpose: these are
    documents, not faults. Nothing below is a bug; every branch is a refusal the
    contract already describes, and a `JSONResponse` is what a refusal is.
    """
    pipeline = request.app.state.pipeline
    settings = request.app.state.settings
    authorizer = request.app.state.authorizer
    request_id = request.state.request_id

    # 1. The path names one of the three closed functions, or it names none.
    wire_function = request.path_params["function_name"]
    if wire_function not in FUNCTION_WIRE_TO_INTERNAL:
        return problem_response(problem(
            PROBLEM_FUNCTION_NOT_FOUND,
            status=404,
            detail=NOT_A_FUNCTION_NOTE.format(name=wire_function),
            request_id=request_id,
        ))
    input_hash = wiring.hash_of_bytes(b"")

    def refuse(document, reason=surface.REASON_UNCLASSIFIED_SHAPE):
        """Record the refusal, then answer it.

        Every refusal at this surface leaves a record. A refusal with no trace
        is not evidence, and a probe sweep with malformed requests would
        otherwise leave none at all — the shape of record a reader is entitled to
        find, named by the request ID this response echoes.
        """
        surface.record_surface_refusal(
            pipeline.audit,
            request_id=request_id,
            function=wire_function,
            input_hash=input_hash,
            policy_version=settings.policy_version,
            policy_mode=settings.policy_mode,
            reason=reason,
        )
        return problem_response(document)

    # 2. Media type. Declared before the body is read, because a body this
    #    surface will not accept is not worth reading.
    media_type = (request.headers.get("content-type") or "").split(";")[0].strip()
    if media_type.lower() != "application/json":
        return refuse(problem(
            PROBLEM_UNSUPPORTED_MEDIA_TYPE,
            status=415,
            detail=(f"{operation} accepts structured JSON only; it does not "
                    "accept DICOM multipart payloads"),
            request_id=request_id,
        ))

    raw = await request.body()
    input_hash = wiring.hash_of_bytes(raw)

    # 3. Body size, measured. The middleware has already refused an oversized
    #    `Content-Length` before the body was read; this is the half a chunked
    #    request cannot avoid, and a guard reading only the header would pass an
    #    oversized body straight through.
    if len(raw) > settings.max_body_bytes:
        return refuse(problem(
            PROBLEM_MALFORMED_REQUEST,
            status=400,
            detail=(f"the request body is larger than the "
                    f"{settings.max_body_bytes} bytes this deployment accepts"),
            request_id=request_id,
        ))

    # 4. The body against the contract's `ExecutionRequest`. This is where an
    #    arbitrary DICOM object or a free-form prompt is refused, and it happens
    #    *before* anything is parsed into a domain object, let alone run.
    try:
        body = ExecutionRequestBody.model_validate(wiring.decode_json(raw))
    except PydanticValidationError as exc:
        offending = wiring.offending_properties(exc)
        detail = ("Unrecognized or disallowed properties present: "
                  f"{', '.join(offending)}. " if offending else "")
        return refuse(problem(
            PROBLEM_REQUEST_VALIDATION,
            status=400,
            detail=(detail + "Medarx does not accept arbitrary DICOM objects or "
                    "free-form prompts at this surface."),
            request_id=request_id,
            errors=wiring.validation_errors(exc),
        ), surface.reason_for_shape(offending))
    except (ValueError, UnicodeDecodeError):
        return refuse(problem(
            PROBLEM_MALFORMED_REQUEST,
            status=400,
            detail="the request body is not valid JSON",
            request_id=request_id,
        ))

    try:
        wiring.resolve_function(body.function, wire_function)
    except ValueError as exc:
        return refuse(problem(
            PROBLEM_REQUEST_VALIDATION,
            status=400,
            detail=str(exc),
            request_id=request_id,
        ))

    # 5. Authorization. The path's function is what is checked, because it is
    #    the one the caller addressed; a body naming a function the contract
    #    does not have is component A's refusal, and it is reached only once the
    #    request has been found permitted to be made at all.
    grants = parse_scopes(request.headers.get(SCOPE_HEADER))
    try:
        authorizer.require(
            request_id, wire_function, body.study_context.study_reference, grants
        )
    except AuthzError as exc:
        return refuse(authz_problem(exc, request_id),
                      surface.reason_for_authz(getattr(exc, "reason", "")))

    return Accepted(
        addressed_function=wire_function,  # type: ignore[arg-type]
        execution=wiring.execution_request_from_body(
            body, wire_function, input_hash
        ),
    )


def authz_problem(exc: AuthzError, request_id: str):
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
