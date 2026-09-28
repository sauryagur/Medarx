"""The boundary's own decisions: request identity, problem documents, translation.

Three things happen here that happen nowhere else, and each is here rather than in
a route because a route is the wrong place for a rule the whole surface obeys.

**Request identity.** `X-Request-Id` is resolved once, by the middleware, before
any body is read: a header still reaches the surface when the body does not,
which is exactly when a refusal is most worth reporting. A supplied ID is
honoured; an absent one is generated; and an ID the audit log could not hold —
its `IDENTIFIER` shape forbids a space — is refused with a `400` **before** the
body is read, because uncaught it would surface later as a `ValueError` from the
audit write and read as a server fault.

**Problem documents.** Every non-privacy error on this API is a `ProblemDetail`
with a stable `type` URI under `https://medarx.invalid/problems/`, which is the
RFC 9457 registration-free convention and the spelling the contract's own
examples use. A privacy block is never one of these: it is always a
`BlockReceipt`, and the two are told apart by status code alone.

**Function names.** The contract's `Draft` / `Prior Summary` / `Ask` and the
kernel's `draft` / `prior_summary` / `ask` are related in exactly one place,
`medarx.pipeline.FUNCTION_WIRE_TO_INTERNAL`, and both directions of that
translation are used here — wire to internal for the component A's allowlist
table is keyed by, and internal to wire for the audit record an auditor reads
next to the contract. Two spellings of one fact in a permanent record is drift,
and this is where the single translation is made.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from fastapi.responses import JSONResponse

from medarx.api.schemas import (
    ExecutionRequest as ExecutionRequestBody,
    ExecutionResponse,
    ModelResponse as ModelResponseBody,
    ModelUsage,
    ProblemDetail,
    ValidationError,
)
from medarx.audit.audit_log import IDENTIFIER
from medarx.models import BlockReceipt, FunctionName, ModelResponse
from medarx.pipeline import (
    FUNCTION_WIRE_TO_INTERNAL,
    ExecutionRequest,
    patient_ref_for,
)
from medarx.extraction.study_context import StudyContext as KernelStudyContext
from medarx.models import PriorStudyReference

__all__ = [
    "IDENTIFIER_PATTERN",
    "PROBLEM_BASE",
    "PROBLEM_PROVIDER_UNAVAILABLE",
    "hash_of_bytes",
    "is_usable_request_id",
    "json_response",
    "block_response",
    "problem",
    "problem_response",
    "resolve_request_id",
    "resolve_function",
    "execution_request_from_body",
    "execution_response_body",
    "decode_json",
    "offending_properties",
    "validation_errors",
    "prefixed",
]

#: The base for every problem type this API returns. The contract's own
#: examples use it, and `medarx.invalid` is reserved precisely so that a
#: demonstration can publish stable problem-type URIs without registering them.
PROBLEM_BASE = "https://medarx.invalid/problems/"

#: The problem types, named once. Each is a real condition with one answer, and a
#: caller may branch on `type` without parsing prose.
PROBLEM_MALFORMED_REQUEST = "malformed-request"
PROBLEM_REQUEST_VALIDATION = "request-validation"
PROBLEM_STUDY_SCOPE_UNAUTHORIZED = "study-scope-unauthorized"
PROBLEM_FUNCTION_NOT_PERMITTED = "function-not-permitted"
PROBLEM_UNAUTHORIZED_SCOPE = "unauthorized-scope"
PROBLEM_FUNCTION_NOT_FOUND = "function-not-found"
PROBLEM_EXECUTION_NOT_FOUND = "execution-not-found"
PROBLEM_AUDIT_RECORD_NOT_FOUND = "audit-record-not-found"
PROBLEM_DECISION_ALREADY_RECORDED = "decision-already-recorded"
PROBLEM_UNSUPPORTED_MEDIA_TYPE = "unsupported-media-type"
PROBLEM_REQUEST_ID_UNUSABLE = "request-id-unusable"
PROBLEM_PROVIDER_UNAVAILABLE = "provider-unavailable"
PROBLEM_INTERNAL_ERROR = "internal-error"

_TITLES = {
    PROBLEM_MALFORMED_REQUEST: "Malformed request",
    PROBLEM_REQUEST_VALIDATION: "Request does not match the execution request schema",
    PROBLEM_STUDY_SCOPE_UNAUTHORIZED: "Study scope not authorized",
    PROBLEM_FUNCTION_NOT_PERMITTED: "Function not permitted",
    PROBLEM_UNAUTHORIZED_SCOPE: "Scope not authorized",
    PROBLEM_FUNCTION_NOT_FOUND: "Function not found",
    PROBLEM_EXECUTION_NOT_FOUND: "Execution not found",
    PROBLEM_AUDIT_RECORD_NOT_FOUND: "Audit record not found",
    PROBLEM_DECISION_ALREADY_RECORDED: "A human decision is already recorded",
    PROBLEM_UNSUPPORTED_MEDIA_TYPE: "Unsupported media type",
    PROBLEM_REQUEST_ID_UNUSABLE: "Request ID cannot be recorded",
    PROBLEM_PROVIDER_UNAVAILABLE: "Model provider unavailable",
    PROBLEM_INTERNAL_ERROR: "Internal error",
}

#: The contract publishes the hash in the `sha256:` spelling. Both hash fields
#: use it on the wire so a reader has one rule rather than two; the stored form
#: is bare hex, and `medarx.audit.audit_log` canonicalises the prefixed spelling
#: on the way in, so one value has two renderings and neither is a second value.
_HASH_PREFIX = "sha256:"

#: The shape a request ID must have to be storable, published so the middleware
#: can name the rule in a refusal rather than point at an implementation.
IDENTIFIER_PATTERN = IDENTIFIER.pattern


# -- Request identity ---------------------------------------------------------


def is_usable_request_id(value: str) -> bool:
    """Whether the audit log could store `value` as a request ID.

    The same `IDENTIFIER` shape `medarx.audit.audit_log` gates the column with,
    so a request ID that is accepted here cannot fail at the write. Checked at
    the boundary rather than caught later: the failure it prevents is a `500` on
    an otherwise-successful request, which tells a caller nothing useful.
    """
    return bool(IDENTIFIER.fullmatch(value))


def resolve_request_id(supplied: str | None, generate) -> str:
    """The request ID for this request: the caller's, or a fresh one.

    `generate` is injected rather than `uuid4` called here so a caller — the
    middleware — controls the generator, and a test can say exactly what it is.
    """
    if supplied is None:
        return generate()
    return supplied.strip() or generate()


def hash_of_bytes(raw: bytes) -> str:
    """The SHA-256 of the caller's input as received, bare hex.

    Computed once, over the bytes the socket delivered, and carried on every
    outcome the request can have — approved, blocked, or refused at the surface.
    One definition of "what the caller sent", so the audit record's `input_hash`
    means the same thing whichever way the request ended.
    """
    return hashlib.sha256(raw).hexdigest()


def prefixed(digest: str | None) -> str | None:
    """`digest` in the contract's `sha256:` spelling, or `None` unchanged."""
    return None if digest is None else f"{_HASH_PREFIX}{digest}"


# -- Responses ----------------------------------------------------------------


def json_response(status: int, payload: dict[str, Any],
                  request_id: str | None = None) -> JSONResponse:
    """A JSON response carrying the request ID as a header.

    The contract declares no response headers, so this one is an addition rather
    than a transcription — and it is on **every** response, blocks and refusals
    included, because a caller that sent `X-Request-Id` needs to find the record
    that request produced without having to have kept the body.
    """
    headers = {"X-Request-Id": request_id} if request_id else None
    return JSONResponse(status_code=status, content=payload, headers=headers)


def problem(name: str, *, status: int, detail: str, request_id: str | None = None,
            errors: "list[ValidationError] | None" = None) -> ProblemDetail:
    """One RFC 9457 problem document, with the request ID in it."""
    return ProblemDetail(
        type=f"{PROBLEM_BASE}{name}",
        title=_TITLES.get(name, name),
        status=status,
        detail=detail,
        request_id=request_id,
        errors=errors or [],
    )


def problem_response(document: ProblemDetail) -> JSONResponse:
    """A problem document on the wire, as `application/problem+json`."""
    return JSONResponse(
        status_code=document.status,
        content=document.as_dict(),
        media_type="application/problem+json",
        headers=({"X-Request-Id": document.request_id}
                 if document.request_id else None),
    )


def block_response(receipt: BlockReceipt) -> JSONResponse:
    """The `422` body. A block receipt, and nothing else.

    The five fields are the whole of it: the contract closes the schema, so
    there is no room for a message and nothing raw can ride out on one.
    """
    return json_response(422, receipt.model_dump(mode="json"), receipt.request_id)


# -- Parsing ------------------------------------------------------------------


def decode_json(raw: bytes) -> Any:
    """The decoded body, or a `ValueError` the caller turns into a `400`."""
    return json.loads(raw.decode("utf-8"))


def validation_errors(exc) -> "list[ValidationError]":
    """A pydantic validation failure as the contract's `ValidationError` items.

    The `field` path is prefixed with `body.` because the offending thing is a
    property of the request body, and the contract's own `MalformedRequest`
    example writes `body.dicom_object` and `body.prompt` that way.
    """
    items: list[ValidationError] = []
    for error in exc.errors():
        location = ".".join(str(part) for part in error.get("loc", ()))
        items.append(
            ValidationError(
                field=f"body.{location}" if location else "body",
                message=str(error.get("msg", "invalid value")),
            )
        )
    return items


def offending_properties(exc) -> "list[str]":
    """The property names a schema violation rejected, for the refusal record.

    Only the ones the schema actually rejected as *extra* — a type error is a
    field this surface declared and got wrong, not an attempt to smuggle
    something past it, and classifying the two the same would put a shape code
    on an ordinary typo.
    """
    return [
        ".".join(str(part) for part in error.get("loc", ()))
        for error in exc.errors()
        if error.get("type") == "extra_forbidden"
    ]


# -- Function names -----------------------------------------------------------


def resolve_function(body_function: str | None, addressed: FunctionName) -> str:
    """The function to run, in whichever vocabulary the case needs.

    Three cases, and the middle one is the reason this is not a dict lookup:

    - the body did not name one — use the path's;
    - the body named one the contract does not have — return it **unchanged**, so
      component A refuses it with `UNKNOWN_FUNCTION`. That is the refusal the
      contract's `FunctionNotFound` response describes, and a surface that
      rejected it first would make that behaviour unreachable;
    - the body named a different one of the three the contract does have — a
      request that contradicts itself, which is a `400` and is checked by the
      caller before it gets here.
    """
    if body_function is None or body_function == addressed:
        return FUNCTION_WIRE_TO_INTERNAL[addressed]
    if body_function in FUNCTION_WIRE_TO_INTERNAL:
        raise ValueError(
            f"the body names function {body_function!r} while the path names "
            f"{addressed!r}; a request may not address two functions"
        )
    return body_function


def execution_request_from_body(body: ExecutionRequestBody,
                                addressed_function: FunctionName,
                                input_hash: str) -> ExecutionRequest:
    """The kernel's request, built from a validated body.

    The translation happens here and nowhere else. `dicom_metadata` is passed
    through as the DICOM keywords it arrived as, because component A's
    known-attribute table *is* the boundary's vocabulary: the contract says so,
    and a test holds the two to the same names. Converting them here would be a
    second vocabulary for a rename to miss.
    """
    metadata = {
        key: value
        for key, value in (body.dicom_metadata.model_dump()
                           if body.dicom_metadata is not None else {}).items()
        if value is not None
    }
    study_reference = body.study_context.study_reference
    patient_ref = patient_ref_for(metadata, study_reference,
                                  body.study_context.patient_reference)
    prior_studies = tuple(
        PriorStudyReference(prior_study_reference=prior.prior_study_reference,
                            study_date=prior.study_date)
        for prior in (body.prior_studies or ())
    )
    # Resolved once, and used for both the request and its study context. A
    # `dict.get(name, fallback)` here would quietly run the *addressed* function
    # when the body named one the contract does not have — which is exactly the
    # refusal the contract says must reach component A as a 422.
    internal_function = resolve_function(body.function, addressed_function)
    study = KernelStudyContext(
        study_uid=study_reference,
        study_ref=study_reference,
        patient_ref=patient_ref,
        function=internal_function,
        prior_study_refs=tuple(s.prior_study_reference for s in prior_studies),
    )
    return ExecutionRequest(
        function=internal_function,
        addressed_function=addressed_function,
        study_context=study,
        report_text=body.report_text.text,
        dicom_metadata=metadata,
        prior_studies=prior_studies,
        model_id=body.model_id,
        input_hash=input_hash,
        requested_language=body.requested_language,
    )


def execution_response_body(result, function: FunctionName) -> dict[str, Any]:
    """The `200` body, assembled from the kernel's own model.

    The nesting is the drafting: `ExecutionResponse.draft` is the gateway's
    answer and nothing else, so the "this has not been approved" statement is
    made by where it sits rather than by a field nobody would read.
    """
    response = result.model_response
    usage = _usage_of(response)
    draft = ModelResponseBody(
        model_id=response.model_id or result.selected_model,
        content=response.content,
        finish_reason=_finish_reason_of(response),
        usage=usage,
    )
    return ExecutionResponse(
        request_id=result.request_id,
        function=function,
        policy_version=result.policy_version,
        policy_mode=result.policy_mode,
        selected_model=result.selected_model,
        approved_payload_hash=prefixed(result.approved_payload_hash),
        input_hash=prefixed(result.input_hash),
        draft=draft,
    ).model_dump(mode="json", exclude_none=False)


def _usage_of(response: ModelResponse) -> ModelUsage | None:
    """The provider's token accounting, when it reported whole numbers."""
    usage = response.raw.get("usage") if isinstance(response.raw, dict) else None
    if not isinstance(usage, dict):
        return None
    counts = {
        name: value for name, value in (
            (key, usage.get(key)) for key in
            ("prompt_tokens", "completion_tokens", "total_tokens")
        ) if isinstance(value, int) and not isinstance(value, bool)
    }
    return ModelUsage(**counts) if counts else None


def _finish_reason_of(response: ModelResponse) -> str | None:
    reason = response.raw.get("finish_reason") if isinstance(response.raw, dict) else None
    if isinstance(reason, str):
        return reason
    choices = response.raw.get("choices") if isinstance(response.raw, dict) else None
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        inner = choices[0].get("finish_reason")
        if isinstance(inner, str):
            return inner
    return None
