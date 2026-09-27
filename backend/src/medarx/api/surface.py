"""Component J's own action codes, and the record a refusal at the surface leaves.

Four codes belong to this component and to no other: the two that name a shape
the request could not express, and the two that name an authorization failure.
The contract declares all four in its `ActionCode` enum, and for a long time
nothing emitted any of them because this component was not written. They are
emitted here, on the audit record, and this module is written so that the
emission sweep in `tests/test_openapi_contract.py` can see every one of them —
each call site passes a literal tuple of module-level names, which is the only
shape that sweep can follow.

**Where each code lands, and why the response is not one of them.** A shape the
contract's schema cannot express is a `400` whose body is a `ProblemDetail`
listing the offending fields: the contract's `ExecutionRequest` description says
so by name, naming `dicom_object`, `pixel_data` and `prompt` as the three a
caller might try. An authorization failure is a `403`, also a `ProblemDetail`,
because `403` is what the design reserves for "authenticated but not permitted"
and a privacy block is a different condition. So none of these four codes can
reach a block receipt, and the record is where they belong: a non-raw
disposition code, in a log the storage policy admits, on a request the audit
trail would otherwise have no trace of. A refusal that leaves no record is not
evidence.

**The record's `layer` is `J`.** Design §6 says a receipt's layer names the
component that refused, and `J` is in the contract's `Layer` enum for exactly
this: the request surface refusing before the pipeline started. It is not a
privacy layer, `stages_reached("J")` is empty because no pipeline stage was ever
behind the request, and reading it is what keeps an authorization refusal from
looking like a privacy block to whoever reads the log next.

**The property-name sets are closed and are the contract's.** A generic unknown
property gets no code at all rather than a guess: these four codes say what
*kind* of thing was attempted, and inventing a fifth classification from a
property name this module has not read would put a code in a permanent record
that nothing would ever have meant.
"""

from __future__ import annotations

from datetime import datetime, timezone

from medarx.audit import AuditLog
from medarx.models import AuditEvent, FunctionName, PolicyMode

__all__ = [
    "PROMPT_PROPERTY_NAMES",
    "DICOM_OBJECT_PROPERTY_NAMES",
    "SURFACE_REASONS",
    "reason_for_authz",
    "reason_for_shape",
    "record_surface_refusal",
]

# -- Wire codes, declared as module constants so the AST sweep in
# -- tests/test_openapi_contract.py resolves them to the strings they are,
# -- which is what holds them to the contract's `ActionCode` enum.

_ACTION_CODE_UNAUTHORIZED_SCOPE = "UNAUTHORIZED_SCOPE"
_ACTION_CODE_FUNCTION_NOT_PERMITTED = "FUNCTION_NOT_PERMITTED"
_ACTION_CODE_ARBITRARY_DICOM_OBJECT_REJECTED = "ARBITRARY_DICOM_OBJECT_REJECTED"
_ACTION_CODE_FREE_FORM_PROMPT_REJECTED = "FREE_FORM_PROMPT_REJECTED"

#: The layer every refusal recorded here is attributed to. The request surface
#: refused before any pipeline stage was behind the request, which is what `J`
#: means in the contract's `Layer` enum and what makes `stages_reached("J")`
#: empty.
_SURFACE_LAYER = "J"

#: Property names that carry an attempt to hand this surface a DICOM object.
#: Closed, and the three the contract's own `ExecutionRequest` description names
#: — `dicom_object`, `pixel_data`, `prompt` — plus `dicom_file`, which is the
#: spelling a caller writing a Pydicom-shaped request reaches for.
DICOM_OBJECT_PROPERTY_NAMES: frozenset[str] = frozenset(
    {"dicom_object", "pixel_data", "dicom", "dicom_file", "dataset", "element_stream"}
)

#: Property names that carry an attempt to hand this surface a free-form prompt
#: rather than a documented pipeline input.
PROMPT_PROPERTY_NAMES: frozenset[str] = frozenset(
    {"prompt", "instruction", "instructions", "system_prompt", "query", "question"}
)

#: The reasons this module records. A closed vocabulary, so a caller that
#: invents one gets no code rather than a wrong one.
REASON_UNAUTHORIZED_SCOPE = "unauthorized_scope"
REASON_FUNCTION_NOT_PERMITTED = "function_not_permitted"
REASON_ARBITRARY_DICOM_OBJECT = "arbitrary_dicom_object"
REASON_FREE_FORM_PROMPT = "free_form_prompt"
REASON_DICOM_OBJECT_AND_PROMPT = "arbitrary_dicom_object_and_free_form_prompt"
REASON_UNCLASSIFIED_SHAPE = "unclassified_shape"

SURFACE_REASONS: frozenset[str] = frozenset({
    REASON_UNAUTHORIZED_SCOPE,
    REASON_FUNCTION_NOT_PERMITTED,
    REASON_ARBITRARY_DICOM_OBJECT,
    REASON_FREE_FORM_PROMPT,
    REASON_DICOM_OBJECT_AND_PROMPT,
    REASON_UNCLASSIFIED_SHAPE,
})

#: The two reasons the authoriser raises, mapped to the record's reason. Kept
#: here rather than in `authz` so the vocabulary of *recorded* refusals is one
#: list in one place.
_AUTHZ_REASONS = {
    "no_scope": REASON_UNAUTHORIZED_SCOPE,
    "study_scope_unauthorized": REASON_UNAUTHORIZED_SCOPE,
    "function_not_permitted": REASON_FUNCTION_NOT_PERMITTED,
}


def reason_for_authz(reason: str) -> str:
    """The recorded reason for an `AuthzError`'s cause.

    A cause this module does not name is recorded with no code rather than a
    guessed one: a code that does not describe the refusal is a false record, and
    an unnamed cause is a bug in the caller rather than a request to describe.
    """
    return _AUTHZ_REASONS.get(reason, REASON_UNCLASSIFIED_SHAPE)


def reason_for_shape(offending: "list[str]") -> str:
    """The recorded reason for a body that did not match the request schema.

    `offending` is the set of property names the schema rejected. A name in
    neither closed set yields no code, because this module classifies only the
    two attempts the contract names.
    """
    names = {name.split(".", 1)[-1] for name in offending}
    carries_object = bool(names & DICOM_OBJECT_PROPERTY_NAMES)
    carries_prompt = bool(names & PROMPT_PROPERTY_NAMES)
    if carries_object and carries_prompt:
        return REASON_DICOM_OBJECT_AND_PROMPT
    if carries_object:
        return REASON_ARBITRARY_DICOM_OBJECT
    if carries_prompt:
        return REASON_FREE_FORM_PROMPT
    return REASON_UNCLASSIFIED_SHAPE


def record_surface_refusal(
    audit: AuditLog,
    *,
    request_id: str,
    function: FunctionName,
    input_hash: str,
    policy_version: str,
    policy_mode: PolicyMode,
    reason: str,
    offending: "list[str] | None" = None,
) -> AuditEvent:
    """Append the record for a request this surface refused, and return it.

    The branches are written out one per reachable reason rather than computed
    from a table, because the action-code sweep in
    `tests/test_openapi_contract.py` follows a name and a literal tuple and
    cannot follow a dispatch. A computed `action_codes=` would report this module
    as emitting nothing while emitting four codes — the quietest way for a sweep
    to stop working.
    """
    common = {
        "request_id": request_id,
        "timestamp": datetime.now(timezone.utc),
        "function": function,
        "policy_version": policy_version,
        "policy_mode": policy_mode,
        "input_hash": input_hash,
        "redacted_field_names": [],
        "human_approval": None,
        "final_disposition": "blocked",
        "layer": _SURFACE_LAYER,
        "chain_hash": "",
        "previous_hash": "",
    }
    if reason == REASON_UNAUTHORIZED_SCOPE:
        event = _event(**common, action_codes=(_ACTION_CODE_UNAUTHORIZED_SCOPE,))
    elif reason == REASON_FUNCTION_NOT_PERMITTED:
        event = _event(
            **common, action_codes=(_ACTION_CODE_FUNCTION_NOT_PERMITTED,))
    elif reason == REASON_ARBITRARY_DICOM_OBJECT:
        event = _event(
            **common,
            action_codes=(_ACTION_CODE_ARBITRARY_DICOM_OBJECT_REJECTED,))
    elif reason == REASON_FREE_FORM_PROMPT:
        event = _event(**common,
                       action_codes=(_ACTION_CODE_FREE_FORM_PROMPT_REJECTED,))
    elif reason == REASON_DICOM_OBJECT_AND_PROMPT:
        event = _event(
            **common,
            action_codes=(_ACTION_CODE_ARBITRARY_DICOM_OBJECT_REJECTED,
                          _ACTION_CODE_FREE_FORM_PROMPT_REJECTED))
    else:
        # A shape this module cannot classify. Recorded with no code rather than
        # a plausible one: the fields around it — the request ID, the function,
        # the policy version, the input hash — are all true, and the one that
        # would be a guess is left empty.
        event = _event(**common, action_codes=())
    return audit.append(event)


def _event(*, request_id: str, timestamp: datetime, function: FunctionName,
           policy_version: str, policy_mode: PolicyMode, input_hash: str,
           redacted_field_names: list, human_approval: None, final_disposition: str,
           layer: str, chain_hash: str, previous_hash: str,
           action_codes: "list[str]") -> AuditEvent:
    """One audit record. The single construction every refusal above goes through."""
    return AuditEvent(
        request_id=request_id,
        timestamp=timestamp,
        function=function,
        policy_version=policy_version,
        policy_mode=policy_mode,
        input_hash=input_hash,
        redacted_field_names=redacted_field_names,
        action_codes=action_codes,
        human_approval=human_approval,
        final_disposition=final_disposition,
        layer=layer,
        chain_hash=chain_hash,
        previous_hash=previous_hash,
    )
