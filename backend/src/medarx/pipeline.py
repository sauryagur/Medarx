"""The composition root: components A to G, wired once, in one order.

This module is where the pieces meet and where the order the whole kernel
depends on is written down:

    A allowlisted extraction → C surrogates and the per-patient date shift →
    D layers 1–3 with E deciding last → E authorises the object it approved →
    F verifies that object and only then sends it.

**Two ways to run it, and the difference is one arrow.** `run` does all five
in one call. `preflight` does the first four, publishes the payload the fifth
would send, and stops; `send_approved` then hands component F the token the
preflight minted and stops there. The split exists so a caller can be shown
the payload before anything leaves, which is what makes `Needs review` a state
the system evaluated rather than one a client asserted. Both paths run the
same components in the same order through `_through_policy`, and both mint the
send token through the same `verify_approved_payload`: the split changes *when
a human is asked*, never *what the kernel decides*.

Each arrow is a place a future edit could put the boundary in the wrong spot, so
each one carries a note saying what it is protecting. The two that matter most:

- **E authorises before F is reached at all.** `authorize_payload` re-derives the
  hash from the payload's own content and refuses anything the decision did not
  cover. The gateway then makes the same check again, at the last point before a
  socket is touched. Two checks of the same property at two distances from the
  wire, not a second opinion: §6 row 7 is a property of the *object*, and the
  only place it can be checked is before it is transmitted.
- **A block returns, it does not raise.** A `MedarxError` is caught, the audit
  record is written, and an `ExecutionResult` carrying the `BlockReceipt` comes
  back. The receipt has five fields and no message, so the codes and the layer
  are the whole of what an auditor gets, and they come from the component that
  refused — never from here.

**The receipt's layer and codes are stated once, in `_receipt_for`.** The
orchestrator in `medarx.redaction.pipeline` applies the same rule when it raises,
and `tests/test_pipeline_wiring.py::test_the_receipt_agrees_with_the_orchestrator`
runs both over the same input and compares them, so the two cannot drift apart
while both stay green.

**What this module refuses to do.** It does not invent a policy mode and takes
none from the request: `ExecutionRequest` has no such field and the model is
`extra="forbid"`, so a caller cannot escalate. It does not read the environment:
`Settings` is constructed by `medarx.config` and passed in, which is what lets a
test build a whole deployment without touching a process variable.
"""

from __future__ import annotations

import json
import logging
import secrets
import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Mapping, Protocol, Sequence

from medarx.audit import AuditLog
from medarx.audit.audit_log import FIELD_PATH
from medarx.audit.code_table import preflight_stages, stages_reached
from medarx.config import Settings
from medarx.errors import GatewayError, MedarxError, PolicyError
from medarx.extraction.payload_extractor import ATTRIBUTE_TO_FIELD, pipeline_for
from medarx.extraction.study_context import StudyContext
from medarx.gateway.openai_gateway import ApprovedSend, ModelGateway
from medarx.models import (
    AuditEvent,
    BlockReceipt,
    FunctionName,
    HumanApproval,
    ModelRequest,
    ModelResponse,
    PriorStudyReference,
    StructuredPayload,
)
from medarx.policy.policy_engine import PolicyEngine
from medarx.pseudonym.mapping_store import MappingStore
from medarx.pseudonym.pseudonymize import pseudonymize_payload
from medarx.redaction.pipeline import _ENGINE_LAYER, run_redaction

if TYPE_CHECKING:  # pragma: no cover - a type reference, not a runtime dependency
    from medarx.redaction.layers import Disposition
    from medarx.redaction.pipeline import RedactionOutcome

    class _RequestFacts(Protocol):
        """The attributes an audit record needs, and no more.

        `ExecutionRequest` and `PendingApproval` both carry exactly these, which
        is what lets `_blocked` and `_record_approved` be written once rather
        than taking a whole request each: a send refused at the last moment has
        no `ExecutionRequest` left to hand them, and inventing one would mean
        reconstructing a request the caller never made.
        """

        function: str
        addressed_function: FunctionName
        input_hash: str

    _Outcome = tuple["RedactionOutcome", StructuredPayload]

__all__ = [
    "FIELD_EXCLUDED",
    "FIELD_INCLUDED",
    "FIELD_TRANSFORMED",
    "ExecutionRequest",
    "ExecutionResult",
    "FUNCTION_INTERNAL_TO_WIRE",
    "FUNCTION_WIRE_TO_INTERNAL",
    "FieldAction",
    "PendingApproval",
    "Pipeline",
    "PreflightResult",
    "build_pipeline",
    "patient_ref_for",
]

#: The layer a block carries when the policy engine is what refused, because no
#: disposition flagged the request. Read from the orchestrator, so the package
#: holds one value rather than two that could disagree.

#: The contract's `FunctionName` enum, and the internal snake_case the kernel
#: uses. **This is the only place the two vocabularies are related.**
#:
#: The audit log stores the contract's spelling, because the record is read next
#: to the contract and a second spelling of one fact in a permanent record is
#: drift; the kernel uses snake_case, because that is what component A's
#: allowlist table is keyed by. `medarx.api.wiring` imports these, so the
#: boundary and the composition root cannot disagree about them.
FUNCTION_WIRE_TO_INTERNAL: Mapping[str, str] = {
    "Draft": "draft",
    "Prior Summary": "prior_summary",
    "Ask": "ask",
}
FUNCTION_INTERNAL_TO_WIRE: Mapping[str, str] = {
    internal: wire for wire, internal in FUNCTION_WIRE_TO_INTERNAL.items()
}

#: The temperature and token budget of the OpenAI-wire request. Constants rather
#: than settings because neither is a deployment choice in Phase 1, and a
#: drafting assistant whose output varies with a temperature is a worse
#: demonstration of a privacy kernel.
_TEMPERATURE = 0.0
_MAX_TOKENS = 512

#: The code for a block that carries no disposition and no engine code of its
#: own. Unreachable while every reason the engine invents maps to a wire code;
#: present so that an inconsistency refuses rather than passing a payload.
_FALLBACK_CODE = "UNAPPROVED_PAYLOAD"

_SYSTEM_PROMPT = (
    "You are a radiology reporting assistant. You draft and structure text from "
    "findings a clinician has already supplied. You do not interpret images, you "
    "do not introduce findings, and you do not make diagnostic or treatment "
    "recommendations. Every response is a draft requiring explicit human "
    "sign-off; nothing you write is submitted anywhere."
)

#: The reviewer-note log. `medarx.api.app.create_app` attaches the
#: sensitive-data filter to this logger *and* to its parent; a logger created
#: after `install_filter` and not named there is not covered.
_APPROVAL_LOG = logging.getLogger("medarx.api.approval")

#: How many validated-but-unsent payloads this process will hold at once.
#:
#: A pending approval **is** a payload: it is held in memory, in this process,
#: for exactly as long as it takes a human to look at the preview and press
#: send. It is deliberately not persisted — the audit log's storage policy
#: admits no field that could hold a value, and writing this one anywhere
#: durable would make the audit store a second copy of what is about to be sent.
#: The cost of holding it in memory is that a restart loses every pending
#: approval, and the send answers `404` for one; the alternative — re-running
#: the pipeline at send time — would transmit a payload nobody previewed, which
#: is the failure this whole mechanism exists to prevent.
#:
#: Bounded, because an unbounded map keyed by caller-supplied request IDs is an
#: unbounded memory cost for a deployment anyone can POST to. The oldest
#: approval is dropped to make room, and a send for a dropped one is the same
#: `404` as a send for one that never existed.
_MAX_PENDING_APPROVALS = 256

#: The action codes a send raises when the thing it would transmit is not the
#: thing the preflight approved. Both are contract members, both are true of
#: the same condition, and neither is invented here: `PAYLOAD_MISMATCH` is
#: design §6 row 7's own name for it and `HASH_MISMATCH` names the check that
#: detected it. Declared here rather than in `medarx.gateway` because the
#: comparison happens in this module and the AST sweep in
#: `tests/test_openapi_contract.py` resolves these names to the strings and
#: holds them to the contract's `ActionCode` enum.
_ACTION_CODE_PAYLOAD_MISMATCH = "PAYLOAD_MISMATCH"
_ACTION_CODE_HASH_MISMATCH = "HASH_MISMATCH"

#: The code for a send whose approval was made under a different policy than
#: the one in force now. Design §6 row 6's condition — an unrecognised or
#: mismatched policy version fails closed — so the code is that row's own.
_ACTION_CODE_UNKNOWN_POLICY_VERSION = "UNKNOWN_POLICY_VERSION"

#: The three states a field of the caller's request can be in on the way to the
#: model, and the only three the contract declares.
FIELD_INCLUDED = "included"
FIELD_TRANSFORMED = "transformed"
FIELD_EXCLUDED = "excluded"


@dataclass(frozen=True)
class ExecutionRequest:
    """One execution, already parsed by the surface.

    `excluded_inputs` is a **declaration, not a transformation**: the request
    properties the surface accepted and that no payload field carries, named
    with the path the caller wrote them at. The surface is the only place that
    can see them — `StudyContext.patient_reference`, `accession_reference`,
    `encounter_reference` and `modality` are read by nothing on the request
    path, which is a fact about this boundary rather than about the kernel's
    inputs, so the kernel is told rather than left to guess. It exists so that
    the field-action summary can name a value the caller supplied as excluded
    instead of leaving it silently absent from a preview that otherwise claims
    to be complete. The kernel reads no value from any of them.

    `function` is the function to run **in the kernel's vocabulary** when the
    caller named one the kernel knows, and **in the caller's own spelling** when
    it did not. That is not a leniency: design §6 row 2 assigns the rejection of
    an unknown function to component A, and the only component that can reject it
    is the one holding the allowlist table.

    `addressed_function` is the function the *path* named, in the contract's
    spelling, and it is what the audit record stores. It is a separate field
    because a body naming a function that does not exist has no member the
    record's `FunctionName` can hold, and the path's name is the truthful answer
    to "which function did this request address".

    `input_hash` is the hash of the caller's input **as received**, computed by
    the surface from the bytes it read and carried here unchanged. It is computed
    once, for every outcome, so the audit log's `input_hash` is the same value
    whether the request was approved, blocked at A, blocked at F, or refused at
    the surface. Component A computes a hash of its own over the fields it
    extracted and carries it on the payload as provenance; that value is internal
    and is never written to the audit log, so the record carries one input hash
    rather than two.

    There is deliberately no `policy_mode` field: the mode is a deployment
    configuration, and a request that could name it could route around the
    boundary by asking for a laxer one.
    """

    function: str
    addressed_function: FunctionName
    study_context: StudyContext
    report_text: str
    dicom_metadata: Mapping[str, str] = field(default_factory=dict)
    prior_studies: tuple[PriorStudyReference, ...] = ()
    model_id: str | None = None
    input_hash: str = ""
    requested_language: str | None = None
    excluded_inputs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.input_hash:
            raise ValueError(
                "input_hash is required and must be the hash of the caller's "
                "input as received; the surface computes it once so that the "
                "audit record carries the same value on every outcome"
            )


@dataclass(frozen=True)
class ExecutionResult:
    """What one execution produced, and why.

    `approved` and `block_receipt` are opposites and that is enforced here: a
    result that was neither approved nor blocked, or both, would leave the route
    to guess, and "the caller decides" is how a fail-closed boundary stops being
    one.

    `addressed_function` is the contract's spelling of the function the request
    named, carried beside `function` — which is the kernel's own snake_case — so
    that a result produced by a **send** can still be rendered with the
    function's contract name. The send holds no `ExecutionRequest` to read it
    from, and a response that guessed the spelling or dropped the field would
    make one caller-visible fact unavailable on one of two paths to the same
    event.
    """

    request_id: str
    function: str
    approved: bool
    input_hash: str
    policy_version: str
    policy_mode: str
    addressed_function: FunctionName | None = None
    block_receipt: BlockReceipt | None = None
    model_response: ModelResponse | None = None
    approved_payload_hash: str | None = None
    selected_model: str | None = None
    dispositions: tuple["Disposition", ...] = ()

    def __post_init__(self) -> None:
        if self.approved == (self.block_receipt is not None):
            raise ValueError(
                "an execution is either approved or blocked, never both and "
                f"never neither; got approved={self.approved} "
                f"block_receipt={self.block_receipt is not None}"
            )
        if self.approved and (self.model_response is None
                              or self.approved_payload_hash is None):
            raise ValueError(
                "an approved result carries the model response and the hash of "
                "the payload that was transmitted; without both, nothing was "
                "approved in any sense the API can report"
            )
        if not self.approved and self.approved_payload_hash is not None:
            raise ValueError(
                "a blocked request approved nothing, so it has no approved "
                "payload hash to report"
            )


@dataclass(frozen=True)
class FieldAction:
    """What happened to one field on the way from the caller's request to the model.

    `field` is either a member of the transformed payload (`report_text`,
    `study_ref`, `dicom_fields.modality`, …) or a request property the pipeline
    read and did not carry (`dicom_metadata.PatientID`,
    `study_context.patient_reference`, …). One namespace, because a preview that
    enumerated only half of what the caller supplied would be the incomplete
    sort, and the incomplete sort is what a privacy drawer has to be trusted not
    to be.

    `state` is one of the three constants at the top of this module and carries
    no value, no count and no score. **An excluded entry never carries the value
    the caller supplied**: that value is the identifier the whole pipeline
    exists to keep away from a model, and answering "what did you drop?" with
    the dropped thing would be a leak in the answer.
    """

    field: str
    state: str

    def __post_init__(self) -> None:
        if self.state not in (FIELD_INCLUDED, FIELD_TRANSFORMED, FIELD_EXCLUDED):
            raise ValueError(
                f"{self.state!r} is not a field state; the set is closed at "
                f"{FIELD_INCLUDED!r}, {FIELD_TRANSFORMED!r} and {FIELD_EXCLUDED!r}"
            )


@dataclass(frozen=True)
class PendingApproval:
    """One preflight's authorisation, held until a send consumes it.

    `approved_send` is component F's own token, minted by
    `verify_approved_payload` **during the preflight**, over the approved
    payload and the wire body built from it. Holding the token rather than the
    payload is what makes "the send transmits exactly what the preview showed"
    a property of the object rather than a promise: the bytes were built and
    encoded at the moment of authorisation, so there is nothing left to
    re-derive at send time and no second chance for them to differ. The
    pipeline does not mint tokens by any other route, and `send` accepts nothing
    else — this is the existing mechanism, wired, not a second one.

    `approved_payload_hash` is kept beside it precisely so the send can check
    that the two still describe the same object. A token and a record that
    disagree cannot both come from one preflight, so a disagreement is a
    substitution, and the send refuses rather than transmitting it.

    `payload` is kept for the record's `approved_payload_hash` and for nothing
    else: the token is what goes, and a second object carrying the same text is
    a second place for that text to live.
    """

    request_id: str
    function: str
    addressed_function: FunctionName
    input_hash: str
    policy_version: str
    policy_mode: str
    payload: StructuredPayload
    approved_payload_hash: str
    approved_send: ApprovedSend
    dispositions: tuple["Disposition", ...]
    approved_at: datetime

    @property
    def selected_model(self) -> str:
        """The model the token will be sent to, read from the token itself."""
        return self.approved_send.request.model


@dataclass(frozen=True)
class PreflightResult:
    """What one preflight produced: a payload awaiting review, or a refusal.

    The either/or is enforced in `__post_init__` for the same reason
    `ExecutionResult` enforces its own: a result that was neither validated nor
    blocked would leave the route to guess, and a guess here is a green tick
    over a payload nobody approved.

    `stages` is the **prefix the preflight actually reached**, and it is not the
    same list as a completed run's. An approved preflight stops before
    component F, so `Model request` is absent from it
    (`medarx.audit.code_table.preflight_stages`); a blocked one carries the
    prefix up to and including the stage that refused
    (`stages_reached`). Both are derived from a table rather than written out,
    so the list cannot name a stage the request did not reach.

    A preflight that validated writes **no** audit record. Nothing was refused
    and nothing was transmitted, and the record's `stages` is derived from a
    stored `layer` whose only null case means "reached all six" — a record here
    would claim a model call that never happened. The record is written by the
    send, or by the block; a validated-and-never-sent preflight leaves no
    trace, and that is the honest size of the trace for a request that changed
    nothing outside this process.
    """

    request_id: str
    function: str
    needs_review: bool
    input_hash: str
    policy_version: str
    policy_mode: str
    stages: tuple[str, ...]
    field_actions: tuple[FieldAction, ...] = ()
    payload: StructuredPayload | None = None
    approved_payload_hash: str | None = None
    selected_model: str | None = None
    block_receipt: BlockReceipt | None = None

    def __post_init__(self) -> None:
        if self.needs_review == (self.block_receipt is not None):
            raise ValueError(
                "a preflight either validated for review or was refused, never "
                f"both and never neither; got needs_review={self.needs_review} "
                f"block_receipt={self.block_receipt is not None}"
            )
        if self.needs_review and self.payload is None:
            raise ValueError(
                "a preflight that needs review must carry the payload it is "
                "reviewing; without one there is nothing to preview and nothing "
                "a later send could be bound to"
            )
        if not self.needs_review and self.payload is not None:
            raise ValueError(
                "a refused preflight produced no payload, so it has none to "
                "report"
            )


def patient_ref_for(dicom_metadata: Mapping[str, str], study_reference: str,
                    patient_reference: str | None = None) -> str:
    """The patient scope component C shifts by, for one request.

    **Three sources, in order, and the third is the one that inverts a guarantee.**

    1. `StudyContext.patient_reference` — what the caller says the patient is.
       This is the reference design §3 C means by "per patient", and supplying it
       is what makes the shift preserve the interval *between* two studies of one
       patient.
    2. `dicom_metadata["PatientID"]` — the contract's own allowlisted attribute,
       which layer A accepts and then drops, so it reaches the input hash and no
       payload field. A caller who puts the identifier there rather than in the
       study context gets the same guarantee.
    3. The study reference, when neither is present.

    **The third fallback is a weaker guarantee and the weakness is measurable.**
    A study is not a patient, so two studies of one patient that supply neither
    reference are shifted by two unrelated offsets, the interval between them is
    not preserved, and it can *invert*: measured through the API before the
    `patient_reference` field existed, a true 7-day interval between
    `20260114` and `20260121` arrived at a provider as **213 days**, with the two
    offsets of opposite sign. The shift still applies to every date, and no
    clinical value is corrupted; what is lost is the relationship *between*
    studies, which is exactly what §3 C's "preserves sequence and duration"
    claims.

    The fallback is kept rather than the request refused, for two reasons that
    are both true: a study reference is enough to pseudonymize a payload and get
    it through the boundary, and refusing would turn a documented degradation
    into a denial of service for every caller the contract lets omit the field.
    What it must never be is silent, which is why the third case is written out
    here, published in `StudyContext`'s own description, and asserted by
    `tests/test_api.py::test_two_studies_of_one_patient_keep_their_interval`.

    The reference is a pseudonymization key and nothing more: it is never
    carried in a payload, never reaches a model provider, and is not stored in
    the audit log, whose storage policy has no field for a subject reference.
    """
    for candidate in (patient_reference, dicom_metadata.get("PatientID")):
        if candidate and candidate.strip():
            return candidate.strip()
    return study_reference.strip()


@dataclass
class Pipeline:
    """Every component, built once, held for the life of the process.

    One `MappingStore` and one `AuditLog`, both over the same database URL and
    both shared by every request. Building either per request would give each
    request its own surrogate table and its own chain head, and the concurrency
    test's two promises — one surrogate, one intact chain — would be promises
    about nothing.

    Not frozen: a test replaces `run` to observe that the route calls it, and a
    frozen object would make that impossible without a subclass.
    """

    settings: Settings
    db_url: str
    store: MappingStore
    audit: AuditLog
    policy: PolicyEngine
    gateway: ModelGateway
    #: Guards the read-then-append in `record_approval`.
    #:
    #: `AuditLog.append` serialises itself with its own lock, but the decision
    #: check is a **read** that happens outside it, so without this two callers
    #: approving the same request at the same instant both see "no decision
    #: recorded" and both append. The audit log is append-only, so a second
    #: decision is not an update that gets lost — it is a permanent second
    #: record, and `409` is the answer the contract promises for it. A re-check
    #: after the append would be too late: the second record would already be in
    #: the chain. This is the same shape as the log's own `_APPEND_LOCK`, one
    #: level up, and it is here for the same reason.
    _approval_lock: threading.RLock = field(default_factory=threading.RLock,
                                           repr=False)

    #: Validated-but-unsent payloads, keyed by request ID, awaiting a human.
    #:
    #: `OrderedDict` because eviction is oldest-first and "oldest" has to mean
    #: something: insertion order is the only clock in here, and a wall clock
    #: would make a send's outcome depend on how long a person spent looking at
    #: a preview. The lock is because two requests can preflight at once and two
    #: sends can race the pop, and an approval that two sends both found is an
    #: approval that was transmitted twice.
    _pending: "OrderedDict[str, PendingApproval]" = field(
        default_factory=OrderedDict, repr=False
    )
    _pending_lock: threading.RLock = field(default_factory=threading.RLock,
                                          repr=False)

    # -- Validate, then send ------------------------------------------------

    def _through_policy(self, request: ExecutionRequest) -> "_Outcome":
        """Components A, C, D and E — everything before the gateway. Raises on refusal.

        The one place the four components run, because `run` and `preflight`
        differ only in what they do with the result and running the sequence
        twice is how a preflight ends up approving something the atomic path
        would have blocked.

        Returns the outcome **and** the payload component A produced, which
        `preflight` needs as the "before" side of every field comparison. A
        `MedarxError` from any of the four propagates; the caller turns it into
        a receipt, which is the one translation `_receipt_from_error` exists
        for.
        """
        # A: allowlisted extraction, per the function's field allowlist.
        extracted = pipeline_for(
            request.function,
            request.study_context,
            request.report_text,
            dict(request.dicom_metadata),
            self.settings.policy_version,
        )
        # C: surrogates for references, one shift for every date.
        pseudonymized = pseudonymize_payload(
            extracted, request.study_context.patient_ref, self.store
        )
        # D then E: layers 1-3, then the fail-closed decision. `source` is the
        # payload as component A produced it, *before* the shift, because two of
        # layer 3's checks are statements about a difference between the
        # original and the transformed payload.
        return run_redaction(
            pseudonymized,
            request.study_context.patient_ref,
            self.store,
            self.policy,
            self.settings,
            source=extracted,
        ), extracted

    def preflight(self, request_id: str,
                  request: ExecutionRequest) -> PreflightResult:
        """Run A, C, D and E, publish the payload, and stop before component F.

        **No provider is contacted and no socket is opened.** The wire body is
        *built* here — component F's `verify_approved_payload` builds it as part
        of verification, and that is how the token comes to exist — but
        `send` is not called, and `last_request_body()` stays `None` because
        that value is assigned inside `send` at the moment bytes are handed to a
        transport.

        The returned payload is the one a send will transmit, not a description
        of it: it is the same frozen object the token was minted over, and the
        hash beside it is the hash F re-derived from that object's own content.
        A caller comparing the preview against the bytes the observer later
        recorded is therefore comparing two values that cannot differ.

        A block is returned as a receipt, exactly as `run` returns one, and is
        recorded in the audit log the same way — so a refused preflight and a
        refused execution leave the same evidence. A validated preflight is
        deliberately **not** recorded; see `PreflightResult`.
        """
        try:
            outcome, extracted = self._through_policy(request)
            if outcome.blocked:
                receipt = _receipt_for(request_id, outcome, self.settings)
                self._blocked(request_id, request, receipt)
                return PreflightResult(
                    request_id=request_id,
                    function=request.function,
                    needs_review=False,
                    input_hash=request.input_hash,
                    policy_version=self.settings.policy_version,
                    policy_mode=self.settings.policy_mode,
                    stages=stages_reached(receipt.layer),
                    block_receipt=receipt,
                )
            approved = outcome.approved
            if approved is None:
                # Unreachable: `run_redaction` ties the two together. Raised
                # rather than asserted, because `assert` vanishes under `-O`.
                raise AssertionError("an unblocked outcome must carry a payload")

            # The same two authorisations `run` performs, in the same place:
            # E vouches the object is the one it decided about, and F mints the
            # only token `send` accepts. A preflight that skipped either would
            # mint a token the atomic path would have refused.
            self.policy.authorize_payload(approved, str(approved.payload_hash))
            model = self.gateway.model_for(request.model_id)
            approved_send = self.gateway.verify_approved_payload(
                approved,
                str(approved.payload_hash),
                ModelRequest(
                    model=model,
                    messages=_messages(approved, request),
                    temperature=_TEMPERATURE,
                    max_tokens=_MAX_TOKENS,
                ),
            )
        except MedarxError as refused:
            receipt = _receipt_from_error(request_id, refused, self.settings)
            self._blocked(request_id, request, receipt)
            return PreflightResult(
                request_id=request_id,
                function=request.function,
                needs_review=False,
                input_hash=request.input_hash,
                policy_version=self.settings.policy_version,
                policy_mode=self.settings.policy_mode,
                stages=stages_reached(receipt.layer),
                block_receipt=receipt,
            )

        self._hold(request_id, PendingApproval(
            request_id=request_id,
            function=request.function,
            addressed_function=request.addressed_function,
            input_hash=request.input_hash,
            policy_version=self.settings.policy_version,
            policy_mode=self.settings.policy_mode,
            payload=approved,
            approved_payload_hash=str(approved.payload_hash),
            approved_send=approved_send,
            dispositions=tuple(outcome.dispositions),
            approved_at=_now(),
        ))
        return PreflightResult(
            request_id=request_id,
            function=request.function,
            needs_review=True,
            input_hash=request.input_hash,
            policy_version=self.settings.policy_version,
            policy_mode=self.settings.policy_mode,
            stages=preflight_stages(),
            field_actions=_field_actions(extracted, approved, request),
            payload=approved,
            approved_payload_hash=str(approved.payload_hash),
            selected_model=model,
        )

    def send_approved(self, request_id: str) -> ExecutionResult:
        """Transmit the exact bytes one preflight authorised, and record it.

        **The payload is not recomputed.** Nothing here runs A, C, D or E: the
        token carried the body built and encoded during the preflight, and
        `send` transmits that object. Re-deriving it would mean sending whatever
        the pipeline produces now, which is a different object from the one the
        reviewer saw, and the preview would be a picture of a payload that never
        left.

        Two things can still refuse it, and both are checked before any byte
        moves:

        - **the policy version moved.** The version the approval was made under
          is compared with the version component E has in force. In
          `build_pipeline` those are the same object and the comparison cannot
          fire; it fires when a deployment is reconfigured under a running
          process, or when a test swaps the engine, and both are states in which
          the payload was approved under a policy the engine no longer holds.
          Design §6 row 6 makes an unrecognised policy version a fail-closed
          block, so this is that row, at the moment the bytes would move.
        - **the token is not the one the approval recorded.** A token and an
          approval are minted together, so a disagreement between their hashes
          is a substitution rather than a coincidence, and it is refused with
          the two codes row 7 names.

        The approval is **consumed** by this call, before either check: an
        authorisation is one-shot, and a second send of the same bytes under one
        request ID would file two records the append-only log cannot tell
        apart. A later send is a `LookupError`, which the surface answers `404`.

        A `ProviderError` is not caught, for the same reason `run` does not
        catch it: availability is not privacy, and recording an outage as a
        block would be a false privacy event in the one store the design names
        as an asset. The bytes were handed to the transport before it was
        raised, and the approval is already spent.
        """
        approval = self._take(request_id)
        try:
            if not secrets.compare_digest(approval.policy_version,
                                          self.policy.policy_version):
                raise PolicyError(
                    action_codes=(_ACTION_CODE_UNKNOWN_POLICY_VERSION,),
                    message=(
                        f"the approval for request {request_id!r} was made under "
                        f"policy version {approval.policy_version!r} and the "
                        f"policy in force is {self.policy.policy_version!r}; a "
                        "payload approved under one policy is not approved "
                        "under another, so nothing may be transmitted. Run the "
                        "preflight again."
                    ),
                )
            if not secrets.compare_digest(approval.approved_payload_hash,
                                          approval.approved_send.approved_payload_hash):
                raise GatewayError(
                    action_codes=(_ACTION_CODE_PAYLOAD_MISMATCH,
                                  _ACTION_CODE_HASH_MISMATCH),
                    message=(
                        "the token this send would transmit was authorised for a "
                        "different payload than the preflight approved; the two "
                        "are minted together, so this is a substitution, and "
                        "nothing may be transmitted"
                    ),
                )
            response = self.gateway.send(approval.approved_send)
        except MedarxError as refused:
            receipt = _receipt_from_error(request_id, refused, self.settings)
            return self._blocked(request_id, approval, receipt)

        self._record_approved(request_id, approval, approval.dispositions,
                              approval.selected_model, approval.payload)
        return ExecutionResult(
            request_id=request_id,
            function=approval.function,
            approved=True,
            input_hash=approval.input_hash,
            policy_version=approval.policy_version,
            policy_mode=approval.policy_mode,
            model_response=response,
            approved_payload_hash=approval.approved_payload_hash,
            selected_model=approval.selected_model,
            dispositions=approval.dispositions,
            addressed_function=approval.addressed_function,
        )

    def _hold(self, request_id: str, approval: PendingApproval) -> None:
        """Remember an approval, dropping the oldest when the map is full."""
        with self._pending_lock:
            self._pending[request_id] = approval
            while len(self._pending) > _MAX_PENDING_APPROVALS:
                self._pending.popitem(last=False)

    def _take(self, request_id: str) -> PendingApproval:
        """Consume an approval. `LookupError` when there is not one to consume."""
        with self._pending_lock:
            approval = self._pending.pop(request_id, None)
        if approval is None:
            raise LookupError(
                f"no pending preflight approval exists for request {request_id!r}. "
                "An approval is consumed by the first send and is not durable, so "
                "a send for an unknown, already-sent, restarted or evicted request "
                "ID is refused rather than served by re-running the pipeline. Run "
                "the preflight again to get a new one."
            )
        return approval

    def pending_for(self, request_id: str) -> "PendingApproval | None":
        """The approval a send would consume, or `None`. Does not consume it.

        For the surface, which has to name a function to record a refusal
        against and must not consume an approval to do it — a caller refused at
        the authorization step must not be able to destroy a pending send
        belonging to someone else merely by naming its request ID.

        A read under the same lock `_take` uses, so it cannot observe an entry
        a concurrent send is in the middle of popping. It is a **peek**, not an
        authorisation: nothing here mints, alters or transmits anything.
        """
        with self._pending_lock:
            return self._pending.get(request_id)

    # -- The one path from a request to a decision -------------------------

    def run(self, request_id: str, request: ExecutionRequest) -> ExecutionResult:
        """Run one request through A, C, D, E and F, and record what happened.

        **The atomic path, and it stays.** `preflight` and `send_approved` split
        the same work in two so a caller can see the payload before anything
        leaves; this does it in one round trip for a caller that does not need
        to. Both run the identical component sequence through
        `_through_policy`, and both authorise through component E and component
        F in the identical order — the split is *when a human is asked*, not
        *what the kernel decides*.

        Returns rather than raises for a privacy block, so the caller has one
        thing to handle. A `ProviderError` is **not** caught: a provider being
        unreachable is availability, not privacy, and design §6 has no row for
        it. Letting it propagate is what keeps a provider outage out of the
        audit log — recorded there as a block, it would be a false privacy
        event in the one store the design names as an asset.
        """
        try:
            outcome, _extracted = self._through_policy(request)
            if outcome.blocked:
                return self._blocked(request_id, request, _receipt_for(
                    request_id, outcome, self.settings))
            approved = outcome.approved
            if approved is None:
                # Unreachable: `run_redaction` ties the two together. Raised
                # rather than asserted, because `assert` vanishes under `-O`.
                raise AssertionError("an unblocked outcome must carry a payload")

            # E authorises the object it approved. The gateway checks the same
            # property again at the last point before a socket; this is E's own
            # check, and it is the difference between "the engine decided" and
            # "the thing being sent is the thing the engine decided about".
            self.policy.authorize_payload(approved, str(approved.payload_hash))

            # F: resolve the model through the registry, build the wire body,
            # verify the payload, and only then send. `verify_approved_payload`
            # is what mints the token `send` accepts, so an unverified send is
            # not expressible rather than merely discouraged.
            model = self.gateway.model_for(request.model_id)
            approved_send = self.gateway.verify_approved_payload(
                approved,
                str(approved.payload_hash),
                ModelRequest(
                    model=model,
                    messages=_messages(approved, request),
                    temperature=_TEMPERATURE,
                    max_tokens=_MAX_TOKENS,
                ),
            )
            response = self.gateway.send(approved_send)
        except MedarxError as refused:
            return self._blocked(request_id, request, _receipt_from_error(
                request_id, refused, self.settings))

        # The record is appended **after** the send, not before. It states what
        # happened — this payload was approved, this model was used, and the
        # draft now awaits a human — and a record written first would claim a
        # transmission that a provider outage then prevented. The cost is that
        # an append failing after a successful send leaves a `500` on a request
        # whose bytes are already on the wire; the failure is loud rather than a
        # silent hole in the audit trail, which is the trade this project makes
        # everywhere else.
        self._record_approved(request_id, request, outcome.dispositions, model,
                              approved)
        return ExecutionResult(
            request_id=request_id,
            function=request.function,
            approved=True,
            input_hash=request.input_hash,
            policy_version=self.settings.policy_version,
            policy_mode=self.settings.policy_mode,
            model_response=response,
            approved_payload_hash=str(approved.payload_hash),
            selected_model=model,
            dispositions=tuple(outcome.dispositions),
            addressed_function=request.addressed_function,
        )

    # -- The records --------------------------------------------------------

    def _blocked(self, request_id: str, subject: "_RequestFacts",
                 receipt: BlockReceipt) -> ExecutionResult:
        """Record the refusal and return the receipt the route will render.

        `request_id` is a separate argument because the two callers hold it in
        different places: `run` receives it as an argument, and an
        `ExecutionRequest` cannot carry it — the contract is
        `additionalProperties: false`, so the request ID is a header rather than
        a body field — while a `PendingApproval` was given one by its preflight.
        `subject` is typed as the attributes both carry rather than as either
        class, because a send refused at the last moment has no
        `ExecutionRequest` left to name and fabricating one would mean
        reconstructing a request the caller never made.

        The receipt is built from the refusing component's own `layer` and
        `action_codes` and from nothing else. There is no message field on it —
        the contract marks `BlockReceipt` closed with five fields — so a code
        that does not describe the refusal is the whole of what an auditor is
        given, and this is the one place that would put a wrong one in.
        """
        self.audit.append(
            AuditEvent(
                request_id=request_id,
                timestamp=_now(),
                function=subject.addressed_function,
                policy_version=self.settings.policy_version,
                policy_mode=self.settings.policy_mode,
                input_hash=subject.input_hash,
                redacted_field_names=[],
                action_codes=list(receipt.action_codes),
                final_disposition="blocked",
                layer=receipt.layer,
                chain_hash="",
                previous_hash="",
            )
        )
        return ExecutionResult(
            request_id=request_id,
            function=subject.function,
            approved=False,
            input_hash=subject.input_hash,
            policy_version=self.settings.policy_version,
            policy_mode=self.settings.policy_mode,
            block_receipt=receipt,
        )

    def _record_approved(self, request_id: str, subject: "_RequestFacts",
                         dispositions: "Sequence[Disposition]", model: str,
                         payload: StructuredPayload) -> None:
        """The pending-human-approval record for a payload that was transmitted.

        One record for both paths, because both transmitted the same thing and a
        second implementation would be a second answer to "what does a
        transmission leave behind". The disposition is the contract's existing
        `pending_human_approval`, not a new member: a preflight's `needs_review`
        is a *transport* state of the preflight response and never becomes a
        stored one, precisely because nothing was transmitted to be pending
        about.

        `redacted_field_names` is the *names* of the fields the layers acted on,
        never the values they held, and a name the storage policy's `FIELD_PATH`
        cannot admit is dropped rather than coerced: a record carrying a sentence
        in a field that should hold a name is the failure that policy exists to
        stop.
        """
        names: list[str] = []
        for disposition in dispositions:
            name = _field_name(disposition.field)
            if name is not None and name not in names:
                names.append(name)
        self.audit.append(
            AuditEvent(
                request_id=request_id,
                timestamp=_now(),
                function=subject.addressed_function,
                selected_model=model,
                policy_version=self.settings.policy_version,
                policy_mode=self.settings.policy_mode,
                input_hash=subject.input_hash,
                approved_payload_hash=payload.payload_hash,
                redacted_field_names=sorted(names),
                # Nothing was refused, so there is no disposition code to record.
                # A resolved disposition carries an *internal* code
                # (`REDACT_LAYER2_REPLACED`) that never reaches the wire, and
                # writing one into an audit record would put a name in the
                # action-code table's namespace that the contract does not have.
                action_codes=[],
                final_disposition="pending_human_approval",
                layer=None,
                chain_hash="",
                previous_hash="",
            )
        )

    # -- Human sign-off -----------------------------------------------------

    def record_approval(self, request_id: str, decision: str, reviewer: str,
                        note: str | None = None) -> AuditEvent:
        """Append the human's decision, and nothing else.

        The draft is not edited, not resubmitted and not published: this is the
        only thing the approval endpoint does, and the design gives Medarx no
        path that submits a report anywhere. The new record is a copy of the
        request's first record with the decision attached, because the log is
        append-only and a record has to stand on its own.

        `note` is logged rather than stored, and the reason is the contract's
        own: `HumanApprovalRequest` declares an optional `note` while
        `HumanApprovalState` — what a readback returns — is closed and has no such
        field, so the audit store has nowhere to put one, and adding one would be
        a new field on a record whose policy says no field may hold free text. The
        note goes to a log surface carrying the same sensitive-data filtering as
        every other, which is what the contract's `note` description says it is
        subject to.
        """
        if decision not in ("approved", "rejected"):
            raise ValueError(
                f"{decision!r} is not a decision; only an explicit human "
                "decision counts, and the only two are 'approved' and 'rejected'"
            )
        if not reviewer.strip():
            raise ValueError(
                "a human decision carries the identity of the human who made "
                "it; an empty reviewer is not a decision"
            )
        with self._approval_lock:
            stored = self.audit.get(request_id)
            if not stored:
                raise LookupError(
                    f"no audit record exists for request {request_id!r}")
            if any(event.human_approval is not None for event in stored):
                raise FileExistsError(
                    f"request {request_id!r} already has a recorded human "
                    "decision; the audit log is append-only, so a decision is "
                    "immutable and a changed mind requires a new execution"
                )
            first = stored[0]
            if first.final_disposition == "blocked" or first.approved_payload_hash is None:
                raise LookupError(
                    f"request {request_id!r} was refused before a payload was "
                    "approved, so it has no draft to sign off; the contract's "
                    "ExecutionNotFound is exactly a request ID with no execution "
                    "behind it"
                )
            return self._append_approval(first, request_id, decision, reviewer,
                                         note)
    def _append_approval(self, first, request_id: str, decision: str,
                         reviewer: str, note: "str | None") -> AuditEvent:
        """The append half of `record_approval`, under its lock.

        Split out so the read and the write it guards are in one `with` block
        above rather than in one function that a reader has to trust.
        """
        if note:
            _APPROVAL_LOG.info("reviewer note for %s by %s: %s", request_id,
                               reviewer, note)
        recorded_at = _now()
        return self.audit.append(
            AuditEvent(
                request_id=request_id,
                timestamp=recorded_at,
                function=first.function,
                selected_model=first.selected_model,
                policy_version=first.policy_version,
                policy_mode=first.policy_mode,
                input_hash=first.input_hash,
                approved_payload_hash=first.approved_payload_hash,
                redacted_field_names=list(first.redacted_field_names),
                action_codes=list(first.action_codes),
                human_approval=HumanApproval(
                    decision=decision, recorded_at=recorded_at, reviewer=reviewer
                ),
                final_disposition=("approved_by_human" if decision == "approved"
                                    else "rejected_by_human"),
                layer=first.layer,
                chain_hash="",
                previous_hash="",
            )
        )

    def close(self) -> None:
        """Release both engines. Called by nothing in the request path."""
        self.store.close()
        self.audit.close()


def build_pipeline(settings: Settings, db_url: str) -> Pipeline:
    """Construct every component once, from `settings` and `db_url` alone.

    The one place a component is created. No route constructs one, and no
    component constructs another: a second `MappingStore` would be a second
    surrogate table and a second `AuditLog` a second chain head, and neither
    would be the one the other requests used.
    """
    return Pipeline(
        settings=settings,
        db_url=db_url,
        store=MappingStore(db_url, settings.audit_key),
        audit=AuditLog(db_url, settings.audit_key),
        policy=PolicyEngine(settings),
        gateway=ModelGateway(settings),
    )



# -- The field-action summary ------------------------------------------------


def _field_actions(before: StructuredPayload, after: StructuredPayload,
                   request: ExecutionRequest) -> tuple[FieldAction, ...]:
    """What happened to every field between the caller's request and the payload.

    **Derived, never asserted.** Each entry is a comparison of two objects the
    pipeline already holds: `before` is what component A produced and `after`
    is what the policy approved. A field whose two values differ was
    transformed by component C, D or E; a field whose values match was carried.
    There is no third source and no inference, so a transformation the layers
    did not perform cannot appear here — the summary is a reading of the
    pipeline's own output, not a description of what it ought to have done.

    The exclusions are derived the same way. A DICOM attribute the caller
    supplied is named `excluded` when no payload field holds its value, decided
    by looking at the approved payload's own `dicom_fields` rather than at a
    second table of which attributes are droppable: the one place that decides
    what a payload carries is component A, and the summary reads its result
    rather than restating its rule. `request.excluded_inputs` covers the request
    properties the kernel cannot see at all, because the surface dropped them
    before the request became a kernel request.

    Ordering is fixed and readable rather than sorted alphabetically: the eight
    payload members in the order `StructuredPayload` declares them, then the
    exclusions. A preview whose rows jump around between two runs of the same
    request is a preview nobody can read.

    No entry carries a value. The transformed payload is returned beside this
    summary and does contain values — that is the preview, and every value in it
    has been approved for a model. The exclusions are the half that must not:
    they are the caller's own identifiers, and a summary that answered "what did
    you drop?" by quoting it would be a leak in the answer.
    """
    actions: list[FieldAction] = []

    def carry(name: str, left: object, right: object) -> None:
        actions.append(FieldAction(
            field=name,
            state=FIELD_INCLUDED if left == right else FIELD_TRANSFORMED,
        ))

    carry("function", before.function, after.function)
    carry("report_text", before.report_text, after.report_text)
    for name in sorted(set(before.dicom_fields) | set(after.dicom_fields)):
        carried = after.dicom_fields.get(name)
        if carried is None:
            # Unreachable on an approved payload: layer 3 refuses a field that
            # vanished, under `MISSING_SURROGATE` or `CONTRACT_VIOLATION`. Named
            # rather than assumed away so that a future layer which can drop a
            # field reports it here instead of failing the next test.
            actions.append(FieldAction(field=f"dicom_fields.{name}",
                                       state=FIELD_EXCLUDED))
        else:
            carry(f"dicom_fields.{name}", before.dicom_fields.get(name), carried)
    carry("study_ref", before.study_ref, after.study_ref)
    carry("prior_study_refs", before.prior_study_refs, after.prior_study_refs)
    carry("policy_version", before.policy_version, after.policy_version)
    carry("input_hash", before.input_hash, after.input_hash)
    # The pre-redaction hash component A wrote and the hash redaction layer 3
    # wrote over it are never equal, so this is always `transformed` — which is
    # what it is.
    carry("payload_hash", before.payload_hash, after.payload_hash)

    payload_fields = {f"dicom_fields.{name}" for name in after.dicom_fields}
    for keyword in sorted(request.dicom_metadata):
        field = ATTRIBUTE_TO_FIELD.get(keyword)
        if field is None or f"dicom_fields.{field}" not in payload_fields:
            actions.append(FieldAction(field=f"dicom_metadata.{keyword}",
                                       state=FIELD_EXCLUDED))
    for name in request.excluded_inputs:
        actions.append(FieldAction(field=name, state=FIELD_EXCLUDED))
    return tuple(actions)


# -- The receipt, and the two paths to it ------------------------------------


def _receipt_for(request_id: str, outcome, settings: Settings) -> BlockReceipt:
    """The receipt for an outcome the orchestrator said was blocked.

    The rule, stated once: the layer is that of the **first** unresolved
    disposition, because that is the layer a reader has to look at, and the
    codes are **every** unresolved disposition's, deduplicated in order, because
    reporting one of two would hide half the reason. A block with no unresolved
    disposition is the policy engine's own verdict and is named under layer E.

    `medarx.redaction.pipeline.run_privacy_kernel` applies the same rule when it
    raises, and the two are compared over the same input by
    `test_the_receipt_agrees_with_the_orchestrator`, so this cannot quietly
    become a second answer.
    """
    unresolved = [d for d in outcome.dispositions if not d.resolved]
    return BlockReceipt(
        request_id=request_id,
        layer=unresolved[0].layer if unresolved else _ENGINE_LAYER,
        action_codes=(list(dict.fromkeys(d.action_code for d in unresolved))
                      or [outcome.decision_code or _FALLBACK_CODE]),
        policy_version=settings.policy_version,
    )


def _receipt_from_error(request_id: str, error: MedarxError,
                        settings: Settings) -> BlockReceipt:
    """The receipt for a refusal a component raised directly.

    Components A, C, E's `authorize_payload` and F each raise rather than return
    an outcome, and each carries the layer and codes that describe it. There is
    nothing to derive here and nothing to infer: this is the transcription, and
    it adds no code of its own.
    """
    return BlockReceipt(
        request_id=request_id,
        layer=error.layer,
        action_codes=list(error.action_codes),
        policy_version=settings.policy_version,
    )


# -- The gateway's messages --------------------------------------------------


def _messages(payload: StructuredPayload,
              request: ExecutionRequest) -> list[dict[str, str]]:
    """The OpenAI-wire messages, built **only** from the approved payload.

    Every value here has been through pseudonymization, redaction and the policy
    decision. Nothing is read from `request` except the output-language hint,
    which the contract describes as a hint and not a prompt, and which is
    appended as a single line — a hint is not a channel for instruction.
    """
    fields = json.dumps(dict(sorted(payload.dicom_fields.items())),
                        separators=(",", ":"))
    priors = ", ".join(payload.prior_study_refs) or "none"
    user = (
        f"Function: {payload.function}\n"
        f"Study reference: {payload.study_ref}\n"
        f"Prior study references: {priors}\n"
        f"Allowlisted metadata: {fields}\n"
        f"Report text:\n{payload.report_text}"
    )
    if request.requested_language:
        user = f"{user}\nOutput language: {request.requested_language}"
    return [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": user},
    ]


# -- Small helpers -----------------------------------------------------------


def _now() -> datetime:
    """UTC, for the audit record's timestamp. Never a naive value."""
    return datetime.now(timezone.utc)


def _field_name(raw: str) -> str | None:
    """A disposition's field as a name the storage policy admits, or `None`.

    `prior_study_refs[0]` names a position as well as a field, and the audit log
    holds the field. The index is dropped for that reason, and a name that still
    does not parse as a field path is dropped altogether rather than written: a
    value in a field that should hold a name is precisely what the storage
    policy's shape gates exist to refuse.
    """
    head = raw.split("[", 1)[0]
    return head if FIELD_PATH.fullmatch(head) else None
