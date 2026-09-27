"""The composition root: components A to G, wired once, in one order.

This module is where the pieces meet and where the order the whole kernel
depends on is written down:

    A allowlisted extraction → C surrogates and the per-patient date shift →
    D layers 1–3 with E deciding last → E authorises the object it approved →
    F verifies that object and only then sends it.

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
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Mapping

from medarx.audit import AuditLog
from medarx.audit.audit_log import FIELD_PATH
from medarx.config import Settings
from medarx.errors import MedarxError
from medarx.extraction.payload_extractor import pipeline_for
from medarx.extraction.study_context import StudyContext
from medarx.gateway.openai_gateway import ModelGateway
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

__all__ = [
    "ExecutionRequest",
    "ExecutionResult",
    "FUNCTION_INTERNAL_TO_WIRE",
    "FUNCTION_WIRE_TO_INTERNAL",
    "Pipeline",
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


@dataclass(frozen=True)
class ExecutionRequest:
    """One execution, already parsed by the surface.

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
    """

    request_id: str
    function: str
    approved: bool
    input_hash: str
    policy_version: str
    policy_mode: str
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


def patient_ref_for(dicom_metadata: Mapping[str, str], study_reference: str) -> str:
    """The patient scope component C shifts by, for one request.

    **The contract's `StudyContext` has no patient identifier**, and this
    surface may not add one: `additionalProperties: false` means a field the
    contract does not declare cannot be sent. So the patient scope is taken from
    `PatientID` when the caller supplies one — the contract's own allowlisted
    attribute, which layer A accepts and then drops, so it reaches the input hash
    and no payload field — and from the study reference otherwise.

    **The limitation this carries, stated rather than smoothed.** A study
    reference identifies a study, not a patient, so two studies of the same
    patient arriving without a `PatientID` get two different date offsets and the
    interval between them is not preserved. The contract's own `StudyContext`
    documentation says the study reference "is not a DICOM StudyInstanceUID and
    is never transmitted as-is", so nothing about it is safe to treat as a
    patient key. This is a Phase 1 gap in the contract, not a choice, and it is
    recorded here so the next reader knows it exists.
    """
    supplied = dicom_metadata.get("PatientID", "").strip()
    return supplied or study_reference.strip()


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

    # -- The one path from a request to a decision -------------------------

    def run(self, request_id: str, request: ExecutionRequest) -> ExecutionResult:
        """Run one request through A, C, D, E and F, and record what happened.

        Returns rather than raises for a privacy block, so the caller has one
        thing to handle. A `ProviderError` is **not** caught: a provider being
        unreachable is availability, not privacy, and design §6 has no row for
        it. Letting it propagate is what keeps a provider outage out of the
        audit log — recorded there as a block, it would be a false privacy
        event in the one store the design names as an asset.
        """
        try:
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
            # D then E: layers 1-3, then the fail-closed decision. `source` is
            # the payload as component A produced it, *before* the shift, because
            # two of layer 3's checks are statements about a difference between
            # the original and the transformed payload.
            outcome = run_redaction(
                pseudonymized,
                request.study_context.patient_ref,
                self.store,
                self.policy,
                self.settings,
                source=extracted,
            )
            if outcome.blocked:
                return self._blocked(request, request_id,
                                     _receipt_for(request_id, outcome, self.settings))
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
            return self._blocked(request, request_id, _receipt_from_error(
                request_id, refused, self.settings))

        # The record is appended **after** the send, not before. It states what
        # happened — this payload was approved, this model was used, and the
        # draft now awaits a human — and a record written first would claim a
        # transmission that a provider outage then prevented. The cost is that
        # an append failing after a successful send leaves a `500` on a request
        # whose bytes are already on the wire; the failure is loud rather than a
        # silent hole in the audit trail, which is the trade this project makes
        # everywhere else.
        self._record_approved(request, request_id, outcome.dispositions, approved,
                              model)
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
        )

    # -- The records --------------------------------------------------------

    def _blocked(self, request: ExecutionRequest, request_id: str,
                 receipt: BlockReceipt) -> ExecutionResult:
        """Record the refusal and return the receipt the route will render.

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
                function=request.addressed_function,
                policy_version=self.settings.policy_version,
                policy_mode=self.settings.policy_mode,
                input_hash=request.input_hash,
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
            function=request.function,
            approved=False,
            input_hash=request.input_hash,
            policy_version=self.settings.policy_version,
            policy_mode=self.settings.policy_mode,
            block_receipt=receipt,
        )

    def _record_approved(self, request: ExecutionRequest, request_id: str,
                         dispositions: "list[Disposition]", payload: StructuredPayload,
                         model: str) -> None:
        """The pending-human-approval record for a run that was transmitted.

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
                function=request.addressed_function,
                selected_model=model,
                policy_version=self.settings.policy_version,
                policy_mode=self.settings.policy_mode,
                input_hash=request.input_hash,
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
