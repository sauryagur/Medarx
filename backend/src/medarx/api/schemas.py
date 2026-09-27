"""The request and response bodies, transcribed from `contracts/openapi.yaml`.

**Field for field**, including `additionalProperties: false` on every schema the
contract closes — which is what makes an unknown property a `400` rather than a
silent pass, and is the structural expression of the design's load-bearing
constraint that this surface cannot express an arbitrary DICOM object or a
free-form prompt. There is no property for a raw object, a byte payload, an
element stream or a file reference, so none of those is expressible here.

Two names deliberately collide with kernel names and mean different things:

- `ModelResponse` is the contract's wire object nested in `ExecutionResponse`
  (`content`, `model_id`, `finish_reason`, `usage`). `medarx.models.ModelResponse`
  is the gateway's internal reply plus the decoded provider body. Different
  shapes, different homes, and each docstring says which is which.
- `PriorStudyReference` is the contract's wire object, whose `study_date` is
  pattern-checked here. `medarx.models.PriorStudyReference` is the kernel's,
  which deliberately does **not** validate a date: component C's job is to
  refuse one it cannot shift, and a model that raised at the boundary would move
  that refusal from layer C to a schema violation. The boundary states the
  shape; the pipeline decides the meaning.

**One deliberate deviation, and why.** `ExecutionRequest.function` is typed `str`
rather than the contract's `FunctionName` enum. The contract's own
`FunctionNotFound` response says that an unknown function arriving "as a body
field against a valid path" is reported as a `422` with `layer: A` and
`UNKNOWN_FUNCTION` — a condition an enum-typed field could never reach, because
it would be rejected as a schema violation first. Typing it as the enum would
make the contract's stated behaviour unreachable, so the surface checks the
value itself and hands an unknown one to the component that owns the allowlist.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

#: Re-exported rather than redeclared. `medarx.models.BlockReceipt` is already
#: the contract's schema — five fields, all required, `extra="forbid"`, codes
#: shape-checked, layer validated against the closed `LAYERS` set — and a second
#: class here would be a second answer to "what does a receipt contain".
from medarx.models import BlockReceipt, FunctionName, PolicyMode
from medarx.pipeline import FUNCTION_WIRE_TO_INTERNAL

__all__ = [
    "AllowlistedDicomMetadata",
    "AuditRecord",
    "AuditRecordCollection",
    "BlockReceipt",
    "DicomDate",
    "ExecutionRequest",
    "ExecutionResponse",
    "FUNCTION_WIRE_TO_INTERNAL",
    "FinalDisposition",
    "FunctionName",
    "HumanApprovalRequest",
    "HumanApprovalResponse",
    "HumanApprovalState",
    "ModelResponse",
    "PolicyConfiguration",
    "PolicyMode",
    "PriorStudyReference",
    "ProblemDetail",
    "ReportText",
    "StudyContext",
    "ValidationError",
]

#: The contract's `FinalDisposition` enum, from the model the audit log stores.
FinalDisposition = Literal["approved", "blocked", "pending_human_approval",
                          "approved_by_human", "rejected_by_human"]

#: A DICOM `DA` value: exactly eight digits. The contract's pattern, verbatim.
#: `^…$` rather than `\A…\Z` because that is what the contract publishes, and a
#: value with a trailing newline is refused downstream anyway — `shift_dicom_date`
#: requires exactly eight characters.
DicomDate = Annotated[str, StringConstraints(pattern=r"^[0-9]{8}$")]

#: A DICOM `AS` age string: three digits and a unit. Layer A bands the age
#: before it reaches the payload, so neither the exact age nor a wide band is
#: ever transmitted. Named `PatientAgeString` and not `PatientAge` because the
#: property it types is itself called `PatientAge`, and a class body resolves an
#: annotation against its own namespace.
PatientAgeString = Annotated[str, StringConstraints(pattern=r"^[0-9]{3}[DWMY]$")]


class _Closed(BaseModel):
    """The base for every schema the contract marks `additionalProperties: false`.

    A base class rather than a repeated option so "closed" is one decision. A
    body that fails it is a `400` listing the offending fields, which is what
    makes a smuggled property a refusal rather than a pass.
    """

    model_config = ConfigDict(extra="forbid")


# -- Requests ----------------------------------------------------------------


class StudyContext(_Closed):
    """Study-scoped context. All Phase 1 study records are synthetic.

    The study reference is an internal reference; the pseudonymization service
    exchanges it for a stable surrogate before anything is sent to a provider.
    There is deliberately no patient identifier here — the contract declares
    none, and `extra="forbid"` means one cannot be smuggled in. See
    `medarx.pipeline.patient_ref_for` for what the kernel does instead.
    """

    study_reference: str
    accession_reference: str | None = None
    encounter_reference: str | None = None
    modality: str | None = None


class PriorStudyReference(_Closed):
    """A reference to a prior study. Only the reference is carried.

    Prior study *content* is not inlined: `AllowlistedDicomMetadata` carries the
    one prose field a prior study contributes, and Orthanc/DICOMweb integration
    is deferred to Phase 2.
    """

    prior_study_reference: str
    study_date: DicomDate | None = None


class AllowlistedDicomMetadata(_Closed):
    """A **closed, allowlisted** set of DICOM metadata fields.

    The property names are the DICOM keywords, because component A's known-
    attribute table *is* the boundary's vocabulary and the two are held to one
    another by a test. There is no translation layer between them, because two
    vocabularies would be two things to keep in step.

    The identifier fields are accepted and then dropped by layer A: they reach
    the input hash and no payload field, which is why `PatientID` is still useful
    to a caller even though it never reaches a model.
    """

    PatientID: str | None = None
    AccessionNumber: str | None = None
    InstitutionName: str | None = None
    StudyDate: DicomDate | None = None
    PatientAge: PatientAgeString | None = None
    Modality: str | None = None
    PriorReportText: str | None = None
    PriorStudyDate: DicomDate | None = None


class ReportText(_Closed):
    """Clinician-supplied report text — the single free-text input on this surface.

    It is a documented pipeline input, **not** a prompt: allowlisted content that
    extraction, pseudonymization and redaction process before any model call.
    Free-form prompts are rejected at this surface, and there is no property here
    one could arrive in.
    """

    text: str = Field(min_length=1)
    source: Literal["synthetic_corpus", "clinician_supplied"] | None = None


class ExecutionRequest(_Closed):
    """An execution request. Every property is one the design places here.

    `function` is a plain `str` on purpose; see the module docstring. There is
    **no** `policy_mode` property: the mode is a deployment configuration, and
    `extra="forbid"` is what turns a request that supplies one into a `400`
    rather than a request that quietly chose its own policy.
    """

    function: str | None = None
    study_context: StudyContext
    report_text: ReportText
    dicom_metadata: AllowlistedDicomMetadata | None = None
    prior_studies: list[PriorStudyReference] | None = None
    model_id: str | None = None
    requested_language: str | None = None


class HumanApprovalRequest(_Closed):
    """A human sign-off decision, by request ID.

    The draft is neither modified nor resubmitted through this path; editing a
    draft requires a new execution, which re-runs the whole privacy pipeline.
    `note` is accepted because the contract declares it, and it reaches a
    filtered log surface rather than the audit store — see
    `medarx.pipeline.Pipeline.record_approval` for why the store cannot hold it.
    """

    decision: Literal["approved", "rejected"]
    reviewer: str = Field(min_length=1)
    note: str | None = None


# -- Responses ---------------------------------------------------------------


class ModelUsage(_Closed):
    """Token accounting, as reported by the provider."""

    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None


class ModelResponse(_Closed):
    """The gateway's answer, returned **as a draft**.

    There is no path by which this becomes clinical content without an explicit
    human decision recorded against the request ID. The drafting is expressed by
    the nesting on `ExecutionResponse.draft`; this schema models the answer and
    nothing more, so it requires no `draft` of its own.
    """

    model_id: str | None = None
    content: str
    finish_reason: str | None = None
    usage: ModelUsage | None = None


class ExecutionResponse(_Closed):
    """The approved-path response.

    The payload is identified by hash, in the contract's `sha256:` spelling:
    the hash is what egress verification checks observed outbound bytes against,
    using two observers both external to the Medarx process. Medarx's own audit
    log is explicitly not accepted as evidence of what left.
    """

    status: Literal["approved"] = "approved"
    request_id: str
    function: FunctionName | None = None
    policy_version: str
    policy_mode: PolicyMode | None = None
    selected_model: str | None = None
    approved_payload_hash: str | None = None
    input_hash: str | None = None
    draft: ModelResponse


class HumanApprovalState(_Closed):
    """A recorded human sign-off. The contract closes this, so it holds no note."""

    decision: Literal["approved", "rejected"]
    recorded_at: datetime
    reviewer: str | None = None


class HumanApprovalResponse(_Closed):
    """Confirmation that a decision was appended to the audit log.

    A record of a human judgement, not a transmission of anything: no clinical
    system is written to.
    """

    request_id: str
    decision: Literal["approved", "rejected"]
    recorded_at: datetime
    final_disposition: FinalDisposition | None = None


class PolicyExtension(_Closed):
    """A documented mode that is **not** implemented."""

    name: Literal["authorized_local"]
    implemented: Literal[False] = False
    note: str


class PolicyConfiguration(_Closed):
    """The policy configuration in force, as read from component E.

    `fail_closed` is a constant, not a reading: it is always `true`, in every
    implemented mode, for every failure. The extension list is present so a
    reader is not left guessing whether `authorized_local` is available.
    """

    policy_mode: PolicyMode
    policy_version: str
    implemented_modes: list[Literal["strict_local", "cloud"]]
    fail_closed: Literal[True] = True
    extensions: list[PolicyExtension] = Field(default_factory=list)


class AuditRecord(_Closed):
    """One record from the append-only, tamper-evident audit log.

    The properties are **exactly** the fields the storage policy persists. There
    is no raw-PHI property here, and that absence is the design rather than an
    omission: raw PHI is never stored in the normal audit log, so there is no
    such field to return.

    `chain_verified` and `stages` are computed on read. `stages` is the pipeline
    prefix derived from `layer`, so nothing about it is persisted; `chain_verified`
    is the walk's answer, so no rewrite can make a record claim it about itself.
    """

    request_id: str
    timestamp: datetime
    function: FunctionName
    policy_version: str
    final_disposition: FinalDisposition
    selected_model: str | None = None
    policy_mode: PolicyMode | None = None
    input_hash: str | None = None
    approved_payload_hash: str | None = None
    redacted_field_names: list[str] = Field(default_factory=list)
    action_codes: list[str] = Field(default_factory=list)
    human_approval: HumanApprovalState | None = None
    layer: str | None = None
    chain_verified: bool | None = None
    stages: list[str] = Field(default_factory=list)


class AuditRecordCollection(_Closed):
    """A page of audit records, oldest first.

    `chain_verified` is the aggregate answer across the returned records and
    reports the whole log, not the page — a caller cannot verify a page and think
    it verified the log.
    """

    records: list[AuditRecord]
    count: int
    chain_verified: bool | None = None
    input_source: Literal["synthetic_corpus", "clinician_supplied"] | None = None


class ValidationError(_Closed):
    """A single request-shape violation."""

    field: str
    message: str


class ProblemDetail(BaseModel):
    """RFC 9457 problem document, used for `400`, `403`, `404`, `409` and `415`.

    The contract does **not** close this schema, so it is left open here as it
    is there: it is the error shape, and a future problem type may carry a
    property no reader of this version expects. A privacy block never uses it —
    that is always a `BlockReceipt`.

    `type` is a plain string rather than a URL-typed field so the values this
    application produces reach the wire byte for byte as the constants they are
    written from; a URL type would be free to normalise them.
    """

    model_config = ConfigDict(extra="allow")

    type: str
    title: str
    status: int
    detail: str | None = None
    request_id: str | None = None
    errors: list[ValidationError] = Field(default_factory=list)

    def as_dict(self) -> dict:
        """The wire body, with the optional members present only when set.

        `errors` is omitted when empty rather than serialised as `[]`: a problem
        document with no field-level detail is not a document with an empty
        list of field-level details, and a client branching on the member's
        presence would read the difference.
        """
        body = self.model_dump(exclude_none=True)
        if not self.errors:
            body.pop("errors", None)
        return body

