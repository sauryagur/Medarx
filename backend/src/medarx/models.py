"""The shared wire models: payloads, receipts, gateway bodies, and audit events.

`ExtractionRequest` is the only way a caller hands data to layer A, and
`StructuredPayload` is the only thing any downstream stage — pseudonymization,
redaction, policy, the audit log — is allowed to see. Nothing else may be
carried across that boundary. `BlockReceipt` and `AuditEvent` are the objects
that leave the process, so both are shaped to be structurally incapable of
holding a raw value: codes, hashes, and field names only.
"""

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from medarx.extraction.study_context import StudyContext

__all__ = [
    "AuditEvent",
    "BlockReceipt",
    "ExtractionRequest",
    "HumanApproval",
    "ModelRequest",
    "ModelResponse",
    "PolicyMode",
    "PriorStudyReference",
    "StructuredPayload",
    "canonical_hash",
]

#: An action code classifies a refusal; it never carries what was refused. The
#: rule is deliberately the strictest one that admits every contract member:
#: uppercase letters joined by single underscores, and **no digits at all** —
#: a digit run is how a medical record number with a prefix ("MRN4452819")
#: turns into evidence, and no classifier in the `ActionCode` enum needs one.
#: `\A`…`\Z` rather than `^`…`$`, because `$` also matches before a trailing
#: newline, and a newline inside a logged code is a log-injection primitive.
CODE_SHAPE = re.compile(r"\A[A-Z]+(?:_[A-Z]+)*\Z")

#: The complete closed set of layer tags, mirroring the `Layer` enum in
#: contracts/openapi.yaml. There is no bare "D": the three redaction layers are
#: tagged D.1, D.2, and D.3 individually.
LAYERS = ("J", "A", "C", "D.1", "D.2", "D.3", "E", "F")

#: The contract's `PolicyMode` enum. Fixed per deployment, never per request.
PolicyMode = Literal["strict_local", "cloud", "authorized_local"]

FinalDisposition = Literal[
    "approved",
    "blocked",
    "pending_human_approval",
    "approved_by_human",
    "rejected_by_human",
]


def canonical_hash(value: Any) -> str:
    """Deterministic SHA-256 over a canonical JSON encoding of `value`.

    No `default=` fallback: a value with no defined JSON encoding raises
    `TypeError` rather than being hashed as its `str()`. This hash anchors an
    audit chain, so its encoding must be defined rather than merely stable for
    a given object. Callers pass a defined encoding, not a live object.
    """
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def check_codes(codes: list[str]) -> list[str]:
    """Reject any action code that is not a bare classifier.

    A code carrying a space, a digit run, lowercase text, or a trailing newline
    is a raw value trying to become evidence, and every model that accepts
    codes runs this check on construction.

    What that check is, precisely — the two halves of the rule live in different
    places, and only one of them is here:

    - **shape** is enforced at *runtime*, by this function, on every value that
      reaches a receipt or an error;
    - **membership** in the contract's `ActionCode` enum is enforced at *test
      time*, by the AST sweep in `tests/test_openapi_contract.py`, and only
      over statically declared emission sites.

    So a code built dynamically at runtime is caught by neither. The shape rule
    narrows that gap; it does not close it, and nothing here claims it does.
    """
    for code in codes:
        if not CODE_SHAPE.match(code):
            raise ValueError(
                f"action code {code!r} is not a bare classifier: codes must match "
                f"{CODE_SHAPE.pattern} and never carry a raw value"
            )
    return list(codes)


class ExtractionRequest(BaseModel):
    """One extraction request: a function, a study, allowlisted metadata, text."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    function: str
    study: StudyContext
    report_text: str
    dicom_metadata: Mapping[str, str] = Field(default_factory=dict)
    policy_version: str


class StructuredPayload(BaseModel):
    """The only shape permitted past layer A.

    `dicom_fields` holds canonical snake_case names drawn from the function's
    allowlist.

    `input_hash` covers what came in and is carried through pseudonymization
    unchanged. `payload_hash` is a **pre-redaction** value written here for
    provenance only: redaction layers 1 and 2 transform the payload in place,
    so the layer-3 contract check MUST overwrite it with a hash of the approved
    payload rather than recompute or trust this one. It stays `None` until
    layer 3 sets it.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    function: str
    report_text: str
    dicom_fields: Mapping[str, str]
    study_ref: str
    prior_study_refs: tuple[str, ...] = ()
    policy_version: str
    input_hash: str = ""
    payload_hash: str | None = None


class PriorStudyReference(BaseModel):
    """A caller-supplied reference to a prior study.

    Only the reference is carried; prior-study content is never inlined, and the
    reference is surrogate-substituted by the pseudonymization service.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    prior_study_reference: str
    study_date: str | None = None


class BlockReceipt(BaseModel):
    """The whole body returned on a privacy block (HTTP 422).

    These five keys are the entire wire object; the contract marks the schema
    `additionalProperties: false` with all five required, and `extra="forbid"`
    keeps it that way here. A receipt is returned in full and logged, so it is
    structurally incapable of carrying a raw value: `action_codes` are
    shape-checked, and there is no field that holds text a detector matched.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: Literal["blocked"] = "blocked"
    request_id: str
    layer: Literal["J", "A", "C", "D.1", "D.2", "D.3", "E", "F"]
    action_codes: list[str] = Field(min_length=1)
    policy_version: str

    @field_validator("action_codes")
    @classmethod
    def _codes_are_shaped_like_codes(cls, codes: list[str]) -> list[str]:
        return check_codes(codes)


class ModelRequest(BaseModel):
    """The OpenAI-wire request component F sends to a provider."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    model: str
    messages: list[dict[str, str]]
    temperature: float
    max_tokens: int


class ModelResponse(BaseModel):
    """A provider's reply, as the gateway sees it.

    This class is **not** the contract's `ModelResponse` schema, despite the
    shared name: the contract's is the API-facing object nested in
    `ExecutionResponse` (`content`, `model_id`, `finish_reason`, `usage`), while
    this one is the gateway-internal reply plus `raw`, the decoded provider body
    kept for capture and audit. The name collision is deliberate for now —
    renaming is a call for the owner, not a silent edit here — and this
    docstring is the note meant to prevent a wrong import.

    `raw` is unbounded by type: the only unvalidated field in the package.
    Nothing reads it back into a request, and the gateway task should give it a
    dedicated model when it lands.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    model_id: str
    content: str
    raw: Mapping[str, Any] = Field(default_factory=dict)


class HumanApproval(BaseModel):
    """A recorded human sign-off. Synthetic reviewer identity in Phase 1."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    decision: Literal["approved", "rejected"]
    recorded_at: datetime
    reviewer: str


class AuditEvent(BaseModel):
    """One append-only audit record.

    Every field the contract models in `AuditRecord` is named as the contract
    names it, and `test_audit_event_names_match_the_contract_audit_record`
    pins that intersection, so the storage layer and the readback layer cannot
    drift on the shared names. The set is *not* an exact match in both
    directions, and the differences are deliberate:

    - `chain_hash` and `previous_hash` are additional. They are the
      tamper-evidence inputs the contract describes as "hash chaining over
      appended records"; the contract describes that chaining but models no
      schema for it, because the storage schema is a Phase 1 decision.
    - `chain_verified` is absent. The contract defines it as a result computed
      on read, not a stored field.

    No field here can hold payload text: the event carries hashes, field
    *names*, and codes only.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    request_id: str
    timestamp: datetime
    function: str
    selected_model: str | None = None
    policy_version: str
    policy_mode: PolicyMode | None = None
    input_hash: str
    approved_payload_hash: str | None = None
    redacted_field_names: list[str] = Field(default_factory=list)
    action_codes: list[str] = Field(default_factory=list)
    human_approval: HumanApproval | None = None
    final_disposition: FinalDisposition
    chain_hash: str
    previous_hash: str

    @field_validator("action_codes")
    @classmethod
    def _codes_are_shaped_like_codes(cls, codes: list[str]) -> list[str]:
        return check_codes(codes)
