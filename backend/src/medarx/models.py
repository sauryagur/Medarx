"""The payload shapes owned by the extraction layer and its consumers.

`ExtractionRequest` is the only way a caller hands data to layer A, and
`StructuredPayload` is the only thing any downstream stage — pseudonymization,
redaction, policy, the audit log — is allowed to see. Nothing else may be
carried across this boundary.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from medarx.extraction.study_context import StudyContext

__all__ = ["ExtractionRequest", "StructuredPayload", "canonical_hash"]


def canonical_hash(value: Any) -> str:
    """Deterministic SHA-256 over a canonical JSON encoding of `value`."""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


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
