"""Component G's action-code table, and the stage boundaries of the log.

The design names G as the source of the codes a block receipt carries, and the
contract's `ActionCode` enum describes this module's table as "the
authoritative source". This is it: every contract code, the component that may
emit it, and — where the design and the kernel disagree, or where a member is
declared but nothing produces it — why.

A code classifies a refusal; it never carries what was refused. That is enforced
upstream by `medarx.models.CODE_SHAPE`, which admits no digits at all, so a
medical record number cannot ride in on a code.

`PIPELINE_STAGES` is the ordered set of stage boundaries the log is
partitioned into. The UI's privacy-details drawer renders exactly this
timeline, and the names are in the contract so that a later change to what the
log records is a change to a published vocabulary rather than a rename of audit
records that already exist.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["CODE_TABLE", "PIPELINE_STAGES", "STAGE_COMPONENTS", "CodeEntry"]


@dataclass(frozen=True)
class CodeEntry:
    """One row of the table: a code, the layers that may emit it, and why.

    `owners` is empty when no component emits the code — either because the
    component that would is not written yet, or because the member is declared
    and argued for rather than produced. `tests/test_audit.py` pins both
    readings: no row may name a layer outside `medarx.models.LAYERS`, and the
    set of owner-less rows is asserted exactly.
    """

    code: str
    owners: tuple[str, ...]
    note: str


#: The stage boundaries, in pipeline order. Each name is a label the UI shows
#: and each maps to components that exist — a stage with no component behind it
#: would be an invention, so `STAGE_COMPONENTS` is asserted against the
#: kernel's own closed layer set.
PIPELINE_STAGES: tuple[str, ...] = (
    "Fields selected",
    "Pseudonymized",
    "Text screened",
    "Payload validated",
    "Policy decision",
    "Model request",
)

#: Which components each stage is the work of. `Text screened` is two layers
#: because it is two layers: the deterministic pass and the NER pass, both of
#: which have to be clean for the stage to be behind the request.
STAGE_COMPONENTS: dict[str, tuple[str, ...]] = {
    "Fields selected": ("A",),
    "Pseudonymized": ("C",),
    "Text screened": ("D.1", "D.2"),
    "Payload validated": ("D.3",),
    "Policy decision": ("E",),
    "Model request": ("F",),
}


#: The table. Ordered by layer, then by code, so it reads the way the pipeline
#: runs; membership is what is contractual, not this order.
CODE_TABLE: tuple[CodeEntry, ...] = (
    # -- J, the application API. Not written in Phase 1; the codes exist because
    # the contract's row-1 example publishes them.
    CodeEntry("ARBITRARY_DICOM_OBJECT_REJECTED", (),
              "J: an arbitrary DICOM object at the request surface. J does not exist yet."),
    CodeEntry("FREE_FORM_PROMPT_REJECTED", (),
              "J: a free-form prompt at the request surface. J does not exist yet."),
    CodeEntry("FUNCTION_NOT_PERMITTED", (),
              "J: the function is not permitted for this scope. J does not exist yet."),
    CodeEntry("UNAUTHORIZED_SCOPE", (),
              "J: the study scope is not authorized. J does not exist yet."),

    # -- A, the structured payload extractor.
    CodeEntry("MALFORMED_METADATA", ("A",),
              "A: allowlisted DICOM metadata that is not the shape it must be."),
    CodeEntry("UNKNOWN_DICOM_ATTRIBUTE", ("A",),
              "A: an allowlisted field holding something that is not that DICOM attribute."),
    CodeEntry("UNKNOWN_FUNCTION", ("A", "D.3"),
              "A: no allowlist for the named function. D.3 raises it too: the "
              "payload that arrived does not satisfy any function's contract."),
    CodeEntry("FIELD_NOT_ALLOWLISTED", ("A", "D.3"),
              "A: a field outside the function allowlist. D.3 raises it for the "
              "same condition found on a payload it was handed."),

    # -- C, the pseudonymization service.
    CodeEntry("SURROGATE_SHAPED_REFERENCE_REJECTED", ("C",),
              "C: a reference that already has the shape of a surrogate. A "
              "distinct condition from a missing one, and the polarity of the "
              "name is the point: reusing MISSING_SURROGATE would give a "
              "receipt no way to tell them apart."),
    CodeEntry("MISSING_SURROGATE", ("C", "D.1", "D.3"),
              "C: no surrogate could be assigned. D.1: a reference it could not "
              "replace. D.3: a reference that reached validation with no "
              "surrogate in front of it."),
    CodeEntry("UNSHIFTED_DATE", ("C", "D.1", "D.2", "D.3"),
              "C: a date field that is not a DICOM date. D.1/D.2: a date the "
              "per-patient shift does not cover. D.3: a date still unshifted at "
              "validation."),

    # -- D.1, the deterministic pass.
    CodeEntry("DETERMINISTIC_REPLACEMENT_FAILED", ("D.1",),
              "D.1: a required structured field that no known pattern removes or "
              "replaces. Never a guess and never a partial sanitisation."),

    # -- D.2, the NER pass.
    CodeEntry("NER_UNRESOLVED", ("D.2",),
              "D.2: an entity flagged with no deterministic replacer. The "
              "unresolved disposition that fails the request closed."),
    CodeEntry("LOW_CONFIDENCE_NER_UNRESOLVED", ("D.2",),
              "D.2: the same condition, named separately because the confidence "
              "score below the threshold is a different thing to investigate "
              "than a missing replacer."),
    CodeEntry("UNRESOLVED_EMPTY_BODY", ("D.2",),
              "D.2: nothing survives redaction in a field that had content."),

    # -- D.3, the second validation pass.
    CodeEntry("CONTRACT_VIOLATION", ("D.3",),
              "D.3: missing field, extra field, or any other breach of the "
              "per-function payload contract."),
    CodeEntry("LEFTOVER_PATTERN_MATCH", ("D.3",),
              "D.3: a deterministic pattern still matching in the transformed "
              "payload, which is the check the NER pass alone cannot make."),

    # -- E, the policy engine.
    CodeEntry("UNKNOWN_POLICY_VERSION", ("E",),
              "E: the policy version on the request is not one the engine has."),
    CodeEntry("POLICY_CONFIG_ERROR", ("E",),
              "E: the policy is misconfigured — including a date order the "
              "deployment has not declared. Fails closed in every mode."),
    CodeEntry("UNAPPROVED_PAYLOAD", ("E",),
              "E: the object about to be authorised is not the one the decision "
              "approved, and — the second emission site — E blocked for a "
              "reason of its own and named no more specific code, so this is "
              "what the block carries. Both sites are E; redaction's "
              "orchestrator raises it under the engine's layer for exactly "
              "that reason."),

    # -- F, the model gateway. The only component that may call a provider.
    CodeEntry("UNKNOWN_MODEL", ("F",),
              "F: a model identifier the registry does not carry. No provider "
              "call is made."),
    CodeEntry("PAYLOAD_MISMATCH", ("F",),
              "F: the payload is not the exact object E approved. Design §6 "
              "row 7's own name for the condition."),
    CodeEntry("HASH_MISMATCH", ("F",),
              "F only, and this row exists because the design implies otherwise. "
              "Design §6 row 5 lists 'hash mismatch' among layer 3's block "
              "conditions and the contract's row-5 example summary repeats the "
              "words, but the kernel does not implement it that way: layer 3 "
              "*overwrites* `payload_hash` with the hash of the payload it "
              "checked rather than comparing a claim against it, so there is no "
              "hash-mismatch condition for it to detect. The comparison happens "
              "in the gateway, which refuses anything but the exact object E "
              "approved. Both halves of that are executed, not asserted, in "
              "tests/test_redaction_layers.py::"
              "test_layer3_overwrites_the_pre_redaction_hash_rather_than_"
              "trusting_it and in tests/test_gateway.py::"
              "test_verify_approved_payload_refuses_a_hash_the_engine_never_"
              "approved."),

    # -- Declared, not emitted.
    CodeEntry("UNRESOLVED_DISPOSITION", (),
              "Kept, deliberately, and nothing emits it. The contract's row-6 "
              "example names it, and the enum is declared open — 'G's table is "
              "the authoritative source and is expected to grow' — so a code the "
              "kernel does not yet produce is a member awaiting its component, "
              "not a lie. It stays unemitted because component E blocks an "
              "unresolved disposition under the disposition's *own* code: the "
              "layer that raised it is the one a reader has to look at, and a "
              "second engine-level code for the same refusal would give one "
              "refusal two different receipts depending on which component the "
              "caller asked. The decision is pinned as pending implementation "
              "in `tests/test_contract_schemas.py::_NOT_YET_EMITTED`, which "
              "fails the moment anything starts emitting it."),
)
