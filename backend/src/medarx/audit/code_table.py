"""Component G's action-code table, and the privacy pipeline's stage vocabulary.

The design names G as the source of the codes a block receipt carries, and the
contract's `ActionCode` enum describes this module's table as "the
authoritative source". This is it: every contract code, the component that may
emit it, and — where the design and the kernel disagree, or where a member is
declared but nothing produces it — why.

A code classifies a refusal; it never carries what was refused. That is enforced
upstream by `medarx.models.CODE_SHAPE`, which admits no digits at all, so a
medical record number cannot ride in on a code.

Two reserved members, `FUNCTION_NOT_PERMITTED` and `UNAUTHORIZED_SCOPE`, are
tracked differently from the other three and say so in their own rows: no
published example carries them, so the example-reachability sweep in
`tests/test_contract_schemas.py` cannot see them at all. They are declared in
`_RESERVED_NOT_ADVERTISED` there and checked only for staleness. The gap is
written down rather than smoothed over — a code no example advertises is a code
no example sweep can enforce.

`PIPELINE_STAGES` is the ordered set of stage boundaries the privacy pipeline
passes through. No stage is stored: a record carries the `layer` that refused
it, and `stages` is derived from that at read time by `stages_reached`, so the
list cannot disagree with the record it was computed from. The UI's
privacy-details drawer renders exactly this timeline, and the names are in the
contract so that a later change to the timeline is a change to a published
vocabulary rather than a rename of audit records that already exist.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "CODE_TABLE",
    "GATEWAY_LAYER",
    "LAYER_STAGE",
    "PIPELINE_STAGES",
    "STAGE_COMPONENTS",
    "CodeEntry",
    "preflight_stages",
    "stages_reached",
]


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

#: The one layer that is permitted to call a provider — the layer a stage must
#: be attributed to before `preflight_stages` will leave it out. A literal,
#: because reading it out of `STAGE_COMPONENTS["Model request"][0]` would make
#: the constant depend on the order of a tuple; instead
#: `tests/test_preflight.py::test_the_gateway_layer_is_the_one_that_owns_the_model_request_stage`
#: holds the two to each other, and `medarx.models.LAYERS` is what says `F` is a
#: layer at all.
GATEWAY_LAYER = "F"


def _layer_stage() -> dict[str, str]:
    """The layer → stage map, *derived* from `STAGE_COMPONENTS` once, at import.

    Derived rather than written out because a hand-maintained copy is a second
    table that can drift: a new D.4 would be added to `LAYERS` and to
    `STAGE_COMPONENTS`, and an inverse written out separately would keep
    answering for the old set. One table, one direction of maintenance.

    Computed once, so `LAYER_STAGE` is a module-level dict and a runtime edit to
    `STAGE_COMPONENTS` is not reflected in it. That is the point of computing it
    at all rather than per call: the stage set does not change under a running
    process, and a half-updated table read concurrently would be worse than a
    stale one.

    A layer with no stage is `J`: the request surface refuses before anything
    enters the pipeline, so no stage was ever behind the request.
    """
    mapping: dict[str, str] = {}
    for stage in PIPELINE_STAGES:
        for layer in STAGE_COMPONENTS[stage]:
            mapping[layer] = stage
    return mapping


LAYER_STAGE: dict[str, str] = _layer_stage()


def stages_reached(layer: str | None) -> tuple[str, ...]:
    """The pipeline stages a record with blocking `layer` got through.

    A *stage* answers "how far did it get" and a *layer* answers "who refused",
    so neither is derivable from the other — but together one gives the other:
    everything up to and including the stage that owns the blocking layer was
    behind the request, and nothing after it was.

    `None` means nothing refused it, so it got through all six. A layer with no
    stage of its own (`J`) is the request surface, which refused before the
    pipeline started: no stage was behind the request at all.
    """
    if layer is None:
        return PIPELINE_STAGES
    stage = LAYER_STAGE.get(layer)
    if stage is None:
        return ()
    return PIPELINE_STAGES[: PIPELINE_STAGES.index(stage) + 1]


def preflight_stages() -> tuple[str, ...]:
    """The stages a preflight reaches: every one component `GATEWAY_LAYER` does not own.

    A preflight runs A, C, D and E and stops before F, so `Model request` is
    not behind it. Derived from `STAGE_COMPONENTS` rather than written as
    `PIPELINE_STAGES[:5]` so that a seventh stage owned by another component
    joins the list and a new stage owned by `F` does not — a hand-written slice
    would silently name a stage the preflight does not reach the day either of
    those happens.

    This is a different question from `stages_reached`, which answers "how far
    did a request with this blocking layer get" and derives from the layer a
    record was *filed under*. Nothing refused a preflight, so that function
    would answer "all six", which would claim the model was called.
    """
    return tuple(stage for stage in PIPELINE_STAGES
                 if GATEWAY_LAYER not in STAGE_COMPONENTS[stage])


#: The table. Ordered by layer, then by code, so it reads the way the pipeline
#: runs; membership is what is contractual, not this order.
CODE_TABLE: tuple[CodeEntry, ...] = (
    # -- J, the application API.
    CodeEntry("ARBITRARY_DICOM_OBJECT_REJECTED", ("J",),
              "J: a body carrying a property that would hand this surface a DICOM "
              "object. The refusal is a 400, not a block receipt — the contract's "
              "`ExecutionRequest` description names `dicom_object` and "
              "`pixel_data` as malformed requests — so the code lands on the audit "
              "record, where a non-raw disposition code belongs. Owned by J and "
              "emitted from medarx.api.surface."),
    CodeEntry("FREE_FORM_PROMPT_REJECTED", ("J",),
              "J: a body carrying a property that would hand this surface a "
              "free-form prompt. Same route as the DICOM-object code: a 400, "
              "recorded rather than returned. Owned by J and emitted from "
              "medarx.api.surface."),
    CodeEntry("FUNCTION_NOT_PERMITTED", ("J",),
              "J: the function is not permitted in the caller's scope. **Still "
              "unadvertised** — no published example carries this code, so the "
              "example-reachability sweep in test_contract_schemas.py cannot see "
              "it, and what enforces it now is "
              "`test_the_two_codes_no_example_advertises_are_component_js`. "
              "Emitted by medarx.api.surface on the record for a 403."),
    CodeEntry("UNAUTHORIZED_SCOPE", ("J",),
              "J: the study scope is not authorized, or no scope was presented at "
              "all. Unadvertised and tracked exactly as FUNCTION_NOT_PERMITTED "
              "is. Emitted by medarx.api.surface on the record for a 403."),

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
    CodeEntry("LEFTOVER_PATTERN_MATCH", ("D.2", "D.3"),
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
