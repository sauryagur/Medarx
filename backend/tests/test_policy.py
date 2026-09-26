"""Tests for the fail-closed policy engine (component E).

The property this file exists to defend, stated once: **every mode fails closed,
every time, without exception.** A block is any refusal to transmit, so
uncertainty here trends to block and never to send — an unknown or missing
policy version, a mode this engine does not implement, a missing payload, a
missing set of dispositions, and any unresolved disposition are all refusals,
and none of them has a fallback that sends anyway.

The tests are named for the design §6 row they exercise, so a failure says
which row's enforcement moved. Rows 1 (the request-shape gate `J`) and 7 (the
egress gateway `F`) are **not** exercised here and cannot be: neither component
exists, so there is nothing to feed this engine. The table records both rows so
the gap is visible in the data rather than only in this sentence, and
`test_this_component_enforces_row_6_and_observes_rows_3_to_5` names the
authority the engine actually has.

Every block reason the engine can produce is checked against the contract's
`ActionCode` enum, and several are checked by *building the receipt* the
decision implies and asserting its five fields. A block receipt is a durable,
returned-in-full record of why a request was refused; a receipt that names a
code the kernel did not emit is a false record, and three separate defects in
this project have been exactly that.
"""

from __future__ import annotations

import inspect

import pytest

from medarx.config import Settings
from medarx.errors import PolicyError
from medarx.models import LAYERS, BlockReceipt, StructuredPayload, payload_hash_of
from medarx.policy.decision_table import RULES, rules_for
from medarx.policy.policy_engine import (
    CHECKS,
    IMPLEMENTED_MODES,
    REASON_CODES,
    WIRE_CODE_BY_REASON,
    Decision,
    PolicyEngine,
    wire_code_for,
)
from medarx.redaction.layers import Disposition
from test_contract_schemas import _contract, _example_receipts

PV = "medarx-policy-1.0.0"

#: The codes the contract's own published block example advertises for each
#: design §6 row, keyed by row. One example per layer, and each `Rule` in
#: `RULES` takes the *leading* code of its row's example — the assertion that
#: ties the two together is
#: `test_each_rule_names_the_leading_code_the_contract_publishes_for_its_row`.
EXAMPLE_CODES_BY_ROW: dict[int, tuple[str, ...]] = {
    1: ("ARBITRARY_DICOM_OBJECT_REJECTED", "FREE_FORM_PROMPT_REJECTED"),
    2: ("FIELD_NOT_ALLOWLISTED", "UNKNOWN_FUNCTION"),
    3: ("DETERMINISTIC_REPLACEMENT_FAILED",),
    4: ("NER_UNRESOLVED",),
    5: ("UNSHIFTED_DATE", "LEFTOVER_PATTERN_MATCH"),
    6: ("UNRESOLVED_DISPOSITION", "UNKNOWN_POLICY_VERSION", "POLICY_CONFIG_ERROR"),
    7: ("PAYLOAD_MISMATCH", "UNKNOWN_MODEL"),
}


def disp(layer, code, resolved, entity=None, field="report_text"):
    """One factory for every Disposition in the suite, so a layer/code pair is
    written once. The brief this file implements defined it twice, and the
    second definition silently shadowed the first; it is not kept."""
    return Disposition(layer, field, entity, code, resolved)


def resolved_disp(layer="D.1", code="REDACT_LAYER1_REPLACED"):
    """A disposition recording work a layer completed."""
    return disp(layer, code, True)


def in_mode(settings: Settings, mode: str) -> Settings:
    """The deployment's settings with its policy mode fixed to `mode`.

    `model_copy` rather than a constructor argument, because
    `Settings.policy_mode` is typed `Literal["strict_local", "cloud"]` and would
    refuse to construct a settings object naming an unimplemented mode at all.
    That refusal is the right default for an operator who sets the variable,
    and it means an unimplemented mode can only be *simulated* — which is
    exactly what the fail-closed test for it needs to do.
    """
    return settings.model_copy(update={"policy_mode": mode})


#: A payload as it arrives: no hash, because nothing has hashed it yet.
_UNHASHED = StructuredPayload(
    function="draft", report_text="FINDINGS: 7mm nodule.",
    dicom_fields={"modality": "CT", "study_date": "20251215",
                  "patient_age_band": "040-049"},
    study_ref="medarx-study-ab12cd34", prior_study_refs=(),
    policy_version=PV, input_hash="h0", payload_hash=None,
)

#: The hash of that payload's content, which is what layer 3 writes and what
#: the engine compares against. It is the real content hash rather than a
#: literal like `"a" * 64`, because `authorize_payload` re-derives it: a
#: fixture whose hash field is a made-up string is not a payload any decision
#: could have approved, and using one would test a case that cannot occur.
CLEAN_HASH = payload_hash_of(_UNHASHED)

#: The same payload, hashed, as it is once layer 3 has written the hash.
PAYLOAD = _UNHASHED.model_copy(update={"payload_hash": CLEAN_HASH})


# -- The decision table is a transcription of design §6 ------------------------


def test_the_decision_table_transcribes_every_row_of_design_section_6():
    assert [r.row for r in RULES] == [1, 2, 3, 4, 5, 6, 7]
    assert [r.layer for r in RULES] == ["J", "A", "D.1", "D.2", "D.3", "E", "F"]
    assert all(r.layer in LAYERS for r in RULES), "a bare 'D' is not a layer"
    assert all(r.condition.strip() for r in RULES)
    # Rows 1 and 2 reject: nothing enters the pipeline, so there is no payload
    # to refuse to send. Rows 3 to 7 block: a payload exists and the refusal is
    # a refusal to transmit it, which is what §6 means by a block.
    assert [r.outcome for r in RULES] == ["reject", "reject", "block", "block",
                                          "block", "block", "block"]


def test_each_rule_names_the_leading_code_the_contract_publishes_for_its_row():
    # `Rule.action_code` is one code per row, and a row names several
    # conditions and therefore several codes. It is the row's *leading* code:
    # the first of the codes the contract's own block example advertises for
    # that row, which is a real code a block at that row can carry. This reads
    # the contract rather than restating it, so an example that moved and a
    # table that did not would fail here.
    published: dict[str, tuple[str, ...]] = {
        layer: codes for _where, layer, codes in _example_receipts(_contract())
    }
    assert set(published) == {r.layer for r in RULES}, (
        "the contract publishes a block example for a layer the table does not "
        "carry, or the table carries a layer the contract publishes none for"
    )
    for rule in RULES:
        assert published[rule.layer] == EXAMPLE_CODES_BY_ROW[rule.row]
        assert rule.action_code == published[rule.layer][0], (
            f"row {rule.row} ({rule.layer}) names {rule.action_code!r}, which is "
            f"not the leading code the contract publishes for that row"
        )


@pytest.mark.parametrize(
    ("prefix", "expected"),
    [
        ("D", ["D.1", "D.2", "D.3"]),
        ("D.1", ["D.1"]),
        ("D.2", ["D.2"]),
        ("D.3", ["D.3"]),
        ("E", ["E"]),
        ("F", ["F"]),
        ("J", ["J"]),
        ("A", ["A"]),
        ("C", []),
        ("", []),
    ],
)
def test_layer_rows_are_attributed_to_the_right_component(prefix, expected):
    # A prefix names a component and the sub-layers beneath it, because a
    # receipt that says only "D" cannot say which check refused the request. A
    # prefix no rule carries — `C` belongs to pseudonymization and no §6 row is
    # a pseudonymization block — is an empty answer, not a wrong one.
    assert [r.layer for r in rules_for(prefix)] == expected
    assert all(r.layer in LAYERS for r in rules_for(prefix))


def test_the_table_refuses_a_rule_tagged_with_a_layer_the_contract_has_no():
    from medarx.policy.decision_table import Rule

    with pytest.raises(ValueError):
        Rule(row=4, layer="D", condition="anything", action_code="NER_UNRESOLVED",
             outcome="block")


# -- The engine's checks, in the order it evaluates them ----------------------


def test_the_engine_checks_are_row_6_and_they_are_evaluated_in_a_stated_order():
    # The order is a property, not an implementation detail: a version this
    # engine cannot identify is reported before anything else, because a
    # deployment running the wrong policy is a different problem from a request
    # it refused, and the receipt has only one code to give.
    assert [c.name for c in CHECKS] == [
        "the policy version is not the one in force",
        "the policy mode is not implemented",
        "there is no payload",
        "there are no dispositions and nothing validated the payload",
        "a disposition is unresolved",
    ]
    assert {c.row for c in CHECKS} == {6}, "the engine enforces §6 row 6 only"


def test_this_component_enforces_row_6_and_observes_rows_3_to_5():
    # Rows 1 and 7 are in the table because §6 is the whole enforcement
    # surface, not because this component touches them. Stating the authority
    # explicitly keeps a future row from being added to `RULES` and then
    # assumed to be enforced.
    enforced = {c.row for c in CHECKS}
    observable = {r.row for r in RULES if r.layer.startswith("D.")}
    assert enforced == {6}
    assert observable == {3, 4, 5}
    assert {1, 7}.isdisjoint(enforced | observable), (
        "rows 1 (J) and 7 (F) are recorded as pending components, not as "
        "enforcement this component performs"
    )


# -- §6 row 6: the conditions that block in every implemented mode -------------


def test_every_unresolved_disposition_blocks_in_every_implemented_mode(settings):
    for mode in sorted(IMPLEMENTED_MODES):
        engine = PolicyEngine(in_mode(settings, mode))
        d = engine.decide(PAYLOAD, [disp("D.2", "NER_UNRESOLVED", False, entity="MRN")],
                          PV)
        assert d.blocked and not d.approved, f"{mode} approved an unresolved payload"
        assert d.reason_code == "NER_UNRESOLVED"


def test_a_clean_payload_is_approved_in_every_implemented_mode(settings):
    for mode in sorted(IMPLEMENTED_MODES):
        engine = PolicyEngine(in_mode(settings, mode))
        d = engine.decide(PAYLOAD, [resolved_disp()], PV)
        assert d.approved and not d.blocked, f"{mode} refused a clean payload"
        assert d.reason_code == "APPROVED"
        assert d.policy_version == PV


def test_a_validated_payload_with_no_dispositions_is_approved(settings):
    # Measured through the real pipeline, not assumed: a report with no
    # identifiers in it produces no dispositions at all, because layers 1-3
    # record what they did and there was nothing to do. An empty list from a
    # run that completed is the shape of a clean result, and blocking on it
    # would refuse every ordinary report while reporting a healthy deployment
    # as a configuration error.
    engine = PolicyEngine(settings)
    d = engine.decide(PAYLOAD, [], PV)
    assert d.approved and not d.blocked
    assert d.reason_code == "APPROVED"


def test_an_unvalidated_payload_with_no_dispositions_blocks(settings):
    # The condition that *is* fail-closed. No dispositions **and** no layer-3
    # hash means no layer ran: the dispositions that should exist were never
    # produced, and nothing else reaches this engine to tell it so.
    engine = PolicyEngine(settings)
    d = engine.decide(_UNHASHED, [], PV)
    assert d.blocked and not d.approved
    assert d.reason_code == "POLICY_NO_DISPOSITIONS"


def test_null_payload_fails_closed(settings):
    engine = PolicyEngine(settings)
    d = engine.decide(None, [resolved_disp()], PV)
    assert d.blocked and d.reason_code == "POLICY_NO_PAYLOAD"


def test_unknown_policy_version_fails_closed(settings):
    engine = PolicyEngine(settings)
    d = engine.decide(PAYLOAD, [resolved_disp()], "medarx-policy-9.9.9")
    assert d.blocked and d.reason_code == "POLICY_UNKNOWN_VERSION"


@pytest.mark.parametrize("missing", ["", "   "])
def test_a_missing_policy_version_fails_closed(settings, missing):
    # §6 row 6 says "unknown *or missing*" policy version. A blank configured
    # version is the case a bare `!=` comparison misses entirely: the version
    # presented and the version in force are both blank, they compare equal,
    # and the payload would be approved under a policy nobody can name.
    engine = PolicyEngine(settings.model_copy(update={"policy_version": missing}))
    d = engine.decide(PAYLOAD, [resolved_disp()], missing)
    assert d.blocked and d.reason_code == "POLICY_UNKNOWN_VERSION"


def test_unimplemented_mode_fails_closed(settings):
    engine = PolicyEngine(in_mode(settings, "authorized_local"))
    d = engine.decide(PAYLOAD, [resolved_disp()], PV)
    assert d.blocked and d.reason_code == "POLICY_UNIMPLEMENTED_MODE"


def test_an_unimplemented_mode_does_not_fall_back_to_a_weaker_one(settings):
    # The worst thing this component could do. The same payload, the same
    # dispositions and the same policy version are approved in each implemented
    # mode and refused in the unimplemented one, so there is no path by which
    # selecting `authorized_local` degrades into `cloud` or `strict_local`.
    payload, dispositions, version = PAYLOAD, [resolved_disp()], PV
    outcomes = {
        mode: PolicyEngine(in_mode(settings, mode)).decide(
            payload, dispositions, version
        ).blocked
        for mode in ("strict_local", "cloud", "authorized_local")
    }
    assert outcomes == {"strict_local": False, "cloud": False,
                        "authorized_local": True}


def test_only_the_two_documented_modes_are_implemented():
    assert IMPLEMENTED_MODES == frozenset({"strict_local", "cloud"})
    # The contract publishes `authorized_local` as an architectural extension
    # that must not be selected by a request, so it is in the contract's
    # `PolicyMode` enum and is deliberately absent here.
    contract_modes = set(
        _contract()["components"]["schemas"]["PolicyMode"]["enum"]
    )
    assert IMPLEMENTED_MODES < contract_modes
    assert contract_modes - IMPLEMENTED_MODES == {"authorized_local"}


def test_a_request_cannot_select_or_escalate_its_own_mode(settings):
    # The mode is a deployment configuration. The contract says so explicitly
    # ("a request cannot choose its mode"), and the only way this engine could
    # be made to honour one is a parameter on `decide`; there is none.
    parameters = inspect.signature(PolicyEngine.decide).parameters
    assert list(parameters) == ["self", "payload", "dispositions", "policy_version"]
    assert "policy_mode" not in parameters and "mode" not in parameters
    assert PolicyEngine(in_mode(settings, "cloud")).mode == "cloud"
    assert PolicyEngine(in_mode(settings, "strict_local")).mode == "strict_local"


# -- A decision is always exactly one of approve or block ----------------------


def test_a_decision_cannot_be_approve_and_block_at_once():
    with pytest.raises(ValueError):
        Decision(approved=True, blocked=True, reason_code="APPROVED",
                 policy_version=PV)
    with pytest.raises(ValueError):
        Decision(approved=False, blocked=False, reason_code="X", policy_version=PV)


def test_every_engine_outcome_is_either_approved_or_blocked(settings):
    # Enumerated rather than reasoned about: each of these is a real input, and
    # a branch that returned neither would leave the caller to decide whether
    # an undecided payload may be sent.
    cases = [
        (PAYLOAD, [resolved_disp()], PV),
        (None, [resolved_disp()], PV),
        (PAYLOAD, [], PV),
        (PAYLOAD, [disp("D.2", "NER_UNRESOLVED", False)], PV),
        (PAYLOAD, [resolved_disp()], "medarx-policy-9.9.9"),
    ]
    for mode in sorted(IMPLEMENTED_MODES):
        engine = PolicyEngine(in_mode(settings, mode))
        for payload, dispositions, version in cases:
            d = engine.decide(payload, dispositions, version)
            assert d.blocked != d.approved
            assert d.reason_code


# -- §6 rows 3, 4 and 5 reach the engine as dispositions ----------------------


@pytest.mark.parametrize(
    ("row", "layer", "code"),
    [
        (3, "D.1", "DETERMINISTIC_REPLACEMENT_FAILED"),
        (4, "D.2", "NER_UNRESOLVED"),
        (5, "D.3", "CONTRACT_VIOLATION"),
    ],
)
def test_an_unresolved_disposition_from_each_redaction_layer_blocks(settings, row,
                                                                   layer, code):
    # Rows 3, 4 and 5 are enforced by the layers that raise them and reach
    # this engine as dispositions. The engine's part is to refuse the payload
    # and to keep the layer's own code: the receipt names the check a reader
    # has to look at, and a code invented here would name a check that did not
    # fire.
    engine = PolicyEngine(settings)
    d = engine.decide(PAYLOAD, [disp(layer, code, False)], PV)
    assert d.blocked and not d.approved, f"§6 row {row} did not block"
    assert d.reason_code == code
    assert rules_for(layer)[0].row == row


def test_a_block_from_a_disposition_is_not_relabelled_as_the_engines_own(settings):
    # The engine has no wire code for a disposition's block, and that absence
    # is deliberate: the receipt for an unresolved disposition is built by the
    # layer that raised it, under that layer's tag. An engine-level code for
    # the same condition would give one refusal two different receipts
    # depending on which component the caller asked.
    engine = PolicyEngine(settings)
    d = engine.decide(PAYLOAD, [disp("D.2", "NER_UNRESOLVED", False)], PV)
    assert d.reason_code not in WIRE_CODE_BY_REASON
    with pytest.raises(ValueError):
        wire_code_for(d.reason_code)


# -- Only the approved payload may leave --------------------------------------


def test_the_approved_payload_is_authorised(settings):
    engine = PolicyEngine(settings)
    assert engine.authorize_payload(PAYLOAD, CLEAN_HASH) is None


def test_only_the_approved_hash_may_leave(settings):
    engine = PolicyEngine(settings)
    tampered = PAYLOAD.model_copy(update={"report_text": "FINDINGS: 8mm nodule."})
    with pytest.raises(PolicyError) as ei:
        engine.authorize_payload(tampered, CLEAN_HASH)
    assert ei.value.action_codes == ("UNAPPROVED_PAYLOAD",)
    assert ei.value.layer == "E"


def test_a_payload_that_claims_the_approved_hash_but_is_not_it_is_refused(settings):
    # The substitution a field comparison cannot see. `model_copy` replaces one
    # field and leaves `payload_hash` exactly as the decision approved it, so a
    # check that compared the field alone would authorise this payload and the
    # altered text would leave the environment. Both the claim and the content
    # are compared, so this is refused.
    engine = PolicyEngine(settings)
    assert PAYLOAD.payload_hash == CLEAN_HASH, "the claim here is meant to match"
    tampered = PAYLOAD.model_copy(update={"report_text": "MRN 4452819."})
    with pytest.raises(PolicyError) as ei:
        engine.authorize_payload(tampered, CLEAN_HASH)
    assert ei.value.action_codes == ("UNAPPROVED_PAYLOAD",)


def test_a_payload_that_never_was_hashed_is_refused(settings):
    # Layer 3 writes the hash; an object nothing has hashed is not an object E
    # could have approved, so an absent hash is a refusal rather than a pass.
    engine = PolicyEngine(settings)
    for unhashable in (_UNHASHED, _UNHASHED.model_copy(update={"payload_hash": None})):
        with pytest.raises(PolicyError) as ei:
            engine.authorize_payload(unhashable, CLEAN_HASH)
        assert ei.value.action_codes == ("UNAPPROVED_PAYLOAD",)


@pytest.mark.parametrize("approved_hash", ["", "b" * 64, None])
def test_an_unusable_approved_hash_authorises_nothing(settings, approved_hash):
    engine = PolicyEngine(settings)
    with pytest.raises(PolicyError) as ei:
        engine.authorize_payload(PAYLOAD, approved_hash)
    assert ei.value.action_codes == ("UNAPPROVED_PAYLOAD",)


# -- A block receipt is truthful -----------------------------------------------


def _receipt_from(decision=None, error=None, request_id="req-1") -> BlockReceipt:
    """The receipt the API surface builds for this decision, built the way
    component J will build it: the engine's own verdict becomes a layer-E
    receipt carrying the wire code the reason maps to, and a `PolicyError` the
    engine raised is already the receipt's content."""
    if error is not None:
        return BlockReceipt(request_id=request_id, layer=error.layer,
                            action_codes=list(error.action_codes),
                            policy_version=PV)
    return BlockReceipt(request_id=request_id, layer="E",
                        action_codes=[wire_code_for(decision.reason_code)],
                        policy_version=decision.policy_version)


def test_the_receipt_an_unimplemented_mode_produces_names_layer_e_and_its_code(settings):
    engine = PolicyEngine(in_mode(settings, "authorized_local"))
    decision = engine.decide(PAYLOAD, [resolved_disp()], PV)
    assert decision.blocked
    assert _receipt_from(decision).model_dump() == {
        "status": "blocked",
        "request_id": "req-1",
        "layer": "E",
        "action_codes": ["UNKNOWN_POLICY_VERSION"],
        "policy_version": PV,
    }


def test_the_receipt_an_unknown_version_produces_names_layer_e_and_its_code(settings):
    engine = PolicyEngine(settings)
    decision = engine.decide(PAYLOAD, [resolved_disp()], "medarx-policy-9.9.9")
    assert decision.blocked
    # The receipt names the version that was presented, not the one in force:
    # the kernel did not apply the configured policy, so claiming it did would
    # be the false record this project has been bitten by before.
    assert _receipt_from(decision).model_dump() == {
        "status": "blocked",
        "request_id": "req-1",
        "layer": "E",
        "action_codes": ["UNKNOWN_POLICY_VERSION"],
        "policy_version": "medarx-policy-9.9.9",
    }


def test_the_receipt_for_a_missing_payload_is_a_configuration_error(settings):
    # A missing payload, and a payload with no dispositions and no layer-3
    # validation, are the engine's own verdict about the request, and neither
    # is a claim about the data: both are `POLICY_CONFIG_ERROR`, the code the
    # contract's row-6 example advertises for them.
    engine = PolicyEngine(settings)
    no_payload = engine.decide(None, [resolved_disp()], PV)
    unvalidated = engine.decide(_UNHASHED, [], PV)
    for decision in (no_payload, unvalidated):
        assert _receipt_from(decision).model_dump() == {
            "status": "blocked",
            "request_id": "req-1",
            "layer": "E",
            "action_codes": ["POLICY_CONFIG_ERROR"],
            "policy_version": PV,
        }


def test_the_receipt_for_a_tampered_payload_names_unapproved_payload(settings):
    engine = PolicyEngine(settings)
    tampered = PAYLOAD.model_copy(update={"report_text": "FINDINGS: 8mm nodule."})
    with pytest.raises(PolicyError) as caught:
        engine.authorize_payload(tampered, CLEAN_HASH)
    assert _receipt_from(error=caught.value).model_dump() == {
        "status": "blocked",
        "request_id": "req-1",
        "layer": "E",
        "action_codes": ["UNAPPROVED_PAYLOAD"],
        "policy_version": PV,
    }


def test_every_reason_the_module_names_has_exactly_one_wire_code():
    # Total over this module's own vocabulary, in both directions: a reason it
    # invents with no wire code would be a block whose receipt could not be
    # built, and a wire code for a reason it cannot produce would be a code
    # advertising a block the kernel cannot make. The approved decision's
    # reason is deliberately not one of them — an approval has no receipt.
    assert set(WIRE_CODE_BY_REASON) == set(REASON_CODES)
    assert "APPROVED" not in REASON_CODES


@pytest.mark.parametrize("reason", sorted(WIRE_CODE_BY_REASON))
def test_every_reason_the_engine_invents_maps_to_a_contract_action_code(reason):
    contract_codes = set(_contract()["components"]["schemas"]["ActionCode"]["enum"])
    code = wire_code_for(reason)
    assert code in contract_codes, f"{reason} maps to {code!r}, which is not an ActionCode"
    # A code is only safe to return if a receipt will accept it, and the
    # receipt's own shape check is what guarantees a code carries no value.
    assert BlockReceipt(request_id="req-1", layer="E", action_codes=[code],
                        policy_version=PV).action_codes == [code]


def test_the_reason_the_authorization_refusal_raises_agrees_with_its_code():
    # The `PolicyError` and the mapping are two routes to the same code. If they
    # drifted, a receipt built from the error would name a different code from
    # one built from the decision's reason, for the same refusal.
    assert wire_code_for("POLICY_UNAPPROVED_PAYLOAD") == "UNAPPROVED_PAYLOAD"


def test_an_unmapped_reason_is_refused_rather_than_guessed():
    for reason in ("", "APPROVED", "SOMETHING_ELSE"):
        with pytest.raises(ValueError):
            wire_code_for(reason)


def test_two_different_engine_blocks_do_not_serialise_to_the_same_receipt(settings):
    # The defect this prevents: a receipt that cannot distinguish two refusal
    # reasons is a false record. An unknown version and a missing payload are
    # different problems with different fixes, so they must not serialise
    # alike — nor may either serialise identically to the layer-2 block, which
    # is a different layer's verdict entirely.
    engine = PolicyEngine(settings)
    unknown_version = engine.decide(PAYLOAD, [resolved_disp()], "medarx-policy-9.9.9")
    no_payload = engine.decide(None, [resolved_disp()], PV)
    receipts = {
        _receipt_from(unknown_version).model_dump_json(),
        _receipt_from(no_payload).model_dump_json(),
        BlockReceipt(request_id="req-1", layer="D.2", action_codes=["NER_UNRESOLVED"],
                     policy_version=PV).model_dump_json(),
    }
    assert len(receipts) == 3, "two refusals produced byte-identical receipts"


# -- The engine the pipeline is actually handed --------------------------------


def _source(report_text: str) -> StructuredPayload:
    """A payload as component A hands it over, before pseudonymization."""
    return StructuredPayload(
        function="draft", report_text=report_text,
        dicom_fields={"modality": "CT", "study_date": "20260114",
                      "patient_age_band": "040-049"},
        study_ref="STU-0001", prior_study_refs=(),
        policy_version=PV, input_hash="h0", payload_hash=None,
    )


#: Clean prose, and prose carrying a ticket number nothing can replace. The
#: second is measured, not chosen: `AMBIGUOUS_REFERENCE` is detected at 0.30
#: and has no registered replacer, so it is unresolved whatever the threshold
#: is.
CLEAN_REPORT = "FINDINGS: 7mm nodule."
UNMAPPED_REPORT = "FINDINGS: 7mm nodule. Ticket ZX-99-ALPHA issued at the counter."


def test_the_pipeline_runs_on_this_engine_and_on_nothing_stand_in_for_it(store,
                                                                        settings):
    # The orchestrator is handed an engine and calls `decide` on it positionally.
    # A test double with the same method name would keep passing while the real
    # signature drifted, so the engine under test here is this one, driving the
    # real layers, in both directions.
    from medarx.errors import RedactionError
    from medarx.pseudonym.pseudonymize import pseudonymize_payload
    from medarx.redaction.pipeline import run_privacy_kernel

    engine = PolicyEngine(settings)

    clean = _source(CLEAN_REPORT)
    approved = run_privacy_kernel(pseudonymize_payload(clean, "PAT-0001", store),
                                  "PAT-0001", store, engine, settings, source=clean)
    # Layer 3 wrote the hash the decision approved, and re-deriving it here
    # succeeds: the content check refuses a substituted payload, not a real one.
    assert approved.payload_hash == payload_hash_of(approved)
    assert engine.authorize_payload(approved, approved.payload_hash) is None

    dirty = _source(UNMAPPED_REPORT)
    with pytest.raises(RedactionError) as caught:
        run_privacy_kernel(pseudonymize_payload(dirty, "PAT-0001", store), "PAT-0001",
                           store, engine, settings, source=dirty)
    assert caught.value.layer == "D.2"
    # Both layers speak, as they do in every run of this report: layer 2 could
    # not resolve the reference and layer 3 then found the deterministic
    # pattern still sitting in the text. The receipt names the first, because
    # that is the layer a reader has to look at.
    assert caught.value.action_codes == ("NER_UNRESOLVED", "LEFTOVER_PATTERN_MATCH")


def test_an_unimplemented_mode_blocks_a_pipeline_run_that_is_otherwise_clean(
        store, settings):
    # The same clean report, the same layers, and a deployment configured with
    # a mode this engine does not implement. There is no fallback, so the run
    # blocks instead of being approved by a weaker mode standing in for the one
    # that was asked for.
    #
    # The layer and code this receipt ends up carrying are deliberately not
    # asserted. They are the orchestrator's own fallback for a block with no
    # unresolved disposition — layer `D.3` and `UNAPPROVED_PAYLOAD` — and
    # neither is what happened when the policy engine is what refused. That is
    # a composition defect in `run_privacy_kernel`, reported to the project
    # owner rather than pinned here: an assertion here would turn it into an
    # invariant, and an invariant that preserves a defect is itself a defect.
    from medarx.errors import RedactionError
    from medarx.pseudonym.pseudonymize import pseudonymize_payload
    from medarx.redaction.pipeline import run_privacy_kernel

    engine = PolicyEngine(in_mode(settings, "authorized_local"))
    clean = _source(CLEAN_REPORT)
    with pytest.raises(RedactionError) as caught:
        run_privacy_kernel(pseudonymize_payload(clean, "PAT-0001", store), "PAT-0001",
                           store, engine, settings, source=clean)
    assert caught.value.action_codes, "a block with no codes could not be rendered"

    # The identical run in an implemented mode approves, so the refusal above
    # was the mode and nothing else.
    engine_in_cloud = PolicyEngine(in_mode(settings, "cloud"))
    approved = run_privacy_kernel(pseudonymize_payload(clean, "PAT-0001", store),
                                  "PAT-0001", store, engine_in_cloud, settings,
                                  source=clean)
    assert approved.payload_hash == payload_hash_of(approved)
