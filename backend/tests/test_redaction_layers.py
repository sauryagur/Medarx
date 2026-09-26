"""Tests for the three redaction layers and the kernel orchestrator.

The claim this file exists to defend, stated once so each test below can be
read as evidence for it: **a block comes from the absence of a safe
replacement, not from a score.** The load-bearing test varies a detection's
score across the whole range and watches the verdict refuse to move, because
the condition is "detected, and nothing can replace it" — a property of the
entity, not of a number a future setting could cross.

One block here *is* threshold-dependent, and it is a different condition: a
detection that has a replacer but scores below the threshold is not replaced,
because applying a replacement on a detection the engine is unsure about is
redaction by guessing. It carries the same `NER_UNRESOLVED` code as the
score-independent block — they are told apart by the entity named in the
disposition, not by the code — so those tests are marked as such where they
appear.

The scores and spans quoted in the comments are what the engine actually
returns on this machine. They were measured, not intended, and several of them
are the reason a mechanism is shaped the way it is — notably that
`'774123'` comes back as `DATE_TIME` at 0.85, and that `'6 weeks'` does too.

Nothing here shadows the shared `settings` and `store` fixtures in
`conftest.py`, and no test builds an `AnalyzerEngine`: `scan_entities` shares
one lazily through an `lru_cache`, so the multi-second spaCy load is paid once
per process rather than per test.
"""

from __future__ import annotations

import types
from datetime import date
from pathlib import Path

import pytest
import yaml

from medarx.config import Settings
from medarx.errors import RedactionError
from medarx.extraction.allowlists import ALLOWED_FIELDS
from medarx.extraction.payload_extractor import pipeline_for
from medarx.extraction.study_context import StudyContext
from medarx.models import LAYERS, StructuredPayload, canonical_hash
from medarx.pseudonym.pseudonymize import pseudonymize_payload
from medarx.redaction import ner
from medarx.redaction.layers import (
    Disposition,
    RedactionContext,
    layer1_deterministic,
    layer2_ner,
    layer3_validation,
)
from medarx.redaction.ner import EntityHit
from medarx.redaction.pipeline import RedactionOutcome, run_privacy_kernel, run_redaction

CONTRACT = Path(__file__).resolve().parents[2] / "contracts" / "openapi.yaml"

#: The policy engine arrives in a later task, so this one answers the only two
#: questions `run_redaction` asks of an engine — is any disposition unresolved,
#: and is there a payload at all. Defining it here rather than importing one is
#: what lets these layers be verified on their own.
class StubPolicyEngine:
    def __init__(self, settings: Settings):
        self.mode = settings.policy_mode
        self.settings = settings

    def decide(self, payload, dispositions, policy_version):
        blocked = [d for d in dispositions if not d.resolved]
        return types.SimpleNamespace(
            approved=payload is not None and not blocked,
            blocked=bool(blocked),
            reason_code=blocked[0].action_code if blocked else "APPROVED",
            policy_version=policy_version,
        )


@pytest.fixture
def engine(settings):
    return StubPolicyEngine(settings)


# Measured on this machine: every one of these is returned with no hits at all
# at `min_score=0.0`, so they are the kernel's blind spot as much as its
# evidence. A recognizer that ate any of them would corrupt clinical text while
# every leak assertion still passed.
CLINICAL_SNIPPETS = (
    "May be a small effusion.",
    "Aorta 3.2 cm, heart rate 72 bpm.",
    "Dose 2.5 mg.",
    "FINDINGS: 7mm nodule.",
    ("FINDINGS: 7mm nodule in the right lower lobe. Comparison with the prior "
     "study shows slight interval growth."),
)

CLEAN = CLINICAL_SNIPPETS[-1]
DIRTY = "FINDINGS: 7mm nodule. MRN: 4452819. Accession: ACC0000417. DOB: 1953-04-11."
UNMAPPED = "FINDINGS: 7mm nodule. Ticket ZX-99-ALPHA issued at the counter."
ONLY_PHI = "MRN: 4452819. Accession: ACC0000417. DOB: 1953-04-11. Patient ID: 774123."
TWO_DATES = "FINDINGS: 7mm nodule on 2026-01-14, unchanged from 2025-12-01."

#: DICOM attributes in keyword form, and a DICOM `DA` date. Layer A maps
#: keywords to the payload's snake_case field names and component C shifts a
#: `YYYYMMDD` value; the contract currently declares snake_case request
#: properties and `format: date`, which the running code does not accept. The
#: fixtures follow the code, and the contract is being corrected separately.
DICOM_METADATA = {
    "Modality": "CT",
    "StudyDate": "20260114",
    "PatientAge": "045Y",
    "PatientID": "PAT-0001",
    "AccessionNumber": "ACC0000417",
}
PATIENT = "PAT-0001"
PV = "medarx-policy-1.0.0"


def source_for(text: str, function: str = "draft") -> StructuredPayload:
    """The payload as it arrives from component A, before pseudonymization."""
    return StructuredPayload(
        function=function,
        report_text=text,
        dicom_fields={"modality": "CT", "study_date": "20260114",
                      "patient_age_band": "040-049"},
        study_ref="STU-0001",
        prior_study_refs=(),
        policy_version=PV,
        input_hash="h0",
        payload_hash=None,
    )


def context_for(source, store, settings, patient_ref: str = PATIENT) -> RedactionContext:
    return RedactionContext.for_patient(source, patient_ref, store, settings)


def pseudonymized(text: str, store, settings, function: str = "draft"):
    """A payload that has been through component C, and the context for it."""
    source = source_for(text, function)
    return pseudonymize_payload(source, PATIENT, store), context_for(source, store, settings)


def _action_codes() -> set[str]:
    schema = yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))
    return set(schema["components"]["schemas"]["ActionCode"]["enum"])


def _unresolved(dispositions) -> list[Disposition]:
    return [d for d in dispositions if not d.resolved]


# -- The context object ------------------------------------------------------


def test_a_context_carries_the_stores_own_offset_not_a_guess(store, settings):
    # The brief's fixture passed a hard-coded -30. The real offset for this
    # patient under this key is 237, and a hard-coded one would have made every
    # shifted date in these tests wrong by an unnoticed amount.
    ctx = context_for(source_for(CLEAN), store, settings)
    assert ctx.replacers.offset == store.offset_for_patient(PATIENT)
    assert ctx.replacers.patient_surrogate == store.surrogate_for_patient(PATIENT)


# -- Layer 1: deterministic structured identifiers ---------------------------


def test_layer1_mints_a_surrogate_for_a_reference_that_arrived_raw(store, settings):
    # Everything else about the payload is already correct, so the reference is
    # the only thing this layer has to do.
    payload, ctx = pseudonymized(CLEAN, store, settings)
    raw = payload.model_copy(update={"study_ref": "STU-0002"})
    out, dispositions = layer1_deterministic(raw, ctx)
    assert out.study_ref == store.surrogate_for_study("STU-0002")
    assert [d.action_code for d in dispositions] == ["REDACT_LAYER1_REPLACED"]
    assert dispositions[0].resolved and dispositions[0].layer == "D.1"


def test_layer1_reshifts_a_date_component_c_left_alone(store, settings):
    # The gap layer 1 exists to close: a date that still equals its pre-shift
    # value was never moved, and a payload whose dates do not match the patient's
    # shift joins against the source system.
    payload, ctx = pseudonymized(CLEAN, store, settings)
    unshifted = payload.model_copy(update={
        "dicom_fields": {**payload.dicom_fields, "study_date": "20260114"},
    })
    out, dispositions = layer1_deterministic(unshifted, ctx)
    expected = date(2026, 1, 14).toordinal() + ctx.replacers.offset
    assert out.dicom_fields["study_date"] == date.fromordinal(expected).strftime("%Y%m%d")
    assert out.dicom_fields["study_date"] != "20260114"
    assert [d.field for d in dispositions] == ["study_date"]
    assert [d.action_code for d in dispositions] == ["REDACT_LAYER1_REPLACED"]


def test_layer1_leaves_an_already_surrogated_payload_completely_alone(store, settings):
    payload, ctx = pseudonymized(CLEAN, store, settings)
    out, dispositions = layer1_deterministic(payload, ctx)
    assert dispositions == []
    assert out == payload


def test_layer1_refuses_a_blank_reference_rather_than_inventing_one(store, settings):
    payload, ctx = pseudonymized(CLEAN, store, settings)
    blank = payload.model_copy(update={"study_ref": "  "})
    out, dispositions = layer1_deterministic(blank, ctx)
    assert out.study_ref == "  ", "a blank reference must not be replaced by a minted one"
    unresolved = _unresolved(dispositions)
    assert [d.action_code for d in unresolved] == ["MISSING_SURROGATE"]
    assert unresolved[0].field == "study_ref"


def test_layer1_refuses_a_date_it_cannot_shift(store, settings):
    # A structured field that cannot be deterministically replaced is layer 1's
    # block condition, and a different condition from "no surrogate for a
    # reference": the value is there, and no transform of it is safe. Component C
    # would have refused this payload with `UNSHIFTED_DATE`, so reaching layer 1
    # with one means C was bypassed — which is exactly the case this check is
    # for, and the reason it exists separately from C's.
    source = source_for(CLEAN).model_copy(update={
        "dicom_fields": {"modality": "CT", "study_date": "14 Jan",
                         "patient_age_band": "040-049"},
    })
    ctx = context_for(source, store, settings)
    payload = source.model_copy(update={"study_ref": store.surrogate_for_study("STU-0001")})
    out, dispositions = layer1_deterministic(payload, ctx)
    assert out.dicom_fields["study_date"] == "14 Jan", "an unshiftable date must not be rewritten"
    assert [d.action_code for d in _unresolved(dispositions)] == [
        "DETERMINISTIC_REPLACEMENT_FAILED"
    ]


def test_layer1_covers_every_prior_study_reference_not_only_the_first(store, settings):
    payload, ctx = pseudonymized(CLEAN, store, settings, function="prior_summary")
    raw = payload.model_copy(update={"prior_study_refs": ("STU-0002", "STU-0003")})
    out, dispositions = layer1_deterministic(raw, ctx)
    assert out.prior_study_refs == (store.surrogate_for_study("STU-0002"),
                                    store.surrogate_for_study("STU-0003"))
    assert sorted(d.field for d in dispositions) == ["prior_study_refs[0]",
                                                      "prior_study_refs[1]"]


def test_layer2_redacts_the_identifiers_it_finds_and_shifts_the_date(store, settings):
    payload, ctx = pseudonymized(DIRTY, store, settings)
    out, dispositions = layer2_ner(payload, ctx)
    assert "4452819" not in out.report_text
    assert "ACC0000417" not in out.report_text
    assert "1953-04-11" not in out.report_text
    assert dispositions and all(d.resolved for d in dispositions)
    assert {d.entity for d in dispositions} == {"MRN", "ACCESSION_NUMBER", "DATE_TIME"}
    # The date is moved, not masked: the surrounding clinical sentence is
    # intact and what stands where the date stood is still a date.
    shifted = date(1953, 4, 11).toordinal() + ctx.replacers.offset
    assert out.report_text.endswith(
        f"DOB: {date.fromordinal(shifted).strftime('%Y-%m-%d')}."
    )


def test_layer2_keeps_the_interval_between_two_dates_in_one_report(store, settings):
    payload, ctx = pseudonymized(TWO_DATES, store, settings)
    out, _ = layer2_ner(payload, ctx)
    before = payload.report_text
    written = [part for part in out.report_text.split() if part[:2] == "20" and "-" in part]
    original = [part.strip(",.") for part in before.split() if part[:2] == "20" and "-" in part]
    assert len(written) == 2 and written[0] != written[1]
    gap = (date.fromisoformat(written[0].strip(",."))
           - date.fromisoformat(written[1].strip(",."))).days
    assert gap == (date.fromisoformat(original[0]) - date.fromisoformat(original[1])).days == 44


def test_layer2_does_not_mutate_the_payload_it_was_given(store, settings):
    payload, ctx = pseudonymized(DIRTY, store, settings)
    before = payload.model_dump()
    layer2_ner(payload, ctx)
    assert payload.model_dump() == before


def test_an_entity_with_no_replacer_is_unresolved_at_any_score(store, settings, monkeypatch):
    # The project's central claim. The score is varied over the whole range and
    # the verdict does not move, because the condition is "detected, and
    # nothing can replace it" — a property of the entity, not of a threshold
    # some future setting could move.
    from medarx.redaction import layers

    payload, ctx = pseudonymized(CLEAN, store, settings)
    for score in (0.01, 0.30, 0.50, 0.85, 0.99):
        monkeypatch.setattr(
            layers, "scan_entities",
            lambda text, min_score, score=score: [
                EntityHit("AMBIGUOUS_REFERENCE", 0, 13, score, "ZX-99-ALPHA")
            ],
        )
        out, dispositions = layer2_ner(payload, ctx)
        assert [d.action_code for d in _unresolved(dispositions)] == ["NER_UNRESOLVED"]
        assert out.report_text == CLEAN, "an unresolved span must not be rewritten"


def test_a_replaceable_hit_below_the_threshold_is_blocked_not_guessed_at(store, settings,
                                                                      monkeypatch):
    # A different failure with a different remedy: here a replacement *exists*,
    # and applying it to a detection the engine is not sure about would corrupt
    # the text on the strength of a guess. "6 weeks" and the bare patient id
    # "774123" are both returned as `DATE_TIME` at 0.85 on this machine, so
    # this is not hypothetical.
    from medarx.redaction import layers

    payload, ctx = pseudonymized("FINDINGS: 7mm nodule.", store, settings)
    monkeypatch.setattr(
        layers, "scan_entities",
        lambda text, min_score: [EntityHit("MRN", 0, 9, 0.01, "FINDINGS:")],
    )
    out, dispositions = layer2_ner(payload, ctx)
    assert [d.action_code for d in _unresolved(dispositions)] == ["NER_UNRESOLVED"]
    assert out.report_text == "FINDINGS: 7mm nodule."


def test_a_date_the_replacer_cannot_shift_is_reported_as_unshifted(store, settings):
    # `'774123'` is returned as `DATE_TIME` at 0.85 by the engine, so the path
    # is reached by a real scan rather than only by a stub.
    payload, ctx = pseudonymized(ONLY_PHI, store, settings)
    _, dispositions = layer2_ner(payload, ctx)
    assert "UNSHIFTED_DATE" in {d.action_code for d in _unresolved(dispositions)}


def test_a_span_reported_under_two_entities_is_replaced_at_most_once(store, settings,
                                                                   monkeypatch):
    # Measured: spaCy reports 'ZX-99-ALPHA' as `ORGANIZATION` at 0.85 on
    # exactly the span `AMBIGUOUS_REFERENCE` claims at 0.30. Both are preserved
    # by `scan_entities`. Here at most one replacement is applied, and the
    # other label is reported rather than dropped -- a hit that is quietly
    # discarded is a block condition that never reaches the receipt.
    from medarx.redaction import layers

    payload, ctx = pseudonymized(UNMAPPED, store, settings)
    monkeypatch.setattr(
        layers, "scan_entities",
        lambda text, min_score: [
            EntityHit("ORGANIZATION", 29, 40, 0.85, "ZX-99-ALPHA"),
            EntityHit("AMBIGUOUS_REFERENCE", 29, 40, 0.30, "ZX-99-ALPHA"),
        ],
    )
    out, dispositions = layer2_ner(payload, ctx)
    assert out.report_text == UNMAPPED, "an unresolvable span must be left as it is"
    assert [d.entity for d in dispositions] == ["ORGANIZATION", "AMBIGUOUS_REFERENCE"]
    assert all(not d.resolved for d in dispositions)


def test_two_labels_on_one_span_that_both_resolve_replace_once_and_report_both(
        store, settings, monkeypatch):
    from medarx.redaction import layers

    payload, ctx = pseudonymized(UNMAPPED, store, settings)
    monkeypatch.setattr(
        layers, "scan_entities",
        lambda text, min_score: [
            EntityHit("MRN", 0, 7, 0.85, "FINDING"),
            EntityHit("PERSON", 0, 7, 0.85, "FINDING"),
        ],
    )
    out, dispositions = layer2_ner(payload, ctx)
    assert out.report_text == "[REDACTED:MRN]" + UNMAPPED[7:]
    assert [d.resolved for d in dispositions] == [True, False]
    assert dispositions[1].entity == "PERSON", "the label that lost must still be reported"


def test_a_report_of_nothing_but_identifiers_is_an_unresolved_empty_body(store, settings):
    # An empty result is not a clean result. Four identifier fields and no
    # clinical text: redacting it leaves no clinical content at all, and a
    # payload like that must block rather than be approved as "nothing found".
    payload, ctx = pseudonymized(ONLY_PHI, store, settings)
    _, dispositions = layer2_ner(payload, ctx)
    assert "UNRESOLVED_EMPTY_BODY" in {d.action_code for d in _unresolved(dispositions)}


def test_a_report_with_clinical_text_is_not_an_empty_body(store, settings):
    payload, ctx = pseudonymized(DIRTY, store, settings)
    _, dispositions = layer2_ner(payload, ctx)
    assert "UNRESOLVED_EMPTY_BODY" not in {d.action_code for d in dispositions}


@pytest.mark.parametrize("empty", ["", "   ", "\n\t "])
def test_an_empty_report_is_a_real_input_and_not_an_empty_body(empty, store, settings):
    payload, ctx = pseudonymized(empty, store, settings)
    out, dispositions = layer2_ner(payload, ctx)
    assert out.report_text == empty
    assert dispositions == []


def test_a_report_the_scan_could_not_cover_is_unresolved(store, settings, monkeypatch):
    # A scan that silently dropped a fifth of a report is indistinguishable
    # from a clean one, which is the failure this kernel exists to make
    # impossible. The flag hit has no replacer, so it blocks.
    monkeypatch.setattr(ner, "_settings", lambda: Settings(audit_key="k", ner_text_limit=10))
    payload, ctx = pseudonymized(CLEAN, store, settings)
    _, dispositions = layer2_ner(payload, ctx)
    unresolved = _unresolved(dispositions)
    assert [d.entity for d in unresolved] == ["TRUNCATED_TEXT"]
    assert unresolved[0].action_code == "NER_UNRESOLVED"


def test_layer2_also_scans_the_prior_report_text_field(store, settings):
    source = source_for(CLEAN, function="prior_summary")
    source = source.model_copy(update={"dicom_fields": {**source.dicom_fields,
                                                         "prior_report_text": "Prior MRN: 4452819."}})
    ctx = context_for(source, store, settings)
    out, dispositions = layer2_ner(source, ctx)
    assert "4452819" not in out.dicom_fields["prior_report_text"]
    assert [d.field for d in dispositions] == ["dicom_fields.prior_report_text"]


def test_layer2_does_not_scan_structured_metadata_as_if_it_were_prose(store, settings):
    # Measured: scanning the allowlisted metadata as free text finds
    # `ORGANIZATION` at 0.85 in "CT" and `PHONE_NUMBER` at 0.4 in the age band
    # "040-049", so a layer that scanned them would replace a modality with a
    # redaction mask. Only prose fields are scanned.
    payload, ctx = pseudonymized(CLEAN, store, settings)
    out, _ = layer2_ner(payload, ctx)
    assert out.dicom_fields == payload.dicom_fields


# -- Layer 3: the contract check over the transformed payload ----------------


def tampered(store, settings, text=CLEAN, **changes):
    """A valid, fully pseudonymized payload with exactly one thing wrong.

    Every layer-3 test starts from a payload that is correct in all the other
    respects, so the disposition it asserts is the one its tamper produced and
    not a second violation that was there all along.
    """
    payload, ctx = pseudonymized(text, store, settings)
    if "dicom_fields" in changes:
        changes["dicom_fields"] = {**payload.dicom_fields, **changes["dicom_fields"]}
    return payload.model_copy(update=changes), ctx


def test_layer3_rejects_a_field_outside_the_allowlist(store, settings):
    payload, ctx = tampered(store, settings,
                            dicom_fields={"institution_name": "Example Imaging"})
    _, dispositions = layer3_validation(payload, ctx)
    assert [d.action_code for d in _unresolved(dispositions)] == ["FIELD_NOT_ALLOWLISTED"]
    assert _unresolved(dispositions)[0].field == "institution_name"


def test_layer3_rejects_a_missing_field_the_function_requires(store, settings):
    payload, ctx = tampered(store, settings)
    thinned = payload.model_copy(update={"dicom_fields": {"study_date":
                                                          payload.dicom_fields["study_date"]}})
    _, dispositions = layer3_validation(thinned, ctx)
    assert {d.action_code for d in _unresolved(dispositions)} == {"CONTRACT_VIOLATION"}
    assert sorted(d.field for d in dispositions) == ["modality", "patient_age_band"]


def test_layer3_rejects_a_field_redaction_dropped(store, settings):
    # Nothing else in the kernel would notice a field quietly going missing
    # between two layers, which is why the check compares against the payload
    # the redaction started from.
    source = source_for(CLEAN, function="prior_summary").model_copy(update={
        "dicom_fields": {"modality": "CT", "study_date": "20260114",
                         "patient_age_band": "040-049",
                         "prior_report_text": "Prior: 6mm nodule."},
    })
    ctx = context_for(source, store, settings)
    payload = pseudonymize_payload(source, PATIENT, store)
    thinned = payload.model_copy(update={
        "dicom_fields": {k: v for k, v in payload.dicom_fields.items()
                         if k != "prior_report_text"},
    })
    _, dispositions = layer3_validation(thinned, ctx)
    assert [d.field for d in _unresolved(dispositions)] == ["prior_report_text"]
    assert _unresolved(dispositions)[0].action_code == "CONTRACT_VIOLATION"


def test_layer3_rejects_an_unshifted_date(store, settings):
    payload, ctx = tampered(store, settings, dicom_fields={"study_date": "20260114"})
    _, dispositions = layer3_validation(payload, ctx)
    assert [d.action_code for d in _unresolved(dispositions)] == ["UNSHIFTED_DATE"]


def test_layer3_rejects_a_date_that_is_not_a_date_at_all(store, settings):
    payload, ctx = tampered(store, settings, dicom_fields={"study_date": "14 Jan 2026"})
    _, dispositions = layer3_validation(payload, ctx)
    assert [d.action_code for d in _unresolved(dispositions)] == ["UNSHIFTED_DATE"]


def test_layer3_rejects_a_reference_without_a_surrogate(store, settings):
    payload, ctx = tampered(store, settings, study_ref="medarx-study-not-a-surrogate")
    _, dispositions = layer3_validation(payload, ctx)
    assert [d.action_code for d in _unresolved(dispositions)] == ["MISSING_SURROGATE"]


def test_layer3_rejects_a_leftover_deterministic_pattern(store, settings):
    payload, ctx = tampered(store, settings, report_text=f"{CLEAN} MRN: 4452819")
    _, dispositions = layer3_validation(payload, ctx)
    assert [d.action_code for d in _unresolved(dispositions)] == ["LEFTOVER_PATTERN_MATCH"]


def test_layer3_accepts_a_payload_the_first_two_layers_have_approved(store, settings):
    # Run in order rather than on the raw pseudonymized payload: layer 3's job
    # is to check what the earlier layers *produced*, and the same payload
    # handed to it before layer 2 has run still contains the MRN, which it
    # correctly refuses.
    payload, ctx = pseudonymized(DIRTY, store, settings)
    after_layer1, _ = layer1_deterministic(payload, ctx)
    after_layer2, layer2 = layer2_ner(after_layer1, ctx)
    out, dispositions = layer3_validation(after_layer2, ctx)
    assert dispositions == []
    assert out.payload_hash is not None
    assert all(d.resolved for d in layer2)


def test_layer3_overwrites_the_pre_redaction_hash_rather_than_trusting_it(store, settings):
    payload, ctx = pseudonymized(CLEAN, store, settings)
    pre = payload.model_copy(update={"payload_hash": "0" * 64})
    out, _ = layer3_validation(pre, ctx)
    assert out.payload_hash is not None and out.payload_hash != "0" * 64
    assert out.payload_hash == canonical_hash(out.model_dump(mode="json",
                                                             exclude={"payload_hash"}))


def test_layer3_hash_covers_the_redacted_payload_not_the_one_it_arrived_with(store, settings):
    payload, ctx = pseudonymized(DIRTY, store, settings)
    out, _ = layer3_validation(payload, ctx)
    assert out.payload_hash == canonical_hash(
        out.model_dump(mode="json", exclude={"payload_hash"})
    )
    assert out.payload_hash != payload.payload_hash


def test_layer3_hash_is_stable_across_calls(store, settings):
    payload, ctx = pseudonymized(CLEAN, store, settings)
    first, _ = layer3_validation(payload, ctx)
    second, _ = layer3_validation(payload, ctx)
    assert first.payload_hash == second.payload_hash


def test_layer3_rejects_an_unknown_function(store, settings):
    payload, ctx = tampered(store, settings, function="summarize_everything")
    _, dispositions = layer3_validation(payload, ctx)
    assert "UNKNOWN_FUNCTION" in {d.action_code for d in _unresolved(dispositions)}


# -- The orchestrator --------------------------------------------------------


def test_the_pipeline_blocks_and_returns_no_payload(store, settings, engine):
    payload, _ = pseudonymized(UNMAPPED, store, settings)
    out = run_redaction(payload, PATIENT, store, engine, settings, source_for(UNMAPPED))
    assert out.blocked is True
    assert out.approved is None
    assert [d.action_code for d in _unresolved(out.dispositions)]


def test_the_raising_form_names_the_flagging_layer_and_its_codes(store, settings, engine):
    payload, _ = pseudonymized(UNMAPPED, store, settings)
    with pytest.raises(RedactionError) as caught:
        run_privacy_kernel(payload, PATIENT, store, engine, settings, source_for(UNMAPPED))
    error = caught.value
    assert error.layer == "D.2"
    assert error.layer in LAYERS
    assert "D" not in LAYERS
    # Both layers speak: layer 2 could not resolve the reference, and layer 3
    # then found the deterministic pattern still sitting in the text. The error
    # names the first, because that is the layer a reader has to look at, and
    # carries every code, because reporting one of two would hide half the
    # reason.
    assert error.action_codes[0] == "NER_UNRESOLVED"
    assert "LEFTOVER_PATTERN_MATCH" in error.action_codes


def test_a_clean_report_is_approved_and_hashed(store, settings, engine):
    source = source_for(CLEAN)
    payload, _ = pseudonymized(CLEAN, store, settings)
    out = run_privacy_kernel(payload, PATIENT, store, engine, settings, source)
    assert out.report_text == CLEAN
    assert out.study_ref.startswith("medarx-study-")
    assert out.dicom_fields["study_date"] != "20260114"
    assert out.payload_hash == canonical_hash(out.model_dump(mode="json",
                                                              exclude={"payload_hash"}))


def test_a_block_is_still_returned_by_the_non_raising_form(store, settings, engine):
    # The demo asserts on dispositions directly, so a privacy block must not be
    # an exception on this path.
    payload, _ = pseudonymized(UNMAPPED, store, settings)
    out = run_redaction(payload, PATIENT, store, engine, settings, source_for(UNMAPPED))
    assert isinstance(out, RedactionOutcome)
    assert out.dispositions and all(d.layer in {"D.1", "D.2", "D.3"} for d in out.dispositions)


def test_a_layer3_violation_alone_blocks_the_pipeline(store, settings, engine):
    # A field the allowlist does not name survives layers 1 and 2 untouched —
    # neither transforms keys — so this is a violation only layer 3 can see.
    source = source_for(CLEAN)
    payload, _ = pseudonymized(CLEAN, store, settings)
    widened = payload.model_copy(update={
        "dicom_fields": {**payload.dicom_fields, "institution_name": "Example Imaging"},
    })
    out = run_redaction(widened, PATIENT, store, engine, settings, source)
    assert out.blocked is True
    assert out.approved is None
    assert [d.layer for d in _unresolved(out.dispositions)] == ["D.3"]


def test_layer1_repairs_an_unshifted_date_before_layer3_ever_sees_it(store, settings, engine):
    # The layers are defence in depth, not four independent chances to fail: a
    # date component C left alone is fixed by layer 1, so the pipeline approves
    # a payload that layer 3 called a violation on its own. Layer 3's check is
    # still asserted directly above; this pins the order the two run in.
    source = source_for(CLEAN)
    payload, _ = pseudonymized(CLEAN, store, settings)
    unshifted = payload.model_copy(update={
        "dicom_fields": {**payload.dicom_fields, "study_date": "20260114"},
    })
    out = run_redaction(unshifted, PATIENT, store, engine, settings, source)
    assert out.blocked is False
    assert out.approved.dicom_fields["study_date"] != "20260114"


def test_the_pipeline_does_not_mutate_the_payload_it_was_given(store, settings, engine):
    source = source_for(DIRTY)
    payload, _ = pseudonymized(DIRTY, store, settings)
    before = payload.model_dump()
    run_privacy_kernel(payload, PATIENT, store, engine, settings, source)
    assert payload.model_dump() == before


def test_no_disposition_carries_a_detected_value(store, settings, engine):
    # A disposition reaches an audit record and a block receipt. It names the
    # field and the entity kind; if it also carried the matched text, the audit
    # log would become the second PHI store the storage policy forbids.
    payload, _ = pseudonymized(ONLY_PHI, store, settings)
    out = run_redaction(payload, PATIENT, store, engine, settings, source_for(ONLY_PHI))
    rendered = " ".join(
        f"{d.layer} {d.field} {d.entity} {d.action_code}" for d in out.dispositions
    )
    for secret in ("4452819", "ACC0000417", "1953-04-11", "774123", "ZX-99-ALPHA"):
        assert secret not in rendered


def test_every_unresolved_disposition_carries_a_contract_code(store, settings, engine):
    # The AST sweep in `test_openapi_contract.py` covers the constants; this
    # covers the values that actually reach a receipt, which the sweep cannot
    # see because a `Disposition` is never serialised.
    payload, _ = pseudonymized(ONLY_PHI, store, settings)
    out = run_redaction(payload, PATIENT, store, engine, settings, source_for(ONLY_PHI))
    codes = {d.action_code for d in _unresolved(out.dispositions)}
    assert codes and codes <= _action_codes(), f"off-contract codes: {codes - _action_codes()}"


def test_every_disposition_layer_is_a_contract_layer_tag(store, settings, engine):
    payload, _ = pseudonymized(ONLY_PHI, store, settings)
    out = run_redaction(payload, PATIENT, store, engine, settings, source_for(ONLY_PHI))
    assert {d.layer for d in out.dispositions} <= set(LAYERS)


def test_a_disposition_refuses_a_layer_tag_the_contract_does_not_have():
    with pytest.raises(ValueError):
        Disposition(layer="D", field="report_text", entity=None,
                    action_code="NER_UNRESOLVED", resolved=False)


# -- The whole boundary, component A through layer 3 -------------------------


def test_a_keyword_metadata_request_survives_the_whole_kernel(store, settings, engine):
    # Component A takes DICOM keywords and component C takes a `YYYYMMDD` date.
    # This is the path the running code actually supports, pinned end to end so
    # a change to either end fails here rather than at the demo.
    study = StudyContext(study_uid="1.2.3.4", study_ref="STU-0001",
                         patient_ref=PATIENT, function="draft")
    source = pipeline_for("draft", study, CLEAN, DICOM_METADATA, PV)
    payload = pseudonymize_payload(source, PATIENT, store)
    out = run_privacy_kernel(payload, PATIENT, store, engine, settings, source)
    assert out.report_text == CLEAN
    assert out.study_ref == store.surrogate_for_study("STU-0001")
    assert out.dicom_fields["study_date"] == payload.dicom_fields["study_date"]
    assert out.dicom_fields["patient_age_band"] == "040-049"
    assert "PAT-0001" not in repr(out.dicom_fields)
    assert "ACC0000417" not in repr(out.dicom_fields)


def test_an_identifier_planted_in_free_text_is_removed_end_to_end(store, settings, engine):
    study = StudyContext(study_uid="1.2.3.4", study_ref="STU-0001",
                         patient_ref=PATIENT, function="draft")
    text = "FINDINGS: 7mm nodule. MRN: 4452819. Accession: ACC0000417."
    source = pipeline_for("draft", study, text, DICOM_METADATA, PV)
    payload = pseudonymize_payload(source, PATIENT, store)
    out = run_privacy_kernel(payload, PATIENT, store, engine, settings, source)
    assert "4452819" not in out.report_text
    assert "ACC0000417" not in out.report_text
    assert "FINDINGS: 7mm nodule." in out.report_text


def test_a_required_field_is_never_one_the_allowlist_forbids():
    # Layer 3 reads both the permitted and the required sets from the one module
    # that blesses field names. A field that was both required and forbidden
    # would make every payload for that function block on two counts at once,
    # so the two sets are asserted consistent here rather than discovered in a
    # demo.
    from medarx.extraction import allowlists

    assert set(allowlists.REQUIRED_FIELDS) == set(ALLOWED_FIELDS)
    for function, required in allowlists.REQUIRED_FIELDS.items():
        assert required <= ALLOWED_FIELDS[function], function
        assert "report_text" not in required, (
            "report_text is a required field of the model, not a dicom field"
        )


def test_a_resolved_dispositions_code_is_never_one_that_could_be_sent(store, settings, engine):
    # The internal codes record that a replacement succeeded. They are never
    # serialised, and this is what keeps that true: a code that a receipt could
    # carry has to be a contract member, so an internal code being a member
    # would mean the two had become indistinguishable.
    source = source_for(DIRTY)
    payload, _ = pseudonymized(DIRTY, store, settings)
    out = run_redaction(payload, PATIENT, store, engine, settings, source)
    resolved = {d.action_code for d in out.dispositions if d.resolved}
    assert resolved, "the approved path replaced something, and said so"
    assert not resolved & _action_codes()
