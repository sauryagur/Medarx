"""The composition root: one construction, and the order the order depends on.

These are the claims a route cannot make for itself. A route that ran the
gateway before the policy engine, or built a second `MappingStore` per request,
would pass every test in `test_api.py` while being wrong; the assertions here
are about the pipeline object itself and about what it does before a socket is
touched.

The load-bearing one is `test_a_block_never_reaches_a_transport`: a privacy block
is a refusal to transmit, and the only way to know a refusal transmitted nothing
is to watch a transport.
"""

from __future__ import annotations

from dataclasses import fields

import pytest

from medarx.config import Settings, load_settings, require_date_order
from medarx.errors import ProviderTransportError
from medarx.pipeline import ExecutionRequest, build_pipeline

from conftest import KEY


@pytest.fixture
def bare_pipeline(tmp_path, provider):
    """A pipeline built the way the server builds one, over its own database."""
    return build_pipeline(
        Settings(audit_key=KEY, date_order="MDY", gateway_base_url=provider.base_url),
        f"sqlite:///{tmp_path / 'wiring.db'}",
    )


def _request(**overrides) -> ExecutionRequest:
    from medarx.extraction.study_context import StudyContext
    from medarx.models import PriorStudyReference

    fields = {
        "function": "draft",
        "addressed_function": "Draft",
        "study_context": StudyContext(
            study_uid="STUDY-SYN-000041",
            study_ref="STUDY-SYN-000041",
            patient_ref="PAT-0001",
            function="draft",
            prior_study_refs=("STUDY-SYN-000012",),
        ),
        "report_text": "FINDINGS: 7 mm nodule in the right upper lobe.",
        "dicom_metadata": {"Modality": "CT", "StudyDate": "20260114"},
        "prior_studies": (PriorStudyReference(prior_study_reference="STUDY-SYN-000012",
                                              study_date="20251201"),),
        "model_id": None,
        "input_hash": "0" * 64,
    }
    fields.update(overrides)
    return ExecutionRequest(**fields)


# -- One construction --------------------------------------------------------


def test_build_pipeline_constructs_every_component_once(bare_pipeline):
    from medarx.audit import AuditLog
    from medarx.gateway import ModelGateway
    from medarx.policy import PolicyEngine
    from medarx.pseudonym import MappingStore

    assert isinstance(bare_pipeline.settings, Settings)
    assert isinstance(bare_pipeline.store, MappingStore)
    assert isinstance(bare_pipeline.audit, AuditLog)
    assert isinstance(bare_pipeline.policy, PolicyEngine)
    assert isinstance(bare_pipeline.gateway, ModelGateway)
    assert bare_pipeline.policy.mode == bare_pipeline.settings.policy_mode


def test_the_pipeline_never_reads_the_environment(bare_pipeline):
    """Only `medarx.config` may. A pipeline built from `Settings` cannot."""
    from medarx import config, pipeline as pipeline_module

    assert pipeline_module.Settings is config.Settings
    source = open(pipeline_module.__file__, encoding="utf-8").read()
    assert "os.environ" not in source
    assert "getenv" not in source


def test_two_runs_of_the_same_study_share_one_surrogate(bare_pipeline):
    first = bare_pipeline.run("req-w-1", _request())
    second = bare_pipeline.run("req-w-2", _request())
    assert first.approved and second.approved
    assert first.approved_payload_hash == second.approved_payload_hash
    assert first.input_hash == second.input_hash


# -- A block reaches nothing -------------------------------------------------


def test_a_block_never_reaches_a_transport(bare_pipeline, provider):
    """The whole point of a block, measured at the socket.

    `AMBIGUOUS_REFERENCE` has no replacer, so the pipeline refuses it; the stub
    must still hold exactly the requests it held before.
    """
    before = list(provider.requests)
    result = bare_pipeline.run(
        "req-w-block",
        _request(report_text="FINDINGS: 7 mm nodule. Ticket ZX-99-ALPHA issued "
                             "at the counter."),
    )
    assert result.approved is False
    assert result.model_response is None
    assert result.approved_payload_hash is None
    assert result.block_receipt is not None
    assert result.block_receipt.layer == "D.2"
    assert list(provider.requests) == before
    assert bare_pipeline.gateway.last_request_body() is None


def test_the_block_is_recorded_before_the_result_is_returned(bare_pipeline):
    result = bare_pipeline.run("req-w-block-2",
                               _request(report_text="FINDINGS: Ticket ZX-99-ALPHA."))
    assert result.approved is False
    stored = bare_pipeline.audit.get("req-w-block-2")
    assert len(stored) == 1
    assert stored[0].final_disposition == "blocked"
    assert stored[0].layer == "D.2"
    assert stored[0].action_codes == list(result.block_receipt.action_codes)


# -- The approval happens before the provider is contacted -------------------


def test_an_unknown_model_is_refused_without_a_request_body_being_built(bare_pipeline,
                                                                       provider):
    before = list(provider.requests)
    result = bare_pipeline.run("req-w-model", _request(model_id="no-such-model"))
    assert result.approved is False
    assert result.block_receipt.layer == "F"
    assert result.block_receipt.action_codes == ["UNKNOWN_MODEL"]
    assert list(provider.requests) == before
    assert bare_pipeline.gateway.last_request_body() is None


def test_a_provider_outage_is_not_a_block(bare_pipeline, provider, tmp_path):
    """Availability, not privacy: it raises rather than returning a receipt.

    `ProviderTransportError` is deliberately outside the `MedarxError` taxonomy,
    so the pipeline cannot turn it into a 422 and no block is recorded.
    """
    unreachable = build_pipeline(
        Settings(audit_key=KEY, date_order="MDY",
                 gateway_base_url="http://127.0.0.1:9/v1", gateway_timeout_s=1.0),
        f"sqlite:///{tmp_path / 'unreachable.db'}",
    )
    with pytest.raises(ProviderTransportError):
        unreachable.run("req-w-outage", _request())
    assert unreachable.audit.get("req-w-outage") == []


def test_the_receipt_agrees_with_the_orchestrator(bare_pipeline):
    """The pipeline's block receipt and `run_privacy_kernel`'s error, compared.

    `medarx.pipeline._receipt_for` restates the orchestrator's rule — first
    unresolved layer, every unresolved code, deduplicated in order — because the
    pipeline needs the dispositions to write the audit record and the raising
    form discards them. Two statements of one rule is drift waiting to happen, so
    both are run over the same input here and compared field for field. If either
    changes, this fails rather than the surface quietly reporting a different
    layer than the orchestrator would.
    """
    from medarx.errors import RedactionError
    from medarx.extraction.payload_extractor import pipeline_for
    from medarx.pseudonym.pseudonymize import pseudonymize_payload
    from medarx.redaction.pipeline import run_privacy_kernel

    text = "FINDINGS: 7 mm nodule. Ticket ZX-99-ALPHA issued at the counter."
    through_api = bare_pipeline.run("req-w-agree", _request(report_text=text))
    assert through_api.approved is False
    assert through_api.block_receipt is not None

    request = _request(report_text=text)
    extracted = pipeline_for("draft", request.study_context, request.report_text,
                             dict(request.dicom_metadata),
                             bare_pipeline.settings.policy_version)
    pseudonymized = pseudonymize_payload(extracted, "PAT-0001", bare_pipeline.store)
    with pytest.raises(RedactionError) as caught:
        run_privacy_kernel(pseudonymized, "PAT-0001", bare_pipeline.store,
                           bare_pipeline.policy, bare_pipeline.settings,
                           source=extracted)

    assert through_api.block_receipt.layer == caught.value.layer
    assert through_api.block_receipt.action_codes == list(caught.value.action_codes)
    assert through_api.block_receipt.action_codes[0] == "NER_UNRESOLVED"


def test_an_approved_result_carries_the_layers_dispositions(bare_pipeline):
    """The record's field names come from the layers, so they are on the result."""
    result = bare_pipeline.run("req-w-fields",
                               _request(report_text="FINDINGS: 7 mm nodule. "
                                                    "MRN: 4452819."))
    assert result.approved is True
    assert {d.field for d in result.dispositions}
    stored = bare_pipeline.audit.get("req-w-fields")[0]
    assert stored.redacted_field_names
    assert all(name == name.lower() for name in stored.redacted_field_names)


# -- The modes are configuration, not parameters -----------------------------


def test_the_policy_mode_is_never_taken_from_the_request(bare_pipeline):
    """`ExecutionRequest` has no mode field, and a caller cannot add one.

    The contract says a request that supplies one is a malformed request, and
    `ExecutionRequest` is `extra="forbid"`, so the field does not exist to be set.
    """
    with pytest.raises(TypeError):
        _request(policy_mode="authorized_local")  # type: ignore[call-arg]
    assert "policy_mode" not in {f.name for f in fields(ExecutionRequest)}
    assert bare_pipeline.policy.mode == bare_pipeline.settings.policy_mode


# -- The startup guard -------------------------------------------------------


def test_require_date_order_refuses_an_undeclared_order():
    with pytest.raises(ValueError, match="MEDARX_DATE_ORDER"):
        require_date_order(Settings(audit_key=KEY, date_order=None))
    require_date_order(Settings(audit_key=KEY, date_order="MDY"))
    require_date_order(Settings(audit_key=KEY, date_order="DMY"))


def test_load_settings_is_the_only_reader_of_the_environment(monkeypatch):
    monkeypatch.setenv("MEDARX_POLICY_MODE", "strict_local")
    monkeypatch.setenv("MEDARX_DATE_ORDER", "DMY")
    settings = load_settings()
    assert settings.policy_mode == "strict_local"
    assert settings.date_order == "DMY"
