import pytest
from medarx.errors import ExtractionError
from medarx.extraction.payload_extractor import pipeline_for
from medarx.extraction.study_context import StudyContext

PV = "medarx-policy-1.0.0"
STUDY = StudyContext(study_uid="1.2.3.4", study_ref="STU-0001", patient_ref="PAT-0001", function="draft")
META = {"Modality": "CT", "StudyDate": "20260114", "PatientAge": "045Y",
        "PatientID": "PAT-0001", "AccessionNumber": "ACC0000417", "InstitutionName": "Example Imaging"}


def test_draft_payload_contains_only_the_draft_allowlist():
    p = pipeline_for("draft", STUDY, "FINDINGS: 7mm nodule.", META, PV)
    assert set(p.dicom_fields) == {"modality", "study_date", "patient_age_band"}
    assert p.report_text == "FINDINGS: 7mm nodule."
    assert p.study_ref == "STU-0001"
    assert p.prior_study_refs == ()


def test_non_allowlisted_metadata_is_dropped_not_rejected():
    p = pipeline_for("draft", STUDY, "FINDINGS: 7mm nodule.", META, PV)
    assert "institution_name" not in p.dicom_fields
    assert "PAT-0001" not in repr(p.dicom_fields.values())
    assert "ACC-9911" not in repr(p.dicom_fields)


def test_prior_summary_allowlist_includes_prior_text():
    p = pipeline_for("prior_summary", STUDY, "FINDINGS: 7mm nodule.",
                     META | {"PriorReportText": "2024 nodule 6mm", "PriorStudyDate": "20240602"}, PV)
    assert "prior_report_text" in p.dicom_fields
    assert "prior_study_date" in p.dicom_fields


def test_non_allowlisted_metadata_is_dropped_not_rejected():
    p = pipeline_for("draft", STUDY, "FINDINGS: 7mm nodule.", META, PV)
    assert "institution_name" not in p.dicom_fields
    assert "PAT-0001" not in repr(p.dicom_fields.values())
    assert "ACC0000417" not in repr(p.dicom_fields)


def test_unknown_function_is_rejected_with_layer_a():
    with pytest.raises(ExtractionError) as ei:
        pipeline_for("summarize_everything", STUDY, "text", META, PV)
    assert ei.value.layer == "A"
    assert ei.value.action_codes == ("UNKNOWN_FUNCTION",)


def test_arbitrary_dicom_object_is_never_accepted():
    with pytest.raises(ExtractionError) as ei:
        pipeline_for("draft", STUDY, "text", {"PixelData": "base64:AAAA"}, PV)
    assert ei.value.action_codes == ("UNKNOWN_DICOM_ATTRIBUTE",)


def test_unknown_dicom_attribute_is_rejected_422():
    with pytest.raises(ExtractionError) as ei:
        pipeline_for("draft", STUDY, "text", META | {"BurnedInAnnotation": "YES"}, PV)
    assert ei.value.action_codes == ("UNKNOWN_DICOM_ATTRIBUTE",)


def test_patient_age_is_band_not_exact_birth_date():
    p = pipeline_for("draft", STUDY, "text", META, PV)
    assert p.dicom_fields["patient_age_band"] == "040-049"


def test_prior_study_refs_are_plumbed_for_prior_functions_only():
    ctx = StudyContext(study_uid="1.2.3.4", study_ref="STU-0001",
                       patient_ref="PAT-0001", function="prior_summary",
                       prior_study_refs=("STU-0000", "STU-0001B"))
    priors = {"PriorReportText": "2024 nodule 6mm", "PriorStudyDate": "20240602"}
    for function in ("prior_summary", "ask"):
        p = pipeline_for(function, ctx, "FINDINGS: 7mm nodule.", META | priors, PV)
        assert p.prior_study_refs == ("STU-0000", "STU-0001B")
    draft = pipeline_for("draft", ctx, "FINDINGS: 7mm nodule.", META, PV)
    assert draft.prior_study_refs == ()


def test_known_attribute_outside_the_function_allowlist_is_not_allowlisted():
    with pytest.raises(ExtractionError) as ei:
        pipeline_for("draft", STUDY, "text", META | {"PriorReportText": "2024 nodule"}, PV)
    assert ei.value.layer == "A"
    assert ei.value.action_codes == ("FIELD_NOT_ALLOWLISTED",)


def test_malformed_patient_age_is_refused():
    with pytest.raises(ExtractionError) as ei:
        pipeline_for("draft", STUDY, "text", META | {"PatientAge": "forty"}, PV)
    assert ei.value.layer == "A"
    assert ei.value.action_codes == ("MALFORMED_METADATA",)


def test_payload_hash_is_none_until_the_contract_check_sets_it():
    from medarx.models import StructuredPayload
    p = StructuredPayload(function="draft", report_text="t", dicom_fields={},
                          study_ref="STU-0001", prior_study_refs=(),
                          policy_version=PV, input_hash="abc", payload_hash=None)
    assert p.payload_hash is None


def test_canonical_hash_refuses_non_serialisable_values():
    from medarx.models import canonical_hash
    with pytest.raises(TypeError):
        canonical_hash({"value": object()})
