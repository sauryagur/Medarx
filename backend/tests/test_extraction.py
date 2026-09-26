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


def _band(age: str) -> str:
    return pipeline_for("draft", STUDY, "text", META | {"PatientAge": age}, PV).dicom_fields[
        "patient_age_band"
    ]


#: Every `AS` spelling the DICOM age-string VR allows, with the band each one
#: produces. Written out rather than generated, because the *values* are the
#: claim: a table is reviewable, and a rule that silently changed its mind
#: about a 30-day-old would not be visible in one.
AGE_BANDS = {
    # Years, by decade. `045Y` is the case the original test pinned.
    "001Y": "000-009",
    "009Y": "000-009",
    "010Y": "010-019",
    "045Y": "040-049",
    "089Y": "080-089",
    # 90 and over, grouped. Measured, not asserted as a rule of thumb.
    "090Y": "090+",
    "099Y": "090+",
    "100Y": "090+",
    "103Y": "090+",
    # Months. Twelve months is one year, so this is the first band above the
    # infant scale rather than the last one on it.
    "000M": "000-002M",
    "003M": "003-005M",
    "006M": "006-008M",
    "009M": "009-011M",
    "011M": "009-011M",
    "012M": "000-009",
    "018M": "000-009",
    # Weeks: 26 weeks is six months, 52 weeks is a year.
    "000W": "000-002M",
    "010W": "000-002M",
    "026W": "006-008M",
    "052W": "000-009",
    # Days: a month is about 30.4 days, so 030D is a one-month-old.
    "000D": "000-002M",
    "007D": "000-002M",
    "030D": "000-002M",
    "090D": "003-005M",
    "364D": "000-009",
}


@pytest.mark.parametrize("age,expected", sorted(AGE_BANDS.items()))
def test_every_as_unit_bands_to_the_age_it_actually_names(age, expected):
    assert _band(age) == expected


def test_a_month_old_never_lands_in_an_adult_decade():
    # The regression: the unit was captured and then ignored, so `030D` — a
    # 30-day-old — was reported as `030-039` and a downstream stage received a
    # clinical age thirty years wrong. `AS` is `ddd[DWMY]`; a sub-year age is
    # not usefully described as a decade of years, so it is banded in months
    # and marked as such with a trailing `M`.
    assert _band("030D") == "000-002M"
    assert _band("030D") != "030-039"
    assert _band("018M") == "000-009"
    assert _band("018M") != "010-019"


def test_weeks_are_a_valid_unit_and_not_a_malformed_value():
    # `W` is one of the four units in the AS VR. Refusing it as
    # MALFORMED_METADATA sent a well-formed 10-week-old down the malformed path.
    assert _band("010W") == "000-002M"


@pytest.mark.parametrize("age", ["045", "45Y", "0045Y", "045X", "0Y", "abc", "-45Y"])
def test_a_value_that_is_not_an_as_age_string_is_refused(age):
    # `AS` is exactly three digits and one of `DWMY`. Everything else is
    # malformed, and stays so: loosening the parse to be helpful is how a
    # 30-day-old becomes a 30-year-old again.
    with pytest.raises(ExtractionError) as ei:
        pipeline_for("draft", STUDY, "text", META | {"PatientAge": age}, PV)
    assert ei.value.action_codes == ("MALFORMED_METADATA",)


@pytest.mark.parametrize("age", ["045y", " 045Y", "045Y "])
def test_surrounding_whitespace_and_a_lowercase_unit_are_tolerated(age):
    # `AS` carries no padding, but a caller assembling the value by hand adds
    # some, and a lowercase unit is a spelling rather than a different age.
    # Both resolve to the same band as the canonical spelling, which is the
    # point: one age, one band, no second error code.
    assert _band(age) == "040-049"


def test_the_bands_are_monotone_in_age():
    # Converting units can easily reorder ages. Across every `AS` value in the
    # representable range, the band index must never go backwards.
    order = {
        band: index
        for index, band in enumerate(
            ["000-002M", "003-005M", "006-008M", "009-011M"]
            + [f"{low:03d}-{low + 9:03d}" for low in (0, 10, 20, 30, 40, 50, 60, 70, 80)]
            + ["090+"]
        )
    }

    def months(age: str) -> int:
        value, unit = int(age[:3]), age[3]
        return {"D": round(value * 12 / 365), "W": round(value * 12 / 52),
                "M": value, "Y": value * 12}[unit]

    pairs = [(f"{v:03d}{u}", m) for u, m in
             (("D", 365), ("W", 52), ("M", 999), ("Y", 122)) for v in range(m)]
    previous = -1
    for age, _ in sorted(pairs, key=lambda pair: months(pair[0])):
        index = order[_band(age)]
        assert index >= previous, f"{age} banded below the previous age in the ordering"
        previous = index


def test_the_whole_age_space_collapses_to_a_handful_of_bands():
    # The de-identification claim, measured rather than assumed: the entire
    # representable `AS` space must not distinguish an individual, which is
    # what the band exists for. Fourteen bands is what the rules below give.
    bands = {
        _band(f"{value:03d}{unit}")
        for unit, top in (("D", 999), ("W", 999), ("M", 999), ("Y", 122))
        for value in range(top)
    }
    assert len(bands) == 14, sorted(bands)


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


def test_extractor_writes_a_pre_redaction_payload_hash_that_tracks_content():
    a = pipeline_for("draft", STUDY, "FINDINGS: 7mm nodule.", META, PV)
    b = pipeline_for("draft", STUDY, "FINDINGS: 9mm nodule.", META, PV)
    # Written at extraction, and distinct from the input attestation.
    assert a.payload_hash is not None
    assert a.payload_hash != a.input_hash
    # Sensitive to the content it attests to: a redaction layer that rewrites
    # the payload without updating this hash is exactly the drift layer 3
    # exists to catch, so the value must not be a constant.
    assert a.payload_hash != b.payload_hash


def test_canonical_hash_refuses_non_serialisable_values():
    from medarx.models import canonical_hash
    with pytest.raises(TypeError):
        canonical_hash({"value": object()})
