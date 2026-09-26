"""The contract must describe bodies that can exist, and the code must agree.

`test_openapi_contract.py` checks that the action codes and layer tags the
kernel emits are contract members. It does not check that the *schemas*
themselves admit anything: a schema that names a property in `required`, does
not declare it, and sets `additionalProperties: false` is unsatisfiable, and
nothing in a code sweep can see that. `ModelResponse` was exactly that, which
left `createFunctionExecution` with no valid `200` body at all — a
response-validation middleware, or a client generated from this document,
rejects every successful execution.

So the tests here build a body *from the contract's own schemas* and validate
it, and sweep every example the contract publishes. The generator is small on
purpose: it fills required properties from their own subschemas, so a `required`
member the schema cannot itself satisfy shows up as a failed body rather than
as a shape nobody ever checked.

The second half is the contract/code agreement the first half cannot express:
every property `AllowlistedDicomMetadata` advertises must be a DICOM keyword
layer A accepts, and every date the contract admits must be a date component C
can shift. The metadata rule is one-way by design, because layer A's table also
holds keywords that are deliberately not request-surface metadata (see
`_DROPPED_ATTRIBUTES`); the date rule is one-way too, for a different reason
that the test itself spells out.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from medarx.errors import ExtractionError
from medarx.extraction.allowlists import ALLOWED_FIELDS
from medarx.extraction.payload_extractor import KNOWN_DICOM_ATTRIBUTES, pipeline_for
from medarx.extraction.study_context import StudyContext
from medarx.pseudonym.pseudonymize import shift_dicom_date

REPO_ROOT = Path(__file__).resolve().parents[2]
CONTRACT = REPO_ROOT / "contracts" / "openapi.yaml"

#: Every operation's `200` body, keyed by the schema it names. Asserted as an
#: exact set by `test_the_200_sweep_covers_every_operation`, so a new operation
#: cannot be added without a body for it being checked here.
EXPECTED_200_SCHEMAS: dict[str, str] = {
    "/v1/functions/{function_name}/executions": "ExecutionResponse",
    "/v1/executions/{request_id}/approval": "HumanApprovalResponse",
    "/v1/policy": "PolicyConfiguration",
    "/v1/audit/records": "AuditRecordCollection",
    "/v1/audit/records/{request_id}": "AuditRecord",
}

#: Layer A's known attributes that map to no payload field: the identifiers and
#: `StudyInstanceUID`, which the extractor accepts and then never carries.
#: `payload_extractor`'s module docstring says so. Named here so that a test
#: asserting a property is *accepted* cannot be read as a claim that it is
#: *carried* — the two differ, and which is which is worth pinning.
_DROPPED_ATTRIBUTES = frozenset(
    {"PatientID", "AccessionNumber", "PatientName", "InstitutionName", "StudyInstanceUID"}
)

#: The property names this contract uses for a DICOM `DA` value: the DICOM
#: keywords layer A accepts, plus the snake_case spelling on
#: `PriorStudyReference`.
_DICOM_DATE_PROPERTIES = frozenset({"StudyDate", "PriorStudyDate", "study_date"})

#: A DICOM `DA` value, and the ISO 8601 spelling `format: date` used to require.
_DICOM_DA = "20260114"
_ISO_DATE = "2026-01-14"

#: Dates that are real calendar days, and one that is not. Component C and the
#: contract are held to the same verdict on each of them. `00010101` is
#: deliberately absent from the first list: `shift_dicom_date` reformats it as
#: `10101`, so it does not round-trip. That is a separate defect from anything
#: asserted here and it is reported, not quietly folded into these tests.
_VALID_DA = ("20260114", "19991231", "19700101", "20000229")
_IMPOSSIBLE_DA = "20260230"


def _contract() -> dict:
    with CONTRACT.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _deref(node: dict, doc: dict) -> dict:
    """Follow local `$ref`s to the schema they name."""
    while isinstance(node, dict) and "$ref" in node:
        pointer = node["$ref"]
        assert pointer.startswith("#/"), f"only local refs are resolvable here: {pointer!r}"
        target: object = doc
        for part in pointer[2:].split("/"):
            target = target[part]
        node = target
    return node


def _validator_for(doc: dict, schema: dict, formats: bool = False) -> Draft202012Validator:
    """A validator for `schema`, with the contract's own pointers resolvable.

    The component table rides on the root document, so the contract's
    `#/components/schemas/...` refs resolve wherever they appear. `formats`
    turns on `format` assertion, which is annotation-only by default: this
    contract leans on `format: date` and `format: date-time` to say what a
    value must look like, and a sweep that ignored them would not be reading it.
    """
    root = {"$ref": "#/__target__", "__target__": schema, "components": doc["components"]}
    return Draft202012Validator(
        root,
        format_checker=Draft202012Validator.FORMAT_CHECKER if formats else None,
    )


def _validator(doc: dict, name: str) -> Draft202012Validator:
    """A validator for the named `components.schemas` entry."""
    return _validator_for(doc, doc["components"]["schemas"][name])


#: A value satisfying each `format` the contract uses on a *generated* body.
#: `pattern` is deliberately absent: nothing generated needs to match a regex,
#: and a sampler that guessed at one would be testing the sampler rather than
#: the contract.
_FORMATS = {
    "date": "2026-01-14",
    "date-time": "2026-01-14T09:30:00Z",
    "uri": "https://medarx.invalid/problems/example",
}


def _minimal(schema: dict, doc: dict) -> object:
    """The smallest instance `schema` permits, built from `schema` itself.

    Every `required` property is filled from its own subschema, so a property
    the schema demands but cannot describe produces a body the validator then
    rejects — which is the point.
    """
    schema = _deref(schema, doc)
    if "const" in schema:
        return schema["const"]
    if "enum" in schema:
        return schema["enum"][0]
    if "allOf" in schema:
        merged: dict = {}
        for part in schema["allOf"]:
            built = _minimal(_deref(part, doc), doc)
            assert isinstance(built, dict), f"allOf over a non-object schema: {schema}"
            merged.update(built)
        return merged
    if "oneOf" in schema:
        return _minimal(schema["oneOf"][0], doc)

    kind = schema.get("type")
    if kind == "object" or "properties" in schema:
        return {
            name: _minimal(schema["properties"][name], doc)
            for name in schema.get("required", [])
        }
    if kind == "array":
        return [_minimal(schema["items"], doc)] if "items" in schema else []
    if kind == "integer":
        return 1
    if kind == "number":
        return 1
    if kind == "boolean":
        return False
    if kind == "null":
        return None
    return _FORMATS.get(schema.get("format"), "x" * schema.get("minLength", 1))


def test_every_200_response_body_the_contract_describes_validates():
    """A body built from the contract, validated against the contract.

    `ModelResponse` listed `draft` in `required`, never declared it, and closed
    on `additionalProperties: false` — so no object was a valid
    `ModelResponse`, and therefore no `200` was a valid `ExecutionResponse`.
    This is the test that would have caught it.
    """
    doc = _contract()
    for path, name in EXPECTED_200_SCHEMAS.items():
        body = _minimal(doc["components"]["schemas"][name], doc)
        try:
            _validator(doc, name).validate(body)
        except ValidationError as exc:
            pytest.fail(f"{path} has no valid 200 body for {name}: {exc.message}")


def test_a_written_out_execution_response_validates():
    """The shape a server would actually return, spelled out.

    The generated body above is minimal; this one is the response the contract's
    own description promises: a draft, the request ID, the policy version, and
    the hash of the payload that was transmitted.
    """
    doc = _contract()
    _validator(doc, "ExecutionResponse").validate(
        {
            "status": "approved",
            "request_id": "7f3c1a90-2b6e-4f1a-9d55-2c8b7e0a1f34",
            "function": "Draft",
            "policy_version": "medarx-policy-1.0.0",
            "policy_mode": "strict_local",
            "selected_model": "medarx-demo-model",
            "approved_payload_hash": "sha256:2f1a0c9d4b7e6a3f",
            "input_hash": "sha256:9c1d0b2a3f4e5d6c",
            "draft": {
                "model_id": "medarx-demo-model",
                "content": "FINDINGS: 7 mm nodule in the right upper lobe.",
                "finish_reason": "stop",
                "usage": {
                    "prompt_tokens": 512,
                    "completion_tokens": 96,
                    "total_tokens": 608,
                },
            },
        }
    )


def test_a_model_response_is_not_required_to_contain_another_draft():
    """`ExecutionResponse.draft` is the nesting; `ModelResponse` is the thing.

    So `ModelResponse` requiring a `draft` of its own asks for a second level
    the response body does not have, and forbidding unknown properties makes it
    unstatable. The nesting is the outer property; the inner schema models the
    gateway's answer and nothing else.
    """
    model_response = _contract()["components"]["schemas"]["ModelResponse"]
    assert "draft" not in model_response.get("required", [])
    assert "draft" not in model_response.get("properties", {})


def test_the_200_sweep_covers_every_operation():
    doc = _contract()
    found = {
        path
        for path, item in doc["paths"].items()
        for operation in item.values()
        if isinstance(operation, dict) and "200" in operation.get("responses", {})
    }
    assert found == set(EXPECTED_200_SCHEMAS)


def _published_examples(doc: dict) -> list[tuple[str, dict, object]]:
    """Every `examples` value the contract publishes, with the schema for it.

    Two shapes exist here: a `properties.<p>.examples` list, whose schema is
    the object declaring it, and a media type's `examples.<name>.value`, whose
    schema is the sibling `schema`.
    """
    found: list[tuple[str, dict, object]] = []

    def walk(node: object, where: str) -> None:
        if isinstance(node, dict):
            if "properties" in node and isinstance(node.get("examples"), list):
                found.extend((f"{where}.examples", node, v) for v in node["examples"])
            for media_type, media in (node.get("content") or {}).items():
                if not isinstance(media, dict) or "schema" not in media:
                    continue
                found.extend(
                    (f"{where}.{media_type}.{name}", media["schema"], entry["value"])
                    for name, entry in (media.get("examples") or {}).items()
                )
            for key, value in node.items():
                walk(value, f"{where}.{key}")
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, f"{where}[{index}]")

    walk(doc["components"], "components")
    return found


def test_every_example_the_contract_publishes_validates_against_its_schema():
    doc = _contract()
    published = _published_examples(doc)
    assert published, "the example sweep found nothing; it is not reading the contract"
    for where, schema, value in published:
        try:
            _validator_for(doc, schema, formats=True).validate(value)
        except ValidationError as exc:
            pytest.fail(f"{where} publishes a value its own schema rejects: {exc.message}")


# -- The contract and layer A must name the same things ------------------------


def _metadata_properties(doc: dict) -> dict[str, dict]:
    schema = doc["components"]["schemas"]["AllowlistedDicomMetadata"]
    assert schema.get("additionalProperties") is False, (
        "the allowlist must stay closed, or an arbitrary DICOM object becomes expressible"
    )
    return schema["properties"]


def test_every_allowlisted_metadata_property_is_a_dicom_keyword_layer_a_accepts():
    """The contract's property names *are* the boundary's vocabulary.

    A `study_description` here was refused at layer A with
    `UNKNOWN_DICOM_ATTRIBUTE` and a `422`, so the contract advertised a request
    the system could not process. Asserting membership — rather than trusting
    two tables to stay in step by hand — is what stops them drifting apart again.
    """
    unknown = sorted(set(_metadata_properties(_contract())) - set(KNOWN_DICOM_ATTRIBUTES))
    assert not unknown, (
        f"the contract advertises metadata layer A refuses: {unknown}. Remove the "
        "property from the contract or teach layer A the keyword — never insert a "
        "translation layer between them, which would be a second vocabulary to keep in step."
    )


_STUDY = StudyContext(
    study_uid="1.2.3.4", study_ref="STU-0001", patient_ref="PAT-0001", function="draft"
)


def _carried_fields(keyword: str, subschema: dict) -> set[str]:
    """The payload fields one metadata property actually fills."""
    examples = subschema.get("examples") or []
    value = str(examples[0]) if examples else "SYNTHETIC"
    try:
        payload = pipeline_for("draft", _STUDY, "text", {keyword: value}, "pv-1")
    except ExtractionError as exc:  # pragma: no cover - the assertion reports it
        pytest.fail(
            f"contract property {keyword}={value!r} is refused at layer A: {exc.action_codes}"
        )
    return set(payload.dicom_fields)


def test_every_allowlisted_metadata_property_is_carried_or_deliberately_dropped():
    """Accepted is not the same as carried, and the difference is a claim.

    Membership proves the keyword is inside the boundary. It does not prove the
    value survives: an accepted-and-dropped property is invisible in the
    payload, so the two sets are asserted separately rather than left to
    whichever reading a reader happened to assume.
    """
    for keyword, subschema in _metadata_properties(_contract()).items():
        carried = _carried_fields(keyword, subschema)
        assert bool(carried) == (keyword not in _DROPPED_ATTRIBUTES), (
            f"{keyword} carried={bool(carried)}, which disagrees with "
            "_DROPPED_ATTRIBUTES: the extractor dropped it, or that set is stale"
        )


def test_the_contract_offers_every_dicom_field_the_draft_allowlist_expects():
    """`Draft` needs a modality, a study date and an age band; the API must say so.

    A property the contract omits is a field a caller cannot supply, so the
    payload the model sees is poorer than the allowlist implies — silently,
    because the allowlist is a code-side table and nothing reconciles it with
    the published request schema.
    """
    reachable: set[str] = set()
    for keyword, subschema in _metadata_properties(_contract()).items():
        reachable |= _carried_fields(keyword, subschema)
    missing = sorted(ALLOWED_FIELDS["draft"] - {"report_text"} - reachable)
    assert not missing, f"the contract offers no property that fills {missing}"


# -- Dates: the contract's date form is the one component C can shift -----------


def _date_properties(doc: dict) -> dict[str, dict]:
    """Every property the contract declares as a DICOM `DA`, by `Schema.name`."""
    found: dict[str, dict] = {}
    for schema_name, schema in doc["components"]["schemas"].items():
        for name, subschema in (schema.get("properties") or {}).items():
            if name in _DICOM_DATE_PROPERTIES:
                found[f"{schema_name}.{name}"] = subschema
    return found


def test_no_property_in_the_contract_is_declared_as_an_iso_8601_date():
    """`format: date` *means* `YYYY-MM-DD`, which component C cannot shift.

    This is the defect in its rawest form: the contract said one thing, the
    shifter implements another, and every request that followed the contract
    blocked with `UNSHIFTED_DATE`. Swept across every schema so the format
    cannot creep back onto a property added later.
    """
    doc = _contract()
    offenders = [
        f"{schema_name}.{name}"
        for schema_name, schema in doc["components"]["schemas"].items()
        for name, subschema in (schema.get("properties") or {}).items()
        if _deref(subschema, doc).get("format") == "date"
    ]
    assert not offenders, f"these are declared as ISO dates: {offenders}"


def test_the_contract_refuses_an_iso_date_where_a_dicom_date_is_required():
    """The regression, asserted on the value rather than on the schema text.

    `format: date` accepted `2026-01-14` and `pseudonymize` refused it, so a
    request that satisfied the contract blocked at layer C. The declaration
    sweep above says the format is gone; this says the string it accepted is
    not accepted either.
    """
    doc = _contract()
    dates = _date_properties(doc)
    assert dates, "the contract declares no DICOM date property; the sweep reads nothing"
    for where, subschema in dates.items():
        validator = _validator_for(doc, subschema)
        validator.validate(_DICOM_DA)
        try:
            validator.validate(_ISO_DATE)
        except ValidationError:
            continue
        pytest.fail(
            f"{where} still admits {_ISO_DATE!r}; component C shifts only the DICOM "
            "DA form, so a request carrying it blocks with UNSHIFTED_DATE"
        )


def test_the_contract_admits_every_date_spelling_component_c_can_shift():
    """The direction that blocks requests: a legal date must be expressible.

    The other direction is deliberately *not* asserted, and the contract says
    why: `DicomDate`'s pattern states the eight-digit shape, so it also admits
    `20260230`, which is eight digits and not a calendar day. Deciding that is
    component C's job — a JSON Schema pattern cannot express a leap-year rule —
    and it refuses such a value rather than forwarding it unshifted. The gap is
    therefore a caller sending an impossible date, not a contract-conformant
    request that cannot be processed, which is what this file exists to rule out.
    """
    doc = _contract()
    checked = 0
    for _where, subschema in _date_properties(doc).items():
        validator = _validator_for(doc, subschema)
        for candidate in _VALID_DA:
            assert shift_dicom_date(candidate, 0) == candidate
            validator.validate(candidate)
            checked += 1
    assert checked, "no date property was checked; the sweep is reading nothing"


def test_component_c_still_judges_the_calendar_day_the_contract_cannot():
    """The residual the previous test documents, pinned so it cannot rot.

    `DicomDate` admits `20260230`; `shift_dicom_date` refuses it. If that ever
    stops being true — because the pattern learned leap years, or the shifter
    grew a lenient path — this test says so, and the note in the test above can
    be rewritten rather than left as a stale excuse.
    """
    doc = _contract()
    with pytest.raises(ValueError):
        shift_dicom_date(_IMPOSSIBLE_DA, 0)
    for _where, subschema in _date_properties(doc).items():
        _validator_for(doc, subschema).validate(_IMPOSSIBLE_DA)
