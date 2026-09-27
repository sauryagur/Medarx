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

The examples are swept a second time for a different fault. Validating an
example proves the *shape* is legal; it says nothing about whether the kernel
can produce it, and a `Blocked` example is a claim about a receipt. A code
stays in the `ActionCode` enum long after the condition it named stops being
emitted, so the enum cannot make that claim true — the receipt sweep below
resolves each published code through the AST emission sweep in
`test_openapi_contract.py` instead. One example is additionally checked by
running the layer that produces it, in `test_redaction_layers.py`.
"""

from __future__ import annotations

import re
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
from test_openapi_contract import _emitted_action_codes


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
    turns on `format` assertion, which is annotation-only by default, and
    which asserts exactly as much as `Draft202012Validator.FORMAT_CHECKER`
    can and no more.

    This contract declares two formats, `date-time` and `uri`, and both are
    enforced: the suite is installed with jsonschema's `[format-nongpl]`
    extra, which supplies the checkers for them. Without that extra the
    bundled checker is `['date', 'email', 'idn-email', 'idn-hostname', 'ipv4',
    'ipv6', 'regex', 'uuid']` and *silently accepts* every `date-time` and
    every `uri` — the contract's format assertions would then be decoration
    that no test ever applies. `test_every_format_the_contract_declares_is_one_the_checker_enforces`
    holds the declared set inside the checker's, so the next format added
    without a checker behind it fails there rather than passing quietly here.
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


def _declared_formats(doc: dict) -> dict[str, list[str]]:
    """Every `format` the contract declares anywhere, mapped to its sites."""
    found: dict[str, list[str]] = {}

    def walk(node: object, where: str) -> None:
        if isinstance(node, dict):
            name = node.get("format")
            if isinstance(name, str):
                found.setdefault(name, []).append(where)
            for key, value in node.items():
                walk(value, f"{where}.{key}")
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, f"{where}[{index}]")

    walk(doc, "root")
    return found


#: The formats this contract declares. Exact-set rather than containment: a
#: new format has to be added here, and that is the moment to check a checker
#: for it really exists and to re-read the claim in `_validator_for`'s
#: docstring, rather than letting the format appear in the contract and in
#: nobody's attention.
_DECLARED_FORMATS = frozenset({"date-time", "uri"})


def test_the_formats_this_contract_declares_are_the_ones_it_documents():
    doc = _contract()
    assert set(_declared_formats(doc)) == _DECLARED_FORMATS


def test_the_format_declarations_the_sweep_reads_are_not_vacuous():
    # The guard below is a subset assertion; if the walk stopped finding
    # anything it would pass on an empty set and the five unenforced contract
    # assertions this file exists to catch would be back. Measured at the
    # time of writing: four `date-time` sites and one `uri` site.
    declared = _declared_formats(_contract())
    assert declared, "the format sweep found nothing; it is not reading the contract"
    assert len(declared["date-time"]) + len(declared["uri"]) > 1


def test_every_format_the_contract_declares_is_one_the_checker_enforces():
    """The guard that makes an unenforceable format fail loudly.

    A `format` with no checker registered is annotation: the value is ignored
    and every one of them validates. The contract's assertions would then be
    unverified rather than violated, which no validation test can report —
    so the set of declared formats is held inside the checker's here.
    """
    declared = set(_declared_formats(_contract()))
    unenforceable = declared - set(Draft202012Validator.FORMAT_CHECKER.checkers)
    assert not unenforceable, (
        f"the contract declares {sorted(unenforceable)} but "
        "Draft202012Validator.FORMAT_CHECKER has no checker for it, so every "
        "value passes and the declaration is unverified: install jsonschema's "
        "[format-nongpl] extra, or drop the format and say what the value must be"
    )


def test_the_format_assertion_rejects_a_value_the_declared_format_forbids():
    """Registration is not assertion; this checks the assertion bites.

    The guard above can be satisfied by a checker that is present and inert.
    This runs the same `_validator_for(..., formats=True)` the example sweep
    uses, on a value of the shape the contract forbids, and requires the
    rejection. Both formats are checked because they are the two the contract
    declares.
    """
    doc = _contract()
    for declared, bad in (("date-time", "14 January 2026 at half past nine"),
                          ("uri", "definitely not a uri")):
        schema = {"type": "string", "format": declared}
        with pytest.raises(ValidationError):
            _validator_for(doc, schema, formats=True).validate(bad)


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
    """Every example value the contract publishes anywhere, with its schema.

    The whole document is walked, not `components.schemas` and not the audit
    record, because the defect this catches is not confined to one schema: a
    property-level `examples` list, a singular `example`, and a media type's
    named `examples.<name>.value` are three different places to publish one, and
    the previous version of this sweep read only the second and third. That is
    why `AuditRecord.redacted_field_names` — a `type: array` property
    publishing three bare strings — went unnoticed: no node it looked for sits
    on a property at all.

    A media type's `examples` is a *mapping* of names to `{value: …}`, while a
    schema's `examples` is a *list* of values; both spellings are handled and
    neither is guessed at from the other's shape.
    """
    found: list[tuple[str, dict, object]] = []

    def walk(node: object, where: str) -> None:
        if isinstance(node, dict):
            named = node.get("examples")
            is_schema = any(
                key in node
                for key in ("type", "$ref", "properties", "allOf", "anyOf", "oneOf")
            )
            # A schema publishes a *list* of values; a media type publishes a
            # *mapping* of name to `{value: …}`. Both spellings exist in this
            # document and they are told apart by shape, not by position,
            # because a property-level `examples` is a list and is exactly the
            # case the previous version of this sweep could not see.
            if isinstance(named, list) and is_schema:
                for index, value in enumerate(named):
                    found.append((f"{where}.examples[{index}]", node, value))
            schema = node.get("schema")
            if isinstance(schema, dict):
                if isinstance(named, dict):
                    for name, entry in named.items():
                        if isinstance(entry, dict) and "value" in entry:
                            found.append(
                                (f"{where}.examples.{name}", schema, entry["value"])
                            )
                if "example" in node:
                    found.append((f"{where}.example", schema, node["example"]))
            elif is_schema and "example" in node:
                # A singular `example` on a schema, a parameter or a header: the
                # node itself is the schema it is an example of.
                found.append((f"{where}.example", node, node["example"]))
            for key, value in node.items():
                if key in ("description", "title", "example"):
                    continue
                walk(value, f"{where}.{key}")
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, f"{where}[{index}]")

    walk(doc, "contract")
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


#: A digest is `<algorithm>:<hex>` or bare `<hex>`, and the hex length is a
#: property of the algorithm rather than a choice. This is the definition the
#: contract's own `sha256:` spelling is written against, so a value carrying
#: that label has to be that algorithm's digest — the label is a claim, and a
#: 63-character one is as false as `sha256:` on a word.
_DIGEST_ALGORITHMS: dict[str, int] = {
    "md5": 32,
    "sha1": 40,
    "sha224": 56,
    "sha256": 64,
    "sha384": 96,
    "sha512": 128,
}
_DIGEST_VALUE = re.compile(r"\A(?:([a-z0-9]+):)?([0-9a-f]+)\Z")


def test_every_published_hash_example_is_a_digest_of_the_algorithm_it_names():
    """The one defect JSON Schema cannot see, and the one the contract shipped.

    `ExecutionResponse.approved_payload_hash` published
    `sha256:2f1a0c9d…` with **63** hex characters. Nothing in the schema
    rejects it — the property is `type: string` with no `pattern` and no
    `format` — so `test_every_example_the_contract_publishes_validates_against_its_schema`
    passed, and the storage policy was the only thing that noticed, by refusing
    the contract's own example. Which is the wrong place for a contract defect
    to surface.

    The rule is a definition and not a shape guess: a property whose own name
    declares it a hash must publish a value that *is* one, and if the value
    names an algorithm, the hex length is that algorithm's digest size. A
    property with no example is not this test's business, and a property that
    is not declared a hash is not either.
    """
    doc = _contract()
    checked = 0
    for name, body in doc["components"]["schemas"].items():
        for prop, schema in (body.get("properties") or {}).items():
            if not prop.endswith(("_hash", "_digest")):
                continue
            published = [
                v
                for v in (
                    *([schema["example"]] if "example" in schema else []),
                    *(schema.get("examples") or []),
                )
            ]
            for value in published:
                checked += 1
                assert isinstance(value, str), (
                    f"{name}.{prop} publishes {value!r}; a hash example is a string"
                )
                match = _DIGEST_VALUE.match(value)
                assert match, (
                    f"{name}.{prop} publishes {value!r}, which is not a digest "
                    f"in either the '<algorithm>:<hex>' or the bare-hex spelling"
                )
                algorithm, hexdigits = match.group(1), match.group(2)
                if algorithm is not None:
                    assert algorithm in _DIGEST_ALGORITHMS, (
                        f"{name}.{prop} labels its example {algorithm!r}, which is "
                        f"not one of {sorted(_DIGEST_ALGORITHMS)}"
                    )
                    expected = _DIGEST_ALGORITHMS[algorithm]
                    assert len(hexdigits) == expected, (
                        f"{name}.{prop} publishes {value!r}: {algorithm} is a "
                        f"{expected}-character digest and the example has "
                        f"{len(hexdigits)}. No digest gate in the package can "
                        f"accept it without being weakened, so the example is "
                        f"the defect, not the gate."
                    )
    assert checked, "the hash-example sweep found nothing; it is not reading the contract"





# -- An example must describe a receipt the kernel can produce ----------------


def _example_receipts(doc: dict) -> list[tuple[str, str, tuple[str, ...]]]:
    """Every published example that is a block receipt: where, layer, codes.

    A block receipt is the only shape the contract publishes that names both a
    layer and a set of action codes, so the two sweeps below need nothing
    else. The layer is read rather than assumed, because the question this
    answers is which layer is being claimed to have produced which code.
    """
    found: list[tuple[str, str, tuple[str, ...]]] = []
    for where, _schema, value in _published_examples(doc):
        if isinstance(value, dict) and isinstance(value.get("action_codes"), list):
            found.append((where, value.get("layer"), tuple(value["action_codes"])))
    return found


def test_every_action_code_a_published_example_names_is_a_contract_member():
    """Membership: a typo in an example becomes a failure, not a receipt.

    `CONTRACT_VIOLATION` remained in the `ActionCode` enum after layer 3
    began emitting `UNSHIFTED_DATE` and `LEFTOVER_PATTERN_MATCH` for two of
    its conditions, so an example naming the old codes kept validating while
    describing a receipt the kernel cannot produce. Membership is necessary
    and not sufficient; the next test is the sufficient half.
    """
    doc = _contract()
    members = set(doc["components"]["schemas"]["ActionCode"]["enum"])
    receipts = _example_receipts(doc)
    assert receipts, "the receipt sweep found nothing; it is not reading the contract"
    off_contract = {
        where: sorted(set(codes) - members)
        for where, _layer, codes in receipts
        if set(codes) - members
    }
    assert not off_contract, (
        f"examples name codes that are not ActionCode members: {off_contract}"
    )


#: The `(layer, code)` pairs a published example advertises for a layer the
#: package has not written: the request-shape gate `J` names two codes that
#: nothing emits, because the component that would emit them does not exist.
#: `E` is here for one code only, and the reason is a decision rather than an
#: omission: the policy engine blocks an unresolved disposition under the
#: disposition's own code, because the layer that raised it is the one a reader
#: has to look at. A second engine-level code for that same refusal would give
#: one refusal two different receipts depending on which component the caller
#: asked. Every other pair must be found by the AST emission sweep in
#: `test_openapi_contract.py`; component `F`'s two codes were removed from this
#: list when the gateway was written, and its own `HASH_MISMATCH` was never here
#: because no published example carries it.
#:
#: This is a list of pending implementation, not of tolerated failures, and
#: `test_a_pending_pair_is_not_already_emitted` fails the moment one of them
#: *is* emitted and left behind — the signal being to delete the entry, not to
#: widen the exemption.
_NOT_YET_EMITTED: frozenset[tuple[str, str]] = frozenset(
    {
        ("J", "ARBITRARY_DICOM_OBJECT_REJECTED"),
        ("J", "FREE_FORM_PROMPT_REJECTED"),
        ("E", "UNRESOLVED_DISPOSITION"),
    }
)


def test_every_action_code_a_published_example_shows_is_reachable_or_declared_pending():
    """The reachability half: a legal code the kernel never emits is a lie.

    A code in the `ActionCode` enum only has to be *legal*; nothing about the
    enum says the kernel produces it, so an example is free to describe a
    block that cannot happen. This is the weaker of the two readings of
    "reachable" — it is static, resolving each code through the AST emission
    sweep rather than by running the kernel and observing a receipt. The gap
    that leaves is stated on `test_a_pending_pair_is_not_already_emitted` — a
    code is matched against every emission site in the package rather than
    against the layer that emitted it — and the example that was wrong is
    closed by execution instead, in
    `test_the_contract_publishes_a_d3_receipt_this_layer_actually_produces`
    in `test_redaction_layers.py`.
    """
    emitted = {code for codes in _emitted_action_codes().values() for code in codes}
    receipts = _example_receipts(_contract())
    reachable = [
        (where, layer, code)
        for where, layer, codes in receipts
        for code in codes
        if code in emitted
    ]
    assert reachable, (
        "no example code resolved to an emission site; the sweep is reading "
        "nothing, so the assertion below would pass vacuously"
    )
    unreachable = {
        f"{where} at {layer}": sorted(
            {
                code
                for code in codes
                if code not in emitted and (layer, code) not in _NOT_YET_EMITTED
            }
        )
        for where, layer, codes in receipts
        if any(
            code not in emitted and (layer, code) not in _NOT_YET_EMITTED
            for code in codes
        )
    }
    assert not unreachable, (
        f"examples show codes the kernel never emits, at layers it does "
        f"implement: {unreachable}"
    )


def test_a_pending_pair_is_not_already_emitted():
    """Keeps the exemption honest in the direction that matters.

    The gap in the sweep above: a code is matched against the *union* of every
    emission site in the package, not against the layer that emitted it. A
    pending pair that the kernel has since started emitting is a stale entry,
    and staleness is how an exemption quietly becomes a dumping ground.
    """
    emitted = {code for codes in _emitted_action_codes().values() for code in codes}
    stale = sorted(
        f"{layer}/{code}" for layer, code in _NOT_YET_EMITTED if code in emitted
    )
    assert not stale, (
        f"{stale} are listed as pending implementation but the package emits "
        "them; delete them from _NOT_YET_EMITTED so they are checked for reachability"
    )


def test_the_pending_pairs_are_exactly_the_ones_the_contract_actually_publishes():
    """The exemption names pairs that exist, and omits none that are pending.

    Equality in both directions against the contract, so the list cannot
    quietly grow to cover a real failure: an entry that no example publishes
    is dead, and a published pair that nothing emits must be listed or the
    sweep above fails.
 """
    emitted = {code for codes in _emitted_action_codes().values() for code in codes}
    published = {
        (layer, code)
        for _where, layer, codes in _example_receipts(_contract())
        for code in codes
        if code not in emitted
    }
    assert _NOT_YET_EMITTED == published

#: Reserved members of the `ActionCode` enum that no published example carries,
#: so the example-reachability sweep above cannot see them: there is no example
#: for them to be unreachable *in*, and `_NOT_YET_EMITTED` is deliberately held
#: equal to the pairs the contract's own examples advertise, so adding them
#: there would fail the equality assertion above.
#:
#: Both belong to component J, which is not written. They are recorded rather
#: than left implicit because a code that nothing tracks is a code that nothing
#: would catch: the sweep below is the only direction available to them, and it
#: is the direction that matters — the moment the package starts emitting one,
#: the contract's description is claiming a reserved code is implemented, and
#: that is a claim about behaviour.
#:
#: Deliberately *not* merged into `_NOT_YET_EMITTED`. Widening the
#: example-reachability exemption to hold codes no example advertises would make
#: that set a place where a real failure could hide, which is exactly what the
#: equality assertion exists to prevent.
_RESERVED_NOT_ADVERTISED: frozenset[str] = frozenset(
    {"FUNCTION_NOT_PERMITTED", "UNAUTHORIZED_SCOPE"}
)


def test_a_reserved_unadvertised_code_is_not_already_emitted():
    """The staleness check for the codes the example sweep cannot see.

    The same signal as `test_a_pending_pair_is_not_already_emitted`, and for the
    same reason — a stale reservation is how a contract's claim about what is
    implemented quietly stops being true. The fix is always to delete the entry
    and let whichever sweep can see the code take over from there.
    """
    emitted = {code for codes in _emitted_action_codes().values() for code in codes}
    stale = sorted(_RESERVED_NOT_ADVERTISED & emitted)
    assert not stale, (
        f"{stale} are reserved for an unwritten component and appear in no "
        f"published example, but the package now emits them; delete them from "
        f"_RESERVED_NOT_ADVERTISED and decide whether the contract still "
        f"describes them as unimplemented"
    )


def test_the_reserved_unadvertised_codes_are_still_reserved_in_the_contract():
    """The declaration matches the artefact: still enum members, still no example.

    Two halves, and both are what make the declaration mean anything. If a code
    left this set the contract would stop describing it as reserved. If an
    example started carrying it, it would become reachable-by-example and belong
    in `_NOT_YET_EMITTED`, where the example-reachability sweep can enforce it —
    and this says so, rather than leaving the move to be discovered later as a
    stale reservation.
    """
    doc = _contract()
    members = set(doc["components"]["schemas"]["ActionCode"]["enum"])
    advertised = {
        code for _where, _layer, codes in _example_receipts(doc) for code in codes
    }
    missing = sorted(_RESERVED_NOT_ADVERTISED - members)
    assert not missing, (
        f"{missing} are declared reserved here but are not members of the "
        f"ActionCode enum"
    )
    newly_advertised = sorted(_RESERVED_NOT_ADVERTISED & advertised)
    assert not newly_advertised, (
        f"{newly_advertised} now appear in a published example, so they are "
        f"reachable-by-example and belong in _NOT_YET_EMITTED, not here"
    )


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
    """The payload fields one metadata property actually fills, in *any* function.

    Every function in `ALLOWED_FIELDS`, not just `draft`. A field is either
    carried or dropped, and which one it is depends on the function: `Modality`
    is carried by all three, `prior_report_text` only by `Prior Summary` and
    `Ask`. Resolving against `draft` alone hardcoded an assumption that every
    contract property is reachable from one function, and that assumption is
    what kept `PriorReportText` out of the contract in the first place — the one
    allowlisted attribute whose value redaction layer 2 actually scans, and so
    the one a caller most needs to be able to send.

    A property that *no* function carries is still accepted, not refused, so
    `ExtractionError` is not a failure here; it is the "dropped" half of the
    claim the caller of this function makes about it.
    """
    examples = subschema.get("examples") or []
    value = str(examples[0]) if examples else "SYNTHETIC"
    carried: set[str] = set()
    refused: dict[str, tuple] = {}
    for function in ALLOWED_FIELDS:
        study = StudyContext(
            study_uid=_STUDY.study_uid, study_ref=_STUDY.study_ref,
            patient_ref=_STUDY.patient_ref, function=function,
        )
        try:
            payload = pipeline_for(function, study, "text", {keyword: value}, "pv-1")
        except ExtractionError as exc:
            refused[function] = exc.action_codes
            continue
        carried |= set(payload.dicom_fields)
    if refused and not carried:
        # Refused by every function is a different condition from refused by
        # one: a property no function can carry is a boundary that does not
        # accept it at all, which is a defect in the contract, not a policy.
        pytest.fail(
            f"contract property {keyword}={value!r} is refused at layer A by every "
            f"function: {refused}"
        )
    return carried


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
