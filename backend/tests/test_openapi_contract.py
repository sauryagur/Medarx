"""Conformance between the emitted action codes and the normative contract.

The contract used to live in the gitignored `.docs/`, which made it
unversioned while the code depending on it was versioned: a contract that can
vanish is not a contract. It now lives in `contracts/openapi.yaml` at the repo
root and is tracked.

The sweep below is the durable part. It reads every emission site in
`backend/src/medarx/` rather than a hand-written list, so adding a code
without adding it to the contract fails here, and dropping a member the code
still emits fails here too.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
import yaml

#: Repo root, resolved from this file so the test works from any CWD.
REPO_ROOT = Path(__file__).resolve().parents[2]
CONTRACT = REPO_ROOT / "contracts" / "openapi.yaml"
SOURCE_ROOT = REPO_ROOT / "backend" / "src" / "medarx"

REQUIRED_TOP_LEVEL_KEYS = {"openapi", "info", "paths", "components"}


def _load_contract() -> dict:
    assert CONTRACT.is_file(), f"normative contract is missing: {CONTRACT}"
    with CONTRACT.open(encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    assert isinstance(doc, dict), "contract must parse as a YAML mapping"
    return doc

#: Modules expected to emit action codes. Asserted as an exact set by
#: `test_the_sweep_actually_finds_emission_sites`, so the guard fails when
#: coverage narrows or a new emitter appears, rather than on a count threshold.
EXPECTED_EMISSION_SITES: frozenset[str] = frozenset(
    {"backend/src/medarx/extraction/payload_extractor.py"}
)


def test_contract_parses_and_declares_the_required_top_level_keys():
    doc = _load_contract()
    missing = REQUIRED_TOP_LEVEL_KEYS - set(doc)
    assert not missing, f"contract is missing top-level keys: {sorted(missing)}"


def _contract_action_codes() -> set[str]:
    schema = _load_contract()["components"]["schemas"]["ActionCode"]
    codes = schema["enum"]
    assert isinstance(codes, list) and codes, "ActionCode must declare a non-empty enum"
    assert len(set(codes)) == len(codes), "ActionCode enum contains a duplicate member"
    return set(codes)


def _string_literals(node: ast.AST) -> list[str]:
    return [
        elt.value
        for elt in ast.walk(node)
        if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
    ]


def _emitted_action_codes() -> dict[str, list[str]]:
    """Every action code this package can emit, keyed by source file.

    Two shapes are collected, and a third is resolved through to the second:

    - a string literal passed directly as `action_codes=("X",)`;
    - a module-level constant whose name marks it as an action-code collection
      (contains `ACTION_CODE`), such as a shared `CODES` tuple;
    - `action_codes=SOME_CONSTANT`, where the argument is a `Name` rather than
      a literal. The name is resolved to its module-level assignment and the
      string elements of that assignment are collected, so routing an
      emission through a constant does not hide it from the sweep.

    All three are found by parsing, so a new site cannot be missed by
    forgetting to register it here.
    """
    found: dict[str, list[str]] = {}
    for path in sorted(SOURCE_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

        # Every module-level assignment — plain and annotated alike, since
        # `CODES: tuple[str, ...] = ("X",)` is the natural way to write one —
        # so an `action_codes=NAME` argument can be resolved to its value.
        assignments: dict[str, ast.AST] = {}
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        assignments[target.id] = node.value
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                if node.value is not None:
                    assignments[node.target.id] = node.value

        codes: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg != "action_codes":
                        continue
                    if isinstance(kw.value, ast.Name):
                        resolved = assignments.get(kw.value.id)
                        assert resolved is not None, (
                            f"{path.relative_to(REPO_ROOT)}: action_codes="
                            f"{kw.value.id!r} does not resolve to a module-level "
                            "assignment; the sweep cannot see what it emits"
                        )
                        codes.extend(_string_literals(resolved))
                    else:
                        codes.extend(_string_literals(kw.value))
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if any(
                    isinstance(t, ast.Name) and "ACTION_CODE" in t.id.upper()
                    for t in targets
                ):
                    codes.extend(_string_literals(node.value))
        if codes:
            found[str(path.relative_to(REPO_ROOT))] = codes
    return found


def test_the_sweep_actually_finds_emission_sites():
    """Guard against a sweep whose coverage quietly narrows.

    A count threshold cannot detect narrowing: it keeps passing as sites
    disappear, right up until the sweep finds nothing at all. So this asserts
    the exact set of modules expected to emit, which fails if a known emission
    site is removed *or* renamed, and fails if a new module starts emitting
    without the guard being updated to say so. Updating this set is the point:
    it is a statement of where codes are emitted, not a liveness ping.
    """
    emitted = _emitted_action_codes()
    assert set(emitted) == EXPECTED_EMISSION_SITES, (
        "the set of modules emitting action codes does not match "
        "EXPECTED_EMISSION_SITES. An empty result means the sweep stopped "
        "finding emission sites and is broken — it would then pass silently "
        "while an off-contract code shipped. A changed set means a site was "
        "removed, renamed, or added and EXPECTED_EMISSION_SITES must be "
        "updated deliberately. "
        f"swept {SOURCE_ROOT.relative_to(REPO_ROOT)}; "
        f"expected={sorted(EXPECTED_EMISSION_SITES)}; found={sorted(emitted)}"
    )


def test_every_emitted_action_code_is_in_the_contract():
    contract_codes = _contract_action_codes()
    emitted = _emitted_action_codes()
    assert emitted, (
        f"no action_codes emission sites were found under "
        f"{SOURCE_ROOT.relative_to(REPO_ROOT)}; the sweep is broken"
    )
    offenders = {
        source: sorted(set(codes) - contract_codes)
        for source, codes in emitted.items()
        if set(codes) - contract_codes
    }
    assert not offenders, (
        "action codes emitted by the code but absent from the "
        f"ActionCode enum in {CONTRACT.name}: {offenders}"
    )


@pytest.mark.parametrize("code", sorted(_contract_action_codes()))
def test_contract_member_is_non_empty_upper_snake_case(code):
    assert code and code.replace("_", "").isupper(), f"malformed ActionCode member: {code!r}"


#: Fields `AuditEvent` carries that the contract's `AuditRecord` does not
#: model, each with the reason it is legitimate rather than a naming drift.
#: Asserted by `test_audit_event_names_match_the_contract_audit_record`.
_AUDIT_STORAGE_ONLY_FIELDS: frozenset[str] = frozenset(
    {"chain_hash", "previous_hash"}
)

#: Fields the contract's `AuditRecord` models that the stored event deliberately
#: lacks, because the contract defines them as results computed on read.
_AUDIT_COMPUTED_ON_READ: frozenset[str] = frozenset({"chain_verified"})


def _contract_layer_tags() -> set[str]:
    schema = _load_contract()["components"]["schemas"]["Layer"]
    return set(schema["enum"])


#: Module-level or class-level names whose assignment declares the layer tags
#: the code can emit. Named without `ACTION_CODE` so `_emitted_action_codes` —
#: which keys off that substring — cannot mistake this declaration for an
#: action-code emission site.
_LAYER_CONSTANTS = frozenset({"LAYER", "LAYERS"})

#: Modules expected to declare layer tags, asserted as an exact set by
#: `test_the_layer_sweep_finds_every_declaration_site`, so an empty sweep
#: cannot make the equality assertion pass vacuously.
EXPECTED_LAYER_SITES: frozenset[str] = frozenset(
    {
        "backend/src/medarx/errors.py",
        "backend/src/medarx/extraction/payload_extractor.py",
        "backend/src/medarx/models.py",
    }
)

def _emitted_layer_tags() -> dict[str, list[str]]:
    """Every layer tag this package can emit, keyed by source file.

    Three declaration shapes carry a layer tag, all collected by parsing so a
    new one cannot be added without appearing here: the `LAYER = "..."` class
    attribute each error class fixes, the `LAYERS` tuple that mirrors the enum,
    and the `layer: Literal[...]` annotation on the receipt. Sweeping every
    `Literal` in the package instead would sweep in unrelated closed sets —
    `status`, `final_disposition`, a sign-off decision — and compare those
    against the layer enum, which is not what this test is about.

    Note on naming: no constant in the swept source carries `ACTION_CODE` in
    its name, so this walk cannot be mistaken for an action-code emission site
    by `_emitted_action_codes`.
    """
    found: dict[str, list[str]] = {}
    for path in sorted(SOURCE_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

        tags: list[str] = []
        for node in ast.walk(tree):
            # LAYER = "A" on an error class: the tag a refusal carries.
            if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id in _LAYER_CONSTANTS for t in node.targets
            ):
                tags.extend(_string_literals(node.value))
            # layer: Literal["J", "A", ...] on the receipt: the tag on the wire.
            elif (
                isinstance(node, ast.AnnAssign)
                and isinstance(node.target, ast.Name)
                and node.target.id == "layer"
                and isinstance(node.annotation, ast.Subscript)
                and _is_literal_subscript(node.annotation.value)
            ):
                tags.extend(_string_literals(node.annotation.slice))

        if tags:
            found[str(path.relative_to(REPO_ROOT))] = tags
    return found


def _is_literal_subscript(value: ast.AST) -> bool:
    """True for `Literal[...]`, the only subscript carrying layer tags here."""
    if isinstance(value, ast.Name):
        return value.id == "Literal"
    if isinstance(value, ast.Attribute):
        return value.attr == "Literal"
    return False


def test_the_layer_sweep_finds_every_declaration_site():
    """Guard against a layer sweep that has quietly stopped seeing anything.

    An empty result would make the equality assertion below pass vacuously —
    an empty code-side set is trivially "equal" to nothing, and the test would
    then guard nothing. So the sites are named: each file that declares a layer
    tag must be found.
    """
    emitted = _emitted_layer_tags()
    assert set(emitted) == EXPECTED_LAYER_SITES, (
        "the set of modules declaring layer tags does not match "
        "EXPECTED_LAYER_SITES. An empty result means the sweep stopped finding "
        "declaration sites and is broken — it would then pass silently while an "
        "off-contract layer shipped. A changed set means a site was removed, "
        "renamed, or added and EXPECTED_LAYER_SITES must be updated "
        f"deliberately. swept {SOURCE_ROOT.relative_to(REPO_ROOT)}; "
        f"expected={sorted(EXPECTED_LAYER_SITES)}; found={sorted(emitted)}"
    )


def test_the_code_layer_set_equals_the_contract_enum():
    """Equality, not containment: a missing tag on either side is a defect.

    Containment alone would not have caught the drift that motivated this test —
    the contract gaining a tag the code has never heard of. The receipt's
    `layer` is a `Literal`, so an off-contract tag cannot be produced at all,
    and a tag the contract names but the code lacks would be silently
    unproducible. Both directions are therefore defects.
    """
    contract_tags = _contract_layer_tags()
    emitted = _emitted_layer_tags()
    assert emitted, (
        f"no layer declaration sites were found under "
        f"{SOURCE_ROOT.relative_to(REPO_ROOT)}; the sweep is broken"
    )
    code_tags = {tag for tags in emitted.values() for tag in tags}
    assert code_tags == contract_tags, (
        "the layer tags the code can emit differ from the Layer enum in "
        f"{CONTRACT.name}: "
        f"in_code_not_in_contract={sorted(code_tags - contract_tags)}, "
        f"in_contract_not_in_code={sorted(contract_tags - code_tags)}; "
        f"declared in {sorted(emitted)}"
    )


@pytest.mark.parametrize("tag", sorted(_contract_layer_tags()))
def test_contract_layer_tag_is_non_empty_string(tag):
    assert isinstance(tag, str) and tag.strip() == tag and tag, (
        f"malformed Layer member: {tag!r}"
    )


def _audit_record_properties() -> set[str]:
    schema = _load_contract()["components"]["schemas"]["AuditRecord"]
    return set(schema["properties"])


def test_audit_event_names_match_the_contract_audit_record():
    """Pin the shared field names; do not pretend the two sets are identical.

    `AuditEvent` is the storage-side event and the contract's `AuditRecord` is
    the API-facing schema, so the sets differ by design: the event adds
    `chain_hash` and `previous_hash` (tamper-evidence inputs the contract
    describes but does not schema) and omits `chain_verified` (computed on
    read). What must never drift is the naming of the fields both have — a
    storage field called `model` behind a readback that expects `selected_model`
    is a silent read-time miss, not an error.
    """
    from medarx.models import AuditEvent

    event_fields = set(AuditEvent.model_fields)
    contract_fields = _audit_record_properties()

    shared = event_fields & contract_fields
    assert shared, (
        "the event and the contract schema share no field names; the "
        "comparison below would be vacuous"
    )
    event_only = {
        f for f in event_fields - contract_fields
        if f not in _AUDIT_STORAGE_ONLY_FIELDS
    }
    assert not event_only, (
        "AuditEvent carries fields the contract does not model and that are "
        f"not declared storage-side: {sorted(event_only)}; declare them in "
        "_AUDIT_STORAGE_ONLY_FIELDS with a reason, or rename them to the "
        "contract's name"
    )
    assert not (contract_fields - event_fields - _AUDIT_COMPUTED_ON_READ), (
        "the contract's AuditRecord models fields the stored event does not "
        "have, other than those computed on read: "
        f"{sorted(contract_fields - event_fields - _AUDIT_COMPUTED_ON_READ)}"
    )
