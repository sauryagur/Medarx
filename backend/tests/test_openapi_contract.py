"""Conformance between the emitted action codes and the normative contract.

The contract used to live in the gitignored `.docs/`, which made it
unversioned while the code depending on it was versioned: a contract that can
vanish is not a contract. It now lives in `contracts/openapi.yaml` at the repo
root and is tracked.

The sweep below is the durable part. It reads every emission site in
`backend/src/medarx/` rather than a hand-written list, so adding a code
without adding it to the contract fails here, and dropping a member the code
still emits fails here too. A name the sweep cannot resolve to a module-level
assignment is an assertion failure rather than a skipped element, so a route
it cannot read is reported instead of passing quietly.
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
    {
        "backend/src/medarx/extraction/payload_extractor.py",
        "backend/src/medarx/pseudonym/pseudonymize.py",
        # Component D. The redaction layers name every wire code they can emit
        # as a module constant so this sweep covers them; the orchestrator adds
        # the one code it can raise on its own.
        "backend/src/medarx/redaction/layers.py",
        "backend/src/medarx/redaction/pipeline.py",
        # Component E. The policy engine names every wire code it can put in a
        # receipt as a module constant, including the codes its internal
        # reasons translate to, so the sweep covers what component J will
        # serialise.
        "backend/src/medarx/policy/policy_engine.py",
        # Component F. The gateway names every wire code it can put in a
        # receipt as a module constant, including `HASH_MISMATCH`, which no
        # other component emits and which was in the contract enum before this
        # one was written.
        "backend/src/medarx/gateway/openai_gateway.py",
    }
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


def _module_assignments(tree: ast.Module) -> dict[str, ast.AST]:
    """Every module-level assignment target -> value node.

    Plain and annotated alike, since `CODES: tuple[str, ...] = ("X",)` is the
    natural way to write one.
    """
    assignments: dict[str, ast.AST] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assignments[target.id] = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.value is not None:
                assignments[node.target.id] = node.value
    return assignments


def _codes_in_value(node: ast.AST, assignments: dict[str, ast.AST], where: str,
                     seen: frozenset[str] = frozenset()) -> list[str]:
    """The action codes in an `action_codes=` value, resolving names.

    A `Name` is resolved to its module-level assignment **at any depth** — as
    the whole argument (`action_codes=CODES`), as an element of a tuple or
    list (`action_codes=(_CODE,)`), behind a star (`action_codes=(*CODES,)`),
    or in either arm of a conditional (`X if flag else Y`). Only names are
    resolved; other nodes are read for their string literals, so this does not
    over-collect unrelated strings that merely happen to sit inside the value.

    `Starred` and `IfExp` are handled explicitly for the reason below: both used
    to fall through to the string-literal reader, which walks past a `Name` and
    returns `[]`. A site written `action_codes=(*CODES,)` was therefore reported
    as emitting nothing while emitting everything, which is the quietest way
    for a sweep to stop working.

    An unresolvable name is an assertion failure, never a silent skip: the
    sweep must be able to say "I could not look here" rather than reporting
    nothing and looking like it found nothing.
    """
    if isinstance(node, ast.Name):
        # Recurse rather than read for string literals, so a name that resolves
        # to a *collection* of names -- `CODES = (*_BASE, *_MORE)` -- is seen
        # through the same rules as one written inline. `seen` stops a name that
        # resolves to itself (`CODES = (*CODES,)`) from recursing forever; such
        # a collection emits nothing new anyway.
        resolved = assignments.get(node.id)
        assert resolved is not None, (
            f"{where}: action_codes={node.id!r} does not resolve to a "
            "module-level assignment; the sweep cannot see what it emits"
        )
        if node.id in seen:
            return []
        return _codes_in_value(resolved, assignments, where, seen | {node.id})
    if isinstance(node, (ast.Tuple, ast.List)):
        codes: list[str] = []
        for element in node.elts:
            codes.extend(_codes_in_value(element, assignments, where, seen))
        return codes
    if isinstance(node, ast.Starred):
        # `action_codes=(*CODES,)`. The starred value *is* the tuple, so it is
        # resolved exactly as one written without the star would be. Handled
        # here rather than left to `_string_literals`, which walks straight
        # past a `Name` and reports nothing — a coverage gap that reads as
        # "this site emits nothing", which is the quietest way for a sweep to
        # stop working.
        return _codes_in_value(node.value, assignments, where, seen)
    if isinstance(node, ast.IfExp):
        # `action_codes=(X if flag else Y)`. Both arms are read, because either
        # can be the one that ships, and a conditional is the one shape where
        # reading only the "then" would under-report what a module can emit.
        return (_codes_in_value(node.body, assignments, where, seen)
                + _codes_in_value(node.orelse, assignments, where, seen))
    return _string_literals(node)


def test_a_starred_code_collection_is_read_rather_than_reported_as_silent():
    # The regression this exists for. `*CODES` is a natural way to extend a
    # shared tuple, and while only `Name`, `Tuple` and `List` were handled the
    # starred value fell through to the string reader, which walks past a
    # `Name` and returns nothing — so a site emitting three codes was recorded
    # as emitting none, with the suite green.
    snippet = (
        '_BASE = ("FIRST_CODE",)\n'
        '_MORE = ("SECOND_CODE", "THIRD_CODE")\n'
        "CODES = (*_BASE, *_MORE)\n"
        "def refuse():\n"
        "    raise Refusal(action_codes=(*CODES,))\n"
    )
    assert _emitted_codes_in_tree(ast.parse(snippet), "snippet.py") == [
        "FIRST_CODE", "SECOND_CODE", "THIRD_CODE",
    ]


def test_both_arms_of_a_conditional_are_read():
    # Either arm can be the one that ships, so reading only the "then" would
    # under-report what a module can emit — the same quiet failure as the star.
    snippet = (
        '_THEN = ("THEN_CODE",)\n'
        '_ELSE = ("ELSE_CODE",)\n'
        "def refuse(flag):\n"
        "    raise Refusal(action_codes=_THEN if flag else _ELSE)\n"
    )
    assert sorted(_emitted_codes_in_tree(ast.parse(snippet), "snippet.py")) == [
        "ELSE_CODE", "THEN_CODE",
    ]


def test_an_unresolvable_name_behind_a_star_still_fails():
    # Handling the star must not have introduced a new quiet path: a name that
    # is not a module-level assignment is still a broken sweep, not a clean one.
    snippet = (
        "def refuse():\n"
        "    raise Refusal(action_codes=(*_NEVER_ASSIGNED_,))\n"
    )
    with pytest.raises(AssertionError, match="does not resolve to a module-level"):
        _emitted_codes_in_tree(ast.parse(snippet), "snippet.py")


def _emitted_codes_in_tree(tree: ast.Module, where: str) -> list[str]:
    """The action codes emitted anywhere in one parsed module."""
    assignments = _module_assignments(tree)
    codes: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg == "action_codes":
                    codes.extend(_codes_in_value(kw.value, assignments, where))
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(
                isinstance(t, ast.Name) and "ACTION_CODE" in t.id.upper()
                for t in targets
            ):
                # An annotated *declaration* with no value emits nothing — a
                # dataclass field such as `action_code: str` matches the name
                # filter and carries no code. Skipping it is not a silent skip
                # of an emission, which is what the unresolvable-name assertion
                # below exists to prevent; there is nothing here to resolve.
                if node.value is not None:
                    codes.extend(_string_literals(node.value))
    return codes


def _emitted_action_codes() -> dict[str, list[str]]:
    """Every action code this package can emit, keyed by source file.

    Three shapes are collected, and every name is resolved to the module's
    top-level assignment before its strings are read:

    - a string literal passed directly as `action_codes=("X",)`;
    - a module-level constant whose name marks it as an action-code collection
      (contains `ACTION_CODE`), such as a shared `CODES` tuple;
    - an `action_codes=` value that *names* a module-level constant, whether
      bare (`action_codes=CODES`) or nested inside the tuple
      (`action_codes=(_CODE,)`).

    A name that resolves to nothing is an assertion failure, not a skipped
    element — see `_codes_in_value`. All three are found by parsing, so a new
    site cannot be missed by forgetting to register it here.
    """
    found: dict[str, list[str]] = {}
    for path in sorted(SOURCE_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        codes = _emitted_codes_in_tree(tree, str(path.relative_to(REPO_ROOT)))
        if codes:
            found[str(path.relative_to(REPO_ROOT))] = codes
    return found


def test_a_name_nested_in_a_tuple_is_resolved_rather_than_skipped():
    # The regression this exists for: `action_codes=(_CODE,)` is a natural way
    # to write an emission, and while names were resolved only as the whole
    # argument, the sweep read the tuple, found no string constant in it, and
    # reported nothing — leaving the code uncovered with the suite still green.
    snippet = (
        '_CODE = "SOME_CODE"\n'
        "def refuse():\n"
        "    raise Refusal(action_codes=(_CODE,))\n"
    )
    assert _emitted_codes_in_tree(ast.parse(snippet), "snippet.py") == ["SOME_CODE"]


def test_a_name_nested_in_a_list_is_resolved_too():
    snippet = (
        '_CODE = "SOME_CODE"\n'
        "def refuse():\n"
        "    raise Refusal(action_codes=[_CODE])\n"
    )
    assert _emitted_codes_in_tree(ast.parse(snippet), "snippet.py") == ["SOME_CODE"]


def test_a_bare_name_and_a_tuple_of_literals_still_resolve():
    snippet = (
        "CODES = ('FIRST_CODE',)\n"
        "def a():\n"
        "    raise Refusal(action_codes=CODES)\n"
        "def b():\n"
        "    raise Refusal(action_codes=('SECOND_CODE',))\n"
    )
    codes = _emitted_codes_in_tree(ast.parse(snippet), "snippet.py")
    assert sorted(codes) == ["FIRST_CODE", "SECOND_CODE"]


def test_an_unresolvable_name_fails_the_sweep_instead_of_being_skipped():
    # Silence must mean "nothing to find", never "I could not look": a name
    # that is not a module-level assignment cannot be resolved, and that is a
    # broken sweep rather than a clean result.
    snippet = (
        "def refuse():\n"
        "    raise Refusal(action_codes=(_NEVER_ASSIGNED_,))\n"
    )
    with pytest.raises(AssertionError, match="does not resolve to a module-level"):
        _emitted_codes_in_tree(ast.parse(snippet), "snippet.py")


def test_the_sweep_sees_every_code_component_c_emits():
    emitted = _emitted_action_codes()
    codes = set(emitted["backend/src/medarx/pseudonym/pseudonymize.py"])
    assert codes == {
        "MISSING_SURROGATE",
        "SURROGATE_SHAPED_REFERENCE_REJECTED",
        "UNSHIFTED_DATE",
    }


def test_the_sweep_sees_every_code_component_d_emits():
    # The exact set, not a count. A code that stops being emitted is as much a
    # defect as one that starts: the block condition it named would be
    # unreachable, and the design's enforcement table would be describing
    # something the kernel no longer does.
    emitted = _emitted_action_codes()
    assert set(emitted["backend/src/medarx/redaction/layers.py"]) == {
        "NER_UNRESOLVED",
        "LOW_CONFIDENCE_NER_UNRESOLVED",
        "UNSHIFTED_DATE",
        "UNRESOLVED_EMPTY_BODY",
        "DETERMINISTIC_REPLACEMENT_FAILED",
        "MISSING_SURROGATE",
        "FIELD_NOT_ALLOWLISTED",
        "UNKNOWN_FUNCTION",
        "CONTRACT_VIOLATION",
        "LEFTOVER_PATTERN_MATCH",
    }
    assert set(emitted["backend/src/medarx/redaction/pipeline.py"]) == {
        "UNAPPROVED_PAYLOAD",
    }


def test_no_internal_code_is_named_as_if_it_reached_the_wire():
    # The layers record a successful replacement and an untouched relative
    # interval under internal codes that are never serialised. Those names
    # deliberately avoid the `ACTION_CODE` substring, which is what keeps them
    # out of the sweep above; this asserts that from the other side, so a rename
    # that made one look like a wire code would fail here rather than shipping
    # an internal code in a receipt.
    emitted = _emitted_action_codes()
    for source in ("backend/src/medarx/redaction/layers.py",
                   "backend/src/medarx/redaction/pipeline.py"):
        assert "REDACT_LAYER" not in "".join(emitted[source])


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
#: `stages` joined `chain_verified` here when the `PipelineStage` enum was wired:
#: both are projections, neither is stored, and neither enters the chain body —
#: which is what keeps every already-chained record's digest unchanged.
_AUDIT_COMPUTED_ON_READ: frozenset[str] = frozenset({"chain_verified", "stages"})


def _contract_layer_tags() -> set[str]:
    schema = _load_contract()["components"]["schemas"]["Layer"]
    return set(schema["enum"])


#: Module-level or class-level names whose assignment declares a single layer
#: tag (an error class's `LAYER`). Named without `ACTION_CODE` so
#: `_emitted_action_codes` — which keys off that substring — cannot mistake this
#: declaration for an action-code emission site.
_LAYER_CONSTANTS = frozenset({"LAYER", "LAYERS"})

#: The declaration that enumerates the whole set, as opposed to naming one tag.
#: Every such declaration is asserted equal to the contract enum on its own, so
#: two copies of the set cannot drift apart while their union still matches.
_LAYER_FULL_SET_CONSTANTS = frozenset({"LAYERS"})

#: Modules expected to declare layer tags, asserted as an exact set by
#: `test_the_layer_sweep_finds_every_declaration_site`, so an empty sweep
#: cannot make the equality assertions pass vacuously.
EXPECTED_LAYER_SITES: frozenset[str] = frozenset(
    {
        "backend/src/medarx/errors.py",
        "backend/src/medarx/extraction/payload_extractor.py",
        "backend/src/medarx/models.py",
    }
)


def _emitted_layer_declarations() -> dict[str, set[str]]:
    """Every layer declaration in the package, keyed by `file:line: what`.

    Three shapes carry a layer tag, all collected by parsing so a new one
    cannot be added without appearing here: the `LAYER = "..."` class attribute
    each error class fixes, the `LAYERS` tuple, and the `layer: Literal[...]`
    annotation on the receipt. Sweeping every `Literal` in the package instead
    would sweep in unrelated closed sets — `status`, `final_disposition`, a
    sign-off decision — and compare those against the layer enum, which is not
    what this test is about.

    Declarations are keyed per site, not unioned per file, on purpose. `LAYERS`
    and the receipt's `Literal` are two copies of the same set, and a union
    hides a drift in either one: break only the `Literal` and the union still
    matches the contract through `LAYERS`. Keyed per site, the broken copy is
    named in the failure.

    Note on naming: no constant in the swept source carries `ACTION_CODE` in
    its name, so this walk cannot be mistaken for an action-code emission site
    by `_emitted_action_codes`.
    """
    found: dict[str, set[str]] = {}
    for path in sorted(SOURCE_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        relative = str(path.relative_to(REPO_ROOT))

        for node in ast.walk(tree):
            # LAYER = "A" on an error class: the tag a refusal carries.
            if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id in _LAYER_CONSTANTS for t in node.targets
            ):
                name = next(t.id for t in node.targets if isinstance(t, ast.Name))
                found[f"{relative}:{node.lineno}:{name}"] = set(
                    _string_literals(node.value)
                )
            # layer: Literal["J", "A", ...] on the receipt: the tag on the wire.
            elif (
                isinstance(node, ast.AnnAssign)
                and isinstance(node.target, ast.Name)
                and node.target.id == "layer"
                and isinstance(node.annotation, ast.Subscript)
                and _is_literal_subscript(node.annotation.value)
            ):
                found[f"{relative}:{node.lineno}:layer Literal"] = set(
                    _string_literals(node.annotation.slice)
                )
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

    An empty result would make the equality assertions below pass vacuously —
    an empty code-side set is trivially "equal" to nothing, and the tests would
    then guard nothing. So the sites are named: each module that declares a
    layer tag must be found.
    """
    declarations = _emitted_layer_declarations()
    found = {site.split(":")[0] for site in declarations}
    assert found == EXPECTED_LAYER_SITES, (
        "the set of modules declaring layer tags does not match "
        "EXPECTED_LAYER_SITES. An empty result means the sweep stopped finding "
        "declaration sites and is broken — it would then pass silently while an "
        "off-contract layer shipped. A changed set means a site was removed, "
        "renamed, or added and EXPECTED_LAYER_SITES must be updated "
        f"deliberately. swept {SOURCE_ROOT.relative_to(REPO_ROOT)}; "
        f"expected={sorted(EXPECTED_LAYER_SITES)}; found={sorted(found)}"
    )


def _full_set_declarations(declarations: dict[str, set[str]]) -> dict[str, set[str]]:
    """The declarations that enumerate the whole layer set, keyed by site.

    A `LAYER = "A"` class attribute names one tag and is checked for membership
    only. `LAYERS` and the receipt's `layer: Literal[...]` each enumerate the
    entire set, so each is compared to the contract on its own.
    """
    return {
        site: tags
        for site, tags in declarations.items()
        if site.rsplit(":", 1)[-1] in _LAYER_FULL_SET_CONSTANTS
        or site.endswith("layer Literal")
    }


def test_the_code_layer_set_equals_the_contract_enum():
    """Equality, not containment: a missing tag on either side is a defect.

    Containment alone would not have caught the drift that motivated this test —
    the contract gaining a tag the code has never heard of. And because the
    set is declared twice (`LAYERS` and the receipt's `Literal`), equality is
    asserted **per declaration**: break one copy and its union still matches
    through the other, so a union-level check would pass over exactly the drift
    that matters. The failure names the divergent site.
    """
    contract_tags = _contract_layer_tags()
    declarations = _emitted_layer_declarations()
    assert declarations, (
        f"no layer declaration sites were found under "
        f"{SOURCE_ROOT.relative_to(REPO_ROOT)}; the sweep is broken"
    )

    full_sets = _full_set_declarations(declarations)
    assert full_sets, (
        "the sweep found layer declarations but none that enumerate the whole "
        f"set; the per-site equality assertion would be vacuous. found "
        f"{sorted(declarations)}"
    )
    divergent = {
        site: {
            "in_code_not_in_contract": sorted(tags - contract_tags),
            "in_contract_not_in_code": sorted(contract_tags - tags),
        }
        for site, tags in full_sets.items()
        if tags != contract_tags
    }
    assert not divergent, (
        "each declaration of the full layer set must equal the Layer enum in "
        f"{CONTRACT.name}, and these do not: {divergent}"
    )


def test_every_single_tag_layer_declaration_is_in_the_contract():
    """An error class fixing a tag the contract does not have is a defect."""
    contract_tags = _contract_layer_tags()
    declarations = _emitted_layer_declarations()
    offenders = {
        site: sorted(tags - contract_tags)
        for site, tags in declarations.items()
        if site.rsplit(":", 1)[-1] not in _LAYER_FULL_SET_CONSTANTS
        and not site.endswith("layer Literal")
        and tags - contract_tags
    }
    assert not offenders, (
        "layer tags declared by the code but absent from the Layer enum in "
        f"{CONTRACT.name}: {offenders}"
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
