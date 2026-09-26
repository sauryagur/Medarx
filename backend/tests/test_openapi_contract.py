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
    assert emitted, (
        "no action_codes emission sites were found under "
 f"{SOURCE_SOURCE}the sweep is broken"
    )
    assert set(emitted) == EXPECTED_EMISSION_SITES, (
        "the set of modules emitting action codes changed; update "
        "EXPECTED_EMISSION_SITES deliberately. "
        f"found={sorted(emitted)}"
    )


def test_every_emitted_action_code_is_in_the_contract():
    contract_codes = _contract_action_codes()
    emitted = _emitted_action_codes()
    assert emitted, "no emission sites found; the sweep is broken"
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
