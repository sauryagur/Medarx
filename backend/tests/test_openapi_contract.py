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


def _emitted_action_codes() -> dict[str, list[str]]:
    """Every action code literal this package can emit, keyed by source file.

    An emission site is a string literal appearing in an `action_codes=`
    keyword argument, or a string literal in a module-level constant whose
    name marks it as an action-code collection. Both shapes are found by
    parsing, so a new site cannot be missed by forgetting to register it here.
    """
    found: dict[str, list[str]] = {}
    for path in sorted(SOURCE_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        codes: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg == "action_codes":
                        codes.extend(
                            elt.value
                            for elt in ast.walk(kw.value)
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
                        )
            elif isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and "ACTION_CODE" in t.id.upper()
                for t in node.targets
            ):
                codes.extend(
                    elt.value
                    for elt in ast.walk(node.value)
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
                )
        if codes:
            found[str(path.relative_to(REPO_ROOT))] = codes
    return found


def test_the_sweep_actually_finds_emission_sites():
    """Guard against a sweep that silently matches nothing."""
    emitted = _emitted_action_codes()
    assert emitted, (
        "no action_codes emission sites were found under "
        f"{SOURCE_ROOT.relative_to(REPO_ROOT)}; the sweep is broken"
    )
    assert sum(len(v) for v in emitted.values()) >= 3


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
