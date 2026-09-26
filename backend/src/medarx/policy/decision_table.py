"""Design §6 as data: the seven rows of the fail-closed enforcement table.

§6 of the design is a table of conditions, each with a consequence, and this
module is that table transcribed — one `Rule` per row, in row order, with the
layer tag the design names. It is the single source both of what the design
says and of what the engine enforces: `policy_engine.CHECKS` is *built* from
`RULES_BY_ROW`, so a check cannot name a §6 row the table does not carry, and a
row the design adds without a check is visible as a row nothing enforces.

Keeping the transcription and the enforcement in separate objects, joined by
row, is deliberate. If they were one object, a change to the behaviour and a
change to the description could not be diffed against each other, and the table
would stop being evidence of what the kernel does.

**What `action_code` means on a `Rule`, precisely, and what it does not.**
§6 rows name several conditions, and a condition that fires is what a receipt
names — so a row has several codes, not one. `Rule.action_code` is the *leading*
code of the block example the contract publishes for that row. Two claims must
not be confused, and only the first is made:

- **what is true:** the value is a member of the contract's `ActionCode` enum,
  and it is the first code of the example the contract publishes for that row.
  `tests/test_policy.py::test_each_rule_names_the_leading_code_the_contract_publishes_for_its_row`
  reads the contract rather than restating it, so an example that moves and a
  table that does not fails.
- **what is *not* claimed:** that the kernel emits it. It does not. For rows 1,
  2 and 7 the leading code belongs to a component this phase has not written,
  and for row 6 the leading code is `UNRESOLVED_DISPOSITION`, which component E
  deliberately does not emit — a block caused by an unresolved disposition is
  reported under that disposition's own code and the layer that raised it. What
  the kernel emits for a row is the subject of `policy_engine`, not of this
  field.

**What `outcome` distinguishes.** §6 opens with "a block is any refusal to
transmit", and both of this table's outcomes are refusals. Rows 1 and 2 are
`reject`: nothing enters the pipeline, so there is no payload to refuse to
send. Rows 3 to 7 are `block`: a payload exists and the consequence is that it
is not transmitted.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal

from medarx.models import LAYERS

__all__ = ["RULES", "RULES_BY_ROW", "Rule", "rules_for"]


@dataclass(frozen=True)
class Rule:
    """One row of design §6: who blocks, on what, and with what consequence.

    `row` is the design's own row number, 1 to 7, so a failure anywhere in the
    kernel can be traced to the row it moved. `layer` is a member of the
    contract's closed `Layer` enum and is checked on construction: there is no
    bare `"D"`, and a receipt that cannot say which of the three redaction
    layers refused is a receipt that cannot be acted on.
    """

    row: int
    layer: str
    condition: str
    action_code: str
    outcome: Literal["reject", "block"]

    def __post_init__(self) -> None:
        if self.layer not in LAYERS:
            raise ValueError(
                f"layer {self.layer!r} is not a member of the contract Layer enum "
                f"{LAYERS}; there is no bare 'D' — the redaction layers are "
                "D.1, D.2, and D.3"
            )


#: Design §6, one entry per row, transcribed. Diff this against the design.
RULES: tuple[Rule, ...] = (
    Rule(
        row=1,
        layer="J",
        condition=(
            "Unauthorized scope, function not permitted, malformed request, "
            "arbitrary DICOM object or free-form prompt"
        ),
        action_code="ARBITRARY_DICOM_OBJECT_REJECTED",
        outcome="reject",
    ),
    Rule(
        row=2,
        layer="A",
        condition="Field outside the function allowlist; unknown function",
        action_code="FIELD_NOT_ALLOWLISTED",
        outcome="reject",
    ),
    Rule(
        row=3,
        layer="D.1",
        condition=(
            "A required structured field cannot be deterministically removed or "
            "replaced"
        ),
        action_code="DETERMINISTIC_REPLACEMENT_FAILED",
        outcome="block",
    ),
    Rule(
        row=4,
        layer="D.2",
        condition=(
            "NER flags an entity with confidence below threshold, or with no "
            "deterministic replacer"
        ),
        action_code="NER_UNRESOLVED",
        outcome="block",
    ),
    Rule(
        row=5,
        layer="D.3",
        condition=(
            "Contract violation: missing/extra field, unshifted date, missing "
            "surrogate for a reference, leftover deterministic-pattern match, "
            "hash mismatch"
        ),
        action_code="UNSHIFTED_DATE",
        outcome="block",
    ),
    Rule(
        row=6,
        layer="E",
        condition=(
            "Any unresolved disposition; unknown or missing policy version; "
            "configuration error"
        ),
        action_code="UNRESOLVED_DISPOSITION",
        outcome="block",
    ),
    Rule(
        row=7,
        layer="F",
        condition=(
            "Anything other than the exact payload object E approved; unknown "
            "model identifier"
        ),
        action_code="PAYLOAD_MISMATCH",
        outcome="block",
    ),
)

#: The same rows, keyed by row number. This is the join the policy engine
#: builds its checks from, so a check and the design row it enforces are the
#: same object rather than two values an integer has to keep in step.
RULES_BY_ROW: Mapping[int, Rule] = MappingProxyType({r.row: r for r in RULES})


def rules_for(layer_prefix: str) -> tuple[Rule, ...]:
    """The rows governed by `layer_prefix`: that layer, and any sub-layer.

    `"D"` returns the three redaction rows and `"D.2"` the one it names,
    because a caller asking which row governs a tag needs the sub-layers
    folded in, and a caller that already knows the exact tag wants the
    narrow answer. A prefix no row carries returns `()` rather than a
    near-miss: `rules_for("C")` is an empty answer, because no §6 row is a
    pseudonymization block and answering it with row 5 would be a guess.
    """
    return tuple(r for r in RULES if r.layer == layer_prefix
                 or r.layer.startswith(f"{layer_prefix}."))
