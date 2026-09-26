"""Component E: policy — the fail-closed decision on whether anything may leave.

The enforcement table the design publishes is in `decision_table`, transcribed
as data so a reviewer can diff it against §6 directly. The engine that
evaluates its own conditions against that table is in `policy_engine`, and it
is the only place in the package that decides anything.
"""

from medarx.policy.decision_table import RULES, Rule, rules_for
from medarx.policy.policy_engine import (
    CHECKS,
    IMPLEMENTED_MODES,
    REASON_CODES,
    WIRE_CODE_BY_REASON,
    Check,
    Decision,
    PolicyEngine,
    wire_code_for,
)

__all__ = [
    "CHECKS",
    "IMPLEMENTED_MODES",
    "REASON_CODES",
    "RULES",
    "WIRE_CODE_BY_REASON",
    "Check",
    "Decision",
    "PolicyEngine",
    "Rule",
    "rules_for",
    "wire_code_for",
]
