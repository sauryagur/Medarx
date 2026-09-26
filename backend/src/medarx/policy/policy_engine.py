"""Component E: the policy engine. It decides; it never transmits.

The one property this module is arranged around:

    **Fail closed. Every mode, every time, without exception.**

A block is any refusal to transmit, so every uncertainty here trends to block
and never to send. A policy version this engine cannot identify, a policy mode
it does not implement, a missing payload, a payload no redaction layer
validated, an unresolved disposition — all of them are refusals, and none of
them has a branch that sends anyway. The case that needs the most care is the
one not on that list: an unimplemented mode has *no fallback*. Degrading to a
weaker mode would be the single worst thing this component could do, because a
deployment that asked for a stronger policy would be given a weaker one and the
receipt would name neither.

**The conditions are a table, not a chain of conditionals.** `CHECKS` is the
ordered list `decide` walks, one `Check` per condition, each carrying the
design §6 row it enforces and the reason it gives. The engine returns on the
first check that fires, so the fail-closed ordering is a property of a list a
reviewer can read rather than of the control flow around it. The design's own
seven-row table is `medarx.policy.decision_table.RULES`, and every `Check`
names the row it belongs to.

**Internal reasons versus wire codes.** `Decision.reason_code` is internal and
is chosen to be the most specific description available: the disposition's own
code when a disposition blocked, `POLICY_NO_PAYLOAD` when there was no payload
at all. It never reaches a receipt. `WIRE_CODE_BY_REASON` translates each
reason this engine *invents* into the one contract `ActionCode` member that
describes it, and `wire_code_for` is the only way to ask. A block whose reason
came from a disposition is deliberately absent from that table: that refusal
belongs to the layer that raised the disposition, under that layer's tag, and a
second engine-level code for the same condition would give one refusal two
different receipts depending on which component the caller asked.

`wire_code_for` raises rather than returning a default, because a receipt that
names a code the kernel did not emit is a false record. All three ways this
project has produced one were a fallback somewhere: a code with the wrong
polarity, two different refusals sharing a code, and a published example
advertising something the kernel can no longer do.

**Modes are a deployment configuration.** The mode is read from `Settings` and
from nowhere else, and `decide` takes no mode parameter, so a request cannot
select or escalate its own policy. `IMPLEMENTED_MODES` is the set of modes this
engine runs; `authorized_local` is the contract's third mode and is
deliberately absent from it, because the contract publishes that mode as
`implemented: false` and says it must not be selected. A deployment configured
with it blocks.
"""

from __future__ import annotations

import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Callable

from medarx.config import Settings
from medarx.errors import PolicyError
from medarx.models import StructuredPayload, payload_hash_of

if TYPE_CHECKING:  # pragma: no cover - a type reference, not a runtime dependency
    from medarx.redaction.layers import Disposition

__all__ = [
    "CHECKS",
    "IMPLEMENTED_MODES",
    "REASON_CODES",
    "WIRE_CODE_BY_REASON",
    "Check",
    "Decision",
    "PolicyEngine",
    "wire_code_for",
]

#: The modes this engine implements. `authorized_local` is the contract's third
#: mode and is deliberately absent: it is documented as an architectural
#: extension, reported `implemented: false`, and never implemented against
#: identifiable data. A deployment configured with it blocks.
IMPLEMENTED_MODES: frozenset[str] = frozenset({"strict_local", "cloud"})

# -- Wire codes, declared as module constants so the AST sweep in
# -- tests/test_openapi_contract.py resolves them to the strings they are,
# -- which is what holds them to the contract's ActionCode enum.

_ACTION_CODE_UNKNOWN_POLICY_VERSION = "UNKNOWN_POLICY_VERSION"
_ACTION_CODE_POLICY_CONFIG_ERROR = "POLICY_CONFIG_ERROR"
_ACTION_CODE_UNAPPROVED_PAYLOAD = "UNAPPROVED_PAYLOAD"

# -- Internal reasons: descriptive, never serialised.

_REASON_UNKNOWN_VERSION = "POLICY_UNKNOWN_VERSION"
_REASON_UNIMPLEMENTED_MODE = "POLICY_UNIMPLEMENTED_MODE"
_REASON_NO_PAYLOAD = "POLICY_NO_PAYLOAD"
_REASON_NO_DISPOSITIONS = "POLICY_NO_DISPOSITIONS"
_REASON_UNAPPROVED_PAYLOAD = "POLICY_UNAPPROVED_PAYLOAD"

#: The reason an approved decision carries. It is not a block, so it is not in
#: `REASON_CODES` and `wire_code_for` refuses it: an approved request has no
#: receipt for a code to appear in.
_REASON_APPROVED = "APPROVED"

#: Every internal reason this module names. A block's reason is always one of
#: these or a disposition's own code, so the mapping below is total over this
#: module's own vocabulary: no reason it can invent is left without a wire
#: code, and a caller translating one never has to ask whether one exists.
REASON_CODES: frozenset[str] = frozenset({
    _REASON_UNKNOWN_VERSION,
    _REASON_UNIMPLEMENTED_MODE,
    _REASON_NO_PAYLOAD,
    _REASON_NO_DISPOSITIONS,
    _REASON_UNAPPROVED_PAYLOAD,
})

#: The wire code each internal reason serialises to.
#:
#: Two reasons share `UNKNOWN_POLICY_VERSION` because the contract has one code
#: for "the policy in force could not be applied" and both are that: a version
#: this engine does not recognise, and a mode it does not implement. The
#: receipt then says what a reader can act on — the policy was not applied —
#: while the specific reason stays in the engine's own reason code, which
#: reaches the audit log rather than the caller. All three codes below are
#: members of the contract's `ActionCode` enum, checked member by member in
#: `tests/test_policy.py`.
WIRE_CODE_BY_REASON: Mapping[str, str] = MappingProxyType({
    _REASON_UNKNOWN_VERSION: _ACTION_CODE_UNKNOWN_POLICY_VERSION,
    _REASON_UNIMPLEMENTED_MODE: _ACTION_CODE_UNKNOWN_POLICY_VERSION,
    _REASON_NO_PAYLOAD: _ACTION_CODE_POLICY_CONFIG_ERROR,
    _REASON_NO_DISPOSITIONS: _ACTION_CODE_POLICY_CONFIG_ERROR,
    _REASON_UNAPPROVED_PAYLOAD: _ACTION_CODE_UNAPPROVED_PAYLOAD,
})


def wire_code_for(reason_code: str) -> str:
    """The contract `ActionCode` member for an internal `reason_code`.

    Raises `ValueError` for anything this module does not name, including the
    reason an approved decision carries and a disposition's own code. A caller
    that arrives here with either is building a receipt for something this
    engine did not refuse, and the honest answer is to stop rather than to
    substitute a plausible code.
    """
    try:
        return WIRE_CODE_BY_REASON[reason_code]
    except KeyError:
        raise ValueError(
            f"{reason_code!r} is not a reason this engine invents; the reasons it "
            f"invents are {sorted(REASON_CODES)}. A block whose reason came from a "
            "disposition belongs to the layer that raised it, not to layer E."
        ) from None


@dataclass(frozen=True)
class Decision:
    """What the engine decided about one payload, and why.

    `approved` and `blocked` are opposites, and that is enforced on
    construction: a decision that is neither would leave the caller to decide
    whether an undecided payload may be sent, and "the caller decides" is how a
    fail-closed engine stops being one. `reason_code` is internal — see the
    module docstring — and `policy_version` is the version that was *presented*,
    so a block for an unrecognised version names the version that was not
    applied instead of claiming the configured one was.
    """

    approved: bool
    blocked: bool
    reason_code: str
    policy_version: str

    def __post_init__(self) -> None:
        if self.approved == self.blocked:
            raise ValueError(
                "a decision is either approved or blocked, never both and never "
                f"neither; got approved={self.approved} blocked={self.blocked}"
            )


@dataclass(frozen=True)
class _Question:
    """Everything one pass of `CHECKS` may ask about."""

    payload: StructuredPayload | None
    dispositions: tuple["Disposition", ...]
    policy_version: str
    expected_version: str
    mode: str


@dataclass(frozen=True)
class Check:
    """One block condition: what the engine asks, and the reason if the answer
    is no. `row` is the design §6 row this condition enforces."""

    name: str
    row: int
    question: Callable[[_Question], bool]
    reason: Callable[[_Question], str]


def _is_identifiable(version: str) -> bool:
    """Whether a policy version names a policy.

    §6 row 6 blocks on an unknown *or missing* policy version, and the missing
    case is the one a bare `!=` comparison misses: with a blank version in
    force, the version presented and the version in force are the same blank
    string, they compare equal, and the payload would be approved under a
    policy nobody can name. A version with no non-whitespace character names
    nothing.
    """
    return bool(version.strip())


def _first_unresolved_code(question: _Question) -> str:
    """The action code of the first unresolved disposition, in the given order.

    The disposition's own code, not one chosen here: it names the check that
    did not resolve — a replacement with no replacer, a sub-threshold
    detection, a missing surrogate — and a code invented at this layer would
    name a check that did not happen.
    """
    for disposition in question.dispositions:
        if not disposition.resolved:
            return disposition.action_code
    raise AssertionError("the unresolved-disposition check fired with none unresolved")


def _is_validated(payload: StructuredPayload | None) -> bool:
    """Whether redaction layer 3 hashed this payload.

    Layer 3 writes `payload_hash` over the payload it checked, so the field
    being present is the evidence that the layers ran and the contract check
    passed. Its absence is the only trace of a skipped redaction that survives
    to this layer, which is what the empty-disposition check is for.
    """
    return (
        payload is not None
        and isinstance(payload.payload_hash, str)
        and bool(payload.payload_hash.strip())
    )


#: The conditions `decide` walks, in order, returning on the first that fires.
#: The order is a property: a policy version this engine cannot identify is
#: reported before anything else, because a deployment running the wrong policy
#: is a different problem from a request it refused, and a receipt has one code
#: to give. Every check here enforces §6 row 6.
CHECKS: tuple[Check, ...] = (
    Check(
        name="the policy version is not the one in force",
        row=6,
        question=lambda q: (
            not _is_identifiable(q.policy_version)
            or not _is_identifiable(q.expected_version)
            or q.policy_version != q.expected_version
        ),
        reason=lambda q: _REASON_UNKNOWN_VERSION,
    ),
    Check(
        name="the policy mode is not implemented",
        row=6,
        question=lambda q: q.mode not in IMPLEMENTED_MODES,
        reason=lambda q: _REASON_UNIMPLEMENTED_MODE,
    ),
    Check(
        name="there is no payload",
        row=6,
        question=lambda q: q.payload is None,
        reason=lambda q: _REASON_NO_PAYLOAD,
    ),
    Check(
        # Measured, not assumed: a report with no identifiers in it produces no
        # dispositions at all. Redaction layers 1-3 record what they *did*, and
        # a clean report gives them nothing to record, so an empty list from a
        # run that completed is the expected shape of a clean result — blocking
        # on it would refuse every ordinary report and report a healthy
        # deployment as misconfigured. What an empty list *does* mean, when the
        # payload carries no layer-3 hash, is that no layer ran: dispositions
        # are required exactly then, because they are the evidence they would
        # have produced. So the block is on the pair, and the pair is the only
        # version of this condition that is both fail-closed and satisfiable.
        name="there are no dispositions and nothing validated the payload",
        row=6,
        question=lambda q: not q.dispositions and not _is_validated(q.payload),
        reason=lambda q: _REASON_NO_DISPOSITIONS,
    ),
    Check(
        name="a disposition is unresolved",
        row=6,
        question=lambda q: any(not d.resolved for d in q.dispositions),
        reason=_first_unresolved_code,
    ),
)


class PolicyEngine:
    """The policy engine for one deployment's configuration.

    Construction reads `Settings` and holds nothing else. The mode is read once,
    here, and is never taken as an argument to `decide`, so no request can
    select or escalate its own policy.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    @property
    def mode(self) -> str:
        """The configured policy mode, as configured — never as requested."""
        return self._settings.policy_mode

    @property
    def policy_version(self) -> str:
        """The de-identification policy version in force."""
        return self._settings.policy_version

    def decide(
        self,
        payload: StructuredPayload | None,
        dispositions: Sequence["Disposition"],
        policy_version: str,
    ) -> Decision:
        """Approve or block, failing closed. Never raises for a privacy block.

        `dispositions` is everything the redaction layers produced, in their
        own order: a decision about "any unresolved disposition" is only
        meaningful to one that can see all of them. It is materialised into a
        tuple first, so every check sees the same set rather than whatever an
        iterator had left.

        Returns on the first `Check` that fires; a payload that fires none is
        approved. No path through this function returns neither approve nor
        block, and `Decision` refuses to be constructed if one arrives.
        """
        question = _Question(
            payload=payload,
            dispositions=tuple(dispositions),
            policy_version=policy_version,
            expected_version=self.policy_version,
            mode=self.mode,
        )
        for check in CHECKS:
            if check.question(question):
                return Decision(
                    approved=False,
                    blocked=True,
                    reason_code=check.reason(question),
                    policy_version=question.policy_version,
                )
        return Decision(
            approved=True,
            blocked=False,
            reason_code=_REASON_APPROVED,
            policy_version=question.policy_version,
        )

    def authorize_payload(self, payload: StructuredPayload, approved_hash: str) -> None:
        """Refuse unless `payload` is the object the decision approved.

        Two things must equal `approved_hash`, and both are required:

        - the `payload_hash` the object carries, which is the claim;
        - the hash recomputed from the object's own content, which is the
          evidence.

        Checking only the claim is a hole with a one-line hole-punch in it.
        `StructuredPayload` is frozen but not sealed: `model_copy(update=...)`
        replaces one field and leaves the rest alone, so a payload whose
        `report_text` was swapped after the decision keeps the approved
        `payload_hash` and passes a comparison of the field against it. That is
        the substitution design §6 row 7 exists to stop, and re-hashing the
        content here is what stops it. It also makes this check independent of
        layer 3 having run: a payload nothing ever hashed is refused, not
        approved.

        `compare_digest` rather than `==`, so a caller probing this with
        candidate payloads cannot learn the approved hash a byte at a time —
        cheap insurance on a check whose whole job is to be trustworthy.

        A hash that is absent, empty or not a string is not a match, because it
        is not a hash E could have approved. Raises `PolicyError` carrying
        `UNAPPROVED_PAYLOAD`; returns `None` when the payload is the approved
        one.
        """
        claim_matches = (
            isinstance(payload.payload_hash, str)
            and isinstance(approved_hash, str)
            and secrets.compare_digest(payload.payload_hash, approved_hash)
        )
        content_matches = claim_matches and secrets.compare_digest(
            payload_hash_of(payload), approved_hash
        )
        if not content_matches:
            raise PolicyError(
                action_codes=(_ACTION_CODE_UNAPPROVED_PAYLOAD,),
                message=(
                    "the payload is not the object the policy decision approved; "
                    "nothing may be transmitted"
                ),
            )
