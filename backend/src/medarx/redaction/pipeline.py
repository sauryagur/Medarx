"""The orchestrator: run the three redaction layers, then ask for a decision.

Two entry points, one behaviour, one difference. `run_redaction` never raises
for a privacy block — it returns `blocked=True`, the dispositions that caused
it, and no approved payload, which is what lets the demo assert on the reason a
request was refused rather than on a traceback. `run_privacy_kernel` is the
raising form the API uses, and it raises exactly one type, `RedactionError`,
carrying the layer that flagged the request and its action codes.

Neither ever returns a payload alongside `blocked=True`. A caller that reads
`approved` on a blocked outcome gets `None`, so "the pipeline was refused" and
"the pipeline produced nothing to send" cannot be confused with "the pipeline
approved an empty payload" — which is the failure an empty result would be if
this returned whatever it had.

**The policy engine is injected, not imported.** The orchestrator depends on the
engine's type but never imports it at runtime, so the direction of the
dependency is one-way: D is handed a policy engine and knows nothing about how
it decides. The engine is asked last and nothing here second-guesses it:
deciding whether an unresolved disposition blocks is the policy engine's job,
and a redaction layer that also decided would be a second, divergent copy of
that decision. What this module guarantees is that no disposition is lost on
the way — every one reaches the caller, every unresolved one reaches the
`RedactionError`, and a block the engine raised is attributed to the engine
rather than to a redaction layer that flagged nothing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from medarx.config import Settings
from medarx.errors import RedactionError
from medarx.models import StructuredPayload
from medarx.pseudonym.mapping_store import MappingStore
from medarx.redaction.layers import (
    Disposition,
    RedactionContext,
    layer1_deterministic,
    layer2_ner,
    layer3_validation,
)

if TYPE_CHECKING:  # pragma: no cover - the engine is injected, never imported here
    from medarx.policy.policy_engine import PolicyEngine

__all__ = ["RedactionOutcome", "run_privacy_kernel", "run_redaction"]

#: The layer a `RedactionError` carries when the policy engine is what refused,
#: because no disposition flagged the request. Design §6 says a receipt's layer
#: names the component that flagged it, and when nothing in D flagged anything
#: that component is E.
_ENGINE_LAYER = "E"

#: The code for a block that carries no disposition and no engine code of its
#: own. Unreachable while every reason the engine invents maps to a wire code
#: and every disposition block arrives with an unresolved disposition beside it;
#: it is here so that an inconsistency refuses rather than passing a payload,
#: because the alternative to a wrong code on a block is no block at all.
_ACTION_CODE_UNAPPROVED_PAYLOAD = "UNAPPROVED_PAYLOAD"


@dataclass(frozen=True)
class RedactionOutcome:
    """What the kernel produced, and why.

    `approved` is the payload to hand onward, or `None`. `blocked` is the
    decision. They are never both surprising at once: `blocked=True` implies
    `approved is None`, and `approved is not None` implies every disposition
    was resolved *and* the engine approved.

    `decision_code` is the contract action code the engine's own verdict
    serialises to, carried here so the raising form can attribute the block to
    the component that made it rather than to a layer that flagged nothing. It
    is `None` for an approved outcome and for a block whose reason came from a
    disposition, because that receipt belongs to the layer that raised it.
    """

    approved: StructuredPayload | None
    dispositions: list[Disposition]
    blocked: bool
    decision_code: str | None = None


def run_redaction(
    payload: StructuredPayload,
    patient_ref: str,
    store: MappingStore,
    engine: PolicyEngine,
    settings: Settings,
    *,
    source: StructuredPayload,
) -> RedactionOutcome:
    """Run layers 1–3 over `payload`, then ask `engine` for a decision.

    `payload` is the payload as it arrived from the pseudonymization service and
    `source` is that same payload before any redaction. The two are separate
    arguments because layer 3's unshifted-date and dropped-field checks are
    statements about a difference, and a difference needs both sides — see
    `RedactionContext.source`.

    `source` is **keyword-only**, and that is a safety property rather than a
    style one. It sits beside another payload argument, and with both
    positional the two could be transposed: passing the *redacted* payload as
    `source` silently disables both of layer 3's difference checks and the
    pipeline approves a payload whose unshifted dates nothing looked at. A
    caller who has to name the argument cannot make that mistake, and one who
    forgets it gets a `TypeError` rather than a weakened boundary.

    The layers run in order and each one's output is the next one's input, so a
    value layer 1 shifted is the value layer 2 scans. Their dispositions are
    concatenated in that order and handed to the engine together: a decision
    about "any unresolved disposition" is only meaningful if it can see all of
    them.
    """
    ctx = RedactionContext.for_patient(source, patient_ref, store, settings)
    after_layer1, layer1 = layer1_deterministic(payload, ctx)
    after_layer2, layer2 = layer2_ner(after_layer1, ctx)
    after_layer3, layer3 = layer3_validation(after_layer2, ctx)
    dispositions = [*layer1, *layer2, *layer3]

    # The version presented to the engine is the one in force in *these*
    # settings, so the engine's own version check fires when the engine and
    # this call disagree about which policy is deployed. Pinned by
    # `tests/test_policy.py::test_the_pipeline_presents_the_configured_policy_version`,
    # because a check that nothing can reach is a check nobody notices rotting.
    decision = engine.decide(after_layer3, dispositions, settings.policy_version)
    blocked = bool(decision.blocked)
    return RedactionOutcome(
        approved=None if blocked else after_layer3,
        dispositions=dispositions,
        blocked=blocked,
        decision_code=decision.wire_code,
    )


def run_privacy_kernel(
    payload: StructuredPayload,
    patient_ref: str,
    store: MappingStore,
    engine: PolicyEngine,
    settings: Settings,
    *,
    source: StructuredPayload,
) -> StructuredPayload:
    """The approved payload, or a `RedactionError` naming why there is none.

    The error carries the layer of the *first* unresolved disposition, because
    that is the layer a reader needs to look at, and every unresolved
    disposition's code — not just the first, and never an internal code. A
    block that reported one code out of four would leave the rest of the reason
    invisible, and the demo asserts on the codes.

    A block with no unresolved disposition is the policy engine's own verdict —
    an unimplemented mode, a policy version it does not recognise, a payload it
    could not verify. It still raises here rather than returning a payload,
    because the caller asked for one, and it names **layer E** with the code
    that verdict serialises to. It used to name `D.3` with
    `UNAPPROVED_PAYLOAD`, on the reasoning that a layer must be named even when
    nothing flagged the request; both were false, because no redaction layer
    flagged anything and the engine's own code already says what happened.
    Design §6 states that a receipt's `layer` names the flagging component, and
    here that component is E.
    """
    outcome = run_redaction(payload, patient_ref, store, engine, settings, source=source)
    if not outcome.blocked:
        # Unreachable by construction: `run_redaction` ties the two together.
        # Raised rather than asserted, because `assert` is removed under `-O`
        # and this is the one place a bug would otherwise hand `None` to a
        # caller expecting a payload.
        if outcome.approved is None:
            raise AssertionError("an unblocked outcome must carry a payload")
        return outcome.approved

    unresolved = [d for d in outcome.dispositions if not d.resolved]
    raise RedactionError(
        layer=unresolved[0].layer if unresolved else _ENGINE_LAYER,
        action_codes=(
            tuple(dict.fromkeys(d.action_code for d in unresolved))
            if unresolved
            # Every reason the engine invents maps to a contract code, so this
            # arm is reachable only through an inconsistency. It refuses rather
            # than passing a payload: a block carrying a code that does not
            # describe it is a smaller failure than no block at all.
            else (outcome.decision_code or _ACTION_CODE_UNAPPROVED_PAYLOAD,)
        ),
        message=(
            f"{len(unresolved)} unresolved disposition(s) across "
            f"{len({d.layer for d in unresolved})} layer(s)"
            if unresolved
            else "the policy engine did not approve this payload "
                 f"({outcome.decision_code})"
        ),
    )
