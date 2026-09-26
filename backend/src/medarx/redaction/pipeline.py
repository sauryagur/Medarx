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

**The policy engine is injected, not imported.** This task runs before the
engine exists, so the type is `TYPE_CHECKING`-only and a caller supplies one. The
engine is asked last and nothing here second-guesses it: deciding whether an
unresolved disposition blocks is the policy engine's job, and a redaction layer
that also decided would be a second, divergent copy of that decision. What this
module guarantees is that no disposition is lost on the way — every one reaches
the caller, and every unresolved one reaches the `RedactionError`.
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

if TYPE_CHECKING:  # pragma: no cover - the engine arrives in a later task
    from medarx.policy.engine import PolicyEngine

__all__ = ["RedactionOutcome", "run_privacy_kernel", "run_redaction"]

#: The code for a block that carries no disposition of its own — an engine that
#: refused for a reason of its own, such as a policy version it does not know.
#: `UNRESOLVED_DISPOSITION` is the reverse case (an unresolved disposition the
#: engine resolved), so reusing it would leave a receipt unable to tell the two
#: apart.
_ACTION_CODE_UNAPPROVED_PAYLOAD = "UNAPPROVED_PAYLOAD"

#: The layer a `RedactionError` carries when no disposition flagged the request,
#: because there is no layer to name. Layer 3 is the last one to run and the one
#: whose contract the payload satisfied, so naming it is the least misleading
#: of the three; a block with no disposition at all is the engine's own verdict.
_FALLBACK_LAYER = "D.3"


@dataclass(frozen=True)
class RedactionOutcome:
    """What the kernel produced, and why.

    `approved` is the payload to hand onward, or `None`. `blocked` is the
    decision. They are never both surprising at once: `blocked=True` implies
    `approved is None`, and `approved is not None` implies every disposition
    was resolved *and* the engine approved.
    """

    approved: StructuredPayload | None
    dispositions: list[Disposition]
    blocked: bool


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

    decision = engine.decide(after_layer3, dispositions, settings.policy_version)
    blocked = bool(decision.blocked)
    return RedactionOutcome(
        approved=None if blocked else after_layer3,
        dispositions=dispositions,
        blocked=blocked,
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

    A block with no unresolved disposition at all is the engine's own verdict
    (an unknown policy version, say). It still raises here rather than returning
    a payload, because the caller asked for one, and it carries
    `UNAPPROVED_PAYLOAD` so the receipt says what happened without inventing a
    layer that did not flag anything.
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
        layer=unresolved[0].layer if unresolved else _FALLBACK_LAYER,
        action_codes=tuple(dict.fromkeys(d.action_code for d in unresolved))
        or (_ACTION_CODE_UNAPPROVED_PAYLOAD,),
        message=(
            f"{len(unresolved)} unresolved disposition(s) across "
            f"{len({d.layer for d in unresolved})} layer(s)"
            if unresolved
            else "the policy engine did not approve this payload"
        ),
    )
