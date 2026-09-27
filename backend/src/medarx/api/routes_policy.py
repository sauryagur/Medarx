"""`GET /v1/policy` — the read-only inspection surface over component E.

**The mode is a deployment configuration and there is nothing here to change
it.** The contract says so twice: the tag description ("the policy mode is a
deployment configuration, not something a request may select") and the operation
description ("a request cannot choose its mode: the mode is fixed for the
deployment precisely so that a caller cannot route around the boundary by picking
a laxer mode"). This route therefore takes no parameters at all, and
`ExecutionRequest` has no `policy_mode` property with `extra="forbid"` refusing
one that does.

**No `403`.** The contract declares only `200` and `500` here, and this route
returns no other status: a response the contract does not declare is drift, and
an `if` that could never fire is decoration. The authorization surface covers
execution, the approval endpoint and the audit readback — the three operations
that touch a study, a draft or a record.

**`authorized_local` is reported as `implemented: false` and is not in
`implemented_modes`.** It is a documented architectural extension whose
definition of a "trusted environment" is deferred beyond Phase 6, and a reader
should not be left guessing whether it is available.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from medarx.api.schemas import PolicyConfiguration, PolicyExtension
from medarx.api.wiring import json_response
from medarx.policy.policy_engine import IMPLEMENTED_MODES

__all__ = ["router"]

router = APIRouter(tags=["policy"])

#: The note the contract publishes for the one mode that is not implemented. The
#: contract requires the property, and this is the text that makes it mean
#: something: a reader who sees `implemented: false` learns *why*.
_EXTENSION_NOTE = (
    "Documented as an architectural extension only. It is never implemented "
    "against identifiable data in the demo, and its definition of a \"trusted "
    "environment\" is deferred beyond Phase 6."
)

#: `authorized_local` is the contract's only declared extension.
_EXTENSION_NAME = "authorized_local"


@router.get("/v1/policy")
async def get_policy_configuration(request: Request) -> JSONResponse:
    """The policy mode and de-identification policy version in force."""
    engine = request.app.state.pipeline.policy
    configuration = PolicyConfiguration(
        policy_mode=engine.mode,  # type: ignore[arg-type]
        policy_version=engine.policy_version,
        implemented_modes=sorted(IMPLEMENTED_MODES),  # type: ignore[arg-type]
        fail_closed=True,
        extensions=[
            PolicyExtension(name=_EXTENSION_NAME, implemented=False,
                            note=_EXTENSION_NOTE)
        ],
    )
    return json_response(200, configuration.model_dump(mode="json"))
