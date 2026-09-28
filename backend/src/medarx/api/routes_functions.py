"""`POST /v1/functions/{function_name}/executions` — component J's front door.

The six ordered checks live in `medarx.api.intake`, because the preflight
accepts the same body and must apply the identical six; this module is what
happens **after** them.

**The atomic path, and it stays.** `createFunctionExecution` validates,
transforms, decides, calls the provider and returns the model response in one
round trip, so `approved` and `sent` are the same instant. `routes_preflight`
splits that into two so a caller can see the payload first; the two are
alternatives, not a replacement, and neither re-implements the other.

**The sixth check.** The pipeline *returns* for a privacy block — a `422` with a
`BlockReceipt` — and *raises* for a provider outage, which is a different
condition in the design's own terms and is rendered by `Boundary`, the one place
in the application that turns an exception into a response. A `ProviderError`
caught here as well would be two handlers for one condition, and the second
would never run.

**Nothing here constructs a component.** Every one of them came from
`app.state.pipeline`, which `create_app` built once, so a test and the server
exercise the same wiring.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from medarx.api import intake, wiring

__all__ = ["router"]

router = APIRouter(tags=["execution"])


@router.post("/v1/functions/{function_name}/executions")
async def create_function_execution(request: Request) -> JSONResponse:
    """Execute a named function over clinician-supplied report text."""
    accepted = await intake.accept_execution(
        request, operation="this endpoint"
    )
    if isinstance(accepted, JSONResponse):
        return accepted
    result = request.app.state.pipeline.run(
        request.state.request_id, accepted.execution
    )
    if not result.approved:
        return wiring.block_response(result.block_receipt)
    return wiring.json_response(
        200, wiring.execution_response_body(result, accepted.addressed_function),
        request.state.request_id)
