"""`create_app` — the one composition point, and the only one.

Everything the server runs comes from here, and everything a test runs comes
from here too. That is deliberate: a second wiring is a second thing to keep in
step, and the failure it hides is a test that passes against an application the
server never builds. `tests/conftest.py` therefore calls this function and reads
`app.state.pipeline` back rather than constructing a `Pipeline` of its own.

**What is attached, and why each piece is here rather than in a route.**

- `app.state.pipeline` — every component, built once by `medarx.pipeline.build_pipeline`.
  A per-request `MappingStore` would be a per-request surrogate table and a
  per-request `AuditLog` a per-request chain head, and neither would be the one
  the other requests used.
- `app.state.settings` — the frozen `Settings` the pipeline was built from, so a
  route reads the deployment's own configuration rather than a copy.
- `app.state.authorizer` — the synthetic scope check, which is stateless.
- `app.state.sensitive_filter` — the installed `SensitiveDataFilter`, attached
  **here** to the application's own loggers. `medarx.logging_filter.install_filter`
  covers the root logger and four named SDK loggers and their subtrees; **a
  logger filter is not inherited**, so the loggers under `medarx.api` are only
  covered because this function attaches the filter to them. A logger created
  after this runs and not named here is not covered, and nothing in the package
  claims otherwise.
- `app.openapi` — the tracked `contracts/openapi.yaml`, served verbatim.

**The served contract is the file, not a rendering of the code.** FastAPI
generates an OpenAPI document from the route signatures, and that document would
drift from the contract the first time a signature and a schema disagreed — with
nothing failing. So the tracked file is read at startup and served as-is, and
`tests/test_api.py::test_the_served_openapi_document_is_the_tracked_contract`
compares the two after parsing. The cost of that choice is that a deployment
which has the package but not the repository cannot serve the document at all;
it is refused at startup with a `FileNotFoundError` naming the path, rather than
serving a document that is not the contract.

**Three startup checks, all fail-closed.** The audit key must be present (the log
refuses to build without one, and `build_pipeline` propagates that). The
numeric date order must be declared — `require_date_order`, whose only caller
this is, and which exists because an ambiguous numeric date would otherwise be a
*per-request* block that reads to whoever sees the receipt like a coverage gap.
And the contract must be readable, for the reason above.
"""

from __future__ import annotations

import logging
import uuid
from pathlib import Path

import yaml
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from medarx import logging_filter
from medarx.api.authz import Authorizer
from medarx.api import (
    routes_approval,
    routes_audit,
    routes_functions,
    routes_policy,
    wiring,
)
from medarx.api.middleware import Boundary
from medarx.api.surface import _SURFACE_LAYER  # noqa: F401 - re-exported name only
from medarx.config import Settings, require_date_order
from medarx.pipeline import build_pipeline

__all__ = ["APPLICATION_LOGGERS", "create_app", "load_contract"]

#: The loggers this application owns, and the ones the server owns. The filter
#: `install_filter` installs covers the root logger and four named SDK loggers;
#: these are the rest, and they are listed rather than discovered because a
#: logger filter is not inherited and a name nobody wrote down is a name nobody
#: attaches. `uvicorn.error` is here for the tracebacks it renders; `uvicorn.access`
#: for the request lines and query strings it writes.
APPLICATION_LOGGERS: tuple[str, ...] = (
    "medarx.api",
    "medarx.api.approval",
    "uvicorn",
    "uvicorn.error",
    "uvicorn.access",
)

#: The tracked contract, found by walking up from this file. A `contract_path`
#: argument overrides it, which is what a packaging change would use.
_CONTRACT_RELATIVE = Path("contracts") / "openapi.yaml"


def load_contract(contract_path: "Path | None" = None) -> dict:
    """The tracked OpenAPI document, parsed.

    Raises `FileNotFoundError` naming where it looked. Serving a generated
    document instead would be the divergence this whole arrangement exists to
    prevent, so a deployment without the file is refused rather than served
    something that is not the contract.
    """
    path = contract_path or _find_contract()
    if not path.is_file():
        raise FileNotFoundError(
            f"the normative contract is not readable at {path}. This application "
            "serves contracts/openapi.yaml verbatim rather than generating a "
            "document from its routes, because a generated document and the "
            "tracked one can disagree with nothing failing. Point "
            "`contract_path` at the file, or ship the repository layout."
        )
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _find_contract() -> Path:
    """`contracts/openapi.yaml`, found by walking up from this module.

    The file is tracked at the repository root and this package lives two
    directories below it, so one `parents[2]` is the answer in the checkout and
    in an editable install. Anything else is a packaging change, not something
    to guess at here.
    """
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / _CONTRACT_RELATIVE
        if candidate.is_file():
            return candidate
    return here.parents[2] / _CONTRACT_RELATIVE


def create_app(settings: Settings, db_url: str, *,
               contract_path: "Path | None" = None) -> FastAPI:
    """Build the application: the guard, the components, the routes, the filter.

    The order is the order the failures should be discovered in. A deployment
    that has not declared its date order, or cannot read its contract, or has no
    audit key, finds out here rather than on the first request that happens to
    need the thing it is missing.
    """
    require_date_order(settings)
    contract = load_contract(contract_path)
    pipeline = build_pipeline(settings, db_url)

    app = FastAPI(
        title="Medarx Application API (Phase 1 Privacy Kernel)",
        version="0.1.0-phase1",
        description=(
            "The HTTP surface for the Medarx Phase 1 privacy kernel. The OpenAPI "
            "document this application serves is contracts/openapi.yaml, read at "
            "startup and served verbatim."
        ),
    )
    app.state.settings = settings
    app.state.pipeline = pipeline
    app.state.authorizer = Authorizer()
    app.state.sensitive_filter = _attach_log_filter()

    app.include_router(routes_functions.router)
    app.include_router(routes_approval.router)
    app.include_router(routes_policy.router)
    app.include_router(routes_audit.router)

    # The tracked document, served as-is. Assigned after the routes so nothing
    # can regenerate it: `app.openapi` is what `/openapi.json` calls.
    app.openapi = lambda: contract  # type: ignore[method-assign]

    app.add_middleware(Boundary, settings=settings)
    return app


def _attach_log_filter() -> logging_filter.SensitiveDataFilter:
    """Install the sensitive-data filter and attach it to this app's loggers.

    `install_filter` is idempotent and returns the one instance; attaching that
    same object to each of `APPLICATION_LOGGERS` is what extends its reach past
    the root logger and the four SDK loggers it covers on its own. **Filters are
    not inherited**, so a logger not named in `APPLICATION_LOGGERS` and created
    after this returns is not covered — which is why the list is a module
    constant a reader can check rather than a set built as the loggers happen.
    """
    installed = logging_filter.install_filter()
    for name in APPLICATION_LOGGERS:
        logging.getLogger(name).addFilter(installed)
    return installed


def problem_detail_response(document) -> JSONResponse:
    """A problem document on the wire. Re-exported from `wiring` for callers
    that already hold this module rather than the one that defines the shape."""
    return wiring.problem_response(document)
