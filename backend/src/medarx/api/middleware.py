"""The boundary middleware: request identity, the body cap, and the 500 that is not a traceback.

Three things have to happen around every request rather than inside any one
route, and this is where they happen — once, for all five paths, so a rule that
applies to the whole surface cannot be true of four of them.

**Request identity.** `X-Request-Id` is resolved here, before the body is read,
because a header still reaches the surface when the body does not and that is
exactly when a refusal is most worth reporting. The resolved ID goes onto
`scope["state"]` for the route to read and onto the response as a header on
**every** response, blocks and refusals included. A supplied ID is honoured; an
absent one is generated; an ID the audit log could not hold is refused with a
`400` naming the rule, because uncaught it would surface later as a `ValueError`
from the audit write and read as a server fault.

**The body cap.** `Content-Length` over `Settings.max_body_bytes` is refused
**before the body is read**, so an oversized request costs the server a header
rather than a megabyte. The routes measure what actually arrived as well, because
a chunked request carries no `Content-Length` at all and a guard reading only
the header would let it straight through — a header is a claim, the received
length is a measurement, and a boundary that believes claims is not one.

**The `500`.** An unhandled exception becomes a `ProblemDetail`, not a
traceback. This is a raw ASGI middleware rather than a Starlette exception
handler precisely so that nothing is re-raised after the response is sent: a
handler that renders a problem document and then lets the exception continue
produces a correct response and an alarming log, and a caller cannot tell the two
apart. The traceback is still logged, through the application's own logger, which
`create_app` has attached the sensitive-data filter to — so the one place most
likely to carry an input value is scrubbed on its way out.

**The `500` is a server fault, not a privacy block.** It carries no layer and no
action code, and nothing is written to the audit log for it: design §6 has no
row for "the code was wrong", and a record saying a request was blocked when it
was not would be a false privacy event in the one store the design names as an
asset.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Awaitable, Callable, MutableMapping

from medarx.api import wiring
from medarx.api.wiring import (
    PROBLEM_INTERNAL_ERROR,
    PROBLEM_MALFORMED_REQUEST,
    PROBLEM_PROVIDER_UNAVAILABLE,
    PROBLEM_REQUEST_ID_UNUSABLE,
    problem,
    problem_response,
)
from medarx.config import Settings
from medarx.errors import ProviderError

__all__ = ["Boundary", "generate_request_id"]

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]


class Boundary:
    """The raw ASGI middleware described in the module docstring."""

    def __init__(self, app, settings: Settings) -> None:
        self.app = app
        self._max_body_bytes = settings.max_body_bytes
        # The application's own logger. `create_app` has attached the
        # sensitive-data filter to it, so anything rendered here is scrubbed
        # before it reaches a handler — including the traceback, which is the
        # part of a record most likely to carry an input value.
        self._log = logging.getLogger("medarx.api.errors")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def respond(response) -> None:
            await response(scope, receive, send)

        supplied = _header(scope, "x-request-id")
        request_id = wiring.resolve_request_id(supplied, generate_request_id)
        scope.setdefault("state", {})
        scope["state"]["request_id"] = request_id

        if supplied is not None and not wiring.is_usable_request_id(request_id):
            await respond(problem_response(problem(
                PROBLEM_REQUEST_ID_UNUSABLE, status=400,
                detail=("X-Request-Id is recorded in the audit log, which holds "
                        "identifiers matching "
                        f"{wiring.IDENTIFIER_PATTERN}. This one does not, and a "
                        "request the log cannot name would leave no record at "
                        "all."),
                request_id=None,
            )))
            return

        declared = _header(scope, "content-length")
        if declared is not None:
            try:
                length = int(declared)
            except ValueError:
                length = -1
            if length > self._max_body_bytes:
                await respond(problem_response(problem(
                    PROBLEM_MALFORMED_REQUEST, status=400,
                    detail=(f"the request body is larger than the "
                            f"{self._max_body_bytes} bytes this deployment "
                            "accepts"),
                    request_id=request_id,
                )))
                return

        try:
            await self.app(scope, receive, _with_request_id(send, request_id))
        except ProviderError:
            # Availability, not privacy. Logged with the request ID and nothing
            # about the request's data, and recorded in the audit log nowhere.
            self._log.exception("the model provider failed for request %s",
                                request_id)
            await respond(problem_response(problem(
                PROBLEM_PROVIDER_UNAVAILABLE, status=500,
                detail=("the model provider could not be reached or did not "
                        "answer. This is an availability failure, not a privacy "
                        "block, and nothing about this request was recorded as "
                        "one"),
                request_id=request_id,
            )))
        except Exception:
            self._log.exception("unhandled failure serving request %s", request_id)
            await respond(problem_response(problem(
                PROBLEM_INTERNAL_ERROR, status=500,
                detail=("the request could not be completed. Sensitive-data "
                        "filtering is applied to this application's logs, so "
                        "nothing about the request is disclosed here or there"),
                request_id=request_id,
            )))


def generate_request_id() -> str:
    """A fresh request ID, for a caller that did not supply one.

    A module-level function rather than a `lambda` at the call site so
    `resolve_request_id` can be given it, and so a test can substitute its own
    generator and know exactly what the server will call.
    """
    return str(uuid.uuid4())


def _with_request_id(send: Send, request_id: str) -> Send:
    """A `send` that stamps `X-Request-Id` on the response headers.

    Added unconditionally and replacing anything already there, so a response
    that carried a *different* ID — which nothing in this application produces —
    could not end up with two.
    """
    async def wrapped(message: Message) -> None:
        if message.get("type") == "http.response.start":
            headers = [(key, value) for key, value in message.get("headers", [])
                       if key.lower() != b"x-request-id"]
            headers.append((b"x-request-id", request_id.encode("latin-1")))
            message = {**message, "headers": headers}
        await send(message)

    return wrapped


def _header(scope: Scope, name: str) -> str | None:
    """One request header by lower-case name, or `None`."""
    for key, value in scope.get("headers", ()):
        if key.lower() == name.encode("latin-1"):
            return value.decode("latin-1")
    return None
