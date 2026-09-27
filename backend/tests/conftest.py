"""Shared fixtures for the backend suite.

The audit key and the `settings` / `store` fixtures live here, in one place, so
that a second definition elsewhere cannot shadow them. Test modules import
`KEY` from here and take `store` as a fixture argument.

Component J's fixtures live here too, so the application is built by exactly one
path in the whole suite. The `app` fixture is that path: it calls `create_app`
once, and `pipeline` and `client` both read the objects the app built rather
than constructing a second set. A test that built its own `Pipeline` would be
exercising a wiring the server never uses.

`provider` is a loopback stub, session-scoped, started once per test session. It
is the only thing the suite ever talks to: no cloud model is contacted and none
may be. Its `requests` list is the evidence the "a 422 sent nothing" tests assert
against, so it is deliberately not reset between tests — a test reads
`len(provider.requests)` before and after instead.
"""

import json
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from fastapi.testclient import TestClient

from medarx.api.app import create_app
from medarx.config import Settings
from medarx.pseudonym.mapping_store import MappingStore

#: A synthetic, non-secret audit key. Test-only; never a real credential.
KEY = "test-audit-key"

#: The chat-completion body the stub answers with: a synthetic draft, generated
#: from nothing real.
STUB_COMPLETION = {
    "object": "chat.completion",
    "model": "medarx-demo-model",
    "choices": [
        {
            "index": 0,
            "message": {
                "role": "assistant",
                "content": "FINDINGS: 7 mm nodule, right upper lobe.",
            },
            "finish_reason": "stop",
        }
    ],
    "usage": {"prompt_tokens": 11, "completion_tokens": 9, "total_tokens": 20},
}

#: The contract's execution path, spelled once. A test that builds this URL by
#: concatenation is re-deriving a path the contract already fixes.
EXEC_URL = "/v1/functions/Draft/executions"

#: The scope a Phase 1 caller presents in `X-Scope`: the one study it may act on
#: and the one function it may run. The vocabulary is synthetic and lives in
#: `medarx.api.authz`; it is written out here rather than imported so that a
#: change to the grammar has to be made in the tests that depend on it.
SCOPE = "scope:study:STUDY-SYN-000041,scope:function:Draft"
SCOPE_HEADERS = {"X-Scope": SCOPE}

#: A request that reaches the gateway and is approved: a known-positive report
#: carrying the synthetic identifiers the corpus plants in it.
KNOWN_POSITIVE_BODY: dict = {
    "study_context": {"study_reference": "STUDY-SYN-000041", "modality": "CT"},
    "report_text": {
        "text": ("FINDINGS: 7 mm nodule in the right upper lobe. "
                 "Correlate with prior MRN 4452819."),
        "source": "synthetic_corpus",
    },
    "dicom_metadata": {
        "PatientID": "4452819",
        "AccessionNumber": "ACC0000417",
        "Modality": "CT",
        "StudyDate": "20260114",
        "PatientAge": "045Y",
    },
}


def body_with(**overrides) -> dict:
    """`KNOWN_POSITIVE_BODY` with top-level properties replaced."""
    return {**KNOWN_POSITIVE_BODY, **overrides}


def body_with_dicom(**overrides) -> dict:
    """The known-positive body with `dicom_metadata` entries replaced."""
    merged = dict(KNOWN_POSITIVE_BODY["dicom_metadata"])
    merged.update(overrides)
    return {**KNOWN_POSITIVE_BODY, "dicom_metadata": merged}


@pytest.fixture
def settings() -> Settings:
    """Settings built explicitly, so no test depends on the process environment.

    `date_order` is left **undeclared** here, exactly as it was before component J
    existed, because several redaction tests measure what the kernel does with
    an ambiguous numeric date and their expected numbers are the ones for the
    undeclared case. The application fixture below declares it, because
    `create_app` refuses to build one that has not.
    """
    return Settings(audit_key=KEY)


@pytest.fixture
def store(tmp_path) -> MappingStore:
    """A `MappingStore` over a throwaway SQLite file, closed on teardown."""
    s = MappingStore(f"sqlite:///{tmp_path / 'map.db'}", KEY)
    try:
        yield s
    finally:
        s.close()


# -- The local observer the gateway is pointed at ----------------------------


@dataclass(frozen=True)
class RecordedRequest:
    """One request as the stub actually received it on the wire."""

    method: str
    path: str
    headers: dict[str, str]
    body: bytes


@dataclass
class StubProvider:
    """A loopback HTTP server that answers the OpenAI chat-completions shape.

    `status` and `body` are per-instance but the server is shared across the
    session, so a test that wants a provider failure builds its own stub rather
    than mutating the shared one; a failure cannot then leak into a later test.
    """

    status: int = 200
    body: bytes = field(default_factory=lambda: json.dumps(STUB_COMPLETION).encode())
    requests: list[RecordedRequest] = field(default_factory=list)
    _httpd: ThreadingHTTPServer | None = None
    _thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        assert self._httpd is not None, "the stub provider is not running"
        host, port = self._httpd.server_address[:2]
        return f"http://{host}:{port}/v1"

    def __enter__(self) -> "StubProvider":
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's name
                length = int(self.headers.get("Content-Length", "0"))
                received = self.rfile.read(length)
                outer.requests.append(
                    RecordedRequest(
                        method=self.command,
                        path=self.path,
                        headers={k.lower(): v for k, v in self.headers.items()},
                        body=received,
                    )
                )
                try:
                    self.send_response(outer.status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(outer.body)))
                    self.end_headers()
                    self.wfile.write(outer.body)
                except OSError:
                    # The client gave up on this connection. Nothing to report.
                    self.close_connection = True

            def log_message(self, *args: object) -> None:
                """Silence the default stderr access log."""

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        assert self._httpd is not None and self._thread is not None
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)


@pytest.fixture(scope="session")
def provider():
    """The one observer. A loopback stub; nothing leaves this machine."""
    with StubProvider() as stub:
        yield stub


# -- Component J: one wiring, reached three ways -----------------------------


@pytest.fixture
def app_settings(settings, provider) -> Settings:
    """The settings the *application* is built from.

    The deployment's own settings with the numeric date order declared and the
    gateway pointed at the loopback stub. Declared rather than inherited because
    `create_app` treats an undeclared date order as a startup failure, and
    setting it here would change what the component-D tests measure.
    """
    return settings.model_copy(update={"date_order": "MDY",
                                      "gateway_base_url": provider.base_url})


@pytest.fixture
def app(tmp_path, app_settings):
    """The application, built by the one path the server uses."""
    return create_app(app_settings, f"sqlite:///{tmp_path / 'kernel.db'}")


@pytest.fixture
def pipeline(app):
    """The composition root the app built, read back rather than rebuilt."""
    return app.state.pipeline


@pytest.fixture
def client(app) -> TestClient:
    return TestClient(app)


@pytest.fixture
def entered(app):
    """Every request ID that actually reached the pipeline.

    Wrapping the instance's own `run` rather than trusting a status code: a 400
    that still called `run` would leave the pipeline having seen a body the
    contract says it cannot express, and no response would say so.
    """
    calls: list[str] = []
    original = app.state.pipeline.run

    def spy(request_id, request):
        calls.append(request_id)
        return original(request_id, request)

    app.state.pipeline.run = spy
    return calls
