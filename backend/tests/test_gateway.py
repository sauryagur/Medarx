"""Component F: the single egress point.

**No test here contacts a provider, and almost none stub the transport
either.** The evidence is a real `http.server` on a loopback port, started per
test, that records the exact request bytes and headers it received and answers
with a scripted response. Everything the egress story rests on is a claim
about what goes on the wire, so it is measured on the wire; and the three
provider failures — unreachable, non-2xx, malformed — are each produced by
changing what the *server* does, which is a condition rather than a mock
configuration. Nothing leaves the machine.

The recorded bytes are compared against `ModelGateway.last_request_body()`.
Those must be the same object of comparison, or the egress check in a later
task compares against something the gateway believed rather than something it
sent.

One test monkeypatches `gw._client.post` — the response-shape parse, which is
about `choices[0].message.content` and not about the wire. One test points the
base URL at a port nothing is listening on, because a refused connection is
the only honest way to produce a transport failure.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from medarx.config import Settings
from medarx.errors import (
    GatewayError,
    ProviderResponseError,
    ProviderStatusError,
    ProviderTransportError,
)
from medarx.gateway.openai_gateway import ModelGateway
from medarx.models import (
    ModelRequest,
    StructuredPayload,
    canonical_hash,
    payload_hash_of,
)

from conftest import KEY

COMPLETION = {
    "object": "chat.completion",
    "model": "medarx-demo-model",
    "choices": [
        {
            "index": 0,
            "message": {"role": "assistant", "content": "Findings: 7mm nodule."},
            "finish_reason": "stop",
        }
    ],
    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
}

REQUEST = ModelRequest(
    model="medarx-demo-model",
    messages=[{"role": "user", "content": "FINDINGS: 7mm nodule."}],
    temperature=0.0,
    max_tokens=512,
)


# -- The local stub provider ------------------------------------------------


@dataclass
class _Recorded:
    """One request as the stub actually received it."""

    method: str
    path: str
    headers: dict[str, str]
    body: bytes


@dataclass
class _StubProvider:
    """A loopback HTTP server that answers with a scripted response.

    `delay_s` is here so a timeout can be observed rather than assumed: a
    server that answers instantly cannot show that the configured timeout is
    the one in force. The delay waits on `release` rather than on
    `time.sleep`, so `__exit__` ends it: a handler that outlived its stub
    would still be writing to a socket the test has finished with, on a port
    the operating system is free to hand to the next stub — which showed up
    once as a `LocalProtocolError` in an unrelated test.
    """

    status: int = 200
    body: bytes = b""
    delay_s: float = 0.0
    requests: list[_Recorded] = field(default_factory=list)
    _httpd: ThreadingHTTPServer | None = None
    _thread: threading.Thread | None = None
    _release: threading.Event = field(default_factory=threading.Event)

    @property
    def base_url(self) -> str:
        assert self._httpd is not None, "the stub is not running"
        host, port = self._httpd.server_address[:2]
        return f"http://{host}:{port}/v1"

    def __enter__(self) -> "_StubProvider":
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's name
                length = int(self.headers.get("Content-Length", "0"))
                received = self.rfile.read(length)
                outer.requests.append(
                    _Recorded(
                        method=self.command,
                        path=self.path,
                        headers={k.lower(): v for k, v in self.headers.items()},
                        body=received,
                    )
                )
                if outer.delay_s:
                    outer._release.wait(outer.delay_s)
                try:
                    self.send_response(outer.status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(outer.body)))
                    self.end_headers()
                    self.wfile.write(outer.body)
                except OSError:
                    # The client gave up on this connection — the timeout test
                    # does exactly that. Nothing to report and nothing to fix.
                    self.close_connection = True

            def log_message(self, *args: object) -> None:
                """Silence the default stderr access log."""

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        assert self._httpd is not None and self._thread is not None
        self._release.set()
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)


def _stub_ok() -> _StubProvider:
    return _StubProvider(body=json.dumps(COMPLETION).encode("utf-8"))


def _client_for(stub: _StubProvider, **overrides) -> ModelGateway:
    return ModelGateway(
        Settings(audit_key=KEY, gateway_base_url=stub.base_url, **overrides)
    )


# -- The body, built before any I/O ----------------------------------------


def test_request_body_is_openai_chat_completions_shaped(settings):
    gw = ModelGateway(settings)
    body = gw.build_body(REQUEST)
    assert set(body) == {"model", "messages", "temperature", "max_tokens"}
    assert body["messages"][0]["role"] == "user"
    assert body["model"] == "medarx-demo-model"
    assert body["temperature"] == 0.0
    assert body["max_tokens"] == 512


def test_the_body_carries_the_request_verbatim_and_adds_no_keys(settings):
    # A body that reordered, renamed or defaulted a field would be a
    # reconstruction of the request rather than the request. What it may never
    # do is quietly drop what the caller supplied.
    gw = ModelGateway(settings)
    body = gw.build_body(REQUEST)
    assert body["messages"] == REQUEST.messages
    other = gw.build_body(REQUEST.model_copy(update={"max_tokens": 7}))
    assert other["max_tokens"] == 7 and body["max_tokens"] == 512


def test_no_vision_parameter_is_ever_sent(settings):
    # The local model reports capabilities ["completion", "tools"], with no
    # vision, so no image content may go out. Asserted against the body, which
    # is what the wire carries.
    gw = ModelGateway(settings)
    body = gw.build_body(REQUEST)
    assert "image_url" not in repr(body) and "modalities" not in body
    assert all("image" not in json.dumps(m) for m in body["messages"])


def test_no_provider_is_named_in_the_gateway_module():
    # The provider-agnostic claim is structural: base URL, model, key and
    # timeout come from `Settings`, so one code path drives Ollama and
    # OpenRouter. A provider name appearing in this module would mean a branch
    # crept in. "openai" is deliberately not in the list: what this module
    # names is the OpenAI *wire spec*, which is the very thing that removes
    # the need for a provider branch. Naming a spec is not naming a provider.
    from pathlib import Path

    import medarx.gateway.openai_gateway as module

    source = Path(module.__file__).read_text(encoding="utf-8").lower()
    for provider in ("openrouter", "ollama", "anthropic", "gemini", "mistral"):
        assert provider not in source, f"the gateway module names {provider!r}"


# -- Row 7: unknown model identifier ---------------------------------------


def test_unknown_model_raises_before_a_request_body_is_built(settings, monkeypatch):
    gw = ModelGateway(settings)
    # Spying on the serialiser, not on `build_body`: `build_body` *is* where
    # the registry check lives, so "was entered" is the wrong question. The
    # claim is that no request body was produced, and the moment one exists is
    # the moment it is encoded for the wire.
    import medarx.gateway.openai_gateway as implementation

    encoded: list[object] = []
    real_encode = implementation._encode_body

    def spy_encode(body):
        encoded.append(body)
        return real_encode(body)

    posted: list[object] = []
    monkeypatch.setattr(implementation, "_encode_body", spy_encode)
    monkeypatch.setattr(gw._client, "post", lambda *a, **k: posted.append(a))
    with pytest.raises(GatewayError) as ei:
        gw.send(ModelRequest(model="gpt-9-imaginary", messages=[], temperature=0.0,
                              max_tokens=1))
    assert ei.value.layer == "F"
    assert ei.value.action_codes == ("UNKNOWN_MODEL",)
    assert encoded == [], "a request body was built for an unknown model"
    assert posted == [], "a provider call was made for an unknown model"
    assert gw.last_request_body() is None


def test_unknown_model_never_reaches_the_wire(settings):
    # The same refusal, proved against a real socket rather than a stubbed
    # `post`: the stub server must record nothing at all.
    with _stub_ok() as stub:
        gw = _client_for(stub)
        with pytest.raises(GatewayError):
            gw.send(ModelRequest(model="gpt-9-imaginary", messages=[], temperature=0.0,
                                  max_tokens=1))
        assert stub.requests == []


def test_model_for_defaults_to_the_configured_model_and_refuses_an_unknown_one(settings):
    gw = ModelGateway(settings)
    assert gw.model_for("openrouter/mock-model") == "openrouter/mock-model"
    assert gw.model_for(None) == settings.gateway_model
    with pytest.raises(GatewayError) as ei:
        gw.model_for("gpt-9-imaginary")
    assert ei.value.action_codes == ("UNKNOWN_MODEL",)


def test_a_configured_model_outside_the_registry_is_refused(settings):
    # Fail closed on a misconfigured deployment: the default is validated the
    # same way a caller's `model_id` is, so a typo in MEDARX_GATEWAY_MODEL
    # blocks rather than sending.
    gw = ModelGateway(settings.model_copy(update={"gateway_model": "typo-model"}))
    with pytest.raises(GatewayError) as ei:
        gw.model_for(None)
    assert ei.value.action_codes == ("UNKNOWN_MODEL",)


# -- Row 7: the payload must be the one E approved -------------------------


def _approved_payload() -> StructuredPayload:
    payload = StructuredPayload(
        function="draft",
        report_text="FINDINGS: 7mm nodule in the right lower lobe.",
        dicom_fields={"modality": "CT"},
        study_ref="STUDY-SYN-000041",
        policy_version="medarx-policy-1.0.0",
    )
    return payload.model_copy(update={"payload_hash": payload_hash_of(payload)})


def test_verify_approved_payload_accepts_the_object_the_engine_approved(settings):
    payload = _approved_payload()
    gw = ModelGateway(settings)
    assert gw.verify_approved_payload(payload, payload.payload_hash) is None


def test_verify_approved_payload_refuses_a_substituted_payload(settings):
    # The substitution §6 row 7 exists to stop: the swapped object keeps the
    # hash E approved, because `model_copy(update=...)` leaves the other fields
    # alone, so a check that trusted the carried field would pass this.
    payload = _approved_payload()
    approved = payload.payload_hash
    swapped = payload.model_copy(update={"report_text": "FINDINGS: 12mm mass."})
    gw = ModelGateway(settings)
    with pytest.raises(GatewayError) as ei:
        gw.verify_approved_payload(swapped, approved)
    assert ei.value.layer == "F"
    assert ei.value.action_codes == ("PAYLOAD_MISMATCH", "HASH_MISMATCH")


def test_verify_approved_payload_refuses_a_hash_the_engine_never_approved(settings):
    payload = _approved_payload()
    gw = ModelGateway(settings)
    with pytest.raises(GatewayError) as ei:
        gw.verify_approved_payload(payload, "0" * 64)
    assert ei.value.action_codes == ("PAYLOAD_MISMATCH", "HASH_MISMATCH")


def test_verify_approved_payload_refuses_a_missing_payload(settings):
    gw = ModelGateway(settings)
    with pytest.raises(GatewayError) as ei:
        gw.verify_approved_payload(None, "0" * 64)
    assert ei.value.action_codes == ("PAYLOAD_MISMATCH", "HASH_MISMATCH")


def test_the_gateway_uses_the_one_payload_hash_definition(settings):
    # The same definition redaction layer 3 and the policy engine use. A second
    # expression here would be a hash that could drift from the one it is
    # checking against, and a drift there is a boundary that authorises
    # everything.
    payload = _approved_payload()
    assert payload.payload_hash == canonical_hash(
        payload.model_dump(mode="json", exclude={"payload_hash"})
    )
    gw = ModelGateway(settings)
    gw.verify_approved_payload(payload, payload.payload_hash)


# -- Timeout ----------------------------------------------------------------


def test_the_configured_timeout_is_the_one_on_the_client(settings):
    # Cold first inference measured ~14.6 s, warm ~1.1 s, so the default is
    # 120 s. Asserted from the client rather than from `Settings`, because the
    # setting being 120 is not the same claim as the client using 120.
    gw = ModelGateway(settings)
    assert gw._client.timeout == httpx.Timeout(settings.gateway_timeout_s)
    assert settings.gateway_timeout_s >= 60.0


def test_a_shortened_timeout_is_honoured_rather_than_ignored():
    # The other direction: a deployment that lowers the timeout must actually
    # get a shorter one. Proven by a stub that never answers in time.
    with _StubProvider(body=b"{}", delay_s=2.0) as stub:
        gw = _client_for(stub, gateway_timeout_s=0.25)
        with pytest.raises(ProviderTransportError):
            gw.send(REQUEST)
    with _stub_ok() as stub:
        gw = _client_for(stub, gateway_timeout_s=10.0)
        assert gw.send(REQUEST).content == "Findings: 7mm nodule."


# -- Success path -----------------------------------------------------------


def test_successful_send_parses_the_openai_response_shape(settings, monkeypatch):
    gw = ModelGateway(settings)
    monkeypatch.setattr(
        gw._client, "post", lambda url, **kw: httpx.Response(200, json=COMPLETION)
    )
    r = gw.send(REQUEST)
    assert r.model_id == "medarx-demo-model"
    assert r.content == "Findings: 7mm nodule."
    assert r.raw["object"] == "chat.completion"


def test_a_real_provider_round_trip_needs_no_provider(settings):
    with _stub_ok() as stub:
        gw = _client_for(stub)
        r = gw.send(REQUEST)
        assert r.content == "Findings: 7mm nodule."
        assert r.model_id == "medarx-demo-model"
        assert r.raw["usage"]["total_tokens"] == 2
        assert len(stub.requests) == 1
        assert stub.requests[0].method == "POST"
        assert stub.requests[0].path == "/v1/chat/completions"


# -- The bytes on the wire --------------------------------------------------


def test_the_bytes_on_the_wire_are_exactly_the_bytes_the_gateway_records():
    with _stub_ok() as stub:
        gw = _client_for(stub)
        gw.send(REQUEST)
        assert stub.requests[0].body == gw.last_request_body()
        assert json.loads(gw.last_request_body()) == gw.build_body(REQUEST)


def test_non_ascii_report_text_is_escaped_and_still_matches_the_recorded_bytes():
    # The encoding choice is load-bearing, so it is measured rather than
    # assumed. `ensure_ascii` on means the bytes are ASCII whatever the report
    # contains, so the evidence `last_request_body` returns cannot depend on
    # how the transport happened to encode UTF-8 — and a mutation to
    # `json=body` fails here, because httpx writes the raw UTF-8 instead and
    # the two byte strings then differ.
    report = "FINDINGS: 7mm nodulo — øst, 37°C"
    with _stub_ok() as stub:
        gw = _client_for(stub)
        gw.send(REQUEST.model_copy(update={"messages": [{"role": "user", "content": report}]}))
    recorded = stub.requests[0].body
    assert recorded == gw.last_request_body()
    assert recorded.isascii(), recorded
    assert json.loads(recorded)["messages"][0]["content"] == report


def test_the_recorded_bytes_decode_to_the_request_and_nothing_more():
    # No normalisation, no extra keys, no reordering by the transport: the
    # recorded body is exactly `build_body`'s four keys.
    with _stub_ok() as stub:
        gw = _client_for(stub)
        gw.send(REQUEST)
        decoded = json.loads(stub.requests[0].body)
    assert decoded == {
        "model": "medarx-demo-model",
        "messages": [{"role": "user", "content": "FINDINGS: 7mm nodule."}],
        "temperature": 0.0,
        "max_tokens": 512,
    }


def test_the_request_is_sent_as_json():
    with _stub_ok() as stub:
        gw = _client_for(stub)
        gw.send(REQUEST)
    assert stub.requests[0].headers["content-type"].startswith("application/json")


def test_the_same_implementation_serves_any_base_url():
    # The provider-agnostic claim, run twice against two different loopback
    # ports: no argument, setting or branch names a provider.
    for _ in range(2):
        with _StubProvider(body=json.dumps(COMPLETION).encode("utf-8")) as stub:
            gw = _client_for(stub)
            assert gw.send(REQUEST).content == "Findings: 7mm nodule."
            assert stub.requests[0].path == "/v1/chat/completions"


# -- The Authorization header ----------------------------------------------


def test_an_empty_api_key_omits_the_authorization_header_entirely():
    with _stub_ok() as stub:
        gw = _client_for(stub, gateway_api_key="")
        gw.send(REQUEST)
    assert "authorization" not in stub.requests[0].headers, (
        "an empty key must send no header at all, not an empty one"
    )


def test_a_configured_api_key_is_sent_as_a_bearer_token():
    with _stub_ok() as stub:
        gw = _client_for(stub, gateway_api_key="synthetic-test-key")
        gw.send(REQUEST)
    assert stub.requests[0].headers["authorization"] == "Bearer synthetic-test-key"


def test_the_default_api_key_is_empty(settings):
    # Checked at its source: a default secret in `config.py` is the thing this
    # whole arrangement exists to prevent.
    assert settings.gateway_api_key == ""


# -- Three different failures, kept apart ----------------------------------


def test_a_non_2xx_response_is_a_status_failure():
    with _StubProvider(status=503, body=b'{"error": "overloaded"}') as stub:
        gw = _client_for(stub)
        with pytest.raises(ProviderStatusError) as ei:
            gw.send(REQUEST)
    assert ei.value.status_code == 503


def test_a_transport_failure_is_a_transport_failure():
    # Nothing is listening on this port: the connection itself fails, which is
    # a different condition from a provider that answered with an error.
    gw = ModelGateway(
        Settings(audit_key=KEY, gateway_base_url="http://127.0.0.1:9/v1")
    )
    with pytest.raises(ProviderTransportError):
        gw.send(REQUEST)


@pytest.mark.parametrize(
    ("label", "body"),
    [
        ("not json", b"<html>gateway timeout</html>"),
        ("no choices", json.dumps({"object": "chat.completion"}).encode()),
        ("empty choices", json.dumps({"choices": []}).encode()),
        (
            "no content",
            json.dumps({"choices": [{"index": 0, "message": {"role": "assistant"}}]}),
        ),
        (
            "content not a string",
            json.dumps({"choices": [{"index": 0, "message": {"content": {"t": "x"}}}]}),
        ),
    ],
)
def test_a_malformed_body_is_a_response_failure(label, body):
    with _StubProvider(body=body.encode() if isinstance(body, str) else body) as stub:
        gw = _client_for(stub)
        with pytest.raises(ProviderResponseError):
            gw.send(REQUEST)


def test_the_three_failures_are_three_distinct_types():
    # The requirement as a property of the exception hierarchy rather than as
    # three separate assertions: a caller must be able to tell them apart
    # without parsing a message.
    assert not issubclass(ProviderStatusError, ProviderTransportError)
    assert not issubclass(ProviderResponseError, ProviderTransportError)
    assert not issubclass(ProviderStatusError, ProviderResponseError)
    assert not issubclass(ProviderStatusError, GatewayError)
    assert not issubclass(ProviderTransportError, GatewayError)
    assert not issubclass(ProviderResponseError, GatewayError)


def test_a_provider_failure_is_not_a_privacy_block():
    # §6 has no row for "the provider was down". A `MedarxError` here would
    # reach the API as a 422 block receipt naming codes for a refusal the
    # privacy kernel never made.
    with _StubProvider(status=500, body=b"{}") as stub:
        gw = _client_for(stub)
        with pytest.raises(ProviderStatusError) as ei:
            gw.send(REQUEST)
        assert not isinstance(ei.value, GatewayError)


# -- State ------------------------------------------------------------------


def test_last_request_body_is_none_before_anything_is_sent(settings):
    assert ModelGateway(settings).last_request_body() is None


def test_a_refused_request_leaves_the_previous_body_untouched():
    # `last_request_body` is the egress evidence for the last request that
    # actually went out. A refusal must not overwrite it with a body that was
    # never sent, or a later comparison would read evidence for a request that
    # did not happen.
    with _stub_ok() as stub:
        gw = _client_for(stub)
        gw.send(REQUEST)
        sent = gw.last_request_body()
        with pytest.raises(GatewayError):
            gw.send(ModelRequest(model="nope", messages=[], temperature=0.0,
                                  max_tokens=1))
        assert gw.last_request_body() == sent
