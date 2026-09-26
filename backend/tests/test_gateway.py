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
from medarx.gateway.openai_gateway import ApprovedSend, ModelGateway
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


def _approved_payload() -> StructuredPayload:
    """A payload carrying the layer-3 hash of its own content, as redaction writes it."""
    payload = StructuredPayload(
        function="draft",
        report_text="FINDINGS: 7mm nodule in the right lower lobe.",
        dicom_fields={"modality": "CT"},
        study_ref="STUDY-SYN-000041",
        policy_version="medarx-policy-1.0.0",
    )
    return payload.model_copy(update={"payload_hash": payload_hash_of(payload)})


def _approve(
    gw: ModelGateway,
    request: ModelRequest = REQUEST,
    payload: StructuredPayload | None = None,
) -> ApprovedSend:
    """The only way into `send`: run the verifier, as the composition root must."""
    subject = _approved_payload() if payload is None else payload
    return gw.verify_approved_payload(subject, subject.payload_hash, request)


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
        gw.verify_approved_payload(
            _approved_payload(),
            _approved_payload().payload_hash,
            ModelRequest(model="gpt-9-imaginary", messages=[], temperature=0.0,
                          max_tokens=1),
        )
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
            _approve(
                gw,
                ModelRequest(model="gpt-9-imaginary", messages=[], temperature=0.0,
                              max_tokens=1),
            )
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


def test_verify_approved_payload_returns_the_token_for_the_approved_object(settings):
    payload = _approved_payload()
    gw = ModelGateway(settings)
    token = gw.verify_approved_payload(payload, payload.payload_hash, REQUEST)
    assert isinstance(token, ApprovedSend)
    assert token.request is REQUEST
    assert token.approved_payload_hash == payload.payload_hash
    assert token.body == gw.build_body(REQUEST)


def test_verify_approved_payload_refuses_a_substituted_payload(settings):
    # The substitution §6 row 7 exists to stop: the swapped object keeps the
    # hash E approved, because `model_copy(update=...)` leaves the other fields
    # alone, so a check that trusted the carried field would pass this.
    payload = _approved_payload()
    approved = payload.payload_hash
    swapped = payload.model_copy(update={"report_text": "FINDINGS: 12mm mass."})
    gw = ModelGateway(settings)
    with pytest.raises(GatewayError) as ei:
        gw.verify_approved_payload(swapped, approved, REQUEST)
    assert ei.value.layer == "F"
    assert ei.value.action_codes == ("PAYLOAD_MISMATCH", "HASH_MISMATCH")


def test_verify_approved_payload_refuses_a_hash_the_engine_never_approved(settings):
    payload = _approved_payload()
    gw = ModelGateway(settings)
    with pytest.raises(GatewayError) as ei:
        gw.verify_approved_payload(payload, "0" * 64, REQUEST)
    assert ei.value.action_codes == ("PAYLOAD_MISMATCH", "HASH_MISMATCH")


def test_verify_approved_payload_refuses_a_missing_payload(settings):
    gw = ModelGateway(settings)
    with pytest.raises(GatewayError) as ei:
        gw.verify_approved_payload(None, "0" * 64, REQUEST)
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
    gw.verify_approved_payload(payload, payload.payload_hash, REQUEST)


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
            gw.send(_approve(gw))
    with _stub_ok() as stub:
        gw = _client_for(stub, gateway_timeout_s=10.0)
        assert gw.send(_approve(gw)).content == "Findings: 7mm nodule."


# -- Success path -----------------------------------------------------------


def test_successful_send_parses_the_openai_response_shape(settings, monkeypatch):
    gw = ModelGateway(settings)
    monkeypatch.setattr(
        gw._client, "post", lambda url, **kw: httpx.Response(200, json=COMPLETION)
    )
    r = gw.send(_approve(gw))
    assert r.model_id == "medarx-demo-model"
    assert r.content == "Findings: 7mm nodule."
    assert r.raw["object"] == "chat.completion"


def test_a_real_provider_round_trip_needs_no_provider(settings):
    with _stub_ok() as stub:
        gw = _client_for(stub)
        r = gw.send(_approve(gw))
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
        gw.send(_approve(gw))
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
        request = REQUEST.model_copy(
            update={"messages": [{"role": "user", "content": report}]}
        )
        gw.send(_approve(gw, request))
    recorded = stub.requests[0].body
    assert recorded == gw.last_request_body()
    assert recorded.isascii(), recorded
    assert json.loads(recorded)["messages"][0]["content"] == report


def test_the_recorded_bytes_decode_to_the_request_and_nothing_more():
    # No normalisation, no extra keys, no reordering by the transport: the
    # recorded body is exactly `build_body`'s four keys.
    with _stub_ok() as stub:
        gw = _client_for(stub)
        gw.send(_approve(gw))
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
        gw.send(_approve(gw))
    assert stub.requests[0].headers["content-type"].startswith("application/json")


def test_the_same_implementation_serves_any_base_url():
    # The provider-agnostic claim, run twice against two different loopback
    # ports: no argument, setting or branch names a provider.
    for _ in range(2):
        with _StubProvider(body=json.dumps(COMPLETION).encode("utf-8")) as stub:
            gw = _client_for(stub)
            assert gw.send(_approve(gw)).content == "Findings: 7mm nodule."
            assert stub.requests[0].path == "/v1/chat/completions"


# -- The Authorization header ----------------------------------------------


def test_an_empty_api_key_omits_the_authorization_header_entirely():
    with _stub_ok() as stub:
        gw = _client_for(stub, gateway_api_key="")
        gw.send(_approve(gw))
    assert "authorization" not in stub.requests[0].headers, (
        "an empty key must send no header at all, not an empty one"
    )


def test_a_configured_api_key_is_sent_as_a_bearer_token():
    with _stub_ok() as stub:
        gw = _client_for(stub, gateway_api_key="synthetic-test-key")
        gw.send(_approve(gw))
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
            gw.send(_approve(gw))
    assert ei.value.status_code == 503


def test_a_transport_failure_is_a_transport_failure():
    # Nothing is listening on this port: the connection itself fails, which is
    # a different condition from a provider that answered with an error.
    gw = ModelGateway(
        Settings(audit_key=KEY, gateway_base_url="http://127.0.0.1:9/v1")
    )
    with pytest.raises(ProviderTransportError):
        gw.send(_approve(gw))


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
            gw.send(_approve(gw))


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
            gw.send(_approve(gw))
        assert not isinstance(ei.value, GatewayError)


# -- State ------------------------------------------------------------------


def test_last_request_body_is_none_before_anything_is_sent(settings):
    assert ModelGateway(settings).last_request_body() is None


def test_a_refused_request_leaves_the_previous_body_untouched():
    # `last_request_body` is the egress evidence for the last request handed to
    # a transport. A refusal must not overwrite it with a body that was never
    # sent, or a later comparison would read evidence for a request that did
    # not happen.
    with _stub_ok() as stub:
        gw = _client_for(stub)
        gw.send(_approve(gw))
        sent = gw.last_request_body()
        with pytest.raises(GatewayError):
            gw.verify_approved_payload(
                _approved_payload().model_copy(update={"report_text": "UNAPPROVED"}),
                _approved_payload().payload_hash,
                REQUEST,
            )
        assert gw.last_request_body() == sent
        assert len(stub.requests) == 1


# -- What can and cannot be sent -------------------------------------------


def test_send_refuses_anything_that_is_not_an_approved_send():
    # The load-bearing test for the token. Under the previous signature this
    # was a legal call: a bare `ModelRequest` went straight to the wire, so a
    # caller could verify the approved payload and transmit a request built
    # from a different one, and `last_request_body` would have reported the
    # substituted bytes for the egress check to certify.
    with _stub_ok() as stub:
        gw = _client_for(stub)
        with pytest.raises(TypeError):
            gw.send(REQUEST)
        assert stub.requests == []
        assert gw.last_request_body() is None


def test_an_approved_send_cannot_be_built_by_hand():
    # The sentinel, not a convention: the constructor refuses any value other
    # than this module's private `_ISSUED`.
    for issued in (None, object(), "issued"):
        with pytest.raises(TypeError):
            ApprovedSend(
                request=REQUEST,
                approved_payload_hash="0" * 64,
                body={},
                body_bytes=b"",
                _issued=issued,
            )


def test_the_sentinel_is_private_to_the_gateway_module():
    # Python has no access control, so this is the strongest available
    # enforcement rather than a guarantee — and the same standard this package
    # already accepts for `ALLOWED_MODELS` and the module-level action codes.
    # What it does buy is that the token cannot be minted by any *other* module
    # in the package, so a second egress path cannot be added by accident.
    import ast
    from pathlib import Path

    import medarx

    root = Path(medarx.__file__).parent
    owner = root / "gateway" / "openai_gateway.py"
    offenders = []
    for path in sorted(root.rglob("*.py")):
        if path == owner:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id == "_ISSUED":
                offenders.append(f"{path}:{node.lineno}")
            elif isinstance(node, ast.Attribute) and node.attr == "_ISSUED":
                offenders.append(f"{path}:{node.lineno}")
    assert not offenders, (
        "the ApprovedSend sentinel is referenced outside the module that owns "
        f"it, so the token can be minted from there: {offenders}"
    )


def test_the_bytes_sent_are_the_bytes_fixed_at_authorisation():
    # One encoding, one body, fixed at the moment of verification. If `send`
    # re-derived the body it would be a second chance for what goes on the wire
    # to differ from what was authorised — and from what the egress check
    # compares against.
    with _stub_ok() as stub:
        gw = _client_for(stub)
        token = _approve(gw)
        assert token.body_bytes == json.dumps(token.body, separators=(",", ":")).encode()
        gw.send(token)
        # `is`, not `==`, for the in-process half: the recorded evidence must
        # be the same object that was authorised, not an equal copy. The wire
        # half is `==` because those bytes cross a socket, where identity
        # cannot survive.
        assert gw.last_request_body() is token.body_bytes
        assert stub.requests[0].body == token.body_bytes


def test_the_request_verified_is_the_request_sent():
    # The identity half of the binding. The token names the request that was
    # authorised; `send` takes one positional argument, so there is nowhere to
    # hand it a different one, and what appears on the wire is the content of
    # the verified request rather than of whatever the caller holds later.
    with _stub_ok() as stub:
        gw = _client_for(stub)
        token = _approve(gw, REQUEST)
        gw.send(token)
    assert token.request is REQUEST
    sent = json.loads(stub.requests[0].body)
    assert sent["messages"] == REQUEST.messages
    assert sent["messages"][0]["content"] == "FINDINGS: 7mm nodule."
