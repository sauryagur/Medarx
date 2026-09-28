"""Beat 3 — the real kernel against a real local model, end to end.

    cd backend && uv run python ../evals/demo_beat3_local_model.py
    cd backend && uv run python ../evals/demo_beat3_local_model.py --json --out /tmp/beat3
    cd backend && uv run python ../evals/demo_beat3_local_model.py --skip-cold

**What is different from beats 1 and 2, and why it matters.** In both of those
the provider is a container that answers the OpenAI chat-completions shape and
writes down what it was sent. There is no model in the path, and the observer
doubles as the evidence. Here the provider is **`gur-prime-2`, a qwen3 4.0B
Q4_K_M model served by Ollama on this host**, and it does exactly one thing
with a request: run inference. It records nothing, which is the whole of the
difference in the evidence section below.

**The path exercised is validate-then-send, not the atomic one.** A preflight
runs components A, C, D and E and stops before F. Nothing is transmitted, and
the report asserts that: `last_request_body()` is `None` immediately after the
preflight returns, which is the gateway's own evidence that no byte moved. The
send is a **second HTTP call by request ID**, and this script makes it after
reading the preview, standing in for the human the contract's `needs_review`
state exists to ask. That is the phase-2 acceptance path, and it is the one
worth demonstrating; the atomic path is unchanged and is what beat 1 shows.

**No provider branch was needed, and this run is the evidence.** The gateway
sends the OpenAI body to whatever `MEDARX_GATEWAY_BASE_URL` names and puts
whatever `MEDARX_GATEWAY_MODEL` names in the `model` field. Ollama already
speaks that spec, so pointing the deployment at it is three environment
variables and one new registry member (`gur-prime-2` in
`medarx.gateway.model_registry`). No module in `medarx/` mentions Ollama, a
local model, or a provider name; the whole provider-neutrality claim rests on
that and on the body the model received, which is printed below and is
byte-identical to the OpenAI body Medarx built.

## The evidence, and how much of it there is

Component I's rule is the **two-observer** rule, and this run has **one**
observer of the wire. That is not a shortcut and it is not hidden:

- **Observer one is the `tcpdump`.** `infra/capture/start_capture.sh` in the
  host network namespace, pointed at `lo` because Ollama is on this host and
  the gateway reaches it over loopback rather than over a Docker bridge. The
  body it reassembles is compared byte for byte against
  `ModelGateway.last_request_body()` with the existing
  `compare_bytes_to_payload`, and both are searched for the approved report
  text the kernel approved in this process.
- **There is no observer two.** The Phase 1 observer is a *provider*, and the
  provider here is a real model with no recording side channel. So the second
  witness is Medarx's own record of what it handed to the transport, and that
  is Medarx attesting to itself. `check_agreement` is run anyway and its
  verdict is reported: it refuses, as an asymmetric observation, which is the
  correct answer and the reason a run in which the second observer is missing
  cannot be read as a pass.

**What that costs, stated plainly.** The tcpdump half is as independent as it
is in beat 1: a process that never handled the request reassembled it. What is
weaker is the *pairing* — "the bytes the capture saw are the bytes the gateway
recorded" is two observations, one of them Medarx's. In beat 1 the pairing was
between two outsiders. The check that the approved payload is what was
transmitted does not depend on that pairing, though: the needle is the approved
report text, read out of the `StructuredPayload` component E approved, and it
is the needle's **absence** from every other body on the wire — and the
identifiers' absence — that this run turns on.

**What is measured, not inherited.** The phase-1 design estimated the model at
~3.4 GB resident; Ollama reports `2497283049` bytes on disk and the measured
resident size is in `memory` below. Latency is measured twice — once after an
explicit `keep_alive: 0` unload, once warm — because a cold first inference is
the request a user waits on and `Settings.gateway_timeout_s` is 120.0.

**`--json` masks the identifiers in the request body and nothing else**, for the
same reason beats 1 and 2 do. The transformed payload, the model's answer and
the captured bytes are printed exactly as they were: a reader seeing the
identifiers *absent* is the entire demonstration.

**Exit codes.** `0` green, `2` the local model is not reachable (so a caller
can skip rather than fail), `1` a red run. A demo that printed a leak and
exited 0 would have converted its own failure into a data point.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

if __package__ in (None, ""):  # run as `python ../evals/demo_beat3_local_model.py`
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evals import beat_support
from evals.synthetic_phi import seed_corpus
from infra.capture.agreement import check_agreement, compare_bytes_to_payload, request_bodies

REPO_ROOT = Path(__file__).resolve().parents[1]
CAPTURE_SCRIPT = REPO_ROOT / "infra" / "capture" / "start_capture.sh"

#: The network argument `start_capture.sh start` still takes when the interface
#: is overridden. The script resolves the bridge from it and the override means
#: it never has to; `medarx` is the name `infra/compose.yaml` fixes, so the
#: argument is a real name rather than a placeholder.
NETWORK = "medarx"

#: The interface the capture watches. **`lo`, not `any`.** Ollama listens on
#: loopback and every byte of this run's request travels over `lo`, so `lo` is
#: the narrow interface that carries exactly the traffic of interest; `any`
#: would capture the whole host's, and a capture that watches a hundred
#: conversations proves less about one of them.
CAPTURE_INTERFACE = "lo"

REQUEST_ID = "req-beat3-local-0001"
WARM_REQUEST_ID = "req-beat3-local-0002"

#: The defaults, which are the *deployment's* configuration for this workstream
#: rather than anything the kernel knows about. They are environment
#: variables, so a deployment pointed somewhere else runs the same code.
DEFAULT_BASE_URL = "http://127.0.0.1:11434/v1"
DEFAULT_MODEL = "gur-prime-2"

#: The policy mode the beat declares rather than inherits, for the reason
#: `beat_support.POLICY_MODE` gives: an audit record is a permanent artefact an
#: auditor reads, and one that says `cloud` for a run whose bytes never left
#: this machine is a false fact in the one store the design names as an asset.
POLICY_MODE = "strict_local"

#: The two corpus cases the input is assembled from, exactly as beat 1 assembles
#: it and for exactly the same reason: `known_positive` is **blocked** at D.2 by
#: the kernel as it stands, so it cannot demonstrate the approved path. These are
#: the corpus's own approved halves — an identifier in the free text, and
#: identifiers in the DICOM header.
REPORT_CASE = "patient_id_label_spelling"
DICOM_CASE = "dicom_header_identifiers"

#: The registry member this run depends on. Spelled out rather than imported,
#: so a change to the registry is a failure of this beat rather than something
#: it quietly agrees with.
REGISTERED_MODEL = "gur-prime-2"


def build_input() -> dict:
    """The clinician-supplied request body, identifiers in both surfaces."""
    cases = {case.name: case for case in seed_corpus.ALL_CASES}
    return {
        "function": "Draft",
        "study_context": {
            "study_reference": seed_corpus.identifiers()["study_reference"],
            "modality": "CT",
        },
        "report_text": {
            "text": cases[REPORT_CASE].report_text,
            "source": seed_corpus.REPORT_SOURCE,
        },
        "dicom_metadata": dict(cases[DICOM_CASE].dicom_metadata),
    }


# -- The model, out of band ---------------------------------------------------


def _ollama_root(base_url: str) -> str:
    """Ollama's own API root from the OpenAI-compatible base URL."""
    return base_url.rsplit("/v1", 1)[0] if base_url.rstrip("/").endswith("/v1") else base_url


def probe_model(base_url: str) -> dict:
    """What the local model server says it is serving. Raises if it cannot be asked.

    Read from the provider rather than declared here, for the same reason beat 1
    spells out `OBSERVER_REPLY` instead of importing it: a value a demo imports
    from the thing it is demonstrating agrees with itself, and agreement with
    itself is what this project keeps having to catch.
    """
    import httpx

    try:
        response = httpx.get(f"{_ollama_root(base_url)}/api/tags", timeout=5.0)
        response.raise_for_status()
        tags = response.json()
    except Exception as exc:  # noqa: BLE001 - any failure is "not available here"
        raise ModelUnavailable(
            f"no local model server answered at {_ollama_root(base_url)}: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    models = [m for m in tags.get("models", []) if m.get("name", "").split(":")[0] == REGISTERED_MODEL]
    if not models:
        raise ModelUnavailable(
            f"the local model server is up but is not serving {REGISTERED_MODEL!r}; "
            f"it serves {[m.get('name') for m in tags.get('models', [])]}"
        )
    entry = models[0]
    return {
        "name": entry.get("name"),
        "size_bytes": entry.get("size"),
        "family": entry.get("details", {}).get("family"),
        "parameters": entry.get("details", {}).get("parameter_size"),
        "quantization": entry.get("details", {}).get("quantization_level"),
        "capabilities": entry.get("capabilities"),
        "vision_capability_present": "vision" in (entry.get("capabilities") or []),
    }


def unload_model(base_url: str) -> bool:
    """Ask the model server to drop the model from memory. `False` if it would not.

    This is what makes "cold" a measurement rather than a recollection. Without
    it the first inference of a run depends on whether anything else on the host
    happened to touch the model, and the number would be whatever the machine's
    last ten minutes left behind.
    """
    import httpx

    try:
        httpx.post(
            f"{_ollama_root(base_url)}/api/generate",
            json={"model": REGISTERED_MODEL, "keep_alive": 0},
            timeout=30.0,
        )
        return True
    except Exception:  # noqa: BLE001 - a refusal to unload is reported, not fatal
        return False


class ModelUnavailable(RuntimeError):
    """The local model is not reachable, so this beat cannot run here."""


# -- Memory -------------------------------------------------------------------


def _meminfo() -> dict:
    """`MemTotal` and `MemAvailable` in MiB, read from procfs."""
    out: dict[str, int] = {}
    for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
        key, _, rest = line.partition(":")
        if key in ("MemTotal", "MemAvailable", "SwapTotal"):
            out[key] = int(rest.split()[0]) // 1024
    return out


def _ollama_rss_mib() -> int:
    """Resident set size of every `ollama` process on this host, in MiB.

    Summed over the server *and* the runner, because the model's weights live in
    the runner and a measurement that only looked at the server would report a
    number an order of magnitude too small — which is the mistake the phase-1
    design's ~3.4 GB estimate was not.
    """
    total_kb = 0
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            comm = (entry / "comm").read_text(encoding="utf-8").strip()
            if not comm.startswith("ollama"):
                continue
            for line in (entry / "status").read_text(encoding="utf-8").splitlines():
                if line.startswith("VmRSS:"):
                    total_kb += int(line.split()[1])
                    break
        except (OSError, ValueError):
            continue
    return total_kb // 1024


def memory_snapshot(label: str) -> dict:
    return {"label": label, **_meminfo(), "ollama_rss_mib": _ollama_rss_mib()}


# -- Driving the real application --------------------------------------------


def drive_through_send(database: Path, base_url: str, model: str, body: dict,
                       request_id: str, scope_study: str) -> dict:
    """Preflight, then send, then read the audit record back.

    Both calls are the real HTTP surface of the real composition root, and the
    gateway is the real one pointed at the real model. Nothing is stubbed: the
    only instrumentation is a read-only tap on `verify_approved_payload`, which
    returns the token it was handed, so the approved payload is read out of the
    object component E approved rather than reconstructed.
    """
    for entry in (str(REPO_ROOT / "backend" / "src"), str(REPO_ROOT)):
        if entry not in sys.path:
            sys.path.insert(0, entry)

    from fastapi.testclient import TestClient  # noqa: PLC0415 - after sys.path setup

    from medarx.api.app import create_app  # noqa: PLC0415
    from medarx.config import Settings  # noqa: PLC0415
    from medarx.models import payload_hash_of  # noqa: PLC0415

    settings = Settings(
        audit_key=beat_support.AUDIT_KEY,
        date_order=beat_support.DATE_ORDER,
        policy_mode=POLICY_MODE,
        gateway_base_url=base_url,
        gateway_model=model,
    )
    app = create_app(settings, f"sqlite:///{database}")
    gateway = app.state.pipeline.gateway
    original = gateway.verify_approved_payload
    approved: dict = {}

    def tap(payload, approved_hash, request):  # type: ignore[no-untyped-def]
        if payload is not None and not approved:
            approved.update({
                "report_text": payload.report_text,
                "dicom_fields": dict(payload.dicom_fields),
                "function": payload.function,
                "policy_version": payload.policy_version,
                "payload_hash": str(payload.payload_hash),
                "recomputed_payload_hash": payload_hash_of(payload),
                "claimed_hash_matches_content":
                    str(payload.payload_hash) == payload_hash_of(payload),
            })
        return original(payload, approved_hash, request)

    gateway.verify_approved_payload = tap  # type: ignore[method-assign]
    headers = {
        "X-Scope": f"scope:study:{scope_study},scope:function:Draft",
        "X-Request-Id": request_id,
    }
    out: dict = {}
    try:
        with TestClient(app) as client:
            preflight = client.post(
                "/v1/functions/Draft/executions/preflight", json=body, headers=headers,
            )
            out["preflight_status"] = preflight.status_code
            out["preflight_body"] = preflight.json()
            # The gateway's own evidence that the preflight transmitted nothing.
            out["request_body_after_preflight"] = gateway.last_request_body()

            started = time.perf_counter()
            sent = client.post(f"/v1/executions/{request_id}/send", headers=headers)
            out["send_elapsed_s"] = time.perf_counter() - started
            out["send_status"] = sent.status_code
            out["send_body"] = sent.json()
            out["request_body_after_send"] = gateway.last_request_body()

            audit = client.get(f"/v1/audit/records/{request_id}", headers=headers)
            out["audit_status"] = audit.status_code
            out["audit_body"] = audit.json() if audit.status_code == 200 else None
    finally:
        gateway.verify_approved_payload = original  # type: ignore[method-assign]
        try:
            app.state.pipeline.close()
        except Exception:  # noqa: BLE001 - teardown must not mask a real failure
            pass
    out["approved_payload"] = approved
    # The settings this run actually ran under, not the defaults: the point of
    # reporting the timeout is to say the number the client used, and the
    # defaults are only that when nothing overrode them.
    out["settings_in_force"] = {
        "gateway_timeout_s": settings.gateway_timeout_s,
        "gateway_model": settings.gateway_model,
        "gateway_base_url": settings.gateway_base_url,
        "policy_mode": settings.policy_mode,
        "policy_version": settings.policy_version,
        "date_order": settings.date_order,
    }
    return out


# -- The capture --------------------------------------------------------------


def _port_of(base_url: str) -> str:
    """The port the configured base URL names, as a BPF filter fragment.

    Read from the deployment's own setting rather than written down, because a
    filter hard-coded to one port would silently watch the wrong thing on any
    deployment that is not the one it was written for — and a capture watching
    the wrong port reports "nothing left" with the same confidence as one
    watching the right one.
    """
    from urllib.parse import urlparse  # noqa: PLC0415 - only needed here

    port = urlparse(base_url).port
    if port is None:
        raise ModelUnavailable(f"the base URL {base_url!r} names no port to capture on")
    return f"tcp port {port}"


def start_capture(out_dir: Path, capture_filter: str) -> None:
    subprocess.run(
        ["bash", str(CAPTURE_SCRIPT), "start", NETWORK, "0", str(out_dir)],
        check=True, capture_output=True, text=True, timeout=300,
        env={**os.environ, "MEDARX_CAPTURE_INTERFACE": CAPTURE_INTERFACE,
             "MEDARX_CAPTURE_FILTER": capture_filter},
    )


def stop_capture(out_dir: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(CAPTURE_SCRIPT), "stop", str(out_dir)],
        check=False, capture_output=True, text=True, timeout=300,
    )


def verify_wire_evidence(captured: "list[bytes]", sent_bytes: bytes,
                         approved: dict, planted: "list[str]") -> dict:
    """Was the approved payload what the model received? Raises if it was not.

    Split out of `run` so the check can be **argued with**: the tests in
    `backend/tests/test_local_model_e2e.py` take the evidence a passing run
    produced and damage it in one specific way each, and assert this refuses.
    A check that only ever returns is not evidence — that is the whole of beat
    1's negative tests, and the reason this is a function rather than a
    sequence of statements at the end of a demo.

    Three things must hold, and each fails differently:

    1. **Exactly one** captured body is byte-identical to what the gateway
       recorded. Not "at least one" — a count other than one means the
       comparison below is not the single comparison it claims to be, and not
       "the first one", which would be a comparison against whatever happened
       to arrive first.
    2. **The approved report text is in those bytes**, in the form the wire
       carries it: a newline in a report travels as a backslash followed by an
       `n`, so the needle
       is `json.dumps` of the content without its quotes, which is exactly what
       the encoder emitted. The needle is the kernel's own approved object, not
       the capture's, which is the distinction this project has already had to
       learn the hard way.
    3. **No value from the fabricated inventory is in any body on the wire** —
       not only the matched one. A second body carrying an identifier is as much
       a leak as the first carrying one, and a check that only looked at the
       body it selected would miss exactly that.
    """
    if not captured:
        raise AssertionError(
            "the capture reassembled no request body at all, so there is nothing to "
            "compare; this is a broken capture, not a result"
        )
    matches = [b for b in captured if b == sent_bytes]
    if len(matches) != 1:
        raise AssertionError(
            f"{len(matches)} captured request bodies are byte-identical to the one the "
            "gateway recorded; exactly one should be, and a count other than one "
            "means the comparison below is not the comparison it claims to be"
        )
    observed = matches[0]

    # The existing comparison, on the existing inputs: the bytes the capture
    # reassembled off the wire against the bytes the gateway handed the
    # transport, each against the approved payload's hash.
    comparison = compare_bytes_to_payload(observed, sent_bytes, approved["payload_hash"])
    if not comparison.observer_bytes_match:
        raise AssertionError(
            "the capture reassembled different bytes from the ones the gateway "
            f"recorded: {comparison.byte_differences}"
        )
    needle = approved["report_text"]
    if json.dumps(needle, ensure_ascii=False)[1:-1].encode("utf-8") not in observed:
        raise AssertionError(
            "the approved report text is not in the bytes the capture reassembled, "
            "so the payload that reached the model is not the payload that was "
            "approved"
        )

    captured_text = observed.decode("utf-8", errors="replace")
    survivors = [k for k in planted if beat_support.value_of(k) in captured_text]
    if survivors:
        raise AssertionError(
            "an identifier from the inventory is present in the captured outbound "
            f"bytes: {survivors}"
        )
    all_wire_text = "\n".join(b.decode("utf-8", errors="replace") for b in captured)
    survivors_anywhere = [k for k in planted if beat_support.value_of(k) in all_wire_text]
    if survivors_anywhere:
        raise AssertionError(
            "an identifier from the inventory is present in some other body on the "
            f"wire: {survivors_anywhere}"
        )
    return {
        "bodies_byte_identical": len(matches),
        "observed": observed,
        "captured_text": captured_text,
        "comparison": comparison,
        "approved_content_on_the_wire": True,
        "identifiers_in_captured_bytes": survivors,
        "identifiers_in_any_captured_body": survivors_anywhere,
    }


# -- The run ------------------------------------------------------------------


def run(out_dir: Path, *, base_url: str, model: str, skip_cold: bool) -> dict:
    """Run the beat and return its report. Raises rather than returning a red run."""
    served = probe_model(base_url)

    # Read the registry out of the running package, and refuse before anything
    # is sent if the model this deployment names is not in it. A beat that
    # discovered the refusal later would have already spent a request to find out.
    for entry in (str(REPO_ROOT / "backend" / "src"), str(REPO_ROOT)):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    from medarx.gateway.model_registry import ALLOWED_MODELS, is_allowed  # noqa: PLC0415

    if not is_allowed(model):
        raise AssertionError(
            f"{model!r} is not in the model registry ({sorted(ALLOWED_MODELS)}); the "
            "gateway would refuse it at layer F before building a body, and this "
            "beat would have nothing to send"
        )

    body = build_input()
    cold_unloaded = False
    memory: list[dict] = [memory_snapshot("before")]
    if not skip_cold:
        cold_unloaded = unload_model(base_url)
        # Ollama's unload is asynchronous; give it a moment so the first request
        # really is a load rather than a race with the unload.
        time.sleep(2.0)
    memory.append(memory_snapshot("after_unload" if not skip_cold else "no_unload"))

    capture_dir = out_dir / "capture"
    capture_dir.mkdir(parents=True, exist_ok=True)
    capture_filter = _port_of(base_url)
    start_capture(capture_dir, capture_filter)
    try:
        cold = drive_through_send(
            out_dir / "kernel-cold.db", base_url, model, body, REQUEST_ID,
            body["study_context"]["study_reference"],
        )
    finally:
        stopped = stop_capture(capture_dir)
    memory.append(memory_snapshot("after_cold_inference"))

    pcap_text = (capture_dir / "out.pcap.txt").read_text(encoding="utf-8")
    captured = request_bodies(pcap_text)

    if cold["preflight_status"] != 200:
        raise AssertionError(
            "the preflight did not validate: HTTP "
            f"{cold['preflight_status']} with {json.dumps(cold['preflight_body'])}"
        )
    if cold["request_body_after_preflight"] is not None:
        raise AssertionError(
            "the gateway recorded a request body during the preflight, so the "
            "preflight transmitted something; a validated preflight contacts no "
            "provider"
        )
    if cold["send_status"] != 200:
        raise AssertionError(
            f"the send did not return an approved execution: HTTP {cold['send_status']} "
            f"with {json.dumps(cold['send_body'])}"
        )
    if not cold["approved_payload"].get("claimed_hash_matches_content"):
        raise AssertionError(
            "the approved payload's own hash field does not match a hash recomputed "
            "from its content, so the hash the API reports is a claim and not a fact"
        )
    sent_bytes = cold["request_body_after_send"]
    if sent_bytes is None:
        raise AssertionError("the gateway recorded no request body for the send")
    planted = beat_support.planted_identifier_keys(json.dumps(body, ensure_ascii=False))
    wire = verify_wire_evidence(
        captured, sent_bytes, cold["approved_payload"], planted,
    )

    # The two-observer rule, run anyway, because its answer is part of the
    # report: with a real model there is no recording observer, and a rule that
    # scored that as agreement would be a rule that cannot fail.
    agreement = check_agreement(
        cold["approved_payload"]["payload_hash"], cold["approved_payload"]["report_text"],
        out_dir / "records", pcap_text, REQUEST_ID, observer_live=True,
    )

    warm = None
    if not skip_cold:
        warm = drive_through_send(
            out_dir / "kernel-warm.db", base_url, model, body, WARM_REQUEST_ID,
            body["study_context"]["study_reference"],
        )
        if warm["send_status"] != 200:
            raise AssertionError(
                f"the warm send did not return an approved execution: HTTP "
                f"{warm['send_status']} with {json.dumps(warm['send_body'])}"
            )
        memory.append(memory_snapshot("after_warm_inference"))


    draft = cold["send_body"]["draft"]
    if not str(draft.get("content", "")).strip():
        raise AssertionError(
            "the model returned no text, so there is no draft; the gateway is "
            "supposed to refuse an empty answer rather than return one"
        )

    return {
        "beat": "beat3-local-model",
        "live": True,
        "evidence_dir": str(out_dir),
        "request_id": REQUEST_ID,
        "status": cold["send_body"]["status"],
        "policy_mode": POLICY_MODE,
        "policy_mode_note": (
            "the deployment mode the audit records in this report carry; the model "
            "is on this host and nothing left it"
        ),
        "model": {
            "registry_member": model,
            "registry": sorted(ALLOWED_MODELS),
            "base_url": base_url,
            "served": served,
            "no_provider_branch": (
                "the gateway builds one OpenAI body and posts it to the configured "
                "base URL; nothing in medarx/ names Ollama or any other provider, "
                "and the captured body below is that same OpenAI body"
            ),
        },
        "timing_s": {
            "cold_send": cold["send_elapsed_s"],
            "warm_send": warm["send_elapsed_s"] if warm else None,
            "configured_timeout_s": cold["settings_in_force"]["gateway_timeout_s"],
            "cold_model_was_unloaded_first": cold_unloaded,
            "note": (
                "cold_send is the round trip from the send call to the model's "
                "answer and includes loading the model into memory when it was not "
                "resident; warm_send is the same path with the model resident"
            ),
        },
        "memory": {
            "snapshots": memory,
            "ollama_rss_at_peak_mib": max(m["ollama_rss_mib"] for m in memory),
            "model_bytes_on_disk": served["size_bytes"],
            "swap_total_mib": memory[0].get("SwapTotal"),
        },
        "evidence": {
            "observers": 1,
            "why": (
                "the tcpdump is the only observer of the wire: a real model has no "
                "recording side channel, so the second witness in the two-observer "
                "rule is the gateway's own record, which is Medarx attesting to "
                "itself. The capture half is as independent as it is in beat 1."
            ),
            "capture_interface": CAPTURE_INTERFACE,
            "capture_filter": capture_filter,
            "capture_filter_why": (
                "lo carries every other process's loopback traffic on a shared "
                "host, and a check that swept every body in the capture for an "
                "identifier would find another program's request and report a "
                "leak that never happened. The capture is scoped to the port "
                "the deployment is pointed at, so the evidence is about this "
                "conversation."
            ),
            "capture_readback_exit_status": stopped.returncode,
            "capture_readback": (capture_dir / "out.pcap.txt").read_text(
                encoding="utf-8", errors="replace")[:400],
            # The third state is only a state if the preflight stopped. The
            # gateway's own record of what it handed a transport is the evidence,
            # and it is `None` at that point in a correct run.
            "preflight_recorded_no_request_body":
                cold["request_body_after_preflight"] is None,
            "captured_request_body_count": len(captured),
            "bodies_byte_identical_to_the_gateway_record":
                wire["bodies_byte_identical"],
            "observer_bytes_match": wire["comparison"].observer_bytes_match,
            "byte_differences": wire["comparison"].byte_differences,
            "hash_matches": wire["comparison"].hash_matches,
            "approved_content_on_the_wire": wire["approved_content_on_the_wire"],
            "two_observer_rule_verdict": agreement.as_dict(),
            "two_observer_rule_note": (
                "check_agreement refuses, as an asymmetric observation, and that is "
                "the correct answer: a run with one observer must not read as "
                "agreement"
            ),
        },
        "artefacts": {
            "input": body,
            "transformed_payload": {
                "approved_by": "component E, via component F's verification",
                "read_from": "the StructuredPayload object, in this process",
                **cold["approved_payload"],
                "report_text_as_it_reached_the_wire":
                    json.loads(wire["captured_text"])["messages"][-1]["content"],
            },
            "model_response": {
                "read_from": "the API's 200 body",
                "body": draft,
            },
            "captured_outbound_request": {
                "read_from": "tcpdump -X readback of lo, this run",
                "body": wire["captured_text"],
            },
        },
        "planted_identifier_keys": planted,
        "identifiers_in_captured_bytes": wire["identifiers_in_captured_bytes"],
        "identifiers_in_any_captured_body": wire["identifiers_in_any_captured_body"],
        "audit_record": cold["audit_body"],
        "audit_final_disposition": (cold["audit_body"] or {}).get("final_disposition"),
    }


# -- Rendering ----------------------------------------------------------------


def render(report: dict) -> str:
    artefacts = report["artefacts"]
    lines = [
        "=" * 72,
        "Beat 3 — the real kernel against a real local model",
        "=" * 72,
        "",
        f"request id            {report['request_id']}",
        f"status                {report['status']}",
        f"model                 {report['model']['registry_member']} "
        f"(registry: {', '.join(report['model']['registry'])})",
        f"base url              {report['model']['base_url']}",
        f"served by the host    {report['model']['served']['name']}, "
        f"{report['model']['served']['parameters']} "
        f"{report['model']['served']['quantization']}, "
        f"capabilities {report['model']['served']['capabilities']}",
        f"vision capability     {report['model']['served']['vision_capability_present']}",
        "",
        "-- TIMING " + "-" * 61,
        f"cold send             {report['timing_s']['cold_send']:.2f} s",
        (
            f"warm send             {report['timing_s']['warm_send']:.2f} s"
            if report["timing_s"]["warm_send"] is not None
            else "warm send             (skipped)"
        ),
        f"configured timeout    {report['timing_s']['configured_timeout_s']} s",
        "",
        "-- MEMORY " + "-" * 62,
    ]
    for snapshot in report["memory"]["snapshots"]:
        lines.append(
            f"  {snapshot['label']:<22} available {snapshot['MemAvailable']:>6} MiB   "
            f"ollama rss {snapshot['ollama_rss_mib']:>6} MiB"
        )
    lines += [
        f"  swap total           {report['memory']['swap_total_mib']} MiB",
        f"  model on disk        {report['memory']['model_bytes_on_disk']} bytes",
        "",
        "-- EVIDENCE " + "-" * 58,
        f"observers             {report['evidence']['observers']} "
        f"({report['evidence']['why']})",
        f"capture interface     {report['evidence']['capture_interface']}",
        f"bodies on the wire    {report['evidence']['captured_request_body_count']}",
        f"byte-identical        {report['evidence']['bodies_byte_identical_to_the_gateway_record']}",
        f"observer_bytes_match  {report['evidence']['observer_bytes_match']}",
        f"approved content      on the wire: {report['evidence']['approved_content_on_the_wire']}",
        f"identifiers on wire   {report['identifiers_in_any_captured_body']}",
        f"two-observer verdict  agree={report['evidence']['two_observer_rule_verdict']['agree']}",
        "",
        "-- 1. INPUT " + "-" * 60,
        json.dumps(artefacts["input"], indent=2, ensure_ascii=False),
        "",
        "-- 2. TRANSFORMED PAYLOAD " + "-" * 47,
        json.dumps(artefacts["transformed_payload"], indent=2, ensure_ascii=False),
        "",
        "-- 3. MODEL RESPONSE " + "-" * 53,
        json.dumps(artefacts["model_response"]["body"], indent=2, ensure_ascii=False),
        "",
        "-- 4. CAPTURED OUTBOUND REQUEST " + "-" * 42,
        json.dumps(artefacts["captured_outbound_request"]["body"], indent=2,
                   ensure_ascii=False),
        "",
        "=" * 72,
    ]
    return "\n".join(lines)


def _masked(report: dict) -> dict:
    """The `--json` rendering: the input's identifiers masked, nothing else.

    The transformed payload, the model's answer and the captured bytes are
    printed exactly as they were, because a reader seeing the identifiers
    *absent* is the entire demonstration; the input is masked because the
    machine-readable output is the part most likely to be pasted into an issue.
    """
    masked = json.loads(json.dumps(report))
    masked["artefacts"]["input"] = beat_support.mask_tree(report["artefacts"]["input"])
    return masked


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", action="store_true",
                        help="emit the whole report as one JSON object on stdout")
    parser.add_argument("--out", type=Path, default=None,
                        help="where the capture and the databases are left")
    parser.add_argument("--skip-cold", action="store_true",
                        help="do not unload the model first; measures the warm path only")
    parser.add_argument("--base-url", default=os.environ.get("MEDARX_GATEWAY_BASE_URL",
                                                             DEFAULT_BASE_URL))
    parser.add_argument("--model", default=os.environ.get("MEDARX_GATEWAY_MODEL",
                                                          DEFAULT_MODEL))
    args = parser.parse_args(argv)

    out_dir = args.out or Path(tempfile.mkdtemp(prefix="medarx-beat3-"))
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        report = run(out_dir, base_url=args.base_url, model=args.model,
                     skip_cold=args.skip_cold)
    except ModelUnavailable as exc:
        print(f"beat3: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(_masked(report), indent=2, ensure_ascii=False))
    else:
        print(render(report))
    return 0


if __name__ == "__main__":  # pragma: no cover - the script's entry point
    raise SystemExit(main())
