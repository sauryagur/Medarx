# Medarx — backend

The privacy kernel: allowlisted extraction, pseudonymization, four-layer
redaction, and a fail-closed policy engine, in front of a model gateway.

The normative API contract is `contracts/openapi.yaml` at the repo root — it is
tracked, because code that depends on it is tracked. `test_openapi_contract.py`
enforces conformance: it sweeps every action code emitted under
`backend/src/medarx/` and fails if any is missing from the `ActionCode` enum.

## Setup

**`uv sync` is a two-step operation here, and both halves are mandatory.** Run
these three commands in order from this directory (`backend/`):

```bash
uv sync
bash src/medarx/scripts/bootstrap_ner_model.sh
uv run pytest
```

1. **`uv sync`** — create the virtual environment and install the pinned
   dependency set. spaCy is pinned to `3.8.16`.
2. **`bash src/medarx/scripts/bootstrap_ner_model.sh`** — install the pinned
   `en_core_web_sm` 3.8.0 NER model. The script is idempotent and deliberately
   does *not* use `python -m spacy download`: spaCy shells out to `pip`, `pip`
   is not on PATH, and the `uv` shim intercepts the call with "No virtual
   environment found". It downloads the wheel and installs it with
   `uv pip install` instead.
3. **`uv run pytest`** — run the test suite.

**Step 1 without step 2 is a broken environment, not a delayed one.** The
model is not a declared dependency, so `uv sync` prunes it from the venv —
`uv` reports it as `Uninstalled 1 package: - en-core-web-sm==3.8.0` — and the
bootstrap script is the only thing that installs it. Re-run the bootstrap after
**every** `uv sync`, and after **any** change to `pyproject.toml` that is
followed by a sync. Treat the two commands as a pair, always; the ordering
below is not a one-time initialisation.

**A missing model does not say it is missing.** It surfaces as a spaCy
recogniser failure —
`OSError: [E050] Can't find model 'en_core_web_sm'. It doesn't seem to be a
Python package or a valid path to a data directory.` — raised from whichever
recogniser tried to load it, so the error points at the recogniser rather than
at the missing dependency. On that error, re-run
`bash src/medarx/scripts/bootstrap_ner_model.sh`; do not debug the recognisers.

There is no schema-initialisation step, and there does not need to be one.
`MappingStore.__init__` creates its own tables, so component C is usable the
moment the store is constructed. The audit store (component G) is a later task
and has no module yet, so a command for it would only be a `ModuleNotFoundError`
in the middle of a setup sequence.

> The virtual environment lives in `backend/.venv`, inside the project
> directory — never under `/tmp`, because `/tmp` is a tmpfs and a venv there
> consumes RAM rather than disk.

## Configuration

Every tunable lives in `backend/src/medarx/config.py`. Settings are read from
the environment with the `MEDARX_` prefix, but **only `config.py` reads the
environment**; every other component takes the `Settings` object returned by
`medarx.config.load_settings()`.

| Variable | Default |
| --- | --- |
| `MEDARX_POLICY_VERSION` | `medarx-policy-1.0.0` |
| `MEDARX_POLICY_MODE` | `cloud` (`strict_local` or `cloud`) |
| `MEDARX_NER_SCORE_THRESHOLD` | `0.50` |
| `MEDARX_NER_TEXT_LIMIT` | `200000` |
| `MEDARX_DICOM_UID_ROOT` | `1.2.826.0.1.3680043.10.1338.` |
| `MEDARX_AUDIT_KEY` | `""` (empty — see [Credentials](#credentials)) |
| `MEDARX_AUDIT_RETENTION_DAYS` | `2555` |
| `MEDARX_GATEWAY_BASE_URL` | `http://127.0.0.1:8080/v1` |
| `MEDARX_GATEWAY_MODEL` | `medarx-demo-model` |
| `MEDARX_GATEWAY_API_KEY` | `""` (empty — see [Credentials](#credentials)) |
| `MEDARX_GATEWAY_TIMEOUT_S` | `120.0` |
| `MEDARX_MAX_BODY_BYTES` | `1048576` |

### Credentials

Both `MEDARX_AUDIT_KEY` and `MEDARX_GATEWAY_API_KEY` default to the empty
string. No credential is baked into source, because a default that looks like a
working key is the kind of thing that gets copied into a real deployment.

Two obligations follow, and they belong to the tasks that own those code paths:

- **The audit store must fail closed on an empty `audit_key`.** Silently
  writing an unauthenticated audit event is worse than refusing to write one.
  Component C's pseudonymization store and date-shift derivation fail closed on
  an empty `audit_key` for the same reason — see [Component C](#component-c--pseudonymization);
  that half is implemented.
- **The gateway client must omit the `Authorization` header entirely when
  `gateway_api_key` is empty**, rather than send an empty one. The Phase 1
  observer needs no authentication, so nothing in this phase sends one by
  default.

## Component B — DICOM de-identifier (offline, not on the request path)

**No request-path code imports `medarx.deident`.** It is not wired into the
pipeline, it is not called during intake, and the only consumer is
`backend/tests/test_conformance_profile.py`. It exists so the PS3.15
de-identification rules can be exercised against synthetic fixtures and
inspected.

`medarx.deident` applies the **implemented subset** of the PS3.15 Basic
Application Level Confidentiality Profile: a `dict` of DICOM keyword → rule in
`profiles.py`, and a thin applier in `dicom_deidentifier.py`. Completeness
against PS3.15 Table E.1-1 is **not** asserted; the profile names the attributes
the Phase 1 fixtures exercise, and an attribute outside that set is passed
through unchanged.

**The Clean Pixel Data option is not implemented.** Burned-in identifiers in
pixel data are not removed, and no output of this module may be described as
free of burned-in PHI. `CLEAN_PIXEL_DATA_IMPLEMENTED` is `False`,
`IMPLEMENTED_OPTIONS` is empty, no rule targets `PixelData`, and no code path
touches it. A dataset passed through this module is de-identified in the header
sense only. See `backend/src/medarx/deident/profiles.py`.

## Component C — pseudonymization

**Pseudonymization is not anonymization.** A surrogate stays re-identifiable to
anyone holding the mapping store. That is why the mapping store is a separate,
access-controlled database and why no component on the model path reads it;
`medarx.pseudonym.mapping_store` is component C's alone.

`MappingStore` assigns stable surrogates (`medarx-study-<8 hex>`,
`medarx-patient-<8 hex>`) and serves the per-patient date shift. A surrogate is
a keyed derivation — `HMAC-SHA256(audit_key, "<domain>:<reference>")`, truncated
to 8 hex characters — so assignment is reproducible by anyone holding the key.
The `pseudonym_study` and `pseudonym_patient` rows make it *sticky* and
auditable, and carry two constraints that guard two different properties. The
**UNIQUE constraint on `surrogate`** is what stops two *different* originals
from ever sharing a surrogate: a collision in the 8-hex truncation (likely past
~65k references in one scope) makes assignment fail loudly rather than
re-bind a live surrogate to a second original. The **primary key on the
original reference** is the separate, weaker guarantee that one original is
never assigned twice. Neither is optional;
`test_pseudonym.py::test_a_surrogate_collision_is_refused` pins the first.

The shift moves every date of one patient by the same number of days in
`[-365, 365]`, which is what preserves sequence and duration — the invariant
clinical meaning depends on. It does not preserve the month, the day of the
month, or the weekday. The one exception is a date already at the edge of the
representable calendar, which saturates at `date.max` / `date.min` rather than
raising, and so loses the duration guarantee for that single date.

`pseudonymize.pseudonymize_payload(payload, patient_ref, store)` is the entry
point that applies the store to a `StructuredPayload`: it records the patient,
maps `study_ref` and every entry in `prior_study_refs` to surrogates, shifts
`study_date` and `prior_study_date` by the one offset for that patient, and
returns a copy. It **never touches `report_text`** — free text passes through
byte-identical, because finding identifiers inside it is the redaction layers'
job, not this one. It leaves `payload_hash` exactly as it arrived: that is
component A's pre-redaction provenance value and layer 3 overwrites it.

Recording the patient is not bookkeeping. `offset_for_patient` derives the shift
and writes nothing, and `surrogate_for_patient` is the only method that writes
the `pseudonym_patient` row, so without that call the shift applied to a
payload would leave no record of which shift it was — the "explained later"
claim above would not hold for any pseudonymized payload. A blank patient, a
blank `study_ref`, and a blank entry in `prior_study_refs` are all refused with
`MISSING_SURROGATE`, the last naming the offending index.

**Call it once per payload.** It cannot tell whether a date it is handed has
already been shifted, so a second application would shift every date again and
return a payload whose intervals are silently wrong. Rather than let that pass,
a study reference that already has the exact shape of a surrogate
(`medarx-study-` plus 8 lowercase hex) is **refused** with
`SURROGATE_SHAPED_REFERENCE_REJECTED` — deliberately *not* `MISSING_SURROGATE`,
which the same module emits for a genuinely blank reference, so a receipt can
always tell a missing surrogate from a pre-minted one. That also closes an
injection channel: `StudyContext.study_reference` is
caller-supplied, so a forged surrogate-shaped string would otherwise pass
through unrecorded and be indistinguishable from a system-minted one. The
check is anchored, so a legitimate reference that merely contains the domain —
`STU-medarx-study-1` — is still processed normally.

**An empty audit key is refused**, by both the derivation and the store, with
`AuditKeyRequired`. Unkeyed surrogates would be a reversible encoding, which
would hand the model path the re-identification key the store exists to
withhold. `AuditKeyRequired` is deliberately not a `MedarxError`: it is a
deployment misconfiguration, not a privacy block, so it carries no layer and no
action code and cannot be rendered into a receipt.

## Component E — policy engine

`medarx.policy` decides; it never transmits. `decision_table.RULES` is design
§6 transcribed as data — one `Rule` per row, in row order, with the layer tag
that row governs — so a reviewer can diff it against the design, and
`rules_for("D")` folds the three redaction rows together the way a caller that
only knows the component needs. `policy_engine.CHECKS` is the ordered list
`decide` walks, one entry per block condition, each carrying the §6 row it
enforces; the engine returns on the first that fires, so the fail-closed
ordering is a property of a list rather than of the control flow around it.

**Two modes run, and a third is refused.** `IMPLEMENTED_MODES` is
`{strict_local, cloud}`. `authorized_local` is in the contract's `PolicyMode`
enum as an architectural extension published `implemented: false`, and
selecting it **blocks** — it does not fall through to a weaker mode, because a
deployment that asked for a stronger policy and received a weaker one would
have a receipt naming neither. The mode is read from `Settings` and from nowhere
else; `decide` takes no mode parameter, so a request cannot select or escalate
its own policy.

**A block is a refusal, and the reasons trend to block.** An unidentifiable
policy version, an unimplemented mode, a missing payload, a payload carrying a
hash this engine did not compute over it, and any unresolved disposition all
refuse. A blank `policy_version` is treated as *missing* even when the presented
version equals it, because two blank strings compare equal and a payload
approved under a policy nobody can name is the case a bare `!=` misses.

**Nothing is approved on a claim.** Two fields a caller controls reach this
layer: the disposition list, and the `payload_hash` the payload carries. Both
are claims about what the redaction layers did, and a claim is checked rather
than believed — `decide` re-derives the hash from the payload's own content and
refuses unless the two agree. Trusting the field instead made the whole
question "did the layers run?" answerable by whoever called: a made-up
64-character string approved a payload nothing had ever checked. The
disposition list needs no separate guard, because a payload this engine cannot
vouch for is refused whatever the list claims.

This is also why an empty disposition list does not block on its own. Layers 1–3
record what they *did*, so a report with no identifiers in it produces no
dispositions at all — measured, not assumed: `"FINDINGS: 7mm nodule."` through
the real pipeline yields `dispositions == []` and a layer-3 hash. An empty list
from a completed run is the shape of a clean result, and refusing on it alone
would refuse every ordinary report while reporting a healthy deployment as a
configuration error. One check covers both cases: an unverified payload has no
dispositions whatever the caller passed, because nothing computed any.

**Only the approved payload may leave, and the check is on the object.**
`authorize_payload(payload, approved_hash)` requires two things to equal the
approved hash: the `payload_hash` the object carries, and the hash recomputed
from its content. The claim alone is a hole with a one-line hole-punch —
`StructuredPayload` is frozen but not sealed, so `model_copy(update=...)` swaps
`report_text` and leaves the approved `payload_hash` untouched. The re-hash is
what stops that, and it also means a payload no layer ever hashed is refused
rather than approved. `models.payload_hash_of` is the one definition of that
hash, shared with redaction layer 3; two copies of it could drift, and a drift
there is a boundary that refuses everything or authorises everything.

**A block is attributed to the component that made it.** `Decision.wire_code`
carries the contract `ActionCode` member the engine's own verdict serialises to,
`RedactionOutcome.decision_code` carries it out of the orchestrator, and
`run_privacy_kernel` raises with `layer="E"` and that code when the engine
refused and no redaction layer flagged anything. It used to name `D.3` with
`UNAPPROVED_PAYLOAD`, which named a layer that flagged nothing and a code that
described neither condition. Design §6 states that `layer` names the flagging
component.

**Internal reasons are not wire codes.** `Decision.reason_code` is descriptive
and never serialised; `WIRE_CODE_BY_REASON` maps each reason the engine *invents*
to the one `ActionCode` member that describes it, and `wire_code_for` raises on
anything else rather than substituting a plausible code. A block whose reason
came from a disposition is deliberately not in that table: the receipt belongs
to the layer that raised the disposition, under that layer's tag, and a second
engine-level code for the same refusal would give one refusal two different
receipts depending on which component the caller asked.

**Two reasons share one wire code, and nothing finer survives.** An unknown
policy version and an unimplemented mode both serialise to
`UNKNOWN_POLICY_VERSION`, because the contract has one code for "the policy in
force could not be applied". The specific reason is in `Decision.reason_code`
and **nothing reads it**: the orchestrator takes `Decision.wire_code` and drops
the decision, so today the coarse code is the whole of what reaches a receipt
or a record. Whether the audit log should carry the reason is an open question
in the phase plan; nothing in this package claims the distinction is preserved.

## Component F — model gateway

`medarx.gateway` is the only component in the package that performs network
I/O. It speaks the OpenAI request/response wire spec, and the base URL, model,
key and timeout all come from `Settings`, so one implementation drives a local
engine and a cloud one. There is no provider branch: a test asserts that no
provider is named in `openai_gateway.py` at all, which is the structural form of
"provider-agnostic by construction" rather than of a promise in a docstring.

**The bytes are the evidence, so they are fixed at authorisation.**
`build_body` returns the body and is public, because a caller that wants to
know what *would* go on the wire can ask without sending anything.
`verify_approved_payload` builds and encodes it, and `send` transmits those
exact bytes and returns the very same object from `last_request_body()`.
Nothing re-encodes, reorders or normalises them in between: the egress check in
component I compares observed bytes against what was approved, and that
comparison is meaningless if the gateway records one encoding and transmits
another. A test measures the bytes at a loopback socket and asserts they equal
the token's `body_bytes`, and that `last_request_body()` is that same object
rather than a copy. The encoding is compact and `ensure_ascii`, so the bytes
are ASCII whatever the report contains; `httpx`'s own `json=` parameter writes
raw UTF-8 instead, which is one of the two behaviours the non-ASCII test
distinguishes.

**An unknown model fails before a body exists.** `build_body` resolves the
model through `model_registry.is_allowed` and holds no I/O, so an unknown
identifier is refused locally rather than by a provider's 4xx. The configured
default goes through the same check, so a typo in `MEDARX_GATEWAY_MODEL` blocks
instead of sending. The registry is a set of whole identifiers: a prefix or
substring rule would admit `medarx-demo-model-and-more`, which is the same
class of hole as a payload check that matches on a prefix.

**What is verified is what is sent, and that is enforced by a type.**
`verify_approved_payload(payload, approved_hash, request)` re-derives the hash
from the object's own content with the shared `models.payload_hash_of` and
refuses unless both the carried claim and the re-derived hash equal the hash the
policy engine approved. It raises `GatewayError` at layer `F` carrying
**`PAYLOAD_MISMATCH` and `HASH_MISMATCH`**: the first is §6 row 7's own name for
the condition and the leading code of the contract's layer-F block example, the
second names the check that detected it. `HASH_MISMATCH` sat in the contract
enum with nothing emitting it — layer 3 overwrites the hash rather than
comparing it — and an enum member the kernel never emits is a claim the
contract cannot keep. §6 row 5 lists "hash mismatch" among D.3's conditions;
§6 assigns *conditions* to layers, not codes, and this receipt carries
`layer: F`, so the code table in component G is where the question of which
layer owns the code belongs.

**`send` takes an `ApprovedSend` and nothing else.** On success the verifier
returns a frozen `ApprovedSend` holding the request that was authorised, the
approved hash, and the body and bytes built at that moment; `send(approved)`
refuses anything else with a `TypeError`, checked at runtime rather than only
in the annotation. Three failures close at once: an unverified send cannot be
expressed, the request is bound to the verification that covered it, and the
verification cannot be skipped because there is nothing else to pass.

This is the fix for a real hole, not a precaution. With `send` taking a bare
`ModelRequest` and the verifier returning `None`, the verified payload and the
transmitted request were unrelated values: a caller could verify the approved
payload and send a request built from a different one, and
`last_request_body()` would have returned the substituted bytes — so the
two-observer agreement check would have **passed and certified the leak**. An
evidence mechanism that cannot fail on the failure it exists to detect is worse
than no evidence.

`ApprovedSend` is constructible only with this module's private `_ISSUED`
sentinel, and a test asserts by AST sweep that the name is referenced nowhere
else under `backend/src/medarx/`. Python has no access control, so that is the
strongest enforcement the language offers rather than a guarantee; it is the
same standard this package already accepts for `ALLOWED_MODELS` and the
module-level action-code constants, and strictly stronger than a comment asking
a caller to do the right thing.

**The composition root sequences the pair.** `build_pipeline` (Task 15) calls
`verify_approved_payload(...)` and passes the result straight to
`send(...)`. It is one call in, one call out, and the token makes the wrong
order unrepresentable rather than merely discouraged.

**Three provider failures, and they are deliberately not blocks.** A transport
failure, a non-2xx response and a malformed body are `ProviderTransportError`,
`ProviderStatusError` and `ProviderResponseError` — three types, so a caller
tells them apart without parsing a message. **None is a `MedarxError`, and that
is a recorded decision rather than an omission:** §6 enumerates what blocks and
has no row for a provider being down, a layer plus action codes on a provider
outage would reach the API as a 422 privacy block receipt naming codes for a
refusal the privacy kernel never made, and the audit log would then hold a
false redaction event — the design names that log as an asset. The contract
answers this with a 500 `ProblemDetail`. The reasoning lives here and in
`medarx.errors`; it is a decision to revisit when component G writes the
receipt and audit code table, not a gap to be filled in by default.

**The timeout is configuration.** It is read from `Settings.gateway_timeout_s`
(default 120 s) onto the client and never lowered in code: a cold first
inference measured ~14.6 s against ~1.1 s warm, so a short default is a timeout
that fires on the one request a user is waiting for. A test drives a stub that
never answers in time and requires the failure, and the same test with a
generous timeout requires the success, so a timeout that was silently ignored
would fail it.

**An empty key sends no header.** `gateway_api_key` defaults to `""` and an
empty key omits `Authorization` entirely rather than sending a bare `Bearer `,
which would put a credential-shaped header on the wire that authenticates
nothing. A non-empty key is sent as `Bearer {key}`. Both are asserted against
the headers the stub server actually received.
