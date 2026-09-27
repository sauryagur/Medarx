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

Neither store needs a schema step to be *usable*: `MappingStore.__init__` and
`AuditLog.__init__` each create their own tables when they are missing, so
either component works the moment its store is constructed. For a deployment
there is one command that creates the whole Phase 1 store —
`uv run python -m medarx.audit.schema_init --db-url <url>` — and it is
idempotent. It is not a migration: it creates what is absent and leaves an
existing table alone, so versioned DDL for a real database belongs with the
compose task. The database URL is an argument rather than an environment
variable because only `config.py` may read the environment.

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

`ApprovedSend` is minted only by the module-private `_issue`, which stamps this
module's private `_ISSUED` sentinel. A test asserts by AST sweep that the name
is referenced in no other file under `backend/src/medarx/` — that is exactly
what it proves, and it is not more: the sweep looks at one name, so it rules
out another *module* quietly acquiring the authority to authorise a send, and
it says nothing about routes that do not name it. Python has no access control,
so the sentinel is the strongest enforcement the language offers rather than a
guarantee; it is the same standard this package already accepts for
`ALLOWED_MODELS` and the module-level action-code constants, and strictly
stronger than a comment asking a caller to do the right thing.

**A frozen dataclass was not sufficient, and the gap was found by running the
bypass.** With the sentinel as an ordinary `init` field, `dataclasses.replace`
copied it onto a new instance: a substituted request went on the wire,
`last_request_body()` reported the substituted bytes, and the two observers
would have agreed — the same failure, reached through a plain library call with
no private name involved. `copy.copy`, `copy.deepcopy` and `pickle` each did
the same, since all three bypass `__init__`. So `_issued` is `init=False` and
set by the private mint path, and all four routes raise. Each is a test.

**What the token guarantees, and what it does not.** It guarantees that `send`
transmits the bytes built and encoded during verification, that
`last_request_body()` returns that same object, that a request never passed to
the verifier cannot be sent at all, and that a token cannot be re-pointed
afterwards by any ordinary library operation. It does **not** guarantee that
the request was derived from the approved payload — no component defines that
derivation, and building the messages is the orchestrator's job — nor that a
caller holding a genuine token is stopped from rewriting it with
`object.__setattr__`, which Python cannot prevent. The second limit is measured
rather than asserted. A caller who reaches that far can equally call
`gw._client.post` directly; the token defends against the ordinary mistake and
against plain-library manipulation, not against an adversary inside the process.

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

## Component G — audit log, readback, and the log filter

`medarx.audit` is the record of what happened, and `medarx.audit.queries` is the
only way anything reads it. The readback returns the stored record and nothing
else — an `AuditEvent`, whose fields are exactly the storage policy's. There is
no joined row and no convenience projection, because a readback whose own idea
of a record is wider than what was written is a second place for a value to
appear that an auditor cannot see is a value.

**Two answers are computed on read, and neither is a field.** `stages` is the
pipeline prefix derived from the record's blocking `layer`, and `chain_verified`
is the chain walk's result. Neither is a column, so neither can be stale; and
`chain_verified` being *absent* from the record is the point — a record carrying
a "verified" field would be making a claim a rewrite would rewrite along with
it. Rewriting a row changes the values the readback returns and flips the
separate verification answer; it cannot make the record say it verifies.

**The filters are the contract's parameters, and the bounds are its bounds.**
`search_records` takes `request_id`, `function`, `disposition`, `since` and
`limit`; a `function` or `disposition` outside the contract's closed enum is
refused rather than matched, because an empty page is a true statement about a
question that was asked. Records come back oldest first, with the chain's own
ordinal breaking a timestamp tie: the sort is presentation, and the chain is
walked in append order regardless, so a clock that moved is something
verification sees rather than something a sort hides.

**A refusal is as visible as a sent request.** A blocked record is read back
with the layer and the action codes that actually refused it — component D's
codes stay D's and component F's stay F's — because a readback that flattened
them would answer "was this refused" and nothing at all about why.

`medarx.logging_filter` covers the surfaces the audit log's storage policy
cannot: application logs, exception traces, and the HTTP and NER SDKs' own debug
output. It reuses the redaction layer's own identifier patterns rather than
keeping a second copy, scrubs the *rendered* message and the traceback, and
never drops a record.

**The named SDK loggers are three different risks, and each was measured.**
Presidio's logger echoes the text it analyses and the context it built around a
hit, at DEBUG — a real PHI surface, and the scrub is verified against it. The
two HTTP packages do not log bodies at all: driven against a live stub with an
identifier in the JSON body and the root logger at DEBUG, `httpx` and `httpcore`
emitted a request line, connection lifecycle and raw response headers, and no
body bytes. They stay registered as defence in depth — an identifier in a URL
or a response header is the residual they would catch.

**The residual the filter cannot catch, on a surface it does cover:** a
tokenised identifier. Presidio splits the text into tokens, so a social security
number reaches the log as `Context list is: ssn 123 6789 45 mrn` — in pieces,
reassemblable by a reader, and not matched by any pattern narrow enough to be
usable. The operative control there is the log level: those lines exist only at
DEBUG.

**Its coverage boundary is stated rather than implied, and it is not the whole
logging tree.** A `logging.Filter` is consulted only for records logged to the
logger it is attached to, so `install_filter` registers on the root logger, on
the SDK loggers, and on everything beneath each SDK name — `httpcore` is a
namespace rather than a logger, and Presidio's is hyphenated
(`presidio-analyzer`), so the names in the design's task list are not the names
the code writes to. Everything else, including the application's own loggers, is
the caller's to attach `SensitiveDataFilter` to. The filter is not installed at
import time; the application entry point and the test session fixture each
decide when, and the tests assert the boundary so it cannot quietly stop being
true.

## Component H — the synthetic PHI corpus and the evaluation harness

```
cd backend
uv run pytest                                              # the backend suite
uv run pytest ../evals/test_eval_harness.py -v             # 37 tests
uv run python ../evals/run_eval.py                         # the table, and a gate
```

**CI runs all three, and the gate is not optional.**
`.github/workflows/ci.yml` runs the backend suite, the harness tests, and then
`run_eval.py` with the gate on — no `--no-gate`. The gate is the only thing
keeping the table above honest: without it a change to a recognizer or to
`replacers._MASKED` that moved `PATIENT_ID` 1/3 or the 5/28 and 6/28 rates
would land with a green suite and a README that no longer describes the code.
It costs a few seconds beside a suite that already loads the same spaCy model.
The gate also refuses to compare at all if the corpus has changed under the
baseline: `baseline.json` carries a SHA-256 over `identifiers.json`,
`report_template.txt` and `clean_prose.py`, so an edit to a fixture cannot read
as an improvement. `baseline.json` is tracked and reviewed; the per-invocation
`eval_results.json` is gitignored, because a file that is dirty after every
*read* of the measurement tool trains everyone to ignore `git status`.

**It is a research instrument for this repository, and nothing else.** Every
value in it is fabricated, `evals/synthetic_phi/identifiers.json` carries the
marker that says so, and the figures below are a measurement of *this codebase
over invented text*. No real patient data, no real DICOM sample, no downloaded
dataset — not TCIA, not MIMIC. TCIA is not a detection-recall oracle in any
case: a corpus already stripped of its identifiers cannot say how many of them a
pipeline would have caught in the form they arrived in. Synthetic injection is
the only thing that gives a detection figure a denominator.

**Four numbers, not one, because they are claims about different things.**

| Claim | Measured | What it is a claim about |
|---|---|---|
| Detection recall, `report_text` | `MRN` 2/2, `ACCESSION_NUMBER` 2/2, `DATE_TIME` 1/1, `PATIENT_ID` **1/3** | redaction layer 2's scan |
| Detection recall, `dicom_header` | `MRN` 1/1, `ACCESSION_NUMBER` 1/1, `PATIENT_ID` **0/1** | the one metadata value that is prose |
| Non-survival | **0/15** planted identifiers reached an approved payload | the whole kernel |
| False positives | **5/28** masked with the date order unset, **6/28** with it declared | the scan, over prose with no identifier in it |

`baseline.json` holds the recorded figures, the corpus fingerprint they were
measured against, and the contract notes; `run_eval.py` exits non-zero when a
figure moves the wrong way, and `--write-baseline` records a new set. The
per-entity-type figures are the row a reader quotes, so they are the ones
pinned by `evals/test_eval_harness.py`.

**Two findings, both measured.**

*`PATIENT_ID` is unreachable on the spelling a report actually uses.*
`scan_entities` blanks every `ANCHOR_LABELS` entry before the analyser runs, so
`Patient ID: 774123` loses the label the `PATIENT_ID` pattern requires, and the
pattern has no bare-value alternative. The value comes back as `DATE_TIME` at
0.85, and is refused as `UNSHIFTED_DATE`. `PatientID: 774123` — no space, so
not an anchor label — does reach the recognizer. Three planted instances, one
detected. Nothing leaks: layer 3's deterministic re-read fires
`LEFTOVER_PATTERN_MATCH` on the leftover, and the run is refused. The gap is in
the *detector*, not in the boundary, and the harness reports the two separately
so a privacy figure of 0/15 is never read as a detection result.

**OWNER:** the recognizer owner (`redaction/recognizers.py`), with the detector
and eval track. **Decision required, and it is not "add a bare value":** a bare
`\d{4,8}` alternative matches `120 HU`, `2.5 mg`, `3.2 cm`, `15 mm` and
`20260114` in the identifier-free corpus above, and overlaps the `MRN`
recognizer's own bare `\b[A-Z]{0,2}\d{7}\b`. Accepting the detection gap, or
reopening the 5/28 false-positive rate to buy the recall, is the call.
**Do not read `test_the_planted_patient_id_recognizer_is_unreachable_on_the_canonical_spelling`
as a failing test:** it is a characterisation test and is *meant* to go red when
the defect is fixed. Recall is pinned at 1/3 and 0/1 in `test_eval_harness.py`,
and `run_eval.py` exits non-zero if either moves.

*Clinical words are still masked in approved payloads, and now have a
denominator.* 5 of 28 with the date order unset, 6 of 28 with it declared, and
6 of the 6 named false-positive sentences. The rate is a property of
`replacers._MASKED` meeting spaCy's named-entity output, it has an owner, and
the number above is what a later change is measured against.

**Why the harness can be believed.** `evals/metrics.py` imports no corpus
module: it is handed spans and hits and knows nothing about radiology, and the
test suite runs it on inputs built inside the test file. The corpus declares
*values*, never spans — the scorer searches the rendered text for each one, and
`locate_planted` raises rather than inventing a truth. Precision is measured on
a **disjoint** corpus (`clean_prose.py`), so recall and precision share no
data. A zero denominator renders as `n/a (0 measured)` and can never print as
`1.00` or `0.00`. And every run plants one identifier no detector can reach and
checks that recall **falls**; a benchmark that cannot report a worse number is
not a benchmark.

**The contract was wrong, and is corrected here.** `PriorReportText` is the only
allowlisted DICOM attribute whose value layer 2 scans, and
`AllowlistedDicomMetadata` declared no such property while layer A accepted it,
`Prior Summary` and `Ask` allowed it, and a replacer path stood behind it — so
the only DICOM-metadata input source with a detection surface could not be
supplied by any caller, and a request following the contract could not reach a
line of the layer-2 code that applies to DICOM. `PriorReportText` and
`PriorStudyDate` are now declared, strictly additively.
`test_every_allowlisted_metadata_property_is_carried_or_deliberately_dropped`
resolved each property against the `Draft` allowlist alone, which hardcoded the
assumption that caused the gap; it now resolves against every function, and
fails if a property is carried by *no* function — a boundary that does not
accept it at all, which is a contract defect rather than a policy.

**What the kernel does not read, stated rather than assumed.** The harness
drives the pipeline from each case's `ExecutionRequest` body, not from the case
object, and `runner.pipeline_inputs` raises on any property it has not been told
about — so a new contract field cannot arrive and be quietly dropped between the
document and the measurement. Three declared fields are read by nothing under
`backend/src/medarx` and are named in `runner.UNREAD_REQUEST_FIELDS`:
`study_context.accession_reference` (PHI-bearing, declared by the contract, and
consumed by no code path), `study_context.modality` (the modality travels in
`dicom_metadata`), and `report_text.source` (audit provenance). The first is a
real gap in the kernel, not in the harness, and it is unmeasured here by
construction.
## Component J — application API and composition root

Build the surface the way the tests build it, which is the way the server builds
it:

```python
from medarx.api.app import create_app
from medarx.config import load_settings

app = create_app(load_settings(), "sqlite:///medarx.db")
```

`create_app` is the **only** composition point. It runs the startup guard, builds
every component through `medarx.pipeline.build_pipeline` exactly once, and puts
them on `app.state`. No route constructs a component, and the test suite reads
`app.state.pipeline` back rather than building a `Pipeline` of its own — two
wirings would be drift, and the second would be the one the server never uses.

**Three startup checks, all fail-closed.** `require_date_order` refuses a
deployment that has not said whether its reports are MDY or DMY; an ambiguous
numeric date would otherwise be a *per-request* block that reads to whoever sees
the receipt like a coverage gap, and this is the caller that guard was written
for. The audit key is refused by the two stores that need it. And
`contracts/openapi.yaml` must be readable, because it is **served verbatim**
rather than regenerated from the route signatures — a generated document and the
tracked one can disagree with nothing failing. `test_api.py::
test_the_served_openapi_document_is_the_tracked_contract` compares them after
parsing. The cost of that choice: a deployment with the package but not the
repository layout cannot serve the document, and is refused at startup with a
`FileNotFoundError` naming the path rather than served something that is not the
contract.

**`X-Scope` is a demonstration input, not authentication.** The contract declares
`security: []` and no security scheme, and the design defers roles and
per-user permissions to Phase 6. The header models an authorization *boundary* —
a caller scoped to one study and one function — and enforces it: an absent, empty
or unreadable header grants no scope and is a `403`. A token the grammar does not
recognise is not an error to be reported and then ignored; it is a grant that was
not made. Anyone who can reach the server can present any scope, and
`test_api.py::test_the_scope_header_is_not_an_authentication_mechanism`
demonstrates exactly that, so no future reader mistakes the header for a control.
The grammar is closed and synthetic: `scope:study:<reference>` and
`scope:function:<FunctionName>`, comma-separated.

**`AuthzError` is outside the `MedarxError` taxonomy, on purpose.** It carries
no `layer` and no action codes, so the handler that renders a `BlockReceipt` for a
`MedarxError` cannot catch it by accident. A caller tells a privacy block from an
authorization failure **by status code alone** — `422` against `403` — without
parsing the body, which is the design's own §6 requirement and the reason the
split is structural rather than a status chosen at a call site.

**The order inside one request is the boundary.** Media type (`415`), then the
measured body size (`400`; a chunked request carries no `Content-Length`, and a
guard reading only the header would pass an oversized body straight through),
then the schema (`400`, which is where an arbitrary DICOM object or a free-form
prompt is refused, before anything is parsed into a domain object), then
authorization (`403`), then the pipeline. A provider outage is a `500` and is
recorded **nowhere**: §6 has no row for "the provider is down", and a record
saying a request was blocked when it was not would be a false privacy event in
the one store the design names as an asset.

**The error taxonomy decides the status, and three hierarchies meet here.**
`MedarxError` and its subclasses are `422` with a `BlockReceipt`; `AuthzError` is
`403` with a `ProblemDetail`; `ProviderError` and its subclasses are `500` with a
`ProblemDetail`. `BlockReceipt` has exactly five fields and `extra="forbid"`, so
**no message reaches the response or the record** — the action codes are all an
auditor gets, which is why `_receipt_for` in `medarx.pipeline` states its rule
once and `test_the_receipt_agrees_with_the_orchestrator` runs it against
`run_privacy_kernel`'s own `RedactionError` over the same input.

**A request cannot select its own policy mode.** The mode is a deployment
configuration, `ExecutionRequest` has no `policy_mode` field, and
`AllowlistedDicomMetadata` and `ExecutionRequest` are both `extra="forbid"` — so
a request that supplies one is a `400` because the field does not exist to be
set, not because a handler noticed.

**The audit readback is behind the same authorization surface, and it is
unfiltered.** Phase 1 does not filter a readback by study, and could not: the
storage policy has no study field, and adding one would put a study identifier
into a log required never to hold one. The routes require a presented scope and
document the limit rather than leaving it looking like a missing feature.

**Two contract gaps are recorded here rather than smoothed over.**

- The contract's `StudyContext` declares **no patient identifier**, and the
  surface may not add one. Component C needs a patient scope to choose a date
  offset, so `medarx.pipeline.patient_ref_for` takes it from the allowlisted
  `PatientID` when the caller supplies one — accepted by layer A and then
  dropped, so it reaches the input hash and no payload field — and from the study
  reference otherwise. **Two studies of one patient arriving without a
  `PatientID` therefore get two offsets**, and the interval between them is not
  preserved. That is a contract gap, not a choice.
- `HumanApprovalRequest` declares an optional `note` while
  `HumanApprovalState` — what a readback returns — is closed and has no such
  field, and the audit store's policy forbids a field that could hold free text.
  The note is therefore logged rather than stored, through the application's own
  logger, which is what the contract's own `note` description says it is subject
  to: "the same sensitive-data filtering as every other log surface".

**The log filter reaches this application's loggers because `create_app` attaches
it.** `medarx.logging_filter.install_filter` covers the root logger and four
named SDK loggers and their subtrees. **A logger filter is not inherited**, so
`medarx.api`, `medarx.api.approval`, `medarx.api.errors` and the three `uvicorn`
loggers are covered because `APPLICATION_LOGGERS` in `app.py` names them. A
logger created after `install_filter` and not named there is **not** covered, and
nothing in the package claims otherwise.

**Two of §6's seven rows are unreachable through this surface, and the tests say
so with evidence.** §6 row 3 (layer D.1) fires only when a date still equals the
value component C was given, and component C always shifts it first or refuses
the request. §6 row 6 (layer E) fires only on a misconfiguration `Settings`
forbids or a state the orchestrator cannot be in: an unresolved disposition does
block, and the orchestrator attributes that block to the layer that raised the
disposition, so one refusal cannot produce two different receipts.
`test_block_conditions.py` drives the five reachable rows through HTTP, one
request body each, and asserts that a D.2 block carries no policy code and a
policy block carries no redaction code.

**The request ID is a header, and it is checked against the audit log's own
shape.** `X-Request-Id` is honoured when supplied and generated when not, and it
is on the response of **every** request including blocks and refusals. An ID
holding a space is a `400` at the boundary, because the audit log holds request
IDs to an identifier shape and an uncaught refusal there would surface later as a
`500` that reads as a server fault.
