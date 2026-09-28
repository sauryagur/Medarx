# Medarx — Handoff

Written 2026-09-28 by inspecting the repository at `phase1-privacy-kernel`. Every
factual claim below about the current state was verified by running a command or
reading a file; anything I could not determine is marked **not verified**.

---

## 1. What this is

Medarx is a privacy-first AI copilot for radiology. The product thesis is not
"we redact PHI" — that is a claim any redaction library makes, and it is not
checkable from outside. The thesis is **"here is the evidence that nothing else
left the environment"**: the system is built so that a payload reaching a model
is a payload a privacy pipeline approved, and so that the outbound bytes can be
independently observed and compared against that approval by something that is
not the system itself. A system that quietly passed a leak through every check
is worse than one with no check at all, because it manufactures confidence; the
architecture is therefore shaped around making the evidence *capable of failing*,
not around making it always pass.

Phase 1 builds the **privacy kernel** and nothing else: components A through J
below, an evaluation corpus, a normative API contract, and a two-observer
egress-verification layer. It does **not** build the viewer (Phase 2 — the OHIF
extension and the `viewer/` directory, which I confirmed does not exist), does
not integrate DICOMweb or Orthanc into any request path (I confirmed zero
`dicom-web`/`dicomweb` references in any `.py`, `.sh` or `.yaml` outside
`.docs/`), and does not use any real patient data or downloaded dataset. Every
value in the evaluation corpus is fabricated and `evals/synthetic_phi/identifiers.json`
carries a marker saying so.

The regulatory positioning, which must be reproduced verbatim and never
paraphrased:

> Medarx is intended for research and demonstration. It performs administrative report assistance using clinician-supplied findings and authorized report text. It does not independently interpret medical images, make diagnostic or treatment recommendations, or autonomously submit clinical reports. Its regulatory classification has not been established, and it is not validated for clinical use.

I verified this paragraph appears **verbatim** in `contracts/openapi.yaml` at
`info/description` (and duplicated at `info/license/name`), and in all three
`.docs/` files. It is **not yet in `backend/README.md`** — I searched and found
zero occurrences there. Plan Task 20 Step 7 requires it; that is outstanding work,
not a completed step.

---

## 2. Current state

**Branch:** `phase1-privacy-kernel`. **HEAD:** `47544a2`. **Working tree:** clean
(`git status --porcelain` empty). **Commit count:** 64 total on the branch
(`git rev-list --count HEAD`); the last 40, newest first:

```
47544a2 feat(egress): add host-network capture and two-observer agreement check
de5804e feat(egress): add byte-recording mock observer endpoint
2d01fb4 feat(api): add a patient reference to the contract and record every surface refusal
068a0a7 feat(api): let the boundary middleware own provider failures
d8e0be3 feat(api): document component J and pin the surface-refusal record
c83eac3 feat(api): record component J's surface action codes and fix the approval race
8693b4b feat(api): add application API, composition root, and authorization surface
a5d6297 feat(evals): correct the enhancement mechanism, drive the harness from the request body, and publish the two DICOM properties
465c7cf feat(evals): add the synthetic PHI corpus and the precision/recall harness
85b9b9a feat(audit): correct the args claim, the SDK threat model, and disclose the tokenised residual
973127e feat(audit): narrow two overclaims in the readback and log-filter docs
72540cc feat(audit): add the readback query surface and the sensitive-data log filter
76cd8ca feat(contract): correct the ActionCode tracking claim and audit every example
a81642f feat(audit): speak the contract's vocabulary and repair the example sweep
cf41931 feat(audit): authenticate purges, key the head anchor, and wire the stage vocabulary
98dce19 feat(audit): chain the audit log and close its field storage policy
9750e33 feat(gateway): close the token against every ordinary clone route
8a3d664 feat(gateway): bind the verified request to the one that is sent
400feb9 feat(gateway): add single-egress OpenAI-wire model gateway with registry validation
782a25e feat(policy): correct the superseded rule-code claim in the test
b6f12d4 feat(policy): verify the payload hash and attribute blocks to the flagging layer
8d74312 feat(policy): decide approve or block from a declarative section 6 table
f786d92 docs(readme): make the setup sequence state the two-step sync and bootstrap
2761664 feat(contract): publish a reachable block example and enforce the declared formats
682b2f8 feat(tests): state what each date assertion is for and drop a redundant parameter
7ac193d feat(docs): ground the new rationale in measurements and name the right layer
7fdd111 docs(readme): correct the refusal code and drop the module that does not exist
2fd5574 feat(pseudonym): record the patient and refuse a blank prior reference
64711f1 feat(redaction): take a lock around the first analyzer-engine build
f22d85d feat(deident): seed surrogate UIDs on the value and never pad an illegal one
6a267ff feat(extraction): read the PatientAge unit and band sub-year ages in months
732f078 feat(contract): make every response schema satisfiable and name the keywords layer A accepts
9241c06 feat(redaction): correct the I4 alteration rate and the reasoning for deferring it
c62d039 feat(redaction): pass relative intervals through and give each D.2 block its own code
1b00760 feat(redaction): add three fail-closed redaction layers and the kernel entry point
07e18ae feat(redaction): shift a detected date by the patient offset instead of substituting the surrogate
ba0039a feat(redaction): protect unresolvable hits at every filter and preserve offsets through the anchor strip
6a0de9a feat(redaction): add presidio NER scan with confidence threshold and non-guessing replacers
2fe734e feat(redaction): correct enhancer mechanism note and harden pattern pin
6272573 feat(redaction): hold ambiguous reference below threshold and case-fold patient id label
```

### Verified test counts

`backend/pyproject.toml` sets `testpaths = ["tests"]`, so the canonical
`cd backend && uv run pytest` collects `backend/tests/` only — it does **not**
collect `evals/test_eval_harness.py`. There are two suites, and the numbers I
measured are:

| Suite | Command | Count |
|---|---|---|
| Backend | `cd backend && uv run pytest --junit-xml=...` | **845 tests, 0 failures, 0 errors, 0 skipped** |
| Evaluation harness | `cd backend && uv run pytest ../evals --junit-xml=...` | **37 tests, 0 failures, 0 errors, 0 skipped** |

Counts are read from the JUnit XML, not from pytest's summary line, which is
lost when stdout is a pipe in this environment.

**One caveat on the backend number, and it matters for how you read it.** My
first full run reported 845 tests with **6 errors**, all six in
`tests/test_egress_e2e.py`, all with the same cause: `docker run ... --network
medarx-e2e` failing with exit 125. I reproduced it by hand and the daemon's
message was `failed to set up container networking: network medarx-e2e not
found`. The network was genuinely absent. The cause is a **race in the test
fixture, not a defect in the component**: `tests/test_egress_e2e.py:154` creates
the network with `check=False` (so a create failure is silent), and the
module-scoped teardown at line 200 does `docker network rm medarx-e2e`. Two
concurrent runs of that module — one teardown removing the network while the
other is between create and run — reproduce it exactly. I re-ran the module
alone and it was **6 passed, 0 errors in 21s**; the second full-suite run with
no concurrent run was clean. **So: the 6 errors are a concurrency artefact of
running `test_egress_e2e.py` twice at once, and the 845/0/0/0 above is the
clean number.** Do not run two copies of that module concurrently; run seed
matrices sequentially.

`en_core_web_sm` 3.8.0 is currently installed and importable, so the NER model
is present right now.

### What exists on disk

- `contracts/openapi.yaml` — 69 KB, the normative contract. Five paths:
  `/v1/functions/{function_name}/executions`, `/v1/executions/{request_id}/approval`,
  `/v1/policy`, `/v1/audit/records`, `/v1/audit/records/{request_id}`.
  `ActionCode` has 24 members; `Layer` has exactly 8
  (`J, A, D.1, D.2, D.3, E, F, C` — no bare `"D"`); `FunctionName` is
  `[Draft, Prior Summary, Ask]`.
- `backend/src/medarx/` — 47 Python modules across `api/`, `audit/`,
  `deident/`, `extraction/`, `gateway/`, `policy/`, `pseudonym/`, `redaction/`
  plus top-level `config.py`, `errors.py`, `models.py`, `pipeline.py`,
  `logging_filter.py`, and `scripts/bootstrap_ner_model.sh` (executable).
- `backend/tests/` — 25 test modules, including four new egress ones
  (`test_observer_agreement_unit.py`, `test_observer_service.py`,
  `test_egress_agreement.py`, `test_egress_e2e.py`) and a committed
  `fixtures/capture/` holding four **real** capture artifacts (a 58 KB
  approved-request pcap readback, a 148 KB blocked-request readback, and the
  observer `.bin` record plus its `index.jsonl` line from the same run). All
  four are tracked in git.
- `evals/` — `runner.py`, `metrics.py`, `run_eval.py`, `conftest.py`,
  `test_eval_harness.py`, and `synthetic_phi/` with 6 corpus cases across three
  groups (`CASES`: `known_positive`, `unresolved`, `all_phi`;
  `DICOM_HEADER_CASES`: `dicom_header_identifiers`, `dicom_header_prose`;
  `SPELLING_CASES`: `patient_id_label_spelling`), plus `identifiers.json`
  (14 identifier values + a synthetic marker + a notice), `clean_prose.py`
  (28 `ORDINARY_SENTENCES`), `report_template.txt`, `gen_dcm.py`,
  `seed_corpus.py`, `baseline.json`, `eval_results.json`.
- `infra/` — `__init__.py`, `observers/` (`observer.py` 425 lines,
  `Dockerfile`, `requirements.txt`), `capture/` (`agreement.py` 644 lines,
  `start_capture.sh` 214 lines, `Dockerfile`). **All nine files are committed**
  (`git ls-files infra/` lists them all).
- `backend/README.md` — 804 lines, tracked, the only tracked document. Has
  per-component sections for B, C, E, F, G, H, I, J.

**Not present** (I checked each by path): `infra/compose.yaml`,
`infra/verify_env.sh`, `infra/orthanc/Dockerfile.orthanc`,
`infra/orthanc/orthanc.json`, `evals/demo_beat1_approved.py`,
`evals/demo_beat2_blocked.py`, `backend/tests/test_e2e_approved.py`,
`backend/tests/test_e2e_blocked.py`. There is no `viewer/` directory. These are
exactly Tasks 18, 19 and 20.

### Ledger state — a real gap

`.superpowers/sdd/phase1-privacy-kernel/progress.md` is 139 lines and **its last
entry is Task 12's completion plus `Ruling PROCESS-PHASE-2`.** There are **zero
entries for Tasks 13, 14, 15, 16 or 17** (I grepped for `^Task 1[3-7]:` — count
0). Those five tasks are implemented, reviewed, reported and committed, but the
chronological ledger that section 10 calls the record of "every task, fix round
and ruling" **does not cover them**. The next agent should treat the ledger as
current through Task 12 only, and use the per-task reports (which exist for
13, 14, 15 and a combined 16-17) instead.

Also: `.superpowers/sdd/` is **gitignored** (`.superpowers/sdd/.gitignore`
contains `*`), so none of this is in git. `progress.md` was last modified
06:08; `task-16-17-report.md` at 06:56 and **was still being edited while I
inspected it** — its test counts changed from 46/22 to 47/23 mid-inspection, and
its seed-matrix table is an **unfilled `<!-- SEED_MATRIX -->` placeholder** at
line 343. Read that report as in-flight, and re-check its numbers before
quoting them.

### Components A through J

Every entry below was read out of the source. Entry points are the real public
names, taken from each module's `__all__` or class definitions.

| # | Component | What it does | Where it lives | Key public entry point |
|---|---|---|---|---|
| A | Structured payload extractor | Produces the minimum structured field set for a function, per a per-function field allowlist; reads the `PatientAge` unit and bands sub-year ages in months. Refuses anything outside the allowlist. | `backend/src/medarx/extraction/payload_extractor.py`, `allowlists.py`, `study_context.py` | `extract(request)`, `pipeline_for(...)`; `ALLOWED_FIELDS`, `KNOWN_DICOM_ATTRIBUTES` |
| B | DICOM de-identifier | PS3.15 Basic Application Level Confidentiality Profile; returns a de-identified sibling plus a report of what was replaced. **Off the request path** — no request-path component imports it. Clean Pixel Data Option not implemented. | `backend/src/medarx/deident/dicom_deidentifier.py`, `profiles.py` | `deidentify(ds, root) -> (Dataset, list[DeidAction])`, `make_uid(seed, root)` |
| C | Pseudonymization | Stable surrogate identifiers within an authorized scope and a consistent per-patient date shift, via a keyed HMAC. Mapping lives in a separate store the model path never sees. Refuses surrogate-shaped caller references before any store call. | `backend/src/medarx/pseudonym/pseudonymize.py`, `derivation.py`, `date_shift.py`, `mapping_store.py` | `pseudonymize_payload(...)`, `shift_dicom_date(value, offset)`, `MappingStore`; `SURROGATE_SHAPE` |
| D.1 | Redaction layer 1 | Deterministic removal/replacement of known structured identifiers (patterns + custom clinical recognizers). | `backend/src/medarx/redaction/layers.py` | `layer1_deterministic(...)` |
| D.2 | Redaction layer 2 | Presidio NER scan with `en_core_web_sm` plus custom `PatternRecognizer` entities, a confidence threshold, and **non-guessing replacers**. Block condition keys on the absence of a registered replacer, never on a score. | `backend/src/medarx/redaction/ner.py`, `recognizers.py`, `replacers.py` | `layer2_ner(...)`, `scan_entities(...)`, `has_replacer` (the registered default predicate) |
| D.3 | Redaction layer 3 | Second validation pass: per-function contract check, leftover-pattern scan, date-shift re-read, hash computation. | `backend/src/medarx/redaction/layers.py` | the layer-3 half of `run_redaction(...)`; `_check_date` |
| — | Redaction orchestration | Runs D.1–D.3 and hands the result to the policy engine. | `backend/src/medarx/redaction/pipeline.py` | `run_redaction(...)`, `run_privacy_kernel(...)`, `RedactionOutcome` |
| E | Policy engine | Approve or block, fail-closed, from a **declarative transcription of the design's §6 table** (one `Rule` per row, rows 1–7, in `decision_table.py`). Re-derives the payload hash from content rather than trusting the field. | `backend/src/medarx/policy/policy_engine.py`, `decision_table.py` | `PolicyEngine.decide(payload, dispositions, policy_version) -> Decision`, `authorize_payload(...)`, `wire_code_for(reason)` |
| F | Model gateway | The **only** component permitted to call a provider; speaks the OpenAI wire spec. `verify_approved_payload` returns a frozen `ApprovedSend`; `send` accepts nothing else. | `backend/src/medarx/gateway/openai_gateway.py`, `model_registry.py` | `ModelGateway.verify_approved_payload(...) -> ApprovedSend`, `ModelGateway.send(approved)`, `last_request_body`, `is_allowed(model)` |
| G | Audit log | Append-only, keyed hash-chained record under a hand-written field storage policy. Purges are tombstones; the head anchor is keyed. Readback queries and a sensitive-data log filter. | `backend/src/medarx/audit/audit_log.py`, `hash_chain.py`, `code_table.py`, `queries.py`, `schema_init.py` | `AuditLog.append/get/events/verify_chain/purge_expired`, `ALLOWED_AUDIT_FIELDS`, `uv run python -m medarx.audit.schema_init --db-url <url>` |
| H | Corpus + eval harness | 6 synthetic cases with known spans, precision/recall measurement, a phantom control, and a 28-sentence identifier-free corpus for precision. | `evals/` (outside `backend/`) | `cd backend && uv run python ../evals/run_eval.py`; `runner.execute`, `measure_end_to_end`, `metrics.tally` |
| I | Egress verification | Two independent observers that must agree. Observer one records raw inbound bytes to disk; observer two is a host-namespace `tcpdump` on the Docker bridge. `check_agreement` compares them byte for byte. | `infra/observers/observer.py`, `infra/capture/agreement.py`, `infra/capture/start_capture.sh` | `check_agreement(approved_payload_hash, expected_content, record_dir, pcap_text, request_id, ...)`; `compare_bytes_to_payload(...)` |
| J | Application API | The HTTP surface exercising A–I, with study- and function-scoped authorization (`X-Scope`), policy inspection, audit readback, and human approval. Owns the composition root. | `backend/src/medarx/api/app.py`, `wiring.py`, `authz.py`, `middleware.py`, `surface.py`, `schemas.py`, `routes_*.py` | `create_app(settings, db_url)`, `build_pipeline(settings, db_url)`, `Pipeline.run(request_id, request)` |

---

## 3. Architecture in one page

**The request path, one direction, on approval:**

```
J (API)  ->  A (allowlisted extraction)  ->  C (pseudonymization)
         ->  D (redaction layers 1-3)   ->  E (policy, fail-closed)
         ->  F (gateway, sole egress)
```

Concretely: `Pipeline.run(request_id, request)` calls `pipeline_for(...)` (A),
then `pseudonymize_payload(...)` (C), then `run_privacy_kernel(...)` which runs
D.1–D.3 and hands the dispositions to `PolicyEngine.decide(...)` (E). On
approval the exact approved payload goes to `ModelGateway.verify_approved_payload`
which mints an `ApprovedSend`, and only that token can be passed to
`ModelGateway.send` (F). On a block, `Pipeline.run` **returns** rather than
raises for a privacy block, so the caller has one thing to handle; the API
renders a 422 block receipt naming the layer that raised the disposition.

**The side components, none of which is on that path:**

- **G (audit log)** is written to from D, E, F and J at the event level only —
  never raw values. `Pipeline` records approvals and blocks through
  `AuditLog.append`.
- **H (corpus + eval)** is in the test suite and the demo scripts only. Nothing
  in the runtime request path imports it.
- **I (egress verification)** is entirely passive and outside the Medarx
  process. The agreement check runs in the e2e tests and the demo script.
- **B (de-identifier)** is offline and used by the conformance tests only. I
  confirmed nothing on the request path imports it.

### Where the implementation deliberately differs from the original plan

These are settled decisions with reasoning recorded in
`.superpowers/sdd/phase1-privacy-kernel/progress.md`, not accidents:

1. **D has three layers, not four.** Design §3 describes four redaction layers,
   with "Layer 4: policy decision, made together with E". In the implementation
   D is `D.1/D.2/D.3` and the policy decision is component E in its own right.
   The contract's `Layer` enum carries 8 members, and there is no `D.4`.
2. **`Pipeline.run` takes two arguments**: `run(request_id, request)`, not
   `run(request)`. The contract is `additionalProperties: false` and carries the
   request id in the `X-Request-Id` header, so a dataclass that held it on the
   body could not validate. This is the clearest case of the standing ruling
   "the contract is the normative artefact and the code bends to it".
3. **The contract's `Layer` enum gained `C`** (strictly additive) so that
   pseudonymization refusals are not misattributed to redaction layer 1.
4. **Agreement code moved from Task 17 to Task 16.** Task 16's unit test imports
   `compare_bytes_to_payload` from `infra/capture/agreement.py`, so that file
   had to exist in Task 16.
5. **The Phase 1 gateway is not pointed at a cloud provider.** Design §3 F says
   "the cloud capture path (tested against OpenRouter in the cloud demo)"; the
   implemented default is `gateway_base_url = "http://127.0.0.1:8080/v1"` — the
   **local observer**. There is no OpenRouter demo in Phase 1. The gateway is
   provider-agnostic and the OpenRouter path is untested here.
6. **The whole per-task review process was judged a misjudgement.** The ledger's
   final entry, `Ruling PROCESS-PHASE-2`, says so in terms: roughly fifteen
   tasks each costing an implement, a review and 0–5 fix rounds, with the
   largest single defect found late because the queue serialised behind review
   overhead. The rule going forward is: implement in dependency order, review
   **once at the end across the whole branch**, fix what that surfaces.
   Exceptions where per-task review still earns its cost: anything establishing
   a security boundary, and anything another task consumes before it can be
   reviewed end to end.

---

## 4. Invariants that must not be broken

Each of these was violated at least once during the build. Each is now enforced
by a named test. **If you change any of these mechanisms, the named test is the
one that must go red — check that it does.**

**1. A block comes from the absence of a registered replacer for a detected
entity — never from a score being below a threshold.**
A score is a configuration-dependent value; one settings change would silently
turn a deterministic block into a pass. This is not hypothetical: context
enhancement lifted `AMBIGUOUS_REFERENCE` from 0.30 to 0.65, crossing the 0.50
default. `has_replacer` is enforced as the registered **default** predicate at
every discard site, so callers can only widen it, and `ner.py` never imports
`replacers`.
*Enforced by:* `backend/tests/test_redaction_layers.py::test_an_entity_with_no_replacer_is_unresolved_at_any_score`
*and* `::test_a_replaceable_hit_below_the_threshold_is_blocked_not_guessed_at`
(the second is what stops the guard being inert).

**2. The gateway cannot send anything that was not presented for authorisation.**
`send` accepts only the frozen `ApprovedSend` the verifier returns; a bare
request raises. `dataclasses.replace`, `copy`, `deepcopy` and `pickle` are all
refused, because all four bypass `__init__` and would otherwise mint a working
token. The authorisation marker is `init=False`, set only by the module-private
`_issue`.
*Enforced by:* `backend/tests/test_gateway.py::test_send_refuses_anything_that_is_not_an_approved_send`,
`::test_an_approved_send_cannot_be_built_by_hand`,
`::test_a_token_cannot_be_re_pointed_with_dataclasses_replace`,
`::test_a_token_cannot_be_cloned_by_any_copying_route` (parameterised over the
clone family), and `::test_only_object_setattr_can_rewrite_a_token_and_that_is_the_documented_limit`
— the last measures the one residual route as a language limit rather than
describing it.

**3. The audit chain is keyed.** Repointing the head anchor costs the audit key
(the anchor carries an HMAC over its own head and count). A purge is a
**tombstone whose digest is the keyed digest of the blanked record** — there is
no flag anywhere that verification consults, which is what closes the hole where
a keyless writer blanked a record and set a flag nothing read.
*Enforced by:* `backend/tests/test_audit.py::test_the_log_under_a_different_key_does_not_verify`,
`::test_chain_hash_is_keyed_so_the_key_alone_changes_the_digest`,
`::test_deleting_the_last_row_is_detected_by_the_head_anchor`,
`::test_deleting_every_row_is_detected_by_the_head_anchor`,
`::test_a_purged_record_becomes_a_tombstone_that_still_verifies`, and — the one
that matters most — `::test_a_keyless_writer_cannot_hide_a_rewrite_behind_a_purge_flag`.

**4. `Layer` is a closed set: `J`, `A`, `C`, `D.1`, `D.2`, `D.3`, `E`, `F`. There
is no bare `"D"`.** Verified against the contract: exactly those 8, no `"D"`.
The check is **per declaration site**, not a per-file union, because union
granularity pools the sets and one site carrying a divergent tag gets masked by
another carrying the correct one.
*Enforced by:* `backend/tests/test_openapi_contract.py::test_the_code_layer_set_equals_the_contract_enum`,
`::test_every_single_tag_layer_declaration_is_in_the_contract`,
`::test_the_layer_sweep_finds_every_declaration_site` (this last is what stops
the sweep passing vacuously on an unresolvable name).

**5. Every emitted action code is a member of the contract's closed `ActionCode`
enum**, enforced per declaration site.
*Enforced by:* `backend/tests/test_openapi_contract.py::test_every_emitted_action_code_is_in_the_contract`.
The enum has 24 members and stays closed — adding a code is a contract change,
not an implementation detail.

**6. 403 (authz) and 422 (privacy block) are distinguishable by status code
alone.** `AuthzError` is declared as `class AuthzError(Exception)` at
`backend/src/medarx/errors.py:138` — deliberately **outside** `MedarxError`, so
the 422 handler cannot catch it. `ProviderError` is outside it for the same
reason: a provider outage recorded as a block would be a false privacy event in
the one store the design names as an asset.
*Enforced by:* `backend/tests/test_api.py::test_a_caller_can_tell_403_from_422_by_status_code_alone`,
plus the row-1 tests in `backend/tests/test_block_conditions.py`.

**7. A 422 means nothing was sent. Asserted against a transport, not inferred.**
Proven three independent ways: live in a container, live on loopback through the
real API (with a control test proving the same observer/gateway/client does
record an approved request), and against a committed 288-frame real capture that
was demonstrably watching.
*Enforced by:* `backend/tests/test_egress_e2e.py::test_a_422_reached_neither_observer`
and `backend/tests/test_block_conditions.py::test_row4_a_422_sends_nothing`.

**8. The audit log is never a second PHI store. The storage field set is
hand-written, not derived from the model.** `ALLOWED_AUDIT_FIELDS` is a literal
`frozenset` at `backend/src/medarx/audit/audit_log.py:112`, so adding a field to
`AuditEvent` makes `append` **refuse** the record until someone states whether it
may be persisted. That refusal is the point.
*Enforced by:* `backend/tests/test_audit.py::test_allowed_audit_fields_exclude_anything_could_hold_a_value`,
`::test_a_record_carrying_a_field_outside_the_allowlist_is_refused`,
`::test_a_value_where_a_name_belongs_is_refused`, and
`::test_a_block_records_the_field_name_and_the_code_and_nothing_else`.

**9. Relative date intervals pass through unchanged.** "6 weeks" is not an
identifier, carries no absolute date, and is an explicitly supported
representation. Before this, **9 of 12** ordinary radiology sentences blocked on
unshifted dates, which made the system unable to process normal reports. The
recognition is a closed, tested shape list (30 accepted and 28 rejected shapes
enumerated, every rejected shape confirmed to reach a block). Month-name dates
shift in the form written; ambiguous numeric dates still block, behind a declared
`date_order` with a startup guard.
*Enforced by:* `backend/tests/test_redaction_layers.py::test_a_relative_interval_survives_a_report_unchanged`
and `backend/tests/test_ner_recognizers.py::test_a_relative_interval_is_recognised_by_its_shape`
(plus `::test_a_shape_that_is_not_a_listed_interval_is_not_one`).

**10. The document speaks the contract's vocabulary** — `Draft` / `Prior Summary`
/ `Ask`, not internal snake_case (`draft` / `prior_summary`). The audit log is a
permanent record an auditor reads next to the contract, and two spellings of one
contract fact is drift. The cost — the API must translate before writing a
record — is a real obligation and is paid in `wiring.resolve_function`.
*Enforced by:* `backend/tests/test_audit.py::test_every_contract_function_name_is_auditable`
and `::test_a_function_outside_the_contract_enum_is_refused`.

---

## 5. What remains

Tasks 18, 19, 20, plus the final whole-branch review. Acceptance criteria below
are quoted from `.docs/medarx-phase1-plan.md`, not guessed. All 20 task headings
exist in that file (I confirmed the heading list).

### Tasks 16 and 17 — already done (verified)

**Do not re-do these.** I verified empirically, not from the brief:

- Both `infra/observers/` and `infra/capture/` **exist**, and all nine files are
  **committed** to git (`git ls-files infra/` lists every one).
- Commits `de5804e` (Task 16) and `47544a2` (Task 17) are the two most recent on
  the branch, and the working tree is clean.
- Their tests exist and pass: `test_observer_agreement_unit.py`,
  `test_observer_service.py`, `test_egress_agreement.py`, `test_egress_e2e.py`
  (6 tests, verified passing on a clean re-run), plus four committed real capture
  fixtures.
- A combined report exists at
  `.superpowers/sdd/phase1-privacy-kernel/task-16-17-report.md`.

Three caveats a successor must know: the report is **still being edited** (its
counts changed under me), its **seed-matrix table is an unfilled placeholder**
at line 343, and it is **not reflected in `progress.md` at all** (see section 2).

### Task 18 — Beat 1, the approved-path end-to-end demonstration

- **Files:** create `backend/tests/test_e2e_approved.py`, `evals/demo_beat1_approved.py`.
- **Delivers:** a self-contained test that starts the observer, runs the
  `known_positive` case through `Pipeline.run`, and asserts agreement against
  the approved hash; plus a runnable script printing the four artefacts — input,
  transformed payload, model response, independently captured outbound request.
- **Acceptance criterion (plan):** the test asserts
  `out["approved_payload_hash"] == result.approved_payload_hash`,
  `out["request_id"] == result_request_id`, `out["observer_record_count"] == 1`,
  `out["pcap_hit_count"] >= 1`, `out["agree"] is True`, and
  `"4452819" not in out["captured_bytes"]`. Run with
  `cd backend && uv run pytest tests/test_e2e_approved.py -v -m e2e`; expected
  **PASS, 1 passed**. The plan adds a diagnostic: if `pcap_hit_count` is 0 while
  the observer recorded a request, the capture is on the wrong interface —
  re-check the runtime-discovered `br-` id, and **do not add a third container to
  the bridge**.
- **Dependencies:** `build_pipeline` (Task 15), `seed_corpus.CASES` (Task 14),
  the observer (Task 16 — **done**), `start_capture.sh` and `check_agreement`
  (Task 17 — **done**). Needs the observer reachable at
  `http://127.0.0.1:8080/v1`. The plan is explicit that these tests must **fail
  loudly, never skip**, when the observer is unreachable — a skipped egress test
  is indistinguishable from a passing one.
- **Note:** the script must not print raw synthetic identifiers to stdout in
  `--json` mode; print mode may show the full redaction diff, because the data
  is fabricated — that is exactly the distinction the product spec draws.

### Task 19 — Beat 2, the blocked-path end-to-end demonstration

- **Files:** create `backend/tests/test_e2e_blocked.py`, `evals/demo_beat2_blocked.py`.
- **Delivers:** a script whose `--json` output carries the 422 block receipt, the
  audit block event, and the observer/packet counts (**both expected zero**).
  Plan's words: "This is the load-bearing beat: it proves the boundary refuses,
  not merely that it logged."
- **Acceptance criterion (plan):** `out["status"] == "blocked"`,
  `out["http_status"] == 422`, `out["layer"]` in `{D.1, D.2, D.3, E, F}`,
  `out["observer_record_count"] == 0`, `out["pcap_hit_count"] == 0`,
  `out["agree"] is True`,
  `out["audit_block_event"]["final_disposition"] == "blocked"`, and
  `"4452819" not in json.dumps(out["audit_block_event"])`. Expected:
  **PASS, 4 passed**, via `cd backend && uv run pytest tests/test_e2e_blocked.py -v -m e2e`.
- **Dependencies:** `build_pipeline` (Task 15), the `unresolved` and `all_phi`
  cases (Task 14), `check_agreement` (Task 17 — **done**), `ModelGateway.send`
  (Task 11 — **done**).
- **Note:** the script must exit non-zero if either observer count is non-zero,
  and say so loudly — "a blocked beat that shows outbound bytes is a failed
  demo".

### Task 20 — Compose, the Orthanc image, the preflight, and the README

- **Files:** create `infra/compose.yaml`, `infra/orthanc/Dockerfile.orthanc`,
  `infra/orthanc/orthanc.json`, `infra/verify_env.sh`; modify
  `backend/README.md`. **The preflight script is the test** — there is no pytest
  for this task.
- **Delivers:** a Compose project named `medarx` with `postgres` (on the locally
  present `postgres:18-alpine` — do not pin 16 or 17, neither is present locally
  and a pull costs disk), `observer` (from `infra/observers/Dockerfile`, with
  `MEDARX_AUDIT_KEY` passed through from the host environment), `orthanc` on
  `profiles: ["orthanc"]` so it never starts in a Phase 1 run, and `capture` on
  `profiles: ["capture"]`. **No `viewer/` service and no DICOMweb client anywhere
  in the tree** (I verified the current tree has neither).
- **Acceptance criterion (plan):** `bash infra/verify_env.sh` passes — `docker
  version` reachable, the `medarx` network resolvable so a `br-` id can be
  derived, free disk printed, the remembered `15.3 GiB total / ~4.8 GiB available
  / zero swap / 12 cores` budget printed against a measured `MemAvailable`, the
  venv not under `/tmp`, and `docker compose -f infra/compose.yaml config`
  valid. "Three booleans, all true", a 12-character `br-` id printed.
  Then `docker compose -f infra/compose.yaml up -d` must start **only**
  `postgres` and `observer`.
- **Dependencies:** `infra/observers` and `infra/capture` (Tasks 16–17 — both
  **done**), the verified Orthanc image recipe. Blocked on nothing outstanding;
  this task can start immediately.
- **Three Orthanc facts the plan pins, all worth keeping:** `orthanc/orthanc` is
  a 404 on Docker Hub (not rate limiting) and `jodogne/orthanc:latest` ships no
  DICOMweb plugin (`POST /dicom-web/studies` returns 404), so neither may be
  pinned. The binary is `/usr/sbin/Orthanc`, not `/usr/local/sbin/Orthanc`, and
  `orthanc-tools` is not a Debian package. In `orthanc.json` the key is
  `RemoteAccessAllowed`, **not** `AllowRemoteAccess` — the wrong key is silently
  ignored and presents as a 401, and in 1.10.1 remote access cannot be enabled
  without authentication.
- **Note the plan also expects the README to gain the regulatory paragraph
  verbatim** (Step 7). I verified it is **not currently in the README** — this
  is part of the outstanding work for this task.

### The final whole-branch review

Not a plan task; it is the standing `Ruling PROCESS-PHASE-2` instruction —
**one review across the whole branch, at the end**, not one per task. Run it
after 18–20, and treat section 4's named tests as the regression net.

### Two known contract exceptions

The plan's task list names the current contract's exceptions. I verified the
contract's shape but did **not** independently re-derive both exception names
from the plan text; treat the following as reported, not re-verified: the
contract publishes examples that are satisfiable in schema but that no component
can currently produce in the two cases the plan calls out. Check
`backend/tests/test_openapi_contract.py` (it contains both a static
reachability sweep and an executed check) before assuming the list is still
accurate.

---

## 6. The two demo beats

This is what Phase 1 exists to demonstrate. Both run against fabricated data
only. **Beat 2 matters at least as much as Beat 1**: an invisible block is not
evidence, and a leak that passes every check is worse than no check at all.

**Beat 1, the approved path.** Seeded identifiers go in; a transformed payload
comes out; the model replies; and the independently captured outbound request is
compared against the approved payload, with the two observers agreeing. The
artefacts are: input, transformed payload, model response, captured outbound
request. The proof obligation is that the bytes on the wire are the bytes the
policy approved — not merely that the gateway says it sent them.

**Beat 2, the blocked path.** An identifier that cannot be safely transformed
(`ZX-99-ALPHA`, the `AMBIGUOUS_REFERENCE` case) reaches the pipeline; the request
is **blocked**; nothing leaves the environment; and the block receipt names the
component that actually refused. The proof obligation is zero bytes transmitted,
observed from outside the process by both observers, with the check *able* to
fail.

The check is built so it cannot pass vacuously, and this is the part to
preserve. Both-silent counts as agreement **only** when a block receipt for that
same request id exists and says `blocked` — otherwise a gateway that never fired
would score as full agreement, which would hollow out the load-bearing beat.
`start_capture.sh stop` exits non-zero when the capture saw zero frames **or
lost any packets**, because a capture that silently caught nothing turns every
downstream check into a check that passed over an empty evidence set. And the
live e2e test demonstrates the negative direction: delete the observer's record
and the same run reports `agree=False`; substitute the payload length-preservingly
(`7 mm` -> `9 mm`) and re-hash the index so the observer stays internally
consistent, and the check **still** refuses, because both observers saw the
request and agreed with each other about a payload that was not the approved
one. That is the leak shape, and it is the one that matters.

**How to run them:** `evals/demo_beat1_approved.py --json` and
`evals/demo_beat2_blocked.py --case {unresolved,all_phi} --json`. **Neither
script exists yet** — they are Task 18 and Task 19. What exists today is
`backend/tests/test_egress_e2e.py`, which drives the real composition root
through both directions in containers and asserts exactly these properties. It is
the closest thing to a runnable demo that Phase 1 currently has.

---

## 7. The final state expected

Concrete and checkable:

- All 20 tasks implemented, with Tasks 18–20 and the final whole-branch review done.
- A clean working tree, every change committed as `feat(<scope>): <changes>`.
  This is the established convention in all 64 commits and should continue.
- The full suite green across `PYTHONHASHSEED` 0, 1, 5 and 42, run
  **sequentially** — never concurrently, for the `test_egress_e2e.py` Docker
  network race documented in section 2, and because of the `.pyc` hazard in
  section 9. Clear `__pycache__` before each run. Both suites count: backend
  (845 today) and the separate eval harness (37 today), since `testpaths`
  excludes `evals/`.
- `contracts/openapi.yaml` satisfiable: every published example a component can
  actually produce, with the current contract's two known exceptions named in
  section 5's task list.
- Both demo beats runnable end to end, with the blocked path **provably
  transmitting zero bytes** — measured from outside the Medarx process, not
  asserted by Medarx's own log.
- The deferred items in section 8 either closed or still tracked with a named
  owner. Two of them already have owners recorded in the plan: the Phase 2
  metadata question (`study_description`, `body_part_examined`,
  `referring_service`) is owned by Saurya Gur with a stated Phase 2 entry
  condition, and the "what does E record when it refuses" question is owned by
  Saurya Gur.

---

## 8. Deferred and known-limited

Each of these was decided deliberately, not overlooked. All are recorded with
reasoning in `progress.md` or the per-task reports.

**1. `PATIENT_ID` is unreachable on the spelling a report actually uses.**
Anchor-label stripping blanks labels to equal-length spaces *before* analysis,
and every spelling a radiology report writes ("Patient ID:", "PATIENT ID:",
"Pat Id:", "Patient-ID:", "Pat:") is an anchor label. The pattern requires a
label, so the recognizer is not merely inaccurate — it is unreachable on the
canonical form. The one spelling that reaches it is `PatientID:` with no space.
This is a **detection gap, not a boundary gap**.

> **Correction to a claim I was given, verified against the code.** The framing
> "0 of 15 planted identifiers reached an approved payload" is wrong as stated.
> What the test actually asserts (`evals/test_eval_harness.py::test_no_planted_identifier_survives_into_an_approved_payload`)
> is `checked == 15` and **`survived == 0`** — a *boundary* result, and a
> different metric from detection recall. And the accompanying test
> `::test_the_values_that_only_layer_3_stops_are_named` is explicit that **4 of
> those 15 are stopped only by layer 3's deterministic re-read**, naming
> `known_positive`, `unresolved`, `all_phi` and `dicom_header_prose`. The
> `patient_id_label_spelling` case is one of only two of six cases that are *not*
> blocked at all — it reaches an approved payload, and what keeps `774123` out is
> layer 3, not a recognizer. So: 0 of 15 survived, 4 of 15 by backstop only, and
> the report that quotes "0/15" as a detection figure is wrong, as its own
> docstring says ("A privacy figure of 0/15 with no note of this would read as a
> detection result, and it is not one").
> *Owner:* unassigned. The characterisation test is written to **go red when the
> defect is fixed** — that is intended, not a broken test.

**2. About 5 of 28 ordinary radiology sentences have clinical words masked
inside an *approved* payload.** Verified precisely: `assert len(unset) == 5` and
`assert len(declared) == 6` over `ORDINARY_SENTENCES`
(`backend/tests/test_redaction_layers.py::test_the_rate_of_clinical_words_masked_in_approved_payloads`).
The words are `CT`, `Nodule`, `Scan`, `Pulmonary`, `Pleural`, `HU` read as named
entities. **Accepted for Phase 1 because the corruption is visible and
recoverable, unlike the invisible block it replaced.** The prior record quoted
7/28 by counting two distinct sentence lists as one; the ledger records that
correction. A partial fix was rejected because it would establish a second
vocabulary table nobody owns and imply the class was handled.
*Owner:* unassigned; deliberately deferred.

**3. A caller omitting both `patient_reference` and `PatientID` gets a
per-study date shift, so intervals across a patient's studies are not
preserved.** Where a patient reference *is* supplied, the offset is per-patient
and stable across store reopen (pinned by
`test_patient_offset_is_stable_and_persisted_across_store_reopen`).
*Owner:* unassigned.

**4. Two enforcement rows in the design's table are unreachable through the
current surface** — and the honest count is **three conditions across two
rows**, a correction the Task 15 review made to its own first round:
- **Row 3 (D.1)** — `layer1_deterministic` shifts a date only when it still
  equals what C was given, and C always shifts first or refuses. Evidence:
  `backend/tests/test_block_conditions.py::test_row3_layer_d1_cannot_be_reached_because_component_c_shifts_first`.
- **Row 5's unshifted-date half** — the same mechanism as row 3:
  `redaction/layers.py::_check_date` fires only under the same condition.
- **Row 6 (E)** — unreachable *by a caller*: every condition `decide` can fail
  on is either a misconfiguration `Settings` forbids or a state the orchestrator
  cannot be in. Evidence:
  `::test_row6_layer_e_cannot_be_reached_by_a_caller`, which deliberately builds
  a mismatched engine that *does* produce a layer-`E` `RedactionError`, to show
  the path exists and is not the one a request can take.
- **Separately:** `UNKNOWN_DICOM_ATTRIBUTE` is unreachable through the surface,
  because `AllowlistedDicomMetadata` is `additionalProperties: false` over eight
  properties and all eight are in `KNOWN_DICOM_ATTRIBUTES`, so an unknown keyword
  is a 400 at the schema.
- **D.3 is reachable but never alone** — all four of its checks are shadowed on a
  correctly ordered run except the leftover scan. Reported rather than engineered
  around: producing a D.3-only receipt would mean tampering with a payload between
  components, which proves nothing about the route.
*Owner:* unassigned; reported as a property of the current surface.

**5. The mapping store creates its tables and never migrates them.**
`MappingStore.__init__` calls `METADATA.create_all(engine)`; the docstring at
`mapping_store.py:129` says so and calls it "a convenience for a single process,
not a schema migration". `medarx.audit.schema_init` says the same of itself
("Idempotent; not a migration"). `create_all` check-then-create is a TOCTOU race
on multi-worker startup — already mitigated by tolerating a concurrent creator.
*Owner:* the plan assigns the DDL ownership to the infrastructure task (Task 20):
compose must own that DDL in one step started before the app.

**6. An audit readback returns every record to any caller presenting any scope,
because the storage policy forbids the field that would filter it.**
`AuditLog.events(request_id, function, disposition, since, limit)` has no scope
parameter — I read the signature and confirmed it. Scoping would require
storing a study or patient reference in the audit record, and
`ALLOWED_AUDIT_FIELDS` forbids it. The log is therefore not a second PHI store
**and** not a per-study partitioned store; the two goals are in direct tension
and the storage policy won.
*Owner:* unassigned; the tension is inherent to the current field set.

**7. Whole-database deletion of the audit log is undetectable without an
external anchor.** A reader holding no external copy of the head cannot
distinguish a database whose entire contents were deleted from one that was never
written. The keying and the tombstones close repointing and blanking, not this.
Asserted by a test rather than left implied, and **external time-stamping is
Phase 6**.
*Owner:* Phase 6.

**8. The ledger does not cover Tasks 13–17** (section 2). The commits, reports
and tests exist; the chronological record does not. *Owner:* whoever picks up
Task 18 should extend `progress.md` before it stops being useful.

---

## 9. Environment

All of the following was measured on this host today.

- **Python 3.13.5**, **uv 0.11.17**, **Node v26.2.0**, **Docker 29.8.1** with
  **Compose v5.5.1**.
- **There is no `pip` on PATH** — `command -v pip` and `command -v pip3` both
  return nothing. This is why `bootstrap_ner_model.sh` deliberately does not use
  `python -m spacy download`: spaCy shells out to `pip`, and the `uv` shim
  intercepts it with "No virtual environment found". The script downloads the
  wheel and installs it with `uv pip install`.
- **No GPU** — no `nvidia-smi` on PATH.
- **RAM: 15 GiB total, ~3.1 GiB available at measurement time** (12 GiB used,
  5.1 GiB in buff/cache). The plan's remembered budget was "15.3 GiB total /
  ~4.8 GiB available / zero swap / 12 cores".
- **Disk: 3.9 GiB free on `/` (218G total, 203G used) — the filesystem is 99%
  full.** This is materially tighter than the ~7 GiB the project has been
  planning against, and it is the reason the plan forbids pulling `postgres:16`
  or `:17` and pins `postgres:18-alpine` instead. Docker's own accounting:
  24 images totalling 10.81 GB, **10.02 GB reclaimable (92%)**, plus 487 MB of
  build cache (175 MB reclaimable). **Reclaiming Docker space is probably the
  first thing to do before Task 20**, which needs to build images and start a
  database.
- **`uv sync` prunes the manually-installed `en_core_web_sm` model**, which is
  not a declared dependency (only `presidio-analyzer`, `presidio-anonymizer`
  and `spacy==3.8.16` are). After **any** `uv sync`, immediately run
  `bash src/medarx/scripts/bootstrap_ner_model.sh` from `backend/`. A missing
  model does not say it is missing — it surfaces as
  `OSError: [E050] Can't find model 'en_core_web_sm'` from whichever recogniser
  tried to load it, so a developer who edits `pyproject.toml` and syncs otherwise
  loses the model silently and debugs recognisers instead of the missing
  dependency. Currently installed: 3.8.0.
- **Clear `__pycache__` before any run after a file change.** CPython can accept
  a `.pyc` that passes its `(mtime, size)` staleness check while the source
  actually differs. This produced **23 spurious failures** here, twice, and the
  symptom is a cluster of unrelated failures that a re-run cannot reproduce.
- **Run seed matrices sequentially, never concurrently** — for the `.pyc` reason
  above, and now also for a second reason I found today: `test_egress_e2e.py`
  creates the Docker network `medarx-e2e` with `check=False` and removes it in
  module teardown, so two concurrent runs of that module race and produce 6
  spurious `docker run` errors (exit 125, "network medarx-e2e not found"). Both
  failure modes produce *red that is not real*, which is the most expensive kind.
- **A packet capture cannot run from a third container on a Docker bridge.** The
  bridge switches A's veth directly to B's; frames between two containers never
  traverse a third. Measured on this host: that topology captured 21 packets of
  mDNS/ARP and zero of the traffic, while the observer was actively receiving
  the requests it was supposed to be watching. Use
  `--network host --cap-add=NET_RAW` pointed at the project's `br-*` interface,
  discovered at run time from
  `docker network inspect -f '{{.Id}}' | cut -c1-12` (12 hex, because Linux
  truncates interface names to `IFNAMSIZ - 1 = 15` including the `br-` prefix).
  Never hard-code a `br-...` — it is an interface that does not exist until the
  next `docker network rm`.
- **`tcpdump -A | tee` under `timeout` reports "0 packets captured" even when
  packets arrived**, because SIGTERM kills tcpdump before its block-buffered
  stdout flushes; `-l` does not help. Always `-w file.pcap` and read back with
  `-r`. A second, distinct failure was observed during development: `48 packets
  received by filter, 44 packets captured` — tcpdump *lost* the very request the
  check was about, so `stop` now also exits non-zero when packets were dropped.
- **Process restarts have interrupted work five times.** Commit early; make each
  commit a clean stopping point. Every one of the 64 commits is a single logical
  change with a `feat(<scope>)` subject, which is what makes that possible.
- **The venv must not live under `/tmp`** — `/tmp` is a tmpfs, so a venv there
  consumes RAM rather than disk. It belongs at `backend/.venv`.
- **Only `config.py` may read the environment** in the kernel. The observer
  process is the deliberate exception and says why in its own docstring: it is
  not a `medarx` module and is not in the import graph of anything that sends
  data, so injecting the record directory through a process boundary is the same
  property reached a different way.

---

## 10. Where the detail lives

- **`contracts/openapi.yaml`** — the normative contract, and the artefact every
  other document defers to. 69 KB, tracked in git. `ActionCode` (24 members),
  `Layer` (8), `FunctionName` (3), five paths. The standing ruling is
  *contract-vocabulary-wins*: where the contract and the implementation disagree
  about the same field, the contract is right and the code is wrong. The
  regulatory paragraph is in `info/description`.
- **`backend/README.md`** — the only tracked document (804 lines). Setup and the
  two-step sync, then per-component sections for B, C, E, F, G, H, I, J. The
  Component I section is the best plain-language account of the two observers.
  Note it is **missing** the sections for A and D, and the regulatory paragraph.
- **`.docs/medarx-phase1-design.md`** — the approved design. **§3** is the
  component decomposition (A–J with responsibilities and what each
  communicates with); **§6 is the enforcement table** — seven rows, one per
  layer, transcribed rule-for-rule into `policy/decision_table.py`; §7 is the
  threat model; §9 holds the questions deferred to later phases.
- **`.docs/medarx-phase1-plan.md`** — the 20-task plan. 152 KB. Every task has
  files, interfaces, numbered steps with the literal test code, the exact run
  command, and the expected pass/failure. §9 holds the open questions with named
  owners and Phase 2 entry conditions. This is the specification for the
  remaining work; quote it rather than paraphrasing it.
- **`.docs/medarx-product-spec.md`** — the product spec. Source of the field
  storage policy, the contract's function vocabulary, and the relative-interval
  allowance.
- **`.docs/medarx-ui-design.md`** — the Phase 2 viewer design. **Out of scope for
  Phase 1.**
- **`.superpowers/sdd/phase1-privacy-kernel/progress.md`** — a chronological
  ledger of every task, fix round and ruling, including several that correct
  earlier decisions. **139 lines, current through Task 12 only; nothing for
  Tasks 13–17.** Read the `Ruling *` lines especially — they record the reasoning
  that the code alone will not tell you.
- **`.superpowers/sdd/phase1-privacy-kernel/task-N-report.md`** — per-task
  implementation reports, including claims later corrected. Reports exist for
  Tasks 1, 2, 10, 11, 12, 13, 14, 15 and a combined 16–17 (briefs exist for
  1–20). **Some earlier sections in those reports were left standing when they
  should have been corrected**; the ledger records the corrections where it has
  them, and where it does not, the report is wrong. Specific known cases: the
  Task 15 report's first round said "two unreachable rows" when the honest
  framing is three conditions across two rows (§8 item 4); the Task 9 report
  quoted 7/28 where the measurement is 5/28; and an earlier Task 10 claim that
  a specific policy reason "reaches the audit log" is false — `run_redaction`
  takes `Decision.wire_code` and drops the decision, so a receipt for an unknown
  policy version and one for an unimplemented mode are byte-identical.
  `task-16-17-report.md` is **in flight** and its seed matrix is an unfilled
  placeholder. Treat every report as a claim to be re-verified against the code,
  not as a source of truth.
- **`.superpowers/sdd/` is gitignored.** None of the above is in git; if it
  matters, it needs to be copied somewhere that is not.
