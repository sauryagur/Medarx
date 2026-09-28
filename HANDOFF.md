# Medarx — Handoff

> **Refreshed 2026-09-28, after Phase 1 completed.** This document was first
> written while Phase 1 was parked at Task 12. Tasks 13–20, the final
> whole-branch review and both review fixes have since been implemented,
> committed and merged to `master`. Every claim below was re-verified by
> running a command or reading a file on **2026-09-28**; anything that could not
> be determined is marked **not verified**. Where the original text was wrong
> about the current state, it has been corrected rather than left standing.

Originally written 2026-09-28 by inspecting the repository, then at
`phase1-privacy-kernel` and HEAD `47544a2`.

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
extension and the `viewer/` directory, which I re-confirmed does not exist), and
it does **not** integrate DICOMweb or Orthanc into any request path. That second
claim was originally justified by "zero `dicom-web`/`dicomweb` references in any
`.py`, `.sh` or `.yaml` outside `.docs/`", which is **no longer true**: Task 20
shipped an Orthanc image and a compose service, and the string now appears in
`contracts/openapi.yaml:872`, `backend/src/medarx/api/schemas.py:124`,
`infra/compose.yaml:19,101-102` and the orthanc config. Every one of those is
**prose or a comment** — I grepped `.py`/`.sh`/`.yaml` for the string and read
every hit. There is still no DICOMweb **client** in the tree and nothing on the
Medarx request path talks to Orthanc. Phase 1 also does not use any real patient
data or downloaded dataset. Every value in the evaluation corpus is
fabricated and `evals/synthetic_phi/identifiers.json`
carries a marker saying so.

The regulatory positioning, which must be reproduced verbatim and never
paraphrased:

> Medarx is intended for research and demonstration. It performs administrative report assistance using clinician-supplied findings and authorized report text. It does not independently interpret medical images, make diagnostic or treatment recommendations, or autonomously submit clinical reports. Its regulatory classification has not been established, and it is not validated for clinical use.

Re-verified 2026-09-28. The paragraph appears **verbatim** in
`contracts/openapi.yaml` at `info/description` — **once**, not duplicated: the
`info/license` block carries only `name: Unlicensed — research and
demonstration use only` and `identifier: "Proprietary"`, so the original
"duplicated at `info/license/name`" claim was wrong. It appears in all three
`.docs/` files, and it is now **in `backend/README.md`** as well, under
"What this software is, and is not" — Plan Task 20 Step 7 is done, and the
original "not yet in the README" note is withdrawn.

---

## 2. Current state

**Phase 1 status: COMPLETE, through Task 20, plus the final whole-branch
review.** Re-verified 2026-09-28.

**Branch:** `master` — **not** `phase1-privacy-kernel`, which is what this
document originally said. **HEAD:** `433cf6a` (`docs: track the phase 1 handoff
document`). **Working tree:** clean (`git status --porcelain` empty).
**Commit count:** 72 (`git rev-list --count HEAD`), up from 64. The last 40,
newest first:

```
433cf6a docs: track the phase 1 handoff document
0b42e49 chore: stop ignoring the root handoff document
eb4070c feat(docs): correct the capture and parser claims in the component I section
d8c89aa feat(demo): declare the policy mode the beats actually run in
e2f20d5 feat(egress): refuse to score a dead sniffer as agreement
1d84d55 feat(infra): add the compose stack, the orthanc image, and the preflight
13f607e feat(demo): add the blocked-path beat and prove its zero is a measurement
db7fea3 feat(demo): add the approved-path beat and a check that can fail
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
```

### What changed since this document was written

Eight commits landed after the `47544a2` this document recorded. Six of them
closed Phase 1; two track this file.

| Commit | What it did |
|---|---|
| `db7fea3` | **Task 18** — beat 1, the approved-path end-to-end demonstration: `evals/demo_beat1_approved.py`, `backend/tests/test_e2e_approved.py`, shared machinery in `evals/beat_support.py`, two fixes to component I |
| `13f607e` | **Task 19** — beat 2, the blocked-path demonstration: `evals/demo_beat2_blocked.py`, `backend/tests/test_e2e_blocked.py` |
| `1d84d55` | **Task 20** — `infra/compose.yaml`, `infra/orthanc/Dockerfile.orthanc`, `infra/orthanc/orthanc.json`, `infra/verify_env.sh`, `backend/README.md` |
| `e2f20d5` | Fix from the final whole-branch review — a dead sniffer scored as agreement (`infra/capture/agreement.py`, `backend/tests/test_egress_agreement.py`) |
| `d8c89aa` | Fix from the final whole-branch review — the audit records named a deployment mode that was not in force (`evals/beat_support.py`, both demo scripts, both beat test modules) |
| `eb4070c` | Fix from the final whole-branch review — the Component I section of `backend/README.md` |
| `0b42e49` | Stop gitignoring the root handoff document |
| `433cf6a` | Track `HANDOFF.md` (it had previously been gitignored) |

**The final whole-branch review was run**, across `efe567d..HEAD` — which is 71
commits — at the standing `Ruling PROCESS-PHASE-2`. It found **1 Critical/High
and 1 Medium**; both are fixed and committed (`e2f20d5`, `d8c89aa`), and the
doc-accuracy fix followed (`eb4070c`). It also verified, and found clean, the
seam no test had ever covered: the whole kernel against the compose stack's real
PostgreSQL 18. Full account in
`.superpowers/sdd/phase1-privacy-kernel/task-18-20-report.md` §6.

### Verified test counts

`backend/pyproject.toml` sets `testpaths = ["tests"]`, so the canonical
`cd backend && uv run pytest` collects `backend/tests/` only — it does **not**
collect `evals/test_eval_harness.py`. There are two suites, and the numbers I
measured are:

| Suite | Command | Count |
|---|---|---|
| Backend | `cd backend && uv run pytest --junit-xml=...` | **877 tests, 0 failures, 0 errors, 0 skipped** |
| Evaluation harness | `cd backend && uv run pytest ../evals --junit-xml=...` | **37 tests, 0 failures, 0 errors, 0 skipped** |

Both numbers were **re-measured on 2026-09-28** and are unchanged from what
`task-18-20-report.md` §4 records. The backend figure is **877, not the 845
this document originally carried**; the branch adds 32 over that baseline — 11
in `test_e2e_approved.py`, 15 in `test_e2e_blocked.py`, 2 cooked-capture cases
and 3 dead-sniffer cases in `test_egress_agreement.py`, plus 1 policy-mode test
per beat module.

Counts are read from the JUnit XML, not from pytest's summary line, which is
lost when stdout is a pipe in this environment.

**One caveat on the backend number, and it matters for how you read it.** The
first full run during the original Phase 1 build reported 845 tests with **6
errors**, all six in `tests/test_egress_e2e.py`, all with the same cause:
`docker run ... --network medarx-e2e` failing with exit 125. The daemon's
message was `failed to set up container networking: network medarx-e2e not
found`. The network was genuinely absent. The cause is a **race in the test
fixture, not a defect in the component**: `tests/test_egress_e2e.py:154` creates
the network with `check=False` (so a create failure is silent), and the
module-scoped teardown at **line 202** (line 200 in the original text — the
block has grown) does `docker network rm medarx-e2e`. Two concurrent runs of
that module — one teardown removing the network while the other is between
create and run — reproduce it exactly. Do not run two copies of that module
concurrently; run seed matrices sequentially.

**The 6 errors were seen again once during Tasks 18–20 and never reproduced.**
`task-18-20-report.md` §4 records one full-suite run with 6 `test_egress_e2e.py`
errors, all `docker run … exit 125` with `network medarx-e2e not found`, and
that it did not reproduce in two paired runs, in a solo run, or in any of the
four seed-matrix runs. Leftover containers from the interrupted handoff session
were present at the time; that explanation is a **hypothesis, not a diagnosed
cause**. My own 2026-09-28 run of the full suite was clean: **877 passed, 0
failures, 0 errors, 0 skipped**, 135 s.

`en_core_web_sm` 3.8.0 is currently installed and importable, so the NER model
is present right now.

### What exists on disk

- `contracts/openapi.yaml` — 69 KB, the normative contract. Five paths:
  `/v1/functions/{function_name}/executions`, `/v1/executions/{request_id}/approval`,
  `/v1/policy`, `/v1/audit/records`, `/v1/audit/records/{request_id}`.
  `ActionCode` has 24 members; `Layer` has exactly 8
  (`J, A, D.1, D.2, D.3, E, F, C` — no bare `"D"`); `FunctionName` is
  `[Draft, Prior Summary, Ask]`.
- `backend/src/medarx/` — **48** Python modules (was 47 when this was written)
  across `api/`, `audit/`,
  `deident/`, `extraction/`, `gateway/`, `policy/`, `pseudonym/`, `redaction/`
  plus top-level `config.py`, `errors.py`, `models.py`, `pipeline.py`,
  `logging_filter.py`, and `scripts/bootstrap_ner_model.sh` (executable).
- `backend/tests/` — **26** test modules, including four new egress ones
  (`test_observer_agreement_unit.py`, `test_observer_service.py`,
  `test_egress_agreement.py`, `test_egress_e2e.py`) and a committed
  `fixtures/capture/` holding four **real** capture artifacts (a 58 KB
  approved-request pcap readback, a 148 KB blocked-request readback, and the
  observer `.bin` record plus its `index.jsonl` line from the same run). All
  four are tracked in git.
- `evals/` — `runner.py`, `metrics.py`, `run_eval.py`, `conftest.py`,
  `test_eval_harness.py`, `__init__.py`, **`beat_support.py`** and the **two
  demo scripts `demo_beat1_approved.py` and `demo_beat2_blocked.py`** (all from
  Tasks 18–19), and `synthetic_phi/` with 6 corpus cases across three
  groups (`CASES`: `known_positive`, `unresolved`, `all_phi`;
  `DICOM_HEADER_CASES`: `dicom_header_identifiers`, `dicom_header_prose`;
  `SPELLING_CASES`: `patient_id_label_spelling`), plus `identifiers.json`
  (14 identifier values + a synthetic marker + a notice), `clean_prose.py`
  (28 `ORDINARY_SENTENCES`), `report_template.txt`, `gen_dcm.py`,
  `seed_corpus.py`, `baseline.json`, `eval_results.json`.
- `infra/` — `__init__.py`, `observers/` (`observer.py` 425 lines,
  `Dockerfile`, `requirements.txt`), `capture/` (`agreement.py` **732** lines,
  `start_capture.sh` **233** lines, `Dockerfile`), plus **`compose.yaml`,
  `verify_env.sh` and `orthanc/` (`Dockerfile.orthanc`, `orthanc.json`)** from
  Task 20. **All thirteen files are committed** — `git ls-files infra/` lists
  every one, including the four Task 20 additions.
- `backend/README.md` — **1072** lines (was 804), tracked. Per-component sections
  for B, C, E, F, G, H, I, J, plus "Phase 1 — running it" and "Known and
  accepted limitations". Still **missing** sections for A and D. It now carries
  the regulatory paragraph verbatim.
- `HANDOFF.md` — this file, now **tracked** (commit `433cf6a`). It was
  gitignored until `0b42e49` stopped that, so there are now **two** tracked
  documents, not one. Nothing under `.docs/` or `.superpowers/` is tracked.

**The eight files this document listed as "Not present" all exist.** I checked
each by path on 2026-09-28: `infra/compose.yaml`, `infra/verify_env.sh`,
`infra/orthanc/Dockerfile.orthanc`, `infra/orthanc/orthanc.json`,
`evals/demo_beat1_approved.py`, `evals/demo_beat2_blocked.py`,
`backend/tests/test_e2e_approved.py`, `backend/tests/test_e2e_blocked.py`. The
"Not present" list is **withdrawn**; those were Tasks 18, 19 and 20, and all
three are done. The only one of the original "not present" claims that still
holds is the one about `viewer/`: **there is still no `viewer/` directory**,
which is correct — that is Phase 2.

### Ledger state — the original gap is closed

This section originally recorded a real defect: `progress.md` stopped at Task
12, with **zero** entries for Tasks 13–17, so the chronological record of "every
task, fix round and ruling" did not cover the work that had actually been done.

**Re-verified 2026-09-28: that gap has been closed.**
`.superpowers/sdd/phase1-privacy-kernel/progress.md` is now **250 lines** (was
139) and `grep -c '^Task 1[3-7]:'` returns **5** (was 0). The append was made
under `Ruling LEDGER-APPEND`, which states the reasoning: *the chronological
ledger is the recovery map after context loss, so a gap in it is a defect in the
record rather than a missing nicety.* The five entries were written from `git
log` SHAs rather than from recollection, and the per-task reports were treated
as claims to re-verify — that is how the append had to reconcile §3's "one
measurement said 7/28 where the measurement is 5/28". The ledger now also
records both final-review findings (`e2f20d5`, `d8c89aa`).

Still true: `.superpowers/sdd/` is **gitignored** (`.superpowers/sdd/.gitignore`
contains `*`), so none of this is in git. `task-16-17-report.md` remains the
one report with an **unfilled `<!-- SEED_MATRIX -->` placeholder** at line 343 —
I confirmed the placeholder is still there. Treat that report's numbers as
unverified; the ledger and the code supersede it.

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
6. **The whole per-task review process was judged a misjudgement.** The ruling
   `Ruling PROCESS-PHASE-2` (ledger line 139) says so in terms: roughly fifteen
   tasks each costing an implement, a review and 0–5 fix rounds, with the
   largest single defect found late because the queue serialised behind review
   overhead. The rule going forward is: implement in dependency order, review
   **once at the end across the whole branch**, fix what that surfaces.
   Exceptions where per-task review still earns its cost: anything establishing
   a security boundary, and anything another task consumes before it can be
   reviewed end to end.

   **The ruling has now been carried out, and it earned its keep.** The final
   whole-branch review was run across `efe567d..HEAD` and found **1
   Critical/High and 1 Medium**, the High being a dead sniffer scoring as
   agreement. Both are fixed. The review is what caught it — per-task review
   had not.

---

## 4. Invariants that must not be broken

Each of these was violated at least once during the build. Each is now enforced
by a named test. **If you change any of these mechanisms, the named test is the
one that must go red — check that it does.**

**Re-verified 2026-09-28, and this section is unchanged.** I checked all 30
named tests in items 1–10 still exist in `backend/tests/` by name, one by one:
all 30 present. `task-18-20-report.md` §6a also re-ran them **by name** against
the final tree — 73 collected after parameterisation, 0 failures, 0 errors, 0
skipped — and notes that the agreement fix and the cooked-capture fix touched
component I only, so **none of the ten went red**, which is the check this
section asks for rather than a claim that nothing was affected. Invariants 4
and 5's per-declaration-site sweeps and invariant 8's `ALLOWED_AUDIT_FIELDS`
literal are unchanged: I re-read `audit_log.py:112` and it is still a
hand-written `frozenset`, and `errors.py:138` is still
`class AuthzError(Exception)`, declared outside `MedarxError`, as invariant 6
requires.

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

**Nothing remains from Phase 1.** All 20 tasks are implemented, committed and
merged; the final whole-branch review ran across `efe567d..HEAD` and both its
findings are fixed. The old text of this section listed Tasks 16–20 and the
review as outstanding — all of that is done, and that list is withdrawn.

**What remains is Phase 2**, and it is already planned. The plan is
`.docs/phase2-plan.md` (47 KB, written 2026-09-28, **not tracked** — `.docs/`
is gitignored). The summary below is drawn from that document; quote it rather
than paraphrasing it, and read it before planning anything.

### Phase 2 scope, in the plan's own words

The acceptance criterion, from `medarx-product-spec.md` §14, quoted verbatim in
the plan:

> **Clinician-supplied text becomes a reviewable draft with no pixel
> interpretation.**

Phase 2 includes, and is limited to: an OHIF **extension** (not a fork)
registering a right-hand copilot panel; Orthanc as the DICOM archive reachable
over DICOMweb; the **Draft** function end to end against a locally served
model; and the privacy drawer, made honest against what the contract actually
returns.

Phase 2 explicitly does **not** include: `Prior Summary` or `Ask` behaviour
(Phase 5); Draft's automated output validation (Phase 4); cloud inference and
independent egress capture (Phase 3); `Authorized local` mode (the contract
documents it as an architectural extension only, `implemented: false`, and no
request can select it); TCIA or MIMIC-CXR data (Phase 6, and the data policy
forbids identifiable records anyway); and anything that would put component B,
the de-identifier, onto the request path — it is off it and stays off it.

### The five workstreams

The Phase 1 lesson — `Ruling PROCESS-PHASE-2`, that per-task review was a
misjudgement — is the reason there are five and not twenty. Each is sized to be
independently meaningful and reviewable as a whole.

**WS1 — Contract and API surface for the viewer.** The minimum contract and API
change that makes the three-state UI and the privacy drawer truthful, and
nothing else. Five deliverables: (1) a **preflight / send split** — an
operation that runs A → C → D → E, stops before F, and returns the
field-action summary, payload hash, stage list and policy version with a
`needs_review` disposition, plus a send operation bound to that exact hash,
using component F's existing `ApprovedSend` rather than inventing a second
authorisation path; (2) `X-Scope` declared as a header parameter on every
operation needing it, because a client generated from the current contract
sends no scope and gets 403 on everything; (3) `stages` (or `layer` + derived
stages) surfaced on the execution path, **or** the contract documenting
explicitly that it is not — silence is not acceptable; (4) a documented
`surface_refused` rendering, so the drawer does not invent one for
`layer: "J"`; (5) the change stays **additive and closed** as in Phase 1, under
the standing `Ruling CONTRACT-VOCABULARY-WINS`. It changes what the surface
*says* and *when a human is asked*, not what the kernel *decides*. It blocks
WS5 and constrains WS2.

**WS2 — Design system and the viewer shell.** `viewer/design/tokens.json`
holding exactly the YAML front-matter of `.docs/medarx-ui-design.md` as
structured data — the 14 colours, 6 type roles, 3 radii, 5 spacing steps and 4
component specs, kept as **token references rather than copies**, because that
front-matter already describes a token graph (its component specs use
`backgroundColor: "{colors.accent}"`). Plus a ~30-line Bun build emitting
`tokens.css` and `tokens.ts`. Kept honest by three things, in increasing order
of how much they hurt when missing: an ESLint `no-restricted-patterns` rule
banning raw hex, `rgb(`, `hsl(` and bare `px`/`rem` in `viewer/src/**` (the
only one that runs on every save); a build-time failure on an unresolved token
reference or an unreferenced token; and a test asserting computed WCAG contrast
ratios for the text/background pairs the design names, because that is what
catches a *token change* breaking the design. Then the OHIF extension module
(`getPanelModule`, consumed through the mode's `layoutTemplate` `rightPanels`),
the panel shell, and the state chip.

**WS3 — Local inference and the Draft function.** Point the gateway at Ollama
and make `Draft` produce a reviewable draft from clinician-supplied text.
Verified end to end by the plan: a real `POST` to
`http://127.0.0.1:11434/v1/chat/completions` with the gateway's own wire shape
returned a normal OpenAI envelope, so this is a **configuration change only**
(`MEDARX_GATEWAY_BASE_URL`) plus one `ALLOWED_MODELS` registry entry — and the
registry is a closed `frozenset` on purpose, so "unknown model" keeps meaning
"not known yet". Add the name; do not make the registry dynamic. Then the Draft
system prompt and function allowlist (both built **only** from the approved
payload), and a measured co-residency profile.

**WS4 — Orthanc and the DICOMweb data source.** Bring up the shipped
`infra/orthanc/` image — the plan reads `Dockerfile.orthanc` and expects no
change to it, and reads `orthanc.json` rather than trusting memory — then make
the **authentication and CORS decisions the config file explicitly defers to
Phase 2**, with `Authentication` set **from the environment, not from a tracked
file**, and CORS decided and verified from a browser at the real dev origin,
not assumed. Then the OHIF data source and a DICOMweb adapter that pulls
**only** allowlisted metadata into the copilot's scope. **No pixel data crosses
into any Medarx path** — that is the no-pixel-interpretation rule at the
transport level, and it is checkable because the adapter reads `/metadata` and
never `*/frames` or `*/rendered`. Plus a synthetic study, so the demo uses
fabricated data only. This is the **first DICOMweb client in the tree**.

**WS5 — Privacy drawer, draft review, and screen verification.** The two
screens that carry the product's claim, and the evidence that the claim holds
in a browser: the privacy details drawer rendering exactly what the API returns
and nothing more — including the **second** audit call the timeline requires
(`stages` is on the audit readback, not on the execution path, and Medarx
attesting to itself is what that avoids), the `J` empty-timeline case, the
prefix-not-results limitation, and `selected_model` legitimately absent on a
blocked request; the payload preview from WS1's preflight, with field-action
categories and hashes, masked values, no mapping store and no raw PHI; Draft
review with source findings beside an editable draft and a restrained text diff
that is never red/green alone, whose disposition line is `Draft accepted for
review`, not `Report completed`; both demo beats **in a browser**; and the
`Independent egress capture` section, which on a local route with no external
observer **does not render at all**.

### Sequencing and review

WS1, WS2, WS3 and WS4 all start immediately and run in parallel — none blocks
another. The only soft coupling is WS2's state chip, which can be built on two
states and take the third when WS1 lands. **WS5 starts when all four are
done**; it is the integration point and the whole-phase review runs across it.

Per-workstream review is earned in exactly two places, under the
`PROCESS-PHASE-2` exception: **WS1** (it establishes a security boundary — it
decides what a client can see, when a human's approval is required, and what is
transmitted) and **WS2** (its tokens and components are consumed by WS5 before
WS5 can be reviewed end to end; its acceptance gate is the contract between
tokens and components). **WS3, WS4 and WS5 get one review, together, at the
end**, with section 4's ten named invariant tests as the regression net.

**The one thing that must not slip:** WS1's preflight/send split is a contract
decision, and every day WS2's chip is built without it is a day of work that
will be redone. If it is to be cut, cut it **before** WS2 starts.

### Decisions Phase 2 needs from the owner, not from an agent

These are the plan's open questions. An agent should not silently pick a side.

1. **Does the preflight/send contract change get approved?** If it does not, the
   plan's stated fallback is that the UI ships **two** states and
   `.docs/medarx-ui-design.md` is amended to record that the third is deferred
   with a named owner and a phase. What is *not* acceptable is shipping a third
   state no API value can produce: a `Needs review` chip the system never
   evaluated is the exact failure mode this project exists to avoid, in the one
   place a user will look for it. The `POST .../executions` call is currently
   atomic — validate, transform, decide, call the provider, respond — so
   `approved` and `sent` are the same instant and there is no moment at which a
   human is being asked to review anything.
2. **The UI design contradicts the contract on the route control, and the
   contract wins.** `.docs/medarx-ui-design.md` says `Cloud` is "selectable";
   `contracts/openapi.yaml:238-241` says the policy mode is a **deployment
   configuration, not a per-request parameter**, and lines 1031-1032 say there
   is deliberately no `policy_mode` property. Implemented literally,
   "selectable" makes the UI an unauthenticated policy-mode selector —
   precisely what the contract exists to prevent. The route control must be
   **display-only**, reflecting `GET /v1/policy`. This is a security
   correction, not a wording one.
3. **The design's v1 screen list includes a Phase 3 deliverable.** It requires
   demonstrating that an *approved cloud request*'s independently captured
   bytes agree with the approved payload; the phasing table puts cloud and
   verifiable egress in **Phase 3**. Either Phase 2 builds a cloud route early
   (scope creep into a security-sensitive area) or that screen moves. Decide
   before WS5 starts, not during it.
4. **Orthanc remote-access authentication.** The shipped `orthanc.json` says so
   itself: in 1.10.1 remote access cannot be enabled without authentication,
   and an in-file plain-text user list is "a credential in a tracked file". Set
   it from the environment. (The three Orthanc traps the plan pins are now
   recorded in `infra/compose.yaml` and `infra/orthanc/orthanc.json` and do not
   need repeating here: `orthanc/orthanc` is a 404 on Docker Hub and
   `jodogne/orthanc:latest` ships no DICOMweb plugin, so neither may be pinned;
   the binary is `/usr/sbin/Orthanc`; and the config key is
   `RemoteAccessAllowed`, not `AllowRemoteAccess` — the wrong key is silently
   ignored and presents as a 401.)

### The other risks the plan raises, restated

- **The browser reaches Ollama and the boundary is gone.** The most severe risk
  and the least likely to be caught, because no test fails. Ollama is on the
  same host the viewer is served from. *Visible early:* WS3's first act is to
  check the listener's bind address and the viewer's dev origin and record both.
  If Ollama listens on `0.0.0.0`, that is a blocker, not a note.
- **Disk.** 13 GB free at 95% (section 9). A Bun/OHIF install is the single
  largest disk item in Phase 2 and **has not been measured**. Measure before
  `bun install`, not after.
- **RAM co-residency.** 15 GB total, ~5 GB available, a 2.5 GB resident model
  (not the ~3.4 GB the phase-1 design guessed — measured at `2497283049` bytes),
  plus FastAPI, Presidio, spaCy, PostgreSQL, Orthanc, the OHIF dev server and
  the test suite. WS3's gate is a measured `MemAvailable` during a full
  end-to-end run, not a design note.
- **The model cannot see pixels**, and that is mechanical rather than policy:
  `GET /api/tags` reports `capabilities: ["completion","tools"]` with no
  `vision`. Worth stating in the About panel.
- **Cold start mistaken for a hang** (14.6 s cold, ~1.1 s warm, against a 120 s
  default gateway timeout). The progress state belongs in WS2's shell, built
  against the real latency.

### Two Phase 1 loose ends carried forward

**The two known contract exceptions. Not verified.** The plan's task list names
the current contract's exceptions as examples that are satisfiable in schema but
that no component can currently produce. I did **not** re-derive either
exception name from the plan text, and the test file the original note pointed
at — `backend/tests/test_openapi_contract.py` — does hold a static sweep and
several executed checks, but when I listed its test names on 2026-09-28 I found
**no test matching that description**. Treat the list as reported, not verified,
and re-derive it from the plan before quoting it.

**Section 8's deferred items are all still deferred.** They were deliberately
not fixed by Tasks 18–20 (`task-18-20-report.md` §5, "Known and accepted, cited
not fixed"), and four of them have no owner. They are Phase 1's, not Phase 2's
scope, but they are not closed.

**The handoff-drift risk this very edit answers.** The Phase 2 plan's risk 9
says: *update `HANDOFF.md` as part of the first WS1 commit, and extend the
ledger, which this document's §8 item 8 records as stopping at Task 12 with no
owner.* The ledger is now extended (section 2) and this file is now refreshed.
Risk 9 is closed.

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
`evals/demo_beat2_blocked.py --case {unresolved,all_phi} --json`. **Both scripts
now exist** — Tasks 18 and 19 shipped them — and the original "neither script
exists yet" note is withdrawn. Both drive the **real composition root over the
real HTTP surface**, with the observer started seconds earlier on a real Docker
bridge and the second observer a `tcpdump` in the host network namespace; the
committed fixtures under `backend/tests/fixtures/capture/` are a *recorded* run
and neither beat touches them. `backend/README.md` §"The two demo beats" has
the runnable invocations.

**What the beats actually proved when they ran** (from
`task-18-20-report.md` §2, which I did not re-run — the two beats need Docker,
a bridge and a capture, and the numbers below are the report's, not a
measurement I took today):
- **Beat 1** — `PatientID: 774123` and a header carrying an MRN, accession
  number, institution name, study date and age in; a payload carrying
  `[REDACTED:PATIENT_ID]`, the header identifiers dropped, dates shifted to
  `20251014`, ages banded to `040-049`; the model replied
  `Findings: 7mm nodule.`; the captured outbound request was byte-identical at
  both observers; `agree = true`, 57 frames, 1 observer record, 1 captured
  request hit.
- **Beat 2** — `ZX-99-ALPHA` was refused with **422 at layer D.2**
  (`NER_UNRESOLVED`, `LEFTOVER_PATTERN_MATCH`); zero bytes at both observers
  (0 records, 0 captured bodies, 64 frames, `agree = true`); the receipt is the
  API's own 422 body, and `GET /v1/audit/records/req-beat2-blocked-0002` returns
  `final_disposition: blocked` for the same request id. `all_phi` is also
  blocked.

**The vacuity guard got stronger than this section describes.** Beat 2 sends a
**control** request first — the beat-1 input, approved, on the same observer,
bridge and capture — and four independent statements must hold before the
blocked request's silence counts. The blocking one is `records_complete`: the
observer's own `/healthz` count against the number of index entries on disk.
Delete the record and the index line and the two disagree, the guard falls, and
`test_deleting_the_observers_records_fails_the_vacuity_guard` says so. The
final review then closed a third silent empty: the silence clause now requires
the capture to have carried **TCP**, because a frame count alone is satisfied
by exactly the bridge chatter (ARP, mDNS, SSDP) a sniffer on the wrong
interface would produce. A capture with no frames, or one holding a single ARP
frame, is now **reported, not agreed** — see §2 and
`test_a_capture_with_no_frames_is_reported_so_a_dead_sniffer_is_visible`.

---

## 7. The final state expected

**This section used to describe the Phase 1 target. Phase 1 reached it.** Every
bullet below is now a statement about what is true, checked on 2026-09-28
rather than a thing still to do:

- **All 20 tasks implemented, with Tasks 18–20 and the final whole-branch review
  done.** ✔ Complete. The review ran across `efe567d..HEAD`; its 1 Critical/High
  and 1 Medium findings are both fixed and committed.
- **A clean working tree, every change committed as
  `feat(<scope>): <changes>`.** ✔ True. `git status --porcelain` is empty. The
  convention is `feat(<scope>): <changes>` for feature work; the two most recent
  commits are `chore:` and `docs:`, which is the right subject for what they
  were.
- **The full suite green across `PYTHONHASHSEED` 0, 1 and 42, run
  sequentially.** ✔ `task-18-20-report.md` §4 records **877 tests, 0 failures,
  0 errors, 0 skipped** at each of seeds 0, 1, 5 and 42, with `__pycache__`
  cleared before each. I re-ran the suite once on 2026-09-28 and read **877,
  0, 0, 0** from the JUnit XML myself. The evaluation harness is **37, 0, 0,
  0**, which I also re-measured today; `testpaths` excludes `evals/`, so it does
  not appear in the backend number. Keep running seed matrices **sequentially**,
  for the two reasons in sections 2 and 9.
- **`contracts/openapi.yaml` satisfiable.** **Not verified.** The two known
  exceptions are still named only in the plan, and the test the original note
  pointed at does not contain the check that note described — see section 5.
- **Both demo beats runnable end to end, with the blocked path provably
  transmitting zero bytes — measured from outside the Medarx process.** ✔ Both
  beats shipped and both ran live. See section 6.
- **The deferred items in section 8 either closed or still tracked with a named
  owner.** **Partly.** Two still have owners recorded in the plan: the Phase 2
  metadata question (`study_description`, `body_part_examined`,
  `referring_service`) is owned by Saurya Gur with a stated Phase 2 entry
  condition, and the "what does E record when it refuses" question is owned by
  Saurya Gur. The other four remain **unassigned**.

### The target from here is Phase 2

The acceptance criterion, from `medarx-product-spec.md` §14:

> **Clinician-supplied text becomes a reviewable draft with no pixel
> interpretation.**

Concretely and checkably, at the end of Phase 2: the OHIF extension panel is
built and the panel contract is enforced; the preflight/send split has landed in
the contract and the API; `Draft` runs against a local model and preserves
laterality, units, negation and uncertainty; a browser at the real dev origin
can read a synthetic study from Orthanc over DICOMweb; the privacy drawer
renders only what the API returns; the blocked path shows **zero observer
records and zero packets** in the browser, with the demo script exiting non-zero
if either is non-zero; and no pixel data has entered any Medarx request.

**Everything else the current target carries forward unchanged:** a clean working
tree, the seed matrix run sequentially, the contract-vocabulary-wins ruling,
and section 4's ten invariants as the regression net for the whole-phase
review. Full workstream detail is in section 5 and in `.docs/phase2-plan.md`.

---

## 8. Deferred and known-limited

Each of these was decided deliberately, not overlooked. All are recorded with
reasoning in `progress.md` or the per-task reports.

**Re-verified 2026-09-28: this section is still accurate, and none of these was
closed by Tasks 18–20.** `task-18-20-report.md` §5 lists them as "Known and
accepted, cited not fixed" and says so by instruction. I re-checked the named
test for every item that has one — items 1, 2, 3 and 4 — and each is still
present under the name given here. **No item has changed.** Only the two line
references below moved, and both are noted in place.

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
`mapping_store.py:134` (line 129 when this was written) says so and calls it
"a convenience for a single process, not a schema migration".
`medarx.audit.schema_init` says the same of itself
("Idempotent; not a migration"). `create_all` check-then-create is a TOCTOU race
on multi-worker startup — already mitigated by tolerating a concurrent creator.
*Owner:* the plan assigned the DDL ownership to the infrastructure task, and
Task 20 has now run — but the item is **not closed**. `infra/compose.yaml` says
so in its own comments rather than implying otherwise: `MappingStore` and
`schema_init` each still call `create_all`, and nothing migrates. *Owner:*
still unassigned.

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

**8. The ledger did not cover Tasks 13–17** (section 2). **CLOSED 2026-09-28.**
The commits, reports and tests existed all along; the chronological record did
not. It now does: `Ruling LEDGER-APPEND` backfilled all five entries from `git
log`, taking SHAs from the log rather than from recollection and treating the
per-task reports as claims to re-verify. `progress.md` is 250 lines and
`grep -c '^Task 1[3-7]:'` returns 5. *Owner:* discharged. The residual gap is
that `.superpowers/sdd/` is still gitignored, so none of it is in git.

---

## 9. Environment

All of the following was measured on this host. Re-measured 2026-09-28; figures
that moved are given as **was → now**.

- **Python 3.13.5**, **uv 0.11.17**, **Node v26.2.0**, **Docker 29.8.1** with
  **Compose v5.5.1**, **Bun 1.4.0**, **12 cores**. All unchanged. (Bun is new
  to this list and matters: Phase 2's design-token build step needs it, and the
  repo has no JS toolchain at all — `find . -name package.json` returns nothing.)
- **There is no `pip` on PATH** — `command -v pip` and `command -v pip3` both
  return nothing. This is why `bootstrap_ner_model.sh` deliberately does not use
  `python -m spacy download`: spaCy shells out to `pip`, and the `uv` shim
  intercepts it with "No virtual environment found". The script downloads the
  wheel and installs it with `uv pip install`.
- **No GPU** — no `nvidia-smi` on PATH.
- **RAM: 15 GiB total, ~4.3 GiB available at measurement time** (11 GiB used,
  6.0 GiB in buff/cache, 782 MiB free) — **was ~3.1 GiB available**. The
  plan's remembered budget is "15.3 GiB total / ~4.8 GiB available / zero swap
  / 12 cores". Availability moves with what is running, so treat it as a range;
  what matters for Phase 2 is that a 2.5 GB resident model plus Orthanc, the
  OHIF dev server and the test suite is tight, not that the number is exact.
- **Disk: 13 GB available on `/` (218G total, 194G used) — the filesystem is
  95% full. This is a large improvement: it was 3.9 GiB free at 99% full.**
  `docker image prune -a -f` during Task 20 reclaimed **10.01 GB**. Docker's
  accounting is now much healthier: 11 images totalling 1.236 GB with **438.3 MB
  reclaimable (35%)**, 16 local volumes (120.3 MB reclaimable), 487.4 MB of
  build cache with **201.8 MB reclaimable**. The reason Phase 1 pinned
  `postgres:18-alpine` and forbade pulling `:16`/`:17` still holds — a pull
  costs disk — but "reclaim Docker space first" is no longer the urgent
  pre-Task-20 action this section used to call for. The prune did remove
  `medarx-observer:latest`, `debian:bookworm-slim` and `postgres:18-alpine`,
  which were re-pulled afterwards; **build cache was left alone deliberately**,
  because rebuilding the observer image needs `python:3.13-slim-bookworm` and a
  network pull on a tight disk is where confusing failures come from.
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
  commit a clean stopping point. All **72** commits are a single logical change
  each; **67** carry a `feat(<scope>)` subject, three `docs(...)`/`docs:` and
  one `chore:`. The convention holds.
- **The venv must not live under `/tmp`** — `/tmp` is a tmpfs, so a venv there
  consumes RAM rather than disk. It belongs at `backend/.venv`.
- **`bash infra/verify_env.sh` is the preflight** (Task 20). It checks `docker
  version` is reachable, the `medarx` network resolves so a `br-` id can be
  derived, prints free disk, prints the remembered budget against a measured
  `MemAvailable`, checks the venv is not under `/tmp`, and validates
  `docker compose -f infra/compose.yaml config`. It is a script, not a pytest —
  **there is no test for it**, so it must be run by hand.
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
- **`backend/README.md`** — a tracked document (**1072 lines**, was 804).
  Setup and the two-step sync, then per-component sections for B, C, E, F, G,
  H, I, J, then "Phase 1 — running it" and "Known and accepted limitations".
  The Component I section is the best plain-language account of the two
  observers, and it was corrected in `eb4070c`. Note it is still **missing** the
  sections for A and D. The regulatory paragraph is now **in** it, under
  "What this software is, and is not".
- **`.docs/medarx-phase1-design.md`** — the approved design. **§3** is the
  component decomposition (A–J with responsibilities and what each
  communicates with); **§6 is the enforcement table** — seven rows, one per
  layer, transcribed rule-for-rule into `policy/decision_table.py`; §7 is the
  threat model; §9 holds the questions deferred to later phases.
- **`.docs/medarx-phase1-plan.md`** — the 20-task plan. 152 KB; all 20 task
  headings verified present. Every task has files, interfaces, numbered steps
  with the literal test code, the exact run command, and the expected
  pass/failure. §9 holds the open questions with named owners and Phase 2 entry
  conditions. **This is now the specification for work that is done, not for
  remaining work** — quote it for history, not for instructions.
- **`.docs/medarx-product-spec.md`** — the product spec. Source of the field
  storage policy, the contract's function vocabulary, and the relative-interval
  allowance.
- **`.docs/medarx-ui-design.md`** — the Phase 2 viewer design. **Out of scope for
  Phase 1.**
- **`.docs/phase2-plan.md`** — **the Phase 2 plan, and the thing to read before
  planning anything next.** 47 KB, written 2026-09-28, untracked. §0 records the
  corrections its author found in this handoff (it is where the "HANDOFF.md is
  stale" finding was first written down); then Scope, five Answers, the five
  workstreams, Sequencing, and ten Risks ordered by expected damage. Section 5
  above summarises it; **read the plan itself for the detail** — in particular
  Answer 2 (the preflight/send contract decision) and Answer 5 (what the
  frontend must never do).
- **`.superpowers/sdd/phase1-privacy-kernel/progress.md`** — a chronological
  ledger of every task, fix round and ruling, including several that correct
  earlier decisions. **250 lines (was 139), now current through Task 20 and the
  final review** — `Ruling LEDGER-APPEND` backfilled Tasks 13–17. Read the
  `Ruling *` lines especially — they record the reasoning that the code alone
  will not tell you.
- **`.superpowers/sdd/phase1-privacy-kernel/task-N-report.md`** — per-task
  implementation reports, including claims later corrected. Reports exist for
  Tasks 1, 2, 10, 11, 12, 13, 14, 15, a combined 16–17, and a combined **18–20**
  (briefs exist for 1–20). **Some earlier sections in those reports were left
  standing when they should have been corrected**; the ledger records the
  corrections where it has them, and where it does not, the report is wrong.
  Specific known cases: the
  Task 15 report's first round said "two unreachable rows" when the honest
  framing is three conditions across two rows (§8 item 4); the Task 9 report
  quoted 7/28 where the measurement is 5/28; and an earlier Task 10 claim that
  a specific policy reason "reaches the audit log" is false — `run_redaction`
  takes `Decision.wire_code` and drops the decision, so a receipt for an unknown
  policy version and one for an unimplemented mode are byte-identical.
  `task-16-17-report.md` still carries an **unfilled `<!-- SEED_MATRIX -->`
  placeholder** at line 343 (re-confirmed 2026-09-28), so its numbers are not
  usable. Treat every report as a claim to be re-verified against the code, not
  as a source of truth — the ledger and `task-18-20-report.md` supersede the
  earlier ones.
- **`.superpowers/sdd/` is gitignored.** None of the above is in git; if it
  matters, it needs to be copied somewhere that is not.

---

*Refreshed 2026-09-28 against `master` at `433cf6a`. Originally written
2026-09-28 against `phase1-privacy-kernel` at `47544a2`. Nothing in this file is
a substitute for running the command it describes.*
