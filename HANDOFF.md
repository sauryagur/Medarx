# Medarx — Handoff

Privacy-first AI copilot for radiology. Thesis: the outbound bytes are provably
the bytes a privacy pipeline approved, checked by a party other than the system.
Evidence must be able to fail. Fabricated data only; no real PHI.

Verified 2026-09-28 unless marked. Phase 2 changes after `433cf6a` are not
reflected in test counts or commit counts.

> Medarx is intended for research and demonstration. It performs administrative report assistance using clinician-supplied findings and authorized report text. It does not independently interpret medical images, make diagnostic or treatment recommendations, or autonomously submit clinical reports. Its regulatory classification has not been established, and it is not validated for clinical use.

The paragraph appears verbatim in `contracts/openapi.yaml` `info/description`,
the three `.docs/` files and `backend/README.md`. Never paraphrase it.

---

## 1. State

- **Phase 1: complete** (Tasks 1–20 + final whole-branch review; both findings fixed in `e2f20d5`, `d8c89aa`, doc fix `eb4070c`).
- **Phase 2 close-out (2026-10-13), HEAD `b2a38ee` at that time.**
- Working tree: Phase 2 changes uncommitted (`git status`). `HANDOFF.md` edits are this session's.
- **Tests (this session, 2026-09-28):** backend `cd backend && uv run pytest -q` = 973 pass, 0 fail, 17 skipped. Harness `cd backend && uv run pytest ../evals` = 37 pass. Viewer `cd viewer && bun run verify` = 47 pass, 0 fail, 78 expects; `tsc` (app + tools) exit 0; design token check clean; `bun run build` exit 0 (before the icon edit; build not re-run after).
- `viewer/` exists (Phase 2). `node_modules` not installed on this host; run `bun install` in `viewer/` before `tsc`/`eslint`. `bun test design src/api` runs without it (32/0).

### Phase 2 status

| WS | Status |
|---|---|
| WS1 contract/API (preflight/send split, `X-Scope`, stages, surface_refused) | **Built.** `api/routes_preflight.py`, `api/intake.py`, `pipeline.py` (`preflight`, `send_approved`, bounded in-memory `_pending`). Contract approval (§5 decision 1) is still the owner's. |
| WS2 design system + shell | Built; reduced-motion emission pinned by `viewer/design/reduced-motion.test.ts` (3 tests) |
| WS3 local inference (Draft, `gur-prime-2`) | **Proven.** Real-model e2e 17/17 (`MEDARX_LOCAL_MODEL_E2E=1`). Cold 31.7 s, warm 2.6 s. Payload byte-identical to approved. |
| WS4 Orthanc/DICOMweb | **Built, browser-checked.** Orthanc forwarder: `RemoteAccessAllowed: false` + socat on 127.0.0.1, no credential in tracked files. DICOMweb adapter `backend/src/medarx/dicomweb/` (`test_dicomweb_adapter.py`, 30 pass): one `GET …/metadata`, not wired into the pipeline, not checked against a live Orthanc response. OHIF loads the synthetic study (1 study, CT, 5 instances) on `/viewer/orthanc?StudyInstanceUIDs=…` through the same-origin dev proxy (`/pacs/dicom-web`). No custom data source file. |
| WS5 Draft UI | **Built, browser-checked on the OHIF route.** Draft, Prior Summary, Ask, privacy drawer, diff. Egress section absent. Draft unavailable on the OHIF route: policy fetch to `127.0.0.1:8000` fails closed (see §5 item 15). |

Phase 2 workstream 4 kernel change: `gur-prime-2` added to `ALLOWED_MODELS`
(`gur-prime-2:latest` still refused). `ModelGateway._parse` refuses empty
`choices[0].message.content`. No provider branch in the kernel
(`test_no_module_in_the_kernel_branches_on_a_provider`, AST walk).

### Gaps from the close-out, status now

- **C-5** keyboard pass: done on the harness tab. 45 tab presses, cycle repeats; every focused element has `outline: solid 2px`. Contrast min 7.11:1 (sampled, not exhaustive). Harness, not OHIF.
- **C-7** browser capture: done. Approved control body observed once (`6mm nodule`, 672 bytes). Blocked case added zero observer records; capture `request_bodies` 1; `ZX-99-ALPHA` 0 hits. The blocked case sends nothing by construction; the capture covers the session.
- **Reduced motion:** partial. `prefers-reduced-motion: reduce` → 0 running animations, transition 0s. The no-preference comparison is not observed (reset left `matches` true). The harness has no animations.
- **C-2** golden corpus + 10-output human review: Phase 3.
- **C-3** DICOMweb adapter artifacts: Phase 3 (superseded, see WS4).

---

## 2. Components

| # | Component | Location | Entry point |
|---|---|---|---|
| A | Allowlisted extraction (reads `PatientAge` unit; sub-year → months) | `extraction/payload_extractor.py`, `allowlists.py`, `study_context.py` | `extract`, `pipeline_for`, `ALLOWED_FIELDS` |
| B | DICOM de-identifier (PS3.15 Basic; no Clean Pixel Data). **Off request path.** | `deident/dicom_deidentifier.py`, `profiles.py` | `deidentify`, `make_uid` |
| C | Pseudonymization (keyed HMAC surrogates; per-patient date shift; separate mapping store) | `pseudonym/pseudonymize.py`, `derivation.py`, `date_shift.py`, `mapping_store.py` | `pseudonymize_payload`, `shift_dicom_date`, `MappingStore` |
| D.1 | Redaction layer 1: deterministic patterns | `redaction/layers.py` | `layer1_deterministic` |
| D.2 | Layer 2: Presidio + `en_core_web_sm`, non-guessing replacers | `redaction/ner.py`, `recognizers.py`, `replacers.py` | `layer2_ner`, `has_replacer` |
| D.3 | Layer 3: contract check, leftover scan, date re-read, hashes | `redaction/layers.py` | `run_redaction`, `_check_date` |
| — | Orchestration | `redaction/pipeline.py` | `run_privacy_kernel`, `RedactionOutcome` |
| E | Policy: approve/block, fail-closed, from §6 table (rows 1–7) | `policy/policy_engine.py`, `decision_table.py` | `PolicyEngine.decide`, `authorize_payload` |
| F | Model gateway: **sole egress**, OpenAI wire spec | `gateway/openai_gateway.py`, `model_registry.py` | `verify_approved_payload` → `ApprovedSend` → `send` |
| G | Audit log: keyed hash chain, field allowlist, tombstones | `audit/audit_log.py`, `hash_chain.py`, `code_table.py`, `queries.py`, `schema_init.py` | `append`, `events`, `verify_chain`, `ALLOWED_AUDIT_FIELDS` |
| H | Corpus + harness (6 synthetic cases; 28 clean sentences) | `evals/` | `run_eval.py`, `measure_end_to_end` |
| I | Egress: two observers (in-process recorder + host-netns `tcpdump`), byte-compare | `infra/observers/observer.py`, `infra/capture/agreement.py`, `start_capture.sh` | `check_agreement`, `compare_bytes_to_payload` |
| J | API: `X-Scope` authz, policy inspection, audit readback, approval; composition root | `api/app.py`, `wiring.py`, `authz.py`, `middleware.py`, `surface.py`, `schemas.py`, `routes_*.py` | `create_app`, `build_pipeline`, `Pipeline.run(request_id, request)` |

Request path: J → A → C → D.1–D.3 → E → F. `Pipeline.run` **returns** on a
privacy block (no raise); the API renders 422. G is written at event level only.
H, I and B are outside the runtime path.

Contract: `contracts/openapi.yaml`. 5 paths, `ActionCode` = 24 members (closed),
`Layer` = `J, A, C, D.1, D.2, D.3, E, F` (no bare `D`), `FunctionName` = `Draft`, `Prior Summary`, `Ask`. Contract wins over code (`Ruling CONTRACT-VOCABULARY-WINS`).

### Deliberate departures from the design

1. D is D.1–D.3. Policy is E. No D.4.
2. `Pipeline.run(request_id, request)`. The request id is in a header; the body schema is `additionalProperties: false`.
3. `Layer` gained `C` so pseudonymization refusals aren't misattributed to D.1.
4. Agreement code is in Task 16 (test imports it).
5. **Gateway default is the local observer**, not OpenRouter. The cloud path is untested.
6. Per-task review was a misjudgement (`Ruling PROCESS-PHASE-2`). Review once across the branch. Exceptions: security boundaries, and anything consumed before end-to-end review.

---

## 3. Invariants (each must go red if broken)

Check the named test after changing any mechanism below.

1. **Block from absent replacer, never from a score.** `test_redaction_layers.py::test_an_entity_with_no_replacer_is_unresolved_at_any_score`, `::test_a_replaceable_hit_below_the_threshold_is_blocked_not_guessed_at`.
2. **Gateway sends only an `ApprovedSend`.** `test_gateway.py::test_send_refuses_anything_that_is_not_an_approved_send`, `::test_an_approved_send_cannot_be_built_by_hand`, `::test_a_token_cannot_be_re_pointed_with_dataclasses_replace`, `::test_a_token_cannot_be_cloned_by_any_copying_route`. Known language limit: `object.__setattr__` (measured, not fixed).
3. **Audit chain keyed; purge = keyed tombstone.** `test_audit.py::test_the_log_under_a_different_key_does_not_verify`, `::test_deleting_the_last_row_is_detected_by_the_head_anchor`, `::test_a_keyless_writer_cannot_hide_a_rewrite_behind_a_purge_flag`.
4. **`Layer` closed set, checked per declaration site.** `test_openapi_contract.py::test_the_code_layer_set_equals_the_contract_enum`, `::test_the_layer_sweep_finds_every_declaration_site`.
5. **Emitted `ActionCode` ∈ contract enum.** `test_openapi_contract.py::test_every_emitted_action_code_is_in_the_contract`.
6. **403 ≠ 422 by status alone.** `AuthzError` and `ProviderError` are outside `MedarxError` (`errors.py:138`). `test_api.py::test_a_caller_can_tell_403_from_422_by_status_code_alone`.
7. **422 means nothing sent, observed at transport.** `test_egress_e2e.py::test_a_422_reached_neither_observer`, `test_block_conditions.py::test_row4_a_422_sends_nothing`.
8. **Audit field set hand-written.** `audit_log.py:112` literal `frozenset`. `test_audit.py::test_allowed_audit_fields_exclude_anything_could_hold_a_value`, `::test_a_record_carrying_a_field_outside_the_allowlist_is_refused`.
9. **Relative intervals ("6 weeks") pass unchanged.** Closed shape list. `test_redaction_layers.py::test_a_relative_interval_survives_a_report_unchanged`, `test_ner_recognizers.py::test_a_relative_interval_is_recognised_by_its_shape`.
10. **Vocabulary is the contract's** (`Prior Summary`, not `prior_summary`). `test_audit.py::test_every_contract_function_name_is_auditable`.

Invariants 1–10: 73 tests after parametrisation, 0 failures (`task-18-20-report.md` §6a).

---

## 4. Demo beats

Run: `evals/demo_beat1_approved.py --json`; `evals/demo_beat2_blocked.py --case {unresolved,all_phi} --json`. Real composition root, real HTTP, real Docker bridge, `tcpdump` in host netns.

- **Beat 1 (approved):** identifiers in → payload out (`[REDACTED:PATIENT_ID]`, dates shifted, ages banded) → model replies → outbound bytes identical at both observers, `agree = true`.
- **Beat 2 (blocked):** `ZX-99-ALPHA` → 422 at D.2 (`NER_UNRESOLVED`, `LEFTOVER_PATTERN_MATCH`). 0 records, 0 captured bodies, `agree = true`. Audit `final_disposition: blocked`.
- **Vacuity guard:** Beat 2 sends a control request first. Silence counts only if the control was observed, `records_complete` holds (`/healthz` count = index entries), and the capture carried TCP. A dead sniffer is reported, not agreed. `start_capture.sh stop` exits non-zero on zero frames or dropped packets.
- Negative direction: delete the observer's record → `agree=False`. Length-preserving payload substitution with re-hashed index → still refuses (leak shape).

---

## 5. Deferred and known limits (none closed)

1. **`PATIENT_ID` unreachable on report spellings** ("Patient ID:" etc.); only `PatientID:` reaches it. **Detection gap.** The "0/15" figure is a *boundary* result, not recall: 4 of 15 are stopped only by layer 3. Owner: unassigned. Characterisation test goes red when fixed; intended.
2. **5 of 28 clean sentences have clinical words masked** (`CT`, `Nodule`, `Scan`, `Pulmonary`, `Pleural`, `HU`). Visible and recoverable. `test_redaction_layers.py::test_the_rate_of_clinical_words_masked_in_approved_payloads`. Owner: unassigned.
3. **No patient reference → per-study date shift**; intervals across studies not preserved. Owner: unassigned.
4. **Unreachable through the surface:** row 3 (D.1), row 5's unshifted-date half, row 6 (E), `UNKNOWN_DICOM_ATTRIBUTE`. D.3 is reachable but never alone. Owner: unassigned.
5. **`MappingStore` and `schema_init` use `create_all`, no migration.** TOCTOU on multi-worker start. Owner: unassigned.
6. **Audit readback has no scope filter** (scoping would need a forbidden field). Owner: unassigned.
7. **Whole-DB deletion of audit log undetectable without external anchor.** Owner: Phase 6.
8. ~~Ledger gap Tasks 13–17~~ **Closed.** `progress.md` covers them. `.superpowers/sdd/` is gitignored.
9. **Local model + full stack don't fit in RAM.** Model ~2.5 GB on disk, ~3.0 GB resident. Zero swap. With model resident ~650 MB available; unloaded ~3.7 GB. An OOM kills whatever else is resident. A model-server outage is `ProviderTransportError`, not a 422. Owner: deployment (cap model size, add swap, or move hardware).
10. **One-observer egress against a real model.** The tcpdump half is independent. The pairing is weaker. `check_agreement` returns `agree: false, observer_record_count: 0`, asserted by `test_local_model_e2e.py::test_the_two_observer_rule_refuses_when_only_one_observer_saw_the_request`. Owner: Phase 3 for cloud.
11. **Kernel does not judge output.** Empty answer refused (`ProviderResponseError`). Textual refusal returned unchanged. Owner: Phase 4.
12. **`Prior Summary` and `Ask` reachable through API but not exercised on the local model.** Containment is the client only. Owner: Phase 5 and viewer.
13. **Orthanc logs not covered by `medarx.logging_filter`.** Owner: unassigned.
14. **`MEDARX_AUDIT_KEY` is required by the `orthanc` compose profile.** Owner: deployment.
15. **No Medarx API proxy on the OHIF route.** `readPolicy` uses `MEDARX_API_BASE`, default `http://127.0.0.1:8000` (`viewer/ohif/policyRoute.ts:42`). Nothing listens there, so the draft path fails closed. The Vite `/v1` proxy is dev-only (`viewer/vite.config.ts` → `:8765`). Owner: unassigned. Decide between a same-origin proxy and CORS.
16. **Viewer `dist/` collides with the OHIF build.** OHIF's `writePluginImportsFile.js` copies extension `dist/` into its own output; `viewer/dist/index.html` conflicts with OHIF's `index.html` (rspack "Conflict"). Running `bun run build` while the OHIF dev server runs breaks it. Recovery: `rm -rf viewer/dist`.
17. **OHIF checkout is patched outside this repo.** `viewer/ohif/mount.sh` edits `platform/app/pluginConfig.json` and `.webpack/resolveConfig.js` (includes a `../../design/tokens$` alias) in `/home/saury/Projects/ohif-viewers` (`v3.13.10`). Not in git here.
18. **Panel icon is a placeholder.** `tab-studies` is used; `chat` is not in OHIF's icon set and rendered "Missing icon".
19. **Preflight post-404 readback.** `GET /v1/audit/records/<preflight id>` returns 404 by design; the UI maps it to `missing`. Harmless.
20. **Ollama loopback residual.** `127.0.0.1:11434` is loopback-only, but a same-host browser can reach localhost.
21. **Phase 3:** cloud screen; independent egress capture for the cloud path; C-2 golden corpus. **Phase 4:** kernel output judgment (§5 item 11).

**Phase 2 decisions the owner must make (plan Answers; status not recorded):**
1. Approve the preflight/send contract change (WS1). Without it, the UI ships two chip states. A third "Needs review" state no API value can produce is not acceptable. `POST …/executions` is currently atomic.
2. Route control is **display-only**, reflecting `GET /v1/policy`. `Cloud` "selectable" in `.docs/medarx-ui-design.md` contradicts `contracts/openapi.yaml:238-241` and `:1031-1032`. This is a security correction.
3. Cloud screen (approved cloud request's egress bytes) is Phase 3. Decide before WS5 starts.
4. Orthanc remote-access auth: decided. `RemoteAccessAllowed: false`, socat forwarder on 127.0.0.1, no credential in tracked files.

Other Phase 2 risks: browser reaching Ollama directly (check listener bind address; `0.0.0.0` is a blocker). Model cannot see pixels (`capabilities: ["completion","tools"]`); say so in the About panel. Cold start 14.6 s vs warm ~1.1 s against a 120 s gateway timeout; show progress.

---

## 6. Environment

- Python 3.13.5, uv 0.11.17, Node 26.2.0, Bun 1.4.0, Docker 29.8.1 / Compose 5.5.1, 12 cores, no GPU, **no `pip` on PATH**.
- RAM 15 GiB, zero swap (see §5.9). Disk `/` 13 GB free at 95%.
- **After any `uv sync`:** run `bash src/medarx/scripts/bootstrap_ner_model.sh` from `backend/`. Otherwise `OSError: [E050] Can't find model 'en_core_web_sm'` appears from some recogniser. Installed: 3.8.0.
- **Clear `__pycache__` before any run after a file change.** Stale `.pyc` caused 23 spurious failures twice.
- **Run seed matrices sequentially.** Two reasons: `.pyc` above, and `test_egress_e2e.py` creates network `medarx-e2e` with `check=False` and removes it in teardown. Concurrent runs give 6 errors (`docker run` exit 125, "network medarx-e2e not found"). Seen once in Tasks 18–20, not reproduced; leftover containers were the suspected cause, undiagnosed. Seeds 0, 1, 5, 42 all clean (877/0).
- **Captures on a Docker bridge:** a third container on the bridge sees nothing. Use `--network host --cap-add=NET_RAW` on the project's `br-*` interface, discovered at run time: `docker network inspect -f '{{.Id}}' <net> | cut -c1-12`. Never hard-code `br-…`.
- **tcpdump:** always `-w file.pcap`, read back with `-r`. `-A | tee` under `timeout` loses packets to buffering. Dropped packets fail `stop`.
- **Venv at `backend/.venv`, not `/tmp`** (tmpfs uses RAM).
- Preflight: `bash infra/verify_env.sh`. Manual only; no test.
- Only `config.py` reads env in the kernel. The observer process is the exception (documented in its docstring).
- Commit early. Process restarts interrupted work five times. Convention: `feat(<scope>): <change>`.

---

## 7. Where the detail lives

- `contracts/openapi.yaml` — normative. Wins over code.
- `backend/README.md` — per-component sections B, C, E–J; running; limitations. **Missing A and D sections.**
- `.docs/medarx-phase1-design.md` — §3 decomposition, §6 enforcement table, §7 threat model, §9 deferred questions.
- `.docs/medarx-phase1-plan.md` — 20-task plan. History only.
- `.docs/medarx-product-spec.md` — field storage policy, function vocabulary, relative-interval allowance.
- `.docs/medarx-ui-design.md` — Phase 2 viewer design. Contains the `Cloud` error in §5.2.
- `.docs/phase2-plan.md` — **read before planning.** Untracked.
- `.superpowers/sdd/phase1-privacy-kernel/progress.md` — ledger; read `Ruling *` lines. Gitignored.
- `task-18-20-report.md` — latest report. Older reports contain known wrong figures (Task 9 7/28 vs 5/28; Task 10 "reaches the audit log" is false; `task-16-17-report.md` has an unfilled `<!-- SEED_MATRIX -->` at line 343). Re-verify before quoting.
- `.superpowers/sdd/phase1-privacy-kernel/phase2-review.md` — review text; was reconstructed after truncation on 2026-10-13.
- `HANDOFF.md` — tracked (since `433cf6a`).

Not verified: WS1 contract approval (owner); DICOMweb adapter against a live Orthanc response; OHIF console-level CORS (only resource origins were checked: one cross-origin request, to `:8000`, which fails closed).
