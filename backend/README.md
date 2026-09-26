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
