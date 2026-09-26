# Medarx — backend

The privacy kernel: allowlisted extraction, pseudonymization, four-layer
redaction, and a fail-closed policy engine, in front of a model gateway.

## Setup

Run these four commands in order from this directory (`backend/`):

```bash
uv sync
bash src/medarx/scripts/bootstrap_ner_model.sh
MEDARX_AUDIT_KEY=... uv run python -m medarx.audit.schema_init
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
3. **`MEDARX_AUDIT_KEY=... uv run python -m medarx.audit.schema_init`** —
   initialize the audit schema: the `audit_event`, `pseudonym_study` and
   `pseudonym_patient` tables.
4. **`uv run pytest`** — run the test suite.

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
| `MEDARX_AUDIT_KEY` | *(none — must be supplied)* |
| `MEDARX_AUDIT_RETENTION_DAYS` | `2555` |
| `MEDARX_GATEWAY_BASE_URL` | `http://127.0.0.1:8080/v1` |
| `MEDARX_GATEWAY_MODEL` | `medarx-demo-model` |
| `MEDARX_GATEWAY_API_KEY` | `medarx-demo-key` |
| `MEDARX_GATEWAY_TIMEOUT_S` | `120.0` |
| `MEDARX_MAX_BODY_BYTES` | `1048576` |
