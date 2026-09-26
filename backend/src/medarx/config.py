"""The single source of configuration for the Medarx privacy kernel.

Every tunable lives here. Every other module takes the `Settings` object that
`load_settings()` returns; **no module other than this one may read
`os.environ` or the process environment directly.** The policy engine, the
redaction stages, the audit store and the gateway client all accept `Settings`
as a parameter, which is what makes them testable and what lets the fail-closed
defaults be asserted in one place.
"""

from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict

__all__ = ["Settings", "load_settings"]


class Settings(BaseSettings):
    """Immutable, environment-overridable settings.

    Environment variables are read with the `MEDARX_` prefix, e.g.
    `MEDARX_POLICY_VERSION` or `MEDARX_GATEWAY_BASE_URL`.
    """

    model_config = SettingsConfigDict(env_prefix="MEDARX_", frozen=True)

    # -- Policy ------------------------------------------------------------
    policy_version: str = "medarx-policy-1.0.0"
    policy_mode: Literal["strict_local", "cloud"] = "cloud"

    # -- Redaction ---------------------------------------------------------
    ner_score_threshold: float = 0.50
    ner_text_limit: int = 200_000

    # -- DICOM pseudonymization -------------------------------------------
    dicom_uid_root: str = "1.2.826.0.1.3680043.10.1338."

    # -- Audit -------------------------------------------------------------
    # No default secret: the operator must supply MEDARX_AUDIT_KEY. The empty
    # default exists only so that a bare `Settings()` stays constructible in
    # tests; audit-writing code paths must fail closed on an empty key.
    audit_key: str = ""
    audit_retention_days: int = 2555

    # -- Model gateway -----------------------------------------------------
    gateway_base_url: str = "http://127.0.0.1:8080/v1"
    gateway_model: str = "medarx-demo-model"
    gateway_api_key: str = "medarx-demo-key"
    gateway_timeout_s: float = 120.0
    # -- Request intake ----------------------------------------------------
    max_body_bytes: int = 1_048_576


def load_settings() -> Settings:
    """Construct the process settings. The only place the environment is read."""
    return Settings()
