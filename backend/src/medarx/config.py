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

__all__ = ["Settings", "load_settings", "require_date_order"]


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

    # -- Dates -------------------------------------------------------------
    # The day and month order of a numeric date such as `03/04/2026`, which is
    # ambiguous in the text: read one way it is 3 April, the other it is
    # 4 March, and the two are months apart. Unset is the deliberate state, not
    # a default to be guessed at — a deployment that has not decided refuses
    # those dates rather than guessing, and `require_date_order` is the startup
    # check that makes the refusal deliberate. See
    # `medarx.redaction.replacers` for what the kernel does with each value.
    date_order: Literal["MDY", "DMY"] | None = None

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
    # Empty by default: the Phase 1 observer requires no authentication, and a
    # credential baked into source is the kind of thing that gets copied into a
    # real deployment. The gateway client MUST omit the Authorization header
    # entirely when this is empty rather than sending an empty one.
    gateway_api_key: str = ""
    gateway_timeout_s: float = 120.0
    # -- Request intake ----------------------------------------------------
    max_body_bytes: int = 1_048_576


def load_settings() -> Settings:
    """Construct the process settings. The only place the environment is read."""
    return Settings()


def require_date_order(settings: Settings) -> None:
    """Raise unless the deployment has declared its numeric date order.

    The startup guard for the setting. The kernel's behaviour without it is
    already fail-closed — an ambiguous numeric date is refused rather than
    guessed — but "refused" is a *per-request* block that reads, to whoever
    sees the receipt, like a coverage gap. Declaring the order is a
    configuration decision someone makes once, deliberately, and this is where
    they are told they have not made it.

    It cannot be a field validator. `Settings` is constructed by
    `load_settings()` from the environment inside tests that never touch a
    numeric date, so a hard requirement would stop the process from starting at
    all over a setting only one code path reads. `None` is therefore a legal
    state of the object and a refusal of the *deployment*.

    Raises `ValueError` naming the setting, so an application entry point can
    turn it into whatever its startup failure mode is.
    """
    if settings.date_order is None:
        raise ValueError(
            "MEDARX_DATE_ORDER is unset: a numeric date such as 03/04/2026 "
            "cannot be read without it. Set it to 'MDY' or 'DMY' to declare "
            "which order your reports are written in. Until then the kernel "
            "refuses ambiguous numeric dates rather than guessing."
        )
