"""Component J's authorization surface: the synthetic Phase 1 scope.

**`X-Scope` is a demonstration input, not authentication.** The contract declares
`security: []` and no security scheme, and the design defers roles and per-user
permissions to Phase 6. The header models an authorization *boundary* — a caller
is scoped to a study and to a function, and a request outside that scope is
refused — and nothing more. Anyone who can reach this server can present any
scope they like; `tests/test_api.py::test_the_scope_header_is_not_an_authentication_mechanism`
demonstrates exactly that, so a future reader cannot mistake it for a security
control.

**The grammar, which is the whole of what is understood.** A comma-separated
list of tokens, each either `scope:study:<reference>` or
`scope:function:<FunctionName>`, where the function name is the contract's
spelling. Anything else grants nothing. That is deliberately fail-closed: a token
this module cannot read is not an error to be reported and then ignored, it is a
grant it did not make. An absent header, an empty header and a header full of
unreadable tokens are therefore the same case — a caller that named no scope
holds none.

**A refusal is `403` and is deliberately not a privacy block.** `AuthzError` is
outside the `MedarxError` taxonomy and carries no layer and no action codes, so
the handler that renders a `BlockReceipt` for a `MedarxError` cannot catch it by
accident. A caller tells the two apart by status code alone, without parsing the
body — which is the design's own requirement and the reason the split is
structural rather than a status-code choice made at the call site.

**Where the scope comes from.** The `X-Scope` request header, never the body.
`ExecutionRequest` has no scope property and the schema is closed, so a body
cannot name a scope even if a caller wanted it to; the header was chosen because
it is still available when the body is unusable, which is exactly when a refusal
is most worth reporting.
"""

from __future__ import annotations

from collections.abc import Iterable

from medarx.errors import AuthzError

__all__ = [
    "AuthzError",
    "Authorizer",
    "REASON_FUNCTION_NOT_PERMITTED",
    "REASON_NO_SCOPE",
    "REASON_STUDY_SCOPE_UNAUTHORIZED",
    "SCOPE_FUNCTION_PREFIX",
    "SCOPE_HEADER",
    "SCOPE_STUDY_PREFIX",
    "parse_scopes",
]

#: The three causes a refusal can have, attached to the `AuthzError` as
#: `.reason`. A closed vocabulary because `medarx.api.surface` maps it to an
#: action code, and a code that does not describe the refusal is a false record
#: in a permanent log.
REASON_NO_SCOPE = "no_scope"
REASON_STUDY_SCOPE_UNAUTHORIZED = "study_scope_unauthorized"
REASON_FUNCTION_NOT_PERMITTED = "function_not_permitted"

#: The header the caller presents its scopes in. Named once so the route, the
#: docstrings and the tests cannot drift to two spellings.
SCOPE_HEADER = "X-Scope"

#: The two token prefixes of the Phase 1 scope grammar.
SCOPE_STUDY_PREFIX = "scope:study:"
SCOPE_FUNCTION_PREFIX = "scope:function:"

#: The separator between tokens. A comma and optional surrounding whitespace; a
#: semicolon is accepted too, because a caller writing a header by hand will
#: eventually try one, and refusing it teaches nothing.
_SEPARATORS = ",;"


def _refuse(reason: str, message: str) -> AuthzError:
    """An `AuthzError` carrying the cause, for the record that will follow it.

    `AuthzError` is a bare `Exception` and stays one — it must not grow a
    `layer` or a `status`, or the handler that renders a `BlockReceipt` for a
    `MedarxError` could one day catch it. A single `reason` string is the only
    thing attached, and it names *why* rather than what to do about it.
    """
    error = AuthzError(message)
    error.reason = reason
    return error


def parse_scopes(raw: str | None) -> frozenset[tuple[str, str]]:
    """The `(kind, value)` grants in an `X-Scope` header.

    `kind` is `"study"` or `"function"`; `value` is the rest of the token. A
    token that is neither is **dropped**, not refused: the header is not a
    contract parameter, so there is no schema to violate, and a header carrying
    one unusable token alongside a usable one should still grant what it
    legitimately names. A header carrying nothing usable grants nothing, and the
    caller is refused at the next line.
    """
    grants: set[tuple[str, str]] = set()
    if not raw:
        return frozenset()
    for token in raw.replace(";", ",").split(","):
        stripped = token.strip()
        if stripped.startswith(SCOPE_STUDY_PREFIX):
            value = stripped[len(SCOPE_STUDY_PREFIX):].strip()
            if value:
                grants.add(("study", value))
        elif stripped.startswith(SCOPE_FUNCTION_PREFIX):
            value = stripped[len(SCOPE_FUNCTION_PREFIX):].strip()
            if value:
                grants.add(("function", value))
    return frozenset(grants)


class Authorizer:
    """The synthetic scope check, with no state of its own.

    Stateless on purpose: one instance serves every request, so there is nothing
    to leak between callers and nothing to reset.
    """

    def require(self, request_id: str, function: str, study_reference: str,
                caller_scopes: Iterable[str] | None) -> None:
        """Raise `AuthzError` unless this caller may run `function` on that study.

        The function is checked first. It is the cheaper half, and a caller
        outside the study's scope is outside it for every function, so checking
        the function first refuses the broader case first and never names a study
        the caller was not entitled to have.

        `caller_scopes` is the already-split grant set from `parse_scopes`; it is
        passed in rather than re-parsed here so there is one parser.
        """
        grants = frozenset(caller_scopes or ())
        if not grants:
            raise _refuse(
                REASON_NO_SCOPE,
                f"request {request_id!r} presented no scope. {SCOPE_HEADER} names "
                "the scopes the caller holds; an absent, empty or unreadable "
                "header grants none, and a scope is an authorization boundary "
                "this Phase 1 API models rather than one it authenticates.",
            )
        if ("function", function) not in grants:
            raise _refuse(
                REASON_FUNCTION_NOT_PERMITTED,
                f"request {request_id!r} is not permitted to run function "
                f"{function!r} in the scope it presented",
            )
        if ("study", study_reference) not in grants:
            raise _refuse(
                REASON_STUDY_SCOPE_UNAUTHORIZED,
                f"request {request_id!r} names study {study_reference!r}, which "
                "is outside the study scope the caller presented",
            )

    def require_any_scope(self, request_id: str,
                          caller_scopes: Iterable[str] | None) -> None:
        """Raise `AuthzError` unless the caller presented any scope at all.

        For the read-only routes — the audit readback and the approval endpoint —
        which the contract puts behind the same `403` but for which there is no
        function and no study to check.

        **What this does not do, and cannot.** It does not filter a readback by
        study. It could not: the audit record has no study field, and the
        storage policy forbids adding one, because the log is required never to
        hold a study identifier. So Phase 1's readback is *authorized* and
        *unfiltered*, and the limit is a privacy decision rather than an omission
        — see `medarx.audit.audit_log.ALLOWED_AUDIT_FIELDS` and
        `tests/test_api.py::test_the_audit_readback_cannot_filter_by_study_because_
        the_record_cannot_carry_one`.
        """
        if not frozenset(caller_scopes or ()):
            raise _refuse(
                REASON_NO_SCOPE,
                f"request {request_id!r} presented no scope. {SCOPE_HEADER} names "
                "the scopes the caller holds; an absent, empty or unreadable "
                "header grants none.",
            )
