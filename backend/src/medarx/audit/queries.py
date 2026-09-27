"""Component G's readback: the only way anything reads the audit log.

**What a reader is shown is the record, and the record is the storage policy.**
`events_for_request` and `search_records` return `AuditEvent` objects and
nothing else — no joined row, no convenience projection, no field the storage
policy does not hold. That is not a stylistic choice: an audit readback whose
own idea of a record is wider than what was written is a second, unauthenticated
place for a value to appear, and an auditor cannot tell which of the two they
are looking at.

**Two answers are computed on read, and they are answers rather than fields.**

- `stages` is the pipeline prefix derived from the record's blocking `layer`
  (`AuditLog.stages_for`). It is deliberately not a column, not a model field,
  and not in the chain body: a stored copy could disagree with the record it is
  computed from, and a tamper-evident table holding an unauthenticated column
  is worse than not having one. The record carries the fact; the projection is
  the reader's arithmetic.
- `chain_verified` is `chain_status`'s answer, and it is deliberately *not* on
  the record. A record carrying a "verified" field would be making a claim about
  itself that a rewrite could not invalidate, because the rewrite would rewrite
  the claim along with it. Rewriting a row changes the values the readback
  returns — visibly, in the fields the storage policy holds — and flips this
  answer to `false`; what no rewrite can do is make the record *say* it is
  verified, because nothing in it says so.

**The record speaks the contract's vocabulary all the way out.** `function` is
stored as the contract spells it, and the `function` filter is the same string;
this module introduces no internal spelling of its own, and a caller passing one
is refused rather than matched.

**Configuration.** Nothing here reads the environment and nothing here needs to:
the audit key is already held by the `AuditLog` it is handed, and a log built
without one cannot be built at all — `AuditLog.__init__` raises
`AuditKeyRequired`, which is deliberately outside the `MedarxError` taxonomy so
a missing key is never rendered as a 422 privacy block. A query therefore has no
way to turn a misconfiguration into a refusal about a patient's data.

**What this module refuses to be.** It is the readback, not the storage policy:
`append` and the shape gates are the only write path, and a caller that wants a
different field added asks `medarx.audit.audit_log` to admit it, not this
module.
"""

from __future__ import annotations

from datetime import datetime
from typing import get_args

from medarx.audit.audit_log import AuditLog
from medarx.models import AuditEvent, FinalDisposition, FunctionName

__all__ = [
    "DEFAULT_LIMIT",
    "MAX_LIMIT",
    "MIN_LIMIT",
    "chain_status",
    "events_for_request",
    "search_records",
]


#: The bounds on `LimitQueryParam` in `contracts/openapi.yaml`, stated here
#: because this is where they are enforced. `tests/test_audit_queries.py` reads
#: the contract and asserts these three against it, so a contract change that
#: does not reach this module fails rather than being absorbed.
MIN_LIMIT: int = 1
MAX_LIMIT: int = 500
DEFAULT_LIMIT: int = 100

#: The contract's two closed filter vocabularies, taken from the model rather
#: than written out: `FunctionName` and `FinalDisposition` are already pinned to
#: the contract's enums by the suite, so restating them here would be a third
#: copy for a rename to miss.
_FUNCTIONS = get_args(FunctionName)
_DISPOSITIONS = get_args(FinalDisposition)


def events_for_request(log: AuditLog, request_id: str) -> list[AuditEvent]:
    """Every stored record for `request_id`, oldest first.

    The per-request readback, `GET /v1/audit/records/{request_id}`. A request
    that produced a refusal, an approval and a human sign-off has three records
    and all three are returned: a record is never merged, summarised, or dropped
    because a later one for the same request exists. A refusal that leaves no
    trace is not evidence, so the trace is whatever was written.

    A request whose records have been purged returns `[]` — the retention purge
    deletes the row and leaves a tombstone carrying only the chain position, so
    there is nothing to rebuild and nothing is invented in its place.
    """
    return log.get(request_id)


def search_records(log: AuditLog, *, request_id: str | None = None,
                   function: str | None = None,
                   disposition: str | None = None,
                   since: datetime | None = None,
                   limit: int = DEFAULT_LIMIT) -> list[AuditEvent]:
    """The filtered page, oldest first: the collection readback.

    The keyword names are the contract's parameter names for
    `GET /v1/audit/records` — `request_id`, `function`, `disposition`, `since`,
    `limit` — and the bounds on `limit` are that parameter's bounds, enforced
    here so the route does not have to restate them.

    A filter value outside its closed enum is **refused**, not treated as
    unmatched. The difference matters: an empty page is a true statement about a
    question that was asked, and a typo in a query string would otherwise look
    exactly like a request with no records.

    `limit` is a page size, not a filter: the chain walk behind
    `chain_verified` always covers the whole log whatever page was asked for, so
    a caller cannot verify a page and think it verified the log.
    """
    if function is not None and function not in _FUNCTIONS:
        raise ValueError(
            f"function={function!r} is not a contract function name: expected "
            f"one of {', '.join(repr(name) for name in _FUNCTIONS)}. The "
            f"internal snake_case spelling is not a second way to ask this "
            f"question; the record stores the contract's own vocabulary."
        )
    if disposition is not None and disposition not in _DISPOSITIONS:
        raise ValueError(
            f"disposition={disposition!r} is not a contract final disposition: "
            f"expected one of "
            f"{', '.join(repr(name) for name in _DISPOSITIONS)}"
        )
    if since is not None and (since.tzinfo is None or since.utcoffset() is None):
        raise ValueError(
            f"since={since.isoformat()!r} carries no UTC offset: a naive "
            f"instant has two readings, and which one is the page's boundary "
            f"would be a guess made silently. RFC 3339 puts the offset on the "
            f"value."
        )
    if not isinstance(limit, int) or isinstance(limit, bool):
        raise ValueError(f"limit must be an integer, got {limit!r}")
    if not MIN_LIMIT <= limit <= MAX_LIMIT:
        raise ValueError(
            f"limit={limit!r} is outside the contract's {MIN_LIMIT}..{MAX_LIMIT} "
            f"range: the parameter declares a minimum and a maximum, and a page "
            f"size outside them is a request the contract does not describe"
        )
    return log.events(request_id=request_id, function=function,
                      disposition=disposition, since=since, limit=limit)


def chain_status(log: AuditLog) -> dict[str, object]:
    """The verification answer for the log, as the readback reports it.

    `chain_verified` is the contract's boolean and the only one of these three
    the API serialises; `checked` and `broken_at_index` are what a person
    investigating a `false` needs, and `ChainReport` is the same information
    with its own types. `broken_at_index` is a position in the chain, not a
    request ID: a caller that has to act on it walks the page against it.

    The walk is over the **whole log**, not over the records a query returned.
    That is stronger than the contract's wording, which is about "the records
    returned", and it is stated rather than assumed because a caller reading
    `chain_verified` from a one-record page would otherwise reasonably assume
    the page was what was checked.
    """
    report = log.verify_chain()
    return {
        "chain_verified": report.ok,
        "checked": report.checked,
        "broken_at_index": report.broken_at_index,
    }
