"""The sensitive-data filter for the log surfaces the design names.

The design puts application logs, exception traces, tracing spans and
model-SDK debug output under "the same sensitive-data filtering" as the audit
log. The audit log has that as a *policy* — a field that could hold a value is
refused at the write, so there is nothing to filter at read time. The other
surfaces have no such policy: a value reaches a log line because somebody
interpolated it into a message, and this module is what stands between that and
a persistently readable file. So it is the **last** line of defence, and
everything it does is written to be a floor rather than a proof.

**Three of those four surfaces are implemented; the fourth is not.** Application
logs, exception traces and the HTTP/NER SDKs' debug output are covered below.
**Tracing spans are not**: no tracer is a dependency, none is installed, and
there is no span to scrub — a surface with no implementation is unaddressed
rather than covered, and this module says so rather than letting the sentence
above imply otherwise. Whether Phase 1 ever emits spans, and where a span's
attributes would be filtered when it does, is undecided.

**One vocabulary of identifier shapes, not two.** The three clinical patterns
are the redaction layer's own (`medarx.redaction.recognizers.PATTERNS`), read
from there rather than copied: an MRN the kernel is told to recognise in a
report and an MRN it is told to scrub in a log are the same shape of string, and
a second copy here is a second thing to keep in step. The cost of the reuse is
that importing this module imports `presidio_analyzer` with it; the redaction
layers sit on every request path, so the process loads it regardless.

**What this filter does *not* cover, stated rather than implied.** A
`logging.Filter` is consulted for records logged *to* the logger it is attached
to — `Logger.filter` reads `self.filters` and nothing else, and
`Logger.callHandlers` walks ancestors' *handlers*, not their filters. So a
filter on the root logger sees nothing any other logger emitted, and
`install_filter` reaching the root logger is not a claim that the whole tree is
filtered. It registers on the root logger, and on the SDK loggers the design
names together with everything beneath each of them: `httpx`, the `httpcore.*`
subtree, and both spellings of Presidio's logger (see `FILTERED_LOGGERS` for
why there are two). Their debug output echoes request bodies verbatim, which is
what makes them worth naming. Every other logger is the caller's business:
attach `SensitiveDataFilter` to it.
`tests/test_logging_filter.py` asserts the limitation, so none of this can
quietly stop being true.

Three further gaps, in the same spirit:

- **A record's `extra` fields are not scrubbed.** A caller that passes
  `extra={"study": raw_text}` puts a raw value on the record, and a formatter
  that renders `record.study` prints it. The filter scrubs the *message*.
- **The traceback is scrubbed, not merely the message**, because the handler
  formats it *after* the filter has run: `filter` renders the exception itself
  with `scrub_exception` and hands the formatter text that is already clean.
  A logger configured by someone else to re-render `exc_info` would undo that,
  so `scrub_exception` is also exported for a caller that formats its own
  tracebacks.
- **`stack_info` is not scrubbed.** `Formatter.format` appends
  `record.stack_info` after the filter has run, the same way it formats the
  traceback, and the filter does not render it. What it would carry is the
  caller's own source lines rather than a value from a report, which is a much
  smaller exposure than the other two — but it is not nothing, and it is the
  caller's own `stack_info=True` that asked for it.

**Nothing is ever dropped.** `filter` returns `True` unconditionally and
scrubs in place. Suppressing a record would remove the fact that something
happened, and a log that quietly omits the event it could not describe is worse
than one that describes the event without its values.
"""

from __future__ import annotations

import logging
import re
import traceback

from medarx.redaction.recognizers import PATTERNS, REGEX_FLAGS

__all__ = [
    "FILTERED_LOGGERS",
    "SENSITIVE_PATTERNS",
    "SensitiveDataFilter",
    "install_filter",
    "scrub_exception",
    "scrub_text",
]


#: The loggers whose debug output carries request bodies. `httpx` logs the
#: outbound request at DEBUG with the body; `httpcore`'s modules log the wire
#: exchanges; Presidio logs the spans it finds, which are the values a report
#: carries.
#:
#: **Both spellings of the Presidio logger are here, and `httpcore` is a
#: namespace rather than a logger.** Both facts were measured against the
#: installed packages rather than assumed:
#:
#: - `presidio_analyzer` is the spelling the design's task list gives, and
#:   `presidio-analyzer` is the one `presidio_analyzer` actually calls
#:   `logging.getLogger` with — the hyphen, in every module of it. A filter on
#:   the underscored name would cover a logger nothing writes to, so both are
#:   registered: the declared spelling costs one tuple entry and is right if a
#:   future release adopts it.
#: - `httpx` is the exact name its client uses. `httpcore` is **not** a logger
#:   anything logs to: its modules use `httpcore.connection`,
#:   `httpcore.http11`, `httpcore.http2`, `httpcore.proxy` and the rest, and a
#:   logger filter is not inherited (see the module docstring), so the name on
#:   its own filters nothing. `install_filter` therefore registers on the whole
#:   subtree beneath each name, not only on the name.
FILTERED_LOGGERS: tuple[str, ...] = (
    "httpx",
    "httpcore",
    "presidio_analyzer",
    "presidio-analyzer",
)


def _loggers_under(names: tuple[str, ...]) -> list[logging.Logger]:
    """`names` themselves, plus every logger that already exists beneath them.

    A logger filter is consulted only for records logged to the logger it is
    attached to, so a name that is a namespace rather than a logger — `httpcore`
    — filters nothing until its children are covered too.

    The children are module-level loggers created when their module is imported,
    which for the HTTP packages is at import of `medarx.gateway`, and therefore
    before an application gets as far as installing a filter. A logger created
    *after* this walk is not covered: that is why the application installs the
    filter at startup rather than at import of this module, and why a new
    namespace is added to `FILTERED_LOGGERS` rather than discovered here.

    A name the manager holds as a `PlaceHolder` — which is what the parent of a
    dotted name is held as until something logs to it, and it has no
    `addFilter` — is skipped. Its children, which are everything that actually
    emits, are not.
    """
    targets = [logging.getLogger(name) for name in names]
    targets += [obj for name, obj in logging.root.manager.loggerDict.items()
                if isinstance(obj, logging.Logger)
                and any(name.startswith(f"{wanted}.") for wanted in names)]
    return [t for t in targets if isinstance(t, logging.Logger)]


def _recognizer_regex(entity: str) -> str:
    """The redaction layer's own pattern for `entity`, as source text.

    Read rather than copied, so the two cannot drift. A missing entity is an
    import-time error rather than a silently absent pattern: coverage that
    disappears without a failure is the failure mode this module exists to
    prevent.
    """
    patterns = PATTERNS.get(entity)
    if not patterns:
        raise KeyError(
            f"medarx.redaction.recognizers.PATTERNS has no pattern for "
            f"{entity!r}; the log filter reuses those patterns and cannot "
            f"scrub a shape the recognizer no longer recognises"
        )
    return patterns[0].regex


#: A US SSN in its written form. The unseparated nine-digit run is deliberately
#: **not** matched: it is indistinguishable from every other nine-digit number
#: that turns up in a log — a nanosecond timestamp, part of a digest — and a
#: filter that redacts those is a filter nobody reads past. The cost is a real
#: miss on an SSN written without separators, and the honest answer to that is
#: that this module is a floor: the kernel's own closed storage policy is what
#: keeps a value out of a log in the first place.
_SSN = r"\b\d{3}[- ]\d{2}[- ]\d{4}\b"

#: An ISO-8601 date, with its time-of-day when it has one. Dates are the
#: identifier that looks least like one: a study date in a log line reads as
#: metadata, and a report full of them is a longitudinal record.
_ISO_DATE = r"\b\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)?\b"

#: Every pattern, paired with the label its matches are replaced by.
#:
#: **The order decides which label a value is reported under, and that is
#: measured rather than argued.** Two of these patterns accept a bare value
#: with no label of its own — the MRN recognizer matches any `[A-Z]{0,2}\d{7}`
#: — so a seven-digit value written under an accession or patient-ID label
#: satisfies two patterns at once. Run MRN first, `ACC 1234567` comes back as
#: `ACC <redacted:MRN>`: the value is gone, but the line now claims a medical
#: record number where the text said an accession number, and the orphaned label
#: is left in it. Run the labelled patterns first, each consumes its own label
#: and value as one span, and the bare-value pattern sees nothing that is left
#: to take. No ordering leaks a value; this one reports the right type.
_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(_recognizer_regex("ACCESSION_NUMBER"), REGEX_FLAGS),
     "ACCESSION_NUMBER"),
    (re.compile(_recognizer_regex("PATIENT_ID"), REGEX_FLAGS), "PATIENT_ID"),
    (re.compile(_recognizer_regex("MRN"), REGEX_FLAGS), "MRN"),
    (re.compile(_SSN, REGEX_FLAGS), "SSN"),
    (re.compile(_ISO_DATE, REGEX_FLAGS), "DATE"),
)

#: The patterns on their own, for a caller that wants to inspect or reuse the
#: shapes without the labels. Derived from `_RULES`, so the two cannot disagree
#: about which patterns are in force.
SENSITIVE_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    pattern for pattern, _ in _RULES
)


def _replacement(label: str) -> "re.Match[str] -> str":
    """The substitution for one pattern: `<redacted:TYPE>`.

    A callable rather than a replacement string, because `re.sub` reads
    backslashes in the replacement and a label is not worth that sharp an edge.
    The label is the *type* and never the value, which is what makes a scrubbed
    line still say what kind of thing was removed.
    """
    return lambda match: f"<redacted:{label}>"


def scrub_text(text: str) -> str:
    """`text` with every sensitive span replaced by `<redacted:TYPE>`.

    Every pattern, in order, each one applied to the result of the last. A
    scrubbed line is still a readable line: only the matched span goes, so the
    sentence, the request ID and the outcome around it survive.
    """
    for pattern, label in _RULES:
        text = pattern.sub(_replacement(label), text)
    return text


def scrub_exception(exc: BaseException) -> str:
    """`exc`'s formatted traceback, with every sensitive span replaced.

    The last line of defence for the case the design names explicitly: an
    exception message is very often built from the input that caused it, and a
    traceback is exactly the place a raw value is most likely to be preserved
    verbatim — in the message, in a frame's source line, or in both.

    The frames are kept. A traceback with the sensitive spans removed and the
    call stack intact is still something a person can act on, and one with the
    stack removed is not a traceback any more.
    """
    return scrub_text("".join(
        traceback.format_exception(type(exc), exc, exc.__traceback__)
    ))


class SensitiveDataFilter(logging.Filter):
    """Scrubs a record's message, and its traceback, in place.

    Mutating the record rather than returning a rewritten one is what makes this
    usable as a `logging.Filter` at all: the handler formats the record after
    the filter has run, so anything the filter does not change reaches the
    output untouched.

    The **rendered** message is scrubbed, not the format string. A lazily
    formatted call — `logger.info("admitting MRN %s now", value)` — keeps the
    value in `record.args`, not in `record.msg`, so scrubbing the template alone
    leaves the value in place for the handler to interpolate. Folding the
    arguments in first and clearing them is what closes that, and it is the
    only reason clearing them is load-bearing rather than tidy: measured, with
    the arguments left in place the raw value is printed verbatim, because
    `getMessage` runs after the filter and interpolates into a template the
    filter has already scrubbed.

    The traceback is rendered here rather than left to the handler, because
    `Formatter.format` builds `exc_text` from `record.exc_info` *after* this
    runs — a filter that only touched the message would leave the one part of
    the record most likely to carry an input value entirely unfiltered.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            rendered = record.getMessage()
        except Exception:
            # Arguments that do not match their format string — a message with a
            # bare `%` in it is the ordinary way to get here. `getMessage`
            # raises, and raising out of a logging call would turn a malformed
            # log line into an application error, which is a worse outcome than
            # a line whose arguments are missing. The handler raises on the
            # same call today and swallows it, so nothing is made worse.
            rendered = str(record.msg)
        record.msg = scrub_text(rendered)
        record.args = ()
        if record.exc_info and not record.exc_text:
            record.exc_text = scrub_text(
                "".join(traceback.format_exception(*record.exc_info)))
        return True


#: The filter `install_filter` put in place, so a second call is a lookup rather
#: than a second copy of the same filter on the same loggers.
_INSTALLED: SensitiveDataFilter | None = None


def install_filter() -> SensitiveDataFilter:
    """Install the filter on the root logger and on the named SDK loggers.

    Returns the single filter instance, having registered it on
    `logging.getLogger()` and on every logger at or beneath a name in
    `FILTERED_LOGGERS`. Calling this more than once is a no-op that returns the
    same object: a second copy on the same logger would scrub the text twice and
    register a duplicate per call.

    The subtree matters: `httpcore` is a namespace, and its modules log on
    `httpcore.connection` and its siblings, which a filter on the parent does
    not reach. Registering the name alone would be a filter on a logger nothing
    writes to — the one outcome this module exists to prevent.

    Not called at import time. An import-time install would make the coverage
    depend on who imported the module first, and the application entry point and
    the test session fixture each decide for themselves when it happens.

    See the module docstring for what this does and does not reach: a logger
    filter is not inherited, so this covers the root logger, the SDK loggers
    and their subtrees, and the application's own loggers are the caller's to
    attach it to.
    """
    global _INSTALLED
    if _INSTALLED is not None:
        return _INSTALLED
    installed = SensitiveDataFilter()
    logging.getLogger().addFilter(installed)
    for logger in _loggers_under(FILTERED_LOGGERS):
        logger.addFilter(installed)
    _INSTALLED = installed
    return installed
