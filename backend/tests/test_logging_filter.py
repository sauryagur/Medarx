"""Sensitive-data filtering on the log surfaces the design names.

The design puts application logs, exception traces and model-SDK debug output
under "the same sensitive-data filtering" as the audit log. The audit log's own
filtering is the closed storage policy, which refuses a value at the write; this
file covers the *other* surfaces, which have no such policy and are therefore
the last line of defence rather than the first.

One of these tests is about what the filter does **not** do. A filter attached
to a logger is not consulted for records that propagate up from a child logger,
which is easy to believe otherwise and is asserted here so that the difference
stays a stated fact rather than becoming a claim.
"""

from __future__ import annotations

import io
import logging

import pytest

from medarx.logging_filter import (
    FILTERED_LOGGERS,
    SENSITIVE_PATTERNS,
    SensitiveDataFilter,
    install_filter,
    scrub_exception,
    scrub_text,
)
from medarx.redaction.recognizers import PATTERNS

# Imported for the same reason an application imports them: the SDK loggers
# exist once their modules do, and `install_filter` registers on the loggers
# that exist when it runs. `medarx.gateway` imports `httpx` at module level, so
# by the time an application installs the filter, the `httpcore.*` loggers are
# already there. This is the same ordering, deliberately.
import httpcore._sync.connection  # noqa: F401
import httpx  # noqa: F401

#: The SDK loggers the design's task list names, and the three this filter is
#: *required* to register on. Written out here rather than imported, so the
#: module's list is checked against the requirement rather than against itself.
SDK_LOGGERS = ("httpx", "httpcore", "presidio_analyzer")

#: The names the installed packages actually log to, measured by reading their
#: sources: `httpx` uses `httpx` exactly, `httpcore`'s modules use
#: `httpcore.connection` and its siblings rather than `httpcore` itself, and
#: every `presidio_analyzer` module uses `presidio-analyzer`, hyphenated.
SDK_LOGGERS_IN_USE = ("httpx", "httpcore.connection", "presidio-analyzer")

#: The clinical shapes the filter reuses from the redaction layer rather than
#: restating, keyed by the entity they belong to.
REUSED = ("MRN", "ACCESSION_NUMBER", "PATIENT_ID")


def _capture(logger_name: str) -> tuple[io.StringIO, logging.Handler]:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    return stream, handler


def _detach(logger_name: str, handler: logging.Handler) -> None:
    logger = logging.getLogger(logger_name)
    logger.removeHandler(handler)
    logger.setLevel(logging.NOTSET)


# -- scrub_text -----------------------------------------------------------------


def test_mrn_is_scrubbed_from_log_text():
    assert scrub_text("admitting MRN 4452819 now") == "admitting <redacted:MRN> now"


def test_iso_dates_are_scrubbed():
    assert "<redacted:DATE>" in scrub_text("study dated 2026-01-14 reported")


@pytest.mark.parametrize("text,label", [
    ("admitting MRN 4452819 now", "MRN"),
    ("accession ACC0000417 filed", "ACCESSION_NUMBER"),
    ("PatientID: 12345678 on the study", "PATIENT_ID"),
    ("ssn 123-45-6789 on file", "SSN"),
    ("study dated 2026-01-14 reported", "DATE"),
    ("at 2026-01-14T09:30:00Z the run began", "DATE"),
])
def test_every_sensitive_type_is_scrubbed(text, label):
    scrubbed = scrub_text(text)
    assert f"<redacted:{label}>" in scrubbed
    assert scrubbed != text, "a pattern that matched nothing would pass the line above"


def test_each_sensitive_span_is_scrubbed_once_and_under_its_own_type():
    # One line holding all five, checked against the exact expected text. No
    # span is taken twice, none is left half-redacted, and each is reported
    # under the type the text gave it. The word `ssn` survives because it is
    # the label rather than the value: only the matched span goes.
    line = ("accession ACC0000417 filed for MRN 4452819 at PatientID: 12345678 "
            "on 2026-01-14 by ssn 123-45-6789")
    assert scrub_text(line) == (
        "accession <redacted:ACCESSION_NUMBER> filed for <redacted:MRN> at "
        "<redacted:PATIENT_ID> on <redacted:DATE> by ssn <redacted:SSN>"
    )


def test_a_bare_value_written_under_a_label_is_reported_under_that_label():
    # The MRN recognizer matches a bare seven-digit run with no label of its
    # own, so `ACC 1234567` and `PatientID: 1234567` each satisfy two patterns
    # at once. Run the labelled patterns first — as the module does — and the
    # line says what kind of thing it removed and leaves no orphaned label.
    # Reordered so MRN runs first, the same two lines come back as
    # `ACC <redacted:MRN>` and `PatientID: <redacted:MRN>`: measured, not
    # assumed, which is what makes the order a decision rather than a habit.
    assert scrub_text("ACC 1234567 filed") == "<redacted:ACCESSION_NUMBER> filed"
    assert scrub_text("PatientID: 1234567 on the study") == (
        "<redacted:PATIENT_ID> on the study"
    )


def test_a_scrubbed_line_is_still_a_usable_log_line():
    # Redaction that destroys the message is not filtering, it is deletion: the
    # surrounding context is what makes a log line worth reading.
    scrubbed = scrub_text("POST /v1/functions/Draft/executions MRN 4452819 -> 422")
    assert scrubbed == "POST /v1/functions/Draft/executions <redacted:MRN> -> 422"


def test_text_with_nothing_sensitive_in_it_is_unchanged():
    line = "gateway returned 200 for medarx-demo-model in 41ms"
    assert scrub_text(line) == line


def test_the_clinical_patterns_are_the_recognizers_shapes_not_a_second_vocabulary():
    # A drift check rather than a restatement: the three clinical shapes are
    # read from the redaction layer, so an edit to one and not the other fails
    # here. The behavioural proof that they are shared is the composite line
    # above; this proves it stays true after either side is edited.
    sources = {pattern.pattern for pattern in SENSITIVE_PATTERNS}
    for entity in REUSED:
        assert PATTERNS[entity][0].regex in sources, (
            f"{entity}'s recognizer pattern is not among the filter's"
        )


# -- install_filter and the loggers it covers -----------------------------------


def test_the_filter_applies_to_http_client_debug_loggers():
    f = install_filter()
    for name in SDK_LOGGERS:
        assert any(isinstance(x, type(f)) for x in logging.getLogger(name).filters)


def test_the_loggers_the_sdk_actually_uses_are_registered():
    # The three names the requirement gives are not the three names the code
    # writes to. `httpcore` is a namespace its modules log *beneath*, and
    # Presidio's logger is hyphenated, so a filter on the required names alone
    # would cover two loggers that emit nothing and miss both real ones.
    install_filter()
    for name in SDK_LOGGERS_IN_USE:
        assert any(isinstance(f, SensitiveDataFilter)
                   for f in logging.getLogger(name).filters), (
            f"{name} is a logger a request body would be echoed to, unfiltered"
        )


def test_the_required_loggers_are_registered_too_and_nothing_unrelated_is():
    install_filter()
    assert set(SDK_LOGGERS) <= set(FILTERED_LOGGERS)
    assert any(isinstance(f, SensitiveDataFilter)
               for f in logging.getLogger().filters), (
        "the root logger carries the same filter"
    )
    assert not any(isinstance(f, SensitiveDataFilter)
                   for f in logging.getLogger("medarx.test.unrelated").filters)


def test_install_filter_is_idempotent():
    first = install_filter()
    second = install_filter()
    assert first is second
    covered = 0
    for name, obj in logging.root.manager.loggerDict.items():
        if not isinstance(obj, logging.Logger):
            continue
        matching = [f for f in obj.filters if isinstance(f, SensitiveDataFilter)]
        if matching:
            covered += 1
            assert matching == [first], f"{name} accumulated duplicate filters"
    assert covered >= len(FILTERED_LOGGERS), (
        "at least the named loggers carry the filter, and a second install "
        "added nothing"
    )


@pytest.mark.parametrize("name", SDK_LOGGERS_IN_USE)
def test_a_record_emitted_by_a_named_sdk_logger_is_scrubbed(name):
    # The SDK loggers are the ones named because their own debug output is
    # where a request body would otherwise be echoed whole.
    install_filter()
    stream, handler = _capture(name)
    try:
        logging.getLogger(name).debug(
            'HTTP Request: POST https://example.invalid/v1/chat/completions '
            '"body": "admitting MRN 4452819"')
    finally:
        _detach(name, handler)
    out = stream.getvalue()
    assert "4452819" not in out
    assert "<redacted:MRN>" in out


def test_a_record_emitted_through_the_filter_has_no_raw_value_in_it():
    # This must go through the installed filter, not through `scrub_text`
    # directly, or it only re-tests what `test_mrn_is_scrubbed_from_log_text`
    # already covers.
    stream, handler = _capture("medarx.test.scrubbed")
    add_f = install_filter()
    logger = logging.getLogger("medarx.test.scrubbed")
    logger.addFilter(add_f)
    try:
        logger.info("admitting MRN 4452819 now")
    finally:
        logger.removeFilter(add_f)
        _detach("medarx.test.scrubbed", handler)
    assert "4452819" not in stream.getvalue()
    assert "<redacted:MRN>" in stream.getvalue()


def test_a_lazily_formatted_message_is_scrubbed_after_interpolation():
    # The value is in `record.args`, not in `record.msg`, and the handler
    # interpolates the arguments *after* the filter has run. Scrubbing the
    # template alone therefore leaves the value in place to be printed: folding
    # the arguments in first, and clearing them, is what closes it. Measured
    # with the clearing removed, the same call prints the raw value verbatim.
    stream, handler = _capture("medarx.test.lazy")
    add_f = install_filter()
    logger = logging.getLogger("medarx.test.lazy")
    logger.addFilter(add_f)
    try:
        logger.info("admitting MRN %s now", "4452819")
    finally:
        logger.removeFilter(add_f)
        _detach("medarx.test.lazy", handler)
    out = stream.getvalue()
    assert "4452819" not in out
    assert out.strip() == "admitting <redacted:MRN> now", (
        "the rendered line, not the template with a %s left in it"
    )


def test_a_message_whose_arguments_do_not_match_its_format_is_not_an_error():
    # A bare `%` in a message is the ordinary way to make `getMessage` raise,
    # and a filter that raised would turn a malformed log line into an
    # exception in the caller's code.
    stream, handler = _capture("medarx.test.malformed")
    add_f = install_filter()
    logger = logging.getLogger("medarx.test.malformed")
    logger.addFilter(add_f)
    try:
        logger.info("cpu at 50%% of budget for MRN 4452819")
    finally:
        logger.removeFilter(add_f)
        _detach("medarx.test.malformed", handler)
    assert "4452819" not in stream.getvalue()


def test_a_record_logged_with_a_traceback_is_scrubbed_through_the_filter():
    # The handler formats the exception *after* the filter has run, so a filter
    # that only touched the message would leave the one part of the record most
    # likely to carry an input value entirely unfiltered.
    stream, handler = _capture("medarx.test.traceback")
    add_f = install_filter()
    logger = logging.getLogger("medarx.test.traceback")
    logger.addFilter(add_f)
    try:
        try:
            raise ValueError("failed for MRN 4452819")
        except ValueError:
            logger.exception("admission failed")
    finally:
        logger.removeFilter(add_f)
        _detach("medarx.test.traceback", handler)
    out = stream.getvalue()
    assert "4452819" not in out
    assert "ValueError" in out
    assert "<redacted:MRN>" in out


def test_a_logger_filter_does_not_reach_a_child_loggers_records():
    # A `logging.Filter` is consulted for records logged *to* the logger it is
    # attached to, and `Logger.callHandlers` walks ancestors' **handlers**, not
    # their filters. So a filter on the root logger does not see a record
    # emitted by `medarx.anything`. This is why the three SDK loggers are named
    # explicitly, and why filtering the application's own loggers is the
    # caller's business: a caller that wants one filtered attaches the filter to
    # it. `install_filter` reaches the root logger and the three named loggers
    # and nothing else, and this test is what keeps that sentence true.
    install_filter()
    stream, handler = _capture("medarx.test.unfiltered")
    try:
        logging.getLogger("medarx.test.unfiltered").info(
            "admitting MRN 4452819 now")
    finally:
        _detach("medarx.test.unfiltered", handler)
    assert "4452819" in stream.getvalue(), (
        "if this ever stops being true, install_filter covers the whole tree and "
        "the docstring claiming otherwise is the thing to fix"
    )


# -- scrub_exception ------------------------------------------------------------


def test_exception_traceback_is_scrubbed():
    try:
        raise ValueError("failed for MRN 4452819")
    except ValueError as e:
        out = scrub_exception(e)
    assert "4452819" not in out
    assert "ValueError" in out


def test_the_scrubbed_traceback_still_says_where_the_failure_was():
    # A traceback whose frames are redacted away is no use to whoever has to fix
    # the failure; only the sensitive spans go.
    try:
        raise RuntimeError("study dated 2026-01-14 exploded")
    except RuntimeError as exc:
        out = scrub_exception(exc)
    assert "RuntimeError" in out
    assert "test_the_scrubbed_traceback_still_says_where_the_failure_was" in out
    assert "<redacted:DATE>" in out
