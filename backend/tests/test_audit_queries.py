"""Readback: what an auditor is shown, and what is not shown to them.

The readback is the query surface component G exists to support, so its honesty
is the whole of the test file. Three things are being asserted here and nothing
else is being exercised for its own sake:

- **The record returned is the record stored.** Three artefacts have to agree —
  the storage policy, the table, and the readback — and a fourth (the derived
  `stages` projection) has to stay out of all three.
- **A refusal is as visible as a sent request.** A blocked record is read back
  with the layer and the action codes that actually refused it, not flattened
  into a single generic "blocked" answer.
- **No raw value can be in the readback**, proved by putting an identifier in
  every free-form position the record allows and watching each one be refused at
  the write, rather than by reading the storage policy and believing it.
"""

from __future__ import annotations

import inspect
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import get_args

import pytest
import yaml
from sqlalchemy import text

from medarx.audit.audit_log import (
    ALLOWED_AUDIT_FIELDS,
    EVENT_TABLE,
    AuditLog,
)
from medarx.audit.code_table import PIPELINE_STAGES, stages_reached
from medarx.audit.hash_chain import GENESIS, chain_hash
from medarx.audit.queries import (
    DEFAULT_LIMIT,
    MAX_LIMIT,
    MIN_LIMIT,
    chain_status,
    events_for_request,
    search_records,
)
from medarx.errors import MedarxError
from medarx.models import AuditEvent, HumanApproval, canonical_hash
from medarx.pseudonym.errors import AuditKeyRequired

from conftest import KEY

NOW = datetime(2026, 1, 14, 12, 0, tzinfo=timezone.utc)
STALE = NOW - timedelta(days=400)
LATER = NOW + timedelta(seconds=5)
EARLIER = NOW - timedelta(minutes=5)

#: Real digests, because the storage policy refuses a hash-shaped field holding
#: anything that is not one, and a placeholder would be refused for the wrong
#: reason and prove nothing.
INPUT_HASH = canonical_hash({"seed": "readback-input"})
PAYLOAD_HASH = canonical_hash({"seed": "readback-payload"})

#: A medical record number. The point of the storage-policy tests is that this
#: string cannot reach the readback from *any* free-form field, so it is the
#: probe used throughout.
MRN = "4452819"

#: The normative contract, read from the repository so the constants and the
#: keyword names below are checked against it rather than against a second copy
#: of it written into this file.
CONTRACT = Path(__file__).resolve().parents[2] / "contracts" / "openapi.yaml"


def _contract() -> dict:
    return yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))


def _resolve(node: dict, document: dict) -> dict:
    while "$ref" in node:
        target = document
        for part in node["$ref"].lstrip("#/").split("/"):
            target = target[part]
        node = target
    return node


def test_the_limit_bounds_are_the_contract_parameter_definition():
    # The bounds are written out in the module, so this is the only thing
    # standing between a contract change and a readback enforcing bounds the
    # contract no longer states.
    schema = _contract()["components"]["parameters"]["LimitQueryParam"]["schema"]
    assert schema["minimum"] == MIN_LIMIT
    assert schema["maximum"] == MAX_LIMIT
    assert schema["default"] == DEFAULT_LIMIT


def test_the_search_keywords_are_the_contract_parameter_names():
    document = _contract()
    declared = document["paths"]["/v1/audit/records"]["get"]["parameters"]
    names = {_resolve(p, document)["name"] for p in declared}
    keyword_only = set(inspect.signature(search_records).parameters) - {"log"}
    assert names == keyword_only


def ev(**kw):
    base = dict(request_id="req-1", timestamp=NOW, function="Draft",
                selected_model="medarx-demo-model",
                policy_version="medarx-policy-1.0.0", policy_mode="cloud",
                input_hash=INPUT_HASH, approved_payload_hash=PAYLOAD_HASH,
                redacted_field_names=["report_text"], action_codes=[],
                final_disposition="approved", layer=None,
                chain_hash="", previous_hash=GENESIS)
    base.update(kw)
    return AuditEvent(**base)


@pytest.fixture
def log(tmp_path):
    a = AuditLog(f"sqlite:///{tmp_path / 'audit.db'}", KEY)
    yield a
    a.close()


# -- Readback returns the stored fields, and only those ------------------------


def test_readback_returns_exactly_the_stored_fields(log):
    # Three hand-maintained artefacts, not one definition read three ways: the
    # storage policy (`ALLOWED_AUDIT_FIELDS`), the table, and the model the
    # readback hands back. A field added to the model without a storage decision
    # fails here, which is the drift the closed set exists to catch.
    persisted = set(EVENT_TABLE.c.keys()) - {"ordinal"}
    assert persisted == ALLOWED_AUDIT_FIELDS

    log.append(ev(request_id="r1"))
    assert [set(r.model_dump()) for r in search_records(log)] == [ALLOWED_AUDIT_FIELDS]
    assert [set(r.model_dump()) for r in events_for_request(log, "r1")] == [
        ALLOWED_AUDIT_FIELDS
    ]


def test_a_readback_record_is_the_record_that_was_written(log):
    stored = log.append(ev(request_id="r1", redacted_field_names=["report_text"],
                           action_codes=["FIELD_REDACTED"]))
    (read_back,) = events_for_request(log, "r1")
    assert read_back == stored

def test_chain_verified_is_an_answer_not_a_field_on_the_record(log):
    # The honest shape of tamper evidence on a readback: the record makes no
    # claim about its own integrity, because a claim stored beside the row
    # would be rewritten along with it. What a rewrite does is change the
    # values the readback returns — visibly, in the fields the storage policy
    # holds — and flip the separate verification answer to False.
    log.append(ev(request_id="r1"))
    (before,) = events_for_request(log, "r1")
    assert chain_status(log)["chain_verified"] is True

    with log.connection() as conn:
        conn.execute(text("UPDATE audit_event SET policy_mode = 'strict_local'"))
    (after,) = events_for_request(log, "r1")
    assert before.policy_mode == "cloud" and after.policy_mode == "strict_local"
    assert set(after.model_dump()) == ALLOWED_AUDIT_FIELDS
    assert "chain_verified" not in after.model_dump()
    assert chain_status(log)["chain_verified"] is False


# -- stages is derived, never stored -------------------------------------------


def test_stages_is_not_a_stored_column_anywhere():
    assert "stages" not in EVENT_TABLE.c
    assert "stages" not in ALLOWED_AUDIT_FIELDS
    assert "stages" not in AuditEvent.model_fields


def test_stages_is_derived_from_the_layer_of_the_record_in_hand(log):
    blocked_low = log.append(ev(request_id="r1", layer="D.2",
                               final_disposition="blocked"))
    sent = log.append(ev(request_id="r2", layer=None))
    # A request that reached the model got through every stage; one stopped at
    # the second redaction layer got through three. Both are computed here, from
    # the record, and neither is a column anyone could disagree with.
    assert log.stages_for(blocked_low) == PIPELINE_STAGES[:3]
    assert log.stages_for(sent) == PIPELINE_STAGES
    # ... and the derivation follows the record, so it cannot be stale.
    assert log.stages_for(blocked_low.model_copy(update={"layer": "E"})) == (
        PIPELINE_STAGES[:5]
    )
    assert log.stages_for(sent) == stages_reached(sent.layer)


def test_no_digest_covers_the_derived_projection(log):
    stored = log.append(ev(request_id="r1", layer="D.2", final_disposition="blocked"))
    (read_back,) = events_for_request(log, "r1")
    body = read_back.model_dump(exclude={"chain_hash"})
    # The digest recomputes from the stored fields alone...
    assert chain_hash(body, read_back.previous_hash, KEY) == read_back.chain_hash
    # ... and a derived field in the body would change it, so the exclusion is
    # a real property of the digest and not an accident of naming.
    assert chain_hash({**body, "stages": PIPELINE_STAGES[:3]},
                      read_back.previous_hash, KEY) != read_back.chain_hash


# -- A block is as visible as a sent request -----------------------------------


def test_a_block_reads_back_with_the_layer_and_codes_that_refused_it(log):
    # Component D refused this one and component F refused that one. A readback
    # that flattened both to "blocked" would still answer the question "was this
    # request refused" and would answer nothing at all about *why* — which is
    # the only reason a refusal is recorded.
    log.append(ev(request_id="req-d", layer="D.2", final_disposition="blocked",
                  redacted_field_names=["report_text"],
                  action_codes=["NER_UNRESOLVED"], selected_model=None,
                  approved_payload_hash=None))
    log.append(ev(request_id="req-f", layer="F", final_disposition="blocked",
                  redacted_field_names=["report_text"],
                  action_codes=["HASH_MISMATCH", "PAYLOAD_MISMATCH"]))

    (by_d,) = events_for_request(log, "req-d")
    (by_f,) = events_for_request(log, "req-f")
    assert by_d.layer == "D.2"
    assert by_d.action_codes == ["NER_UNRESOLVED"]
    assert by_f.layer == "F"
    assert by_f.action_codes == ["HASH_MISMATCH", "PAYLOAD_MISMATCH"]
    assert by_d.action_codes != by_f.action_codes


def test_a_refusal_leaves_a_trace_as_visible_as_a_sent_request(log):
    log.append(ev(request_id="req-ok", final_disposition="approved"))
    log.append(ev(request_id="req-no", layer="E", final_disposition="blocked",
                  action_codes=["UNKNOWN_POLICY_VERSION"]))
    log.append(ev(request_id="req-ok", final_disposition="approved_by_human",
                  human_approval=HumanApproval(decision="approved", recorded_at=NOW,
                                               reviewer="clinician-a")))

    everything = search_records(log)
    assert sorted({r.request_id for r in everything}) == ["req-no", "req-ok"]
    assert [r.final_disposition for r in events_for_request(log, "req-ok")] == [
        "approved", "approved_by_human"
    ]
    assert search_records(log, disposition="blocked") == [
        r for r in everything if r.request_id == "req-no"
    ]
    assert chain_status(log)["chain_verified"] is True, (
        "a refusal that was not chained as evidence is a refusal with no record"
    )


def test_events_for_request_returns_only_that_requests_records(log):
    for index, request_id in enumerate(["a", "b", "a", "c", "a"]):
        log.append(ev(request_id=request_id, timestamp=NOW + timedelta(seconds=index)))
    for_a = events_for_request(log, "a")
    assert len(for_a) == 3
    assert len(events_for_request(log, "b")) == 1
    assert events_for_request(log, "absent") == []
    # Three records for one request are not three consecutive positions, so the
    # chain linkage runs through the other requests' records — and that linkage
    # is on the records themselves, not something the readback reconstructs.
    assert for_a[0].previous_hash == GENESIS
    assert for_a[1].previous_hash == events_for_request(log, "b")[0].chain_hash
    assert for_a[2].previous_hash == events_for_request(log, "c")[0].chain_hash


def test_the_readback_orders_by_timestamp_even_when_the_clock_moved(log):
    # A record appended later but stamped earlier reads back first, because the
    # contract asks the collection endpoint for ascending timestamps. The chain
    # is walked in append order regardless, so a clock that moved is something
    # verification sees rather than something a sort hides.
    log.append(ev(request_id="r1", timestamp=LATER))
    log.append(ev(request_id="r2", timestamp=EARLIER))
    first, second = search_records(log)
    assert (first.request_id, second.request_id) == ("r2", "r1")
    # The chain runs the other way: r1 was appended first, so it chains to
    # GENESIS, and r2 chains onto r1 however the readback ordered the two.
    assert second.previous_hash == GENESIS
    assert first.previous_hash == second.chain_hash
    assert chain_status(log)["chain_verified"] is True


# -- The contract's filter parameters -------------------------------------------


def test_records_come_back_oldest_first(log):
    # The contract says ascending timestamp. The chain's own order is append
    # order, and a clock that moved is a real thing — so the timestamp order the
    # contract asks for is the primary key and the ordinal breaks the tie, which
    # keeps the page total without pretending the sort verifies anything.
    log.append(ev(request_id="third", timestamp=LATER))
    log.append(ev(request_id="first", timestamp=EARLIER))
    log.append(ev(request_id="second", timestamp=NOW))
    assert [r.request_id for r in search_records(log)] == ["first", "second", "third"]


def test_the_ordinal_breaks_a_timestamp_tie(log):
    log.append(ev(request_id="a", timestamp=NOW))
    log.append(ev(request_id="b", timestamp=NOW))
    assert [r.request_id for r in search_records(log)] == ["a", "b"]


@pytest.mark.parametrize("kwargs,expected", [
    ({"request_id": "req-2"}, ["req-2"]),
    ({"function": "Ask"}, ["req-2", "req-3"]),
    ({"disposition": "blocked"}, ["req-4"]),
    ({"since": NOW + timedelta(seconds=1)}, ["req-2", "req-3", "req-4"]),
    ({"request_id": "req-3", "function": "Ask"}, ["req-3"]),
    ({}, ["req-1", "req-2", "req-3", "req-4"]),
])
def test_the_search_filters_on_the_contract_parameters(log, kwargs, expected):
    log.append(ev(request_id="req-1", timestamp=NOW))
    log.append(ev(request_id="req-2", timestamp=NOW + timedelta(seconds=1),
                  function="Ask"))
    log.append(ev(request_id="req-3", timestamp=NOW + timedelta(seconds=2),
                  function="Ask", final_disposition="approved_by_human"))
    log.append(ev(request_id="req-4", timestamp=NOW + timedelta(seconds=3),
                  final_disposition="blocked", layer="E"))
    assert [r.request_id for r in search_records(log, **kwargs)] == expected


def test_the_limit_is_the_contracts_limit(log):
    assert (MIN_LIMIT, MAX_LIMIT, DEFAULT_LIMIT) == (1, 500, 100)
    for index in range(3):
        log.append(ev(request_id=f"r{index}", timestamp=NOW + timedelta(seconds=index)))
    assert len(search_records(log, limit=1)) == 1
    assert len(search_records(log, limit=MAX_LIMIT)) == 3
    for bad in (0, -1, MAX_LIMIT + 1):
        with pytest.raises(ValueError) as ei:
            search_records(log, limit=bad)
        assert "limit" in str(ei.value)


@pytest.mark.parametrize("kwargs", [
    {"function": "prior_summary"},
    {"function": "Unknown"},
    {"disposition": "sent"},
])
def test_a_filter_outside_the_contract_enum_is_refused(log, kwargs):
    # The contract's filters are closed enums, so an unknown value is a caller
    # error rather than an empty page: "no records matched" would be a true
    # statement about a query nobody meant to ask.
    with pytest.raises(ValueError) as ei:
        search_records(log, **kwargs)
    assert next(iter(kwargs)) in str(ei.value)


def test_a_naive_since_is_refused_rather_than_guessed(log):
    with pytest.raises(ValueError) as ei:
        search_records(log, since=datetime(2026, 1, 14, 12, 0))
    assert "since" in str(ei.value)


# -- The record speaks the contract's vocabulary --------------------------------


def test_the_function_stored_and_the_function_filter_are_the_contract_spelling(log):
    # The readback path introduces no second spelling: the stored value is the
    # contract's member, and the filter that finds it is the same string. A
    # readback that translated `Prior Summary` on the way out would be putting a
    # second vocabulary in front of the record it is supposed to attest to.
    for index, function in enumerate(("Draft", "Prior Summary", "Ask")):
        log.append(ev(request_id=f"req-{index}", function=function))
    assert [r.function for r in search_records(log)] == ["Draft", "Prior Summary",
                                                          "Ask"]
    assert [r.function for r in search_records(log, function="Prior Summary")] == [
        "Prior Summary"
    ]
    # The internal spelling is refused as a filter, not silently matched: it is
    # not a second way to ask the same question.
    with pytest.raises(ValueError):
        search_records(log, function="prior_summary")


# -- Chain verification on read -------------------------------------------------


def test_chain_status_reports_the_whole_walk_and_where_it_broke(log):
    assert chain_status(log) == {"chain_verified": True, "checked": 0,
                                 "broken_at_index": None}
    log.append(ev(request_id="r1"))
    log.append(ev(request_id="r2"))
    assert chain_status(log) == {"chain_verified": True, "checked": 2,
                                 "broken_at_index": None}
    with log.connection() as conn:
        conn.execute(text("UPDATE audit_event SET policy_mode = 'strict_local'"
                          " WHERE request_id = 'r2'"))
    status = chain_status(log)
    assert status["chain_verified"] is False
    assert status["broken_at_index"] == 1
    assert status["checked"] == 2, (
        "verification covers the whole log, not the page a caller asked for"
    )


def test_chain_status_is_not_affected_by_which_page_was_asked_for(log):
    log.append(ev(request_id="r1"))
    log.append(ev(request_id="r2", final_disposition="blocked", layer="A",
                  action_codes=["FIELD_NOT_ALLOWLISTED"]))
    before = chain_status(log)
    assert search_records(log, request_id="r1")
    assert chain_status(log) == before


def test_a_purged_record_leaves_the_readback_and_the_chain_still_verifies(log):
    log.append(ev(request_id="old", timestamp=STALE, final_disposition="blocked",
                  layer="A", action_codes=["FIELD_NOT_ALLOWLISTED"]))
    log.append(ev(request_id="new"))
    assert log.purge_expired(NOW, retention_days=1) == 1
    # The refusal is gone as a record; what remains is that something stood
    # there, and the chain says so.
    assert events_for_request(log, "old") == []
    assert [r.request_id for r in search_records(log)] == ["new"]
    assert chain_status(log)["chain_verified"] is True


def test_a_readback_over_an_unkeyed_log_is_a_configuration_error(tmp_path):
    # A missing audit key is a deployment mistake, not a refusal about a
    # patient's data, so it must not arrive as something the 422 privacy-block
    # handler could render. The readback is downstream of this: it cannot be
    # handed an unkeyed log at all.
    with pytest.raises(AuditKeyRequired) as ei:
        AuditLog(f"sqlite:///{tmp_path / 'unkeyed.db'}", "")
    assert not isinstance(ei.value, MedarxError)
    assert "MEDARX_AUDIT_KEY" in str(ei.value)


# -- No raw value can reach the readback ----------------------------------------

#: Every free-form position the record allows, each holding a value that is a
#: name or a digest and not a sentence. The completeness of this enumeration is
#: itself asserted below, so adding a free-form field to the model without
#: adding a case here fails the suite rather than quietly widening the policy.
FREE_FORM_CASES = [
    ("request_id", f"7f3c1a90 MRN {MRN}"),
    ("selected_model", f"medarx-demo-model MRN {MRN}"),
    ("policy_version", f"medarx-policy-1.0.0 for MRN {MRN}"),
    ("input_hash", f"the report said MRN {MRN}"),
    ("approved_payload_hash", f"payload for MRN {MRN}"),
    ("redacted_field_names", [f"MRN {MRN}"]),
    ("action_codes", [f"NER_{MRN}"]),
]

#: The fields whose gate is a closed set, the log's own computation, or a
#: nested model of its own — so there is no free-form position in them for a
#: value to ride through.
GATED_OR_COMPUTED = {
    "function", "policy_mode", "final_disposition", "layer",
    "chain_hash", "previous_hash", "human_approval", "timestamp",
}


def test_the_free_form_enumeration_is_the_whole_free_form_surface():
    # Derived from the model, so a new free-form field shows up here. The
    # expectation is written out rather than imported from the module, so this
    # compares two statements of the policy instead of one against itself.
    string_fields = {
        name for name, field in AuditEvent.model_fields.items()
        if str in get_args(field.annotation) or field.annotation is str
    }
    assert string_fields - GATED_OR_COMPUTED == {
        "request_id", "selected_model", "policy_version", "input_hash",
        "approved_payload_hash", "redacted_field_names", "action_codes",
    }
    assert {case[0] for case in FREE_FORM_CASES} == string_fields - GATED_OR_COMPUTED
    # The nested positions are free-form too, and a reviewer's name is not where
    # a top-level field name would catch it.
    assert {n for n, f in HumanApproval.model_fields.items()
            if str in get_args(f.annotation) or f.annotation is str} == {"reviewer"}


@pytest.mark.parametrize("field,value", FREE_FORM_CASES)
def test_a_value_where_a_name_belongs_is_refused_at_the_write(log, field, value):
    with pytest.raises(ValueError) as ei:
        log.append(ev(**{field: value}))
    assert field in str(ei.value)
    assert log.get("req-1") == []


def test_a_reviewer_naming_a_person_is_refused_at_the_write(log):
    approval = HumanApproval(decision="approved", recorded_at=NOW,
                             reviewer=f"clinician MRN {MRN}")
    with pytest.raises(ValueError):
        log.append(ev(human_approval=approval))
    assert log.get("req-1") == []


def test_nothing_read_back_carries_the_identifier(log):
    # The proof, not the promise: every refusal above leaves the log empty, so
    # this writes a record that *is* accepted and then sweeps every field of
    # every record the readback hands back for the probe string.
    log.append(ev(request_id="req-1", redacted_field_names=["report_text"],
                  action_codes=["NER_UNRESOLVED"], final_disposition="blocked",
                  layer="D.2"))
    records = search_records(log) + events_for_request(log, "req-1")
    assert records
    for record in records:
        for name, value in record.model_dump().items():
            assert MRN not in repr(value), f"{name} carried the identifier"
