"""Component G: the audit log — storage policy, hash chain, tamper evidence.

Three things are load-bearing here and each has a test that can fail:

1. **The log is not a second PHI store.** The field set is a closed, hand-written
   allowlist, and a record carrying a field outside it is refused rather than
   stored or silently dropped.
2. **The chain detects rewriting, reordering, and deletion** — including deletion
   at the tail, which a plain chain misses and which the head anchor exists for.
3. **The chain is keyed**, so it is not re-computable by a party who can read
   the log; and the test that states the limit executes the limit rather than
   asserting it in prose.

A test that restated a definition would be worthless here, so the assertions are
deliberately of the *inverse* kind: build the bad record and watch it be
refused, rather than compare the allowlist to the model that produced it.
"""

from __future__ import annotations

import ast
import hashlib
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml
from sqlalchemy import create_engine, inspect, text

from medarx.audit.audit_log import ALLOWED_AUDIT_FIELDS, AUDIT_METADATA, AuditLog
from medarx.audit.code_table import (
    CODE_TABLE,
    LAYER_STAGE,
    PIPELINE_STAGES,
    STAGE_COMPONENTS,
    stages_reached,
)
from medarx.audit.hash_chain import GENESIS, canonical, chain_hash
from medarx.audit.schema_init import main as schema_init_main
from medarx.errors import MedarxError
from medarx.models import LAYERS, AuditEvent, HumanApproval, canonical_hash
from medarx.pseudonym.errors import AuditKeyRequired

from conftest import KEY

#: Repo root, resolved from this file so the contract is read from any CWD.
REPO_ROOT = Path(__file__).resolve().parents[2]
CONTRACT = REPO_ROOT / "contracts" / "openapi.yaml"
SOURCE_ROOT = REPO_ROOT / "backend" / "src" / "medarx"

NOW = datetime(2026, 1, 14, 12, 0, tzinfo=timezone.utc)
#: The canonical text of `NOW` and one second later — what the table stores.
NOW_TEXT = "2026-01-14T12:00:00Z"
LATER_TEXT = "2026-01-14T12:00:01Z"

#: The six stage names the UI's privacy-details drawer renders, in the order it
#: renders them. Written out here rather than imported, so the contract and
#: component G are each checked against the timeline and not against each other.
DRAWER_STAGES = (
    "Fields selected",
    "Pseudonymized",
    "Text screened",
    "Payload validated",
    "Policy decision",
    "Model request",
)


#: Real digests, because the storage policy refuses a hash-shaped field holding
#: anything that is not one — and "h0" is not.
INPUT_HASH = canonical_hash({"seed": "input"})
PAYLOAD_HASH = canonical_hash({"seed": "approved-payload"})


def ev(**kw):
    base = dict(request_id="req-1", timestamp=NOW, function="draft",
                selected_model="medarx-demo-model", policy_version="medarx-policy-1.0.0",
                policy_mode="cloud", input_hash=INPUT_HASH,
                approved_payload_hash=PAYLOAD_HASH,
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


def _contract_schema(name: str) -> dict:
    doc = yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))
    return doc["components"]["schemas"][name]


# -- The storage policy --------------------------------------------------------


def test_allowed_audit_fields_exclude_anything_could_hold_a_value():
    # Content check, not a definitional one: `ALLOWED_AUDIT_FIELDS` is written
    # out literally in audit_log.py, so this compares two hand-written things.
    assert ALLOWED_AUDIT_FIELDS
    assert not ({"report_text", "prompt", "response", "raw_value", "dicom",
                 "payload", "content", "model_response"} & ALLOWED_AUDIT_FIELDS)


def test_the_allowlist_and_the_event_model_declare_the_same_fields():
    # `ALLOWED_AUDIT_FIELDS` is a literal, not `frozenset(AuditEvent.model_fields)`
    # — writing it as a mirror of the model is what would make this assertion
    # definitional. Written out, a field added to the model without a storage
    # decision fails here *and* makes `append` refuse the record, which is the
    # closed set doing its job.
    assert ALLOWED_AUDIT_FIELDS == set(AuditEvent.model_fields)


def test_a_record_carrying_a_field_outside_the_allowlist_is_refused(log):
    # The inverse test, and the one the storage policy actually turns on: build
    # the record that must not exist and watch it be refused. `extra="forbid"`
    # is the first gate and blocks the obvious path; a subclass carrying an
    # extra field is a path that gets past it, and it must still be refused —
    # the allowlist is the second gate and it is not advisory.
    class WideAuditEvent(AuditEvent):
        raw_value: str = "4452819"

    with pytest.raises(ValueError) as ei:
        log.append(WideAuditEvent(**ev().model_dump()))
    assert "raw_value" in str(ei.value)
    assert log.get("req-1") == [], "a refused record must leave nothing behind"
    assert log.verify_chain().checked == 0


def test_the_allowlist_is_exactly_what_the_table_persists():
    # Two artefacts rather than one definition: the storage policy and the
    # schema. A column that is not on the allowlist is a second store for
    # something; an allowlisted field with no column is a record that silently
    # loses evidence.
    persisted = set(AUDIT_METADATA.tables["audit_event"].columns.keys())
    assert persisted - {"ordinal"} == ALLOWED_AUDIT_FIELDS
    assert "ordinal" in persisted


# -- The chain -----------------------------------------------------------------


def test_first_record_chains_to_genesis(log):
    e = log.append(ev())
    assert e.previous_hash == GENESIS
    assert e.chain_hash == chain_hash(e.model_dump(exclude={"chain_hash"}), GENESIS, KEY)


def test_chain_verifies_for_honest_records(log):
    log.append(ev(request_id="r1"))
    log.append(ev(request_id="r2", final_disposition="blocked"))
    r = log.verify_chain()
    assert r.ok and r.checked == 2 and r.broken_at_index is None


def test_rewritten_row_fails_verification(log):
    log.append(ev(request_id="r1"))
    log.append(ev(request_id="r2", final_disposition="blocked"))
    with log.connection() as c:
        c.execute(text("UPDATE audit_event SET final_disposition='approved' "
                       "WHERE request_id='r2'"))
    r = log.verify_chain()
    assert not r.ok and r.broken_at_index == 1
    # A rewrite is a break *inside* the surviving rows, which is how a caller
    # tells it apart from a truncated chain (see the anchor test below).
    assert r.broken_at_index < r.checked


def test_deleted_row_fails_verification(log):
    log.append(ev(request_id="r1"))
    log.append(ev(request_id="r2"))
    with log.connection() as c:
        c.execute(text("DELETE FROM audit_event WHERE request_id='r1'"))
    r = log.verify_chain()
    assert not r.ok
    # The survivor no longer chains to GENESIS, so the break is inside the rows
    # that remain: a deletion in the middle leaves a gap.
    assert r.broken_at_index < r.checked


def test_reordering_two_rows_fails_verification(log):
    log.append(ev(request_id="r1", timestamp=NOW))
    log.append(ev(request_id="r2", timestamp=NOW + timedelta(seconds=1)))
    with log.connection() as c:
        # Two rows given each other's content, chain fields untouched. A log
        # re-sorted by timestamp instead of by append order looks exactly like
        # this, which is why the chain follows ordinal and not the clock.
        c.execute(text("UPDATE audit_event SET request_id='r2', timestamp=:t "
                       "WHERE ordinal=1").bindparams(t=LATER_TEXT))
        c.execute(text("UPDATE audit_event SET request_id='r1', timestamp=:t "
                       "WHERE ordinal=2").bindparams(t=NOW_TEXT))
    r = log.verify_chain()
    assert not r.ok and r.broken_at_index == 0


def test_deleting_the_last_row_is_detected_by_the_head_anchor(log):
    # The case a plain chain misses: with the tail row gone, what remains is
    # still internally consistent, so linkage alone proves nothing. The head
    # anchor — written in the same transaction as the append — is what makes the
    # truncation visible, and `broken_at_index == checked` is how a report says
    # "the chain is short" rather than "a row was rewritten".
    log.append(ev(request_id="r1"))
    log.append(ev(request_id="r2"))
    with log.connection() as c:
        c.execute(text("DELETE FROM audit_event WHERE ordinal=2"))
    r = log.verify_chain()
    assert not r.ok and r.broken_at_index == r.checked == 1


def test_deleting_every_row_is_detected_by_the_head_anchor(log):
    log.append(ev(request_id="r1"))
    with log.connection() as c:
        c.execute(text("DELETE FROM audit_event"))
    r = log.verify_chain()
    assert not r.ok and r.checked == 0 and r.broken_at_index == 0


def test_a_chain_cut_and_re_appended_to_does_not_verify(log):
    # Cut the chain and append again. The new row's digest matches the anchor
    # the append just wrote, so the head *digest* agrees; what does not is the
    # new row's own link, because SQLite reuses the freed ordinal and it lands
    # at position 0 still chained to a record that no longer exists. The anchor's
    # count is inside the MAC and disagrees too — the walk reaches the link first.
    log.append(ev(request_id="r1"))
    log.append(ev(request_id="r2"))
    with log.connection() as c:
        c.execute(text("DELETE FROM audit_event"))
    log.append(ev(request_id="r3"))
    r = log.verify_chain()
    assert not r.ok


def test_a_block_is_chained_as_evidence_and_not_only_stored(log):
    # A block that leaves no verifiable trace is not evidence, so the refused
    # path has to chain exactly like the approved one.
    log.append(ev(request_id="r1", final_disposition="approved"))
    log.append(ev(request_id="r2", final_disposition="blocked",
                  approved_payload_hash=None, redacted_field_names=["report_text"],
                  action_codes=["NER_UNRESOLVED", "LOW_CONFIDENCE_NER_UNRESOLVED"]))
    r = log.verify_chain()
    assert r.ok and r.checked == 2
    stored = log.get("r2")[0]
    assert stored.final_disposition == "blocked"
    assert stored.approved_payload_hash is None
    assert stored.action_codes == ["NER_UNRESOLVED", "LOW_CONFIDENCE_NER_UNRESOLVED"]
    assert stored.redacted_field_names == ["report_text"]


def test_a_block_records_the_field_name_and_the_code_and_nothing_else(log):
    # The storage policy in one assertion: a refusal is recorded as the *name*
    # of the field and a classifier, never as what the field held.
    log.append(ev(final_disposition="blocked", redacted_field_names=["report_text"],
                  action_codes=["NER_UNRESOLVED"]))
    stored = log.get("req-1")[0]
    assert stored.redacted_field_names == ["report_text"]
    assert stored.action_codes == ["NER_UNRESOLVED"]
    assert set(stored.model_dump()) == ALLOWED_AUDIT_FIELDS


def test_a_record_read_back_re_hashes_to_the_same_value(log):
    # A round trip through the database must not change the hash, or every
    # re-read would look like tampering. This is what pins the stored encodings
    # — the timestamp as canonical ISO-8601 text, the lists as canonical JSON —
    # to the encoding the chain is computed over.
    log.append(ev())
    stored = log.get("req-1")[0]
    assert stored.timestamp == NOW
    assert chain_hash(stored.model_dump(exclude={"chain_hash"}), GENESIS, KEY) \
        == stored.chain_hash


def test_a_human_approval_round_trips_without_changing_the_chain(tmp_path):
    url = f"sqlite:///{tmp_path / 'a.db'}"
    a = AuditLog(url, KEY)
    b = AuditLog(url, KEY)
    try:
        a.append(ev(human_approval=HumanApproval(decision="approved", recorded_at=NOW,
                                                 reviewer="clinician-a")))
        stored = b.get("req-1")[0]
        assert stored.human_approval is not None
        assert stored.human_approval.decision == "approved"
        assert stored.human_approval.recorded_at == NOW
        assert b.verify_chain().ok
    finally:
        a.close()
        b.close()


# -- Canonical encoding --------------------------------------------------------


def test_canonical_serialisation_is_key_order_independent():
    a = {"b": 2, "a": 1, "t": NOW}
    b = {"a": 1, "t": NOW, "b": 2}
    assert canonical(a) == canonical(b)


def test_canonical_agrees_with_the_content_hash_encoding_byte_for_byte():
    # `canonical_hash` in models.py is the one content-hash definition. The chain
    # encoder adds the datetime rule on top of the same JSON options, so for any
    # value with no datetime in it the two must produce identical bytes — a
    # second, drifted encoding is exactly what would make a re-read look tampered.
    value = {"b": [1, 2, {"z": None}], "a": "x", "n": 3, "t": True}
    encoded = canonical(value)
    assert encoded == b'{"a":"x","b":[1,2,{"z":null}],"n":3,"t":true}'
    assert hashlib.sha256(encoded).hexdigest() == canonical_hash(value)


def test_canonical_renders_a_datetime_as_utc_iso_with_a_z_suffix():
    assert b'"2026-01-14T12:00:00Z"' in canonical({"t": NOW})
    east = NOW.astimezone(timezone(timedelta(hours=5)))
    assert b'"2026-01-14T12:00:00Z"' in canonical({"t": east})


def test_canonical_refuses_a_naive_datetime():
    # A naive datetime has two readings, and guessing one would bake the guess
    # into the tamper evidence.
    with pytest.raises(ValueError):
        canonical({"t": datetime(2026, 1, 14, 12, 0)})


def test_canonical_refuses_a_value_with_no_defined_encoding():
    # No `default=` fallback: a value with no defined JSON encoding raises rather
    # than being hashed as its `str()`, because the chain's whole claim is that
    # what was hashed is what was meant.
    with pytest.raises(TypeError):
        canonical({"t": object()})


def test_chain_hash_is_keyed_so_the_key_alone_changes_the_digest():
    record = ev().model_dump(exclude={"chain_hash"})
    assert chain_hash(record, GENESIS, KEY) != chain_hash(record, GENESIS, "another-key")
    with pytest.raises(ValueError):
        chain_hash(record, GENESIS, "")


def test_the_log_under_a_different_key_does_not_verify(tmp_path):
    # The property the key buys, executed: someone who can read and rewrite the
    # rows but does not hold `MEDARX_AUDIT_KEY` cannot produce a chain that
    # verifies under the real key, and rewriting the row breaks it for them too.
    url = f"sqlite:///{tmp_path / 'a.db'}"
    writer = AuditLog(url, KEY)
    reader = AuditLog(url, "an-attacker-guess")
    try:
        writer.append(ev())
        with reader.connection() as c:
            c.execute(text("UPDATE audit_event SET final_disposition='blocked'"))
        assert not writer.verify_chain().ok
        assert not reader.verify_chain().ok
    finally:
        writer.close()
        reader.close()


def test_a_party_holding_the_key_can_write_a_chain_that_verifies(tmp_path):
    # The limit, executed rather than asserted in prose. A log built from
    # scratch by someone holding the key verifies perfectly well, so this design
    # detects rewriting, deletion, and reordering by a party *without* the key —
    # and detects nothing against a privileged writer who has it. What closes
    # that gap is external time-stamping, which the design defers to Phase 6.
    # Stated here so no reader mistakes tamper-*evident* for tamper-*proof*.
    forged = AuditLog(f"sqlite:///{tmp_path / 'forged.db'}", KEY)
    honest = AuditLog(f"sqlite:///{tmp_path / 'honest.db'}", KEY)
    try:
        honest.append(ev(final_disposition="approved"))
        forged.append(ev(final_disposition="blocked", action_codes=["NER_UNRESOLVED"]))
        assert forged.verify_chain().ok
        assert honest.verify_chain().ok
    finally:
        forged.close()
        honest.close()


# -- Retention -----------------------------------------------------------------


def test_retention_purges_but_keeps_the_anchor_ordinal(log):
    log.append(ev(timestamp=NOW))
    n = log.purge_expired(now=NOW + timedelta(days=3650), retention_days=2555)
    assert n >= 1
    assert log.verify_chain().ok


def test_a_purged_record_becomes_a_tombstone_that_still_verifies(log):
    # The brief's "a purged row leaves a tombstone ordinal": a tombstone is a
    # row in its own table carrying the position and the chain fields, not a
    # flag on the record it replaced.
    log.append(ev(request_id="r1"))
    log.append(ev(request_id="r2", timestamp=NOW + timedelta(days=1000)))
    assert log.purge_expired(now=NOW + timedelta(days=3000), retention_days=2555) == 1
    assert log.get("r1") == []
    assert log.get("r2") != []
    with log.connection() as c:
        gone = c.execute(text("SELECT count(*) FROM audit_event "
                              "WHERE request_id='r1'")).scalar_one()
        tomb = c.execute(text("SELECT ordinal, previous_hash, chain_hash, purged_at, "
                              "retention_cutoff FROM audit_tombstone")).one()
    assert gone == 0
    assert tomb.ordinal == 1 and tomb.previous_hash == GENESIS
    assert tomb.purged_at and tomb.retention_cutoff
    r = log.verify_chain()
    assert r.ok and r.checked == 2, "a tombstone verifies by the same rule as a record"


def test_a_purge_re_chains_everything_after_it(log):
    # The purge is a re-chain, not an edit: the record after the purged one gets
    # a new previous hash and a new digest, because the tombstone took its place.
    log.append(ev(request_id="r1"))
    before = log.append(ev(request_id="r2", timestamp=NOW + timedelta(days=1000)))
    assert log.purge_expired(now=NOW + timedelta(days=3000), retention_days=2555) == 1
    after = log.get("r2")[0]
    assert after.previous_hash != before.previous_hash
    assert after.chain_hash != before.chain_hash
    assert after.previous_hash == log.get("r2")[0].previous_hash
    assert log.verify_chain().ok


def test_two_purges_in_one_pass_still_verify(log):
    log.append(ev(request_id="r1"))
    log.append(ev(request_id="r2", timestamp=NOW + timedelta(days=1)))
    log.append(ev(request_id="r3", timestamp=NOW + timedelta(days=1000)))
    assert log.purge_expired(now=NOW + timedelta(days=3000), retention_days=2555) == 2
    assert log.get("r3") != []
    r = log.verify_chain()
    assert r.ok and r.checked == 3


def test_retention_keeps_a_record_inside_the_window(log):
    log.append(ev(timestamp=NOW))
    assert log.purge_expired(now=NOW + timedelta(days=1000), retention_days=2555) == 0
    assert log.get("req-1") != []


def test_retention_refuses_a_non_positive_window(log):
    # "Keep nothing" is a configuration mistake that looks like it worked, and
    # it is a configuration mistake rather than a privacy block — so it is a
    # ValueError, refused before anything is deleted.
    log.append(ev(timestamp=NOW))
    for window in (0, -1):
        with pytest.raises(ValueError):
            log.purge_expired(now=NOW, retention_days=window)
    assert log.get("req-1") != []


# -- The empty key -------------------------------------------------------------


def test_an_empty_audit_key_is_refused_before_any_file_is_created(tmp_path):
    # The same reasoning as the mapping store: a misconfiguration is not a
    # privacy block, so it is a ValueError outside the MedarxError taxonomy.
    # Reporting it as a 422 would write a false privacy event into the very log
    # that is supposed to be the trustworthy one.
    url = f"sqlite:///{tmp_path / 'a.db'}"
    with pytest.raises(AuditKeyRequired) as ei:
        AuditLog(url, "")
    assert not isinstance(ei.value, MedarxError)
    assert "MEDARX_AUDIT_KEY" in str(ei.value)
    assert not (tmp_path / "a.db").exists(), "no connection may be opened first"


# -- The stage vocabulary (the UI's fixed timeline) -----------------------------


@pytest.mark.parametrize("stage", DRAWER_STAGES)
def test_every_drawer_stage_is_a_contract_member(stage):
    # Member by member, against a hand-written copy of the timeline — not against
    # component G's constant, which would only restate G's own definition.
    assert stage in _contract_schema("PipelineStage")["enum"]


def test_the_contract_publishes_the_drawer_timeline_in_order_and_nothing_else():
    assert list(_contract_schema("PipelineStage")["enum"]) == list(DRAWER_STAGES)


def test_component_g_publishes_the_stages_in_the_same_order():
    assert list(PIPELINE_STAGES) == list(DRAWER_STAGES)


def test_every_stage_names_a_layer_the_kernel_actually_has():
    # The ruling asked for this to be checked rather than assumed: a stage
    # naming a component the kernel does not have would be a stage invented to
    # fill a slot. `LAYERS` is itself pinned to the contract's `Layer` enum.
    assert set(STAGE_COMPONENTS) == set(PIPELINE_STAGES)
    for stage, components in STAGE_COMPONENTS.items():
        assert components, f"{stage!r} names no component"
        assert set(components) <= set(LAYERS), (
            f"{stage!r} names a component outside the kernel's layer set: "
            f"{sorted(set(components) - set(LAYERS))}"
        )


# -- G's action-code table -----------------------------------------------------


def _literals(node: ast.AST) -> list[str]:
    return [n.value for n in ast.walk(node)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)]


def _emitted_codes() -> dict[str, list[str]]:
    """Every code the package can emit, keyed by source file: G's table vs reality."""
    found: dict[str, list[str]] = {}
    for path in sorted(SOURCE_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        codes: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and "ACTION_CODE" in t.id.upper()
                for t in node.targets
            ):
                codes.extend(_literals(node.value))
            elif isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg == "action_codes":
                        codes.extend(_literals(kw.value))
        if codes:
            found[str(path.relative_to(REPO_ROOT))] = codes
    return found


def test_the_code_table_covers_exactly_the_contract_enum():
    # Two hand-maintained lists that have to agree: the contract enum and the
    # table component G owns.
    assert sorted(e.code for e in CODE_TABLE) == sorted(_contract_schema("ActionCode")["enum"])


def test_the_codes_the_package_emits_are_all_in_the_code_table():
    emitted = _emitted_codes()
    assert emitted, "the emission sweep found nothing; it is broken"
    missing = sorted({c for codes in emitted.values() for c in codes}
                     - {e.code for e in CODE_TABLE})
    assert not missing, f"emitted codes with no row in G's table: {missing}"


def test_every_code_the_table_attributes_names_only_real_layers():
    for entry in CODE_TABLE:
        assert set(entry.owners) <= set(LAYERS), (
            f"{entry.code} names an owner outside the kernel's layer set: "
            f"{sorted(set(entry.owners) - set(LAYERS))}"
        )


def test_hash_mismatch_belongs_to_the_gateway_and_not_to_layer_three():
    # Design §6 row 5 lists "hash mismatch" among layer 3's block conditions, and
    # the contract's own row-5 example summary repeats the words. The kernel does
    # not implement it that way: layer 3 *overwrites* `payload_hash` rather than
    # comparing it — proved by execution in tests/test_redaction_layers.py,
    # in test_layer3_overwrites_the_pre_redaction_hash_rather_than_trusting_it —
    # and the comparison happens in the gateway. So there is no D.3 hash-mismatch
    # code, and a future reader must not go looking for one.
    entry = next(e for e in CODE_TABLE if e.code == "HASH_MISMATCH")
    assert entry.owners == ("F",)

    emitted = _emitted_codes()
    sites = sorted(p for p, codes in emitted.items() if "HASH_MISMATCH" in codes)
    assert sites == ["backend/src/medarx/gateway/openai_gateway.py"]


def test_the_codes_nothing_emits_are_exactly_the_unwritten_ones():
    # The rows with no owner are the ones Phase 1 has not written: the four
    # request-shape codes belong to component J, which does not exist yet, and
    # `UNRESOLVED_DISPOSITION` is a declared-but-unemitted member whose retention
    # is argued in the table itself and pinned in
    # `tests/test_contract_schemas.py::_NOT_YET_EMITTED`.
    no_owner = sorted(e.code for e in CODE_TABLE if not e.owners)
    assert no_owner == [
        "ARBITRARY_DICOM_OBJECT_REJECTED",
        "FREE_FORM_PROMPT_REJECTED",
        "FUNCTION_NOT_PERMITTED",
        "UNAUTHORIZED_SCOPE",
        "UNRESOLVED_DISPOSITION",
    ]


# -- The one schema-init command ------------------------------------------------


def test_schema_init_creates_the_whole_phase_one_store(tmp_path):
    url = f"sqlite:///{tmp_path / 'store.db'}"
    assert schema_init_main(["--db-url", url]) == 0
    engine = create_engine(url)
    try:
        names = set(inspect(engine).get_table_names())
    finally:
        engine.dispose()
    assert {"audit_event", "audit_tombstone", "audit_chain_head",
            "pseudonym_study", "pseudonym_patient"} <= names


def test_schema_init_is_idempotent(tmp_path):
    url = f"sqlite:///{tmp_path / 'store.db'}"
    assert schema_init_main(["--db-url", url]) == 0
    assert schema_init_main(["--db-url", url]) == 0


def test_schema_init_refuses_without_a_database_url():
    # No module but config.py may read the environment, so the URL cannot come
    # from one; it is an argument, or the command has nothing to act on.
    assert schema_init_main([]) == 2


def test_the_tables_schema_init_creates_are_the_ones_the_stores_use(tmp_path):
    url = f"sqlite:///{tmp_path / 'store.db'}"
    schema_init_main(["--db-url", url])
    store = AuditLog(url, KEY)
    try:
        store.append(ev())
        assert store.verify_chain().ok
    finally:
        store.close()


# -- The two attacks the first round of this component let through ---------------


def test_a_keyless_writer_cannot_hide_a_rewrite_behind_a_purge_flag(log):
    # The attack, executed: rewrite a record's disposition *and* mark it purged,
    # which under the first design made verification skip the record entirely.
    # There is no flag to set now — a purge is a tombstone whose digest is keyed
    # — so the only thing this tamper can do is break the chain, which is the
    # point.
    log.append(ev(request_id="r1"))
    log.append(ev(request_id="r2", final_disposition="blocked"))
    log.append(ev(request_id="r3"))
    with log.connection() as c:
        c.execute(text("UPDATE audit_event SET final_disposition='approved', "
                       "action_codes='[]' WHERE request_id='r2'"))
        # The attacker's best move if a flag existed. There is no such column,
        # so assert that as well as the outcome.
        columns = {row[1] for row in c.execute(text("PRAGMA table_info(audit_event)"))}
    assert "purged" not in columns
    r = log.verify_chain()
    assert not r.ok and r.broken_at_index == 1


def test_a_keyless_writer_cannot_authorise_a_deletion_with_a_tombstone(log):
    # A forged tombstone is a keyed digest of a blanked record, which is exactly
    # what they cannot produce.
    log.append(ev(request_id="r1"))
    log.append(ev(request_id="r2", timestamp=NOW + timedelta(days=1000)))
    with log.connection() as c:
        c.execute(text("DELETE FROM audit_event WHERE request_id='r1'"))
        c.execute(text("INSERT INTO audit_tombstone "
                       "(ordinal, previous_hash, chain_hash, purged_at, retention_cutoff) "
                       "VALUES (1, :p, :h, :a, :a)").bindparams(
                           p=GENESIS, h="0" * 64, a=NOW_TEXT))
    r = log.verify_chain()
    assert not r.ok, "a forged tombstone must not verify"


def test_deleting_the_tail_and_repointing_the_anchor_is_detected(log):
    # C2's attack, executed. Repointing the anchor at the surviving head is what
    # makes the remaining chain verify; it is only possible because the anchor
    # used to be a plain row. The anchor is now MACed with the audit key, so the
    # repoint no longer matches and the chain fails.
    log.append(ev(request_id="r1"))
    log.append(ev(request_id="r2"))
    with log.connection() as c:
        c.execute(text("DELETE FROM audit_event WHERE ordinal=2"))
        c.execute(text("UPDATE audit_chain_head SET head_hash="
                       "(SELECT chain_hash FROM audit_event WHERE ordinal=1), "
                       "row_count=1"))
    r = log.verify_chain()
    assert not r.ok and r.broken_at_index == r.checked == 1


def test_deleting_the_log_and_resetting_the_anchor_is_detected(log):
    log.append(ev(request_id="r1"))
    log.append(ev(request_id="r2"))
    with log.connection() as c:
        c.execute(text("DELETE FROM audit_event"))
        c.execute(text("DELETE FROM audit_tombstone"))
        c.execute(text("UPDATE audit_chain_head SET head_hash=:g, row_count=0"),
                  {"g": GENESIS})
    assert not log.verify_chain().ok


def test_deleting_the_anchor_row_itself_is_detected(log):
    # Verification fails closed when the anchor is gone and records remain: an
    # absent anchor is a fresh database, and this one is not.
    log.append(ev(request_id="r1"))
    with log.connection() as c:
        c.execute(text("DELETE FROM audit_chain_head"))
    r = log.verify_chain()
    assert not r.ok and r.checked == 0 and r.broken_at_index == 0


def test_an_empty_database_with_no_anchor_verifies(log):
    assert log.verify_chain().ok


def test_a_whole_database_deletion_is_the_one_thing_the_anchor_cannot_see(tmp_path):
    # Stated as a test so it stays stated: with every table emptied *and* the
    # anchor gone, a reader with no external copy of the head sees an empty log
    # that verifies. Nothing inside the database can distinguish it from one that
    # was never written. That is what external time-stamping is for (Phase 6).
    url = f"sqlite:///{tmp_path / 'a.db'}"
    log = AuditLog(url, KEY)
    try:
        log.append(ev(request_id="r1"))
        with log.connection() as c:
            c.execute(text("DELETE FROM audit_event"))
            c.execute(text("DELETE FROM audit_tombstone"))
            c.execute(text("DELETE FROM audit_chain_head"))
        assert log.verify_chain().ok, (
            "this is the documented limit, not a fixable defect: a reader with no "
            "external copy of the head cannot tell an emptied log from an empty one"
        )
    finally:
        log.close()


# -- Values in fields that should hold names ------------------------------------


@pytest.mark.parametrize("field,value", [
    ("redacted_field_names", ["MRN 4452819 belongs to John Smith, DOB 1961-04-02"]),
    ("redacted_field_names", ["report_text for John Smith"]),
    ("function", "draft for John Smith"),
    ("policy_version", "medarx policy 1.0.0 for John Smith"),
    ("request_id", "7f3c1a90 2b6e John Smith"),
    ("input_hash", "the report said the patient was John Smith"),
    ("approved_payload_hash", "h0"),
])
def test_a_value_where_a_name_belongs_is_refused(log, field, value):
    with pytest.raises(ValueError) as ei:
        log.append(ev(**{field: value}))
    assert field in str(ei.value)
    assert log.get("req-1") == []


def test_a_reviewer_naming_a_person_is_refused(log):
    approval = HumanApproval(decision="approved", recorded_at=NOW,
                             reviewer="Dr John Smith")
    with pytest.raises(ValueError):
        log.append(ev(human_approval=approval))
    assert log.get("req-1") == []


def test_a_dotted_field_name_is_accepted(log):
    # The gate is a shape, not a keyword list: `dicom_metadata.patient_id` is a
    # field name and is exactly what this field is for.
    log.append(ev(redacted_field_names=["report_text", "dicom_metadata.patient_id"]))
    assert log.get("req-1")[0].redacted_field_names == [
        "report_text", "dicom_metadata.patient_id"]


# -- Stage and layer are different axes ----------------------------------------


def test_an_approved_record_reached_every_stage(log):
    # `layer` is absent when nothing refused it, which is the approved case.
    stored = log.append(ev(final_disposition="approved"))
    assert stored.layer is None
    assert log.stages_for(stored) == DRAWER_STAGES


def test_a_d2_block_reached_three_stages_and_no_model_request(log):
    # Stage says how far it got; layer says who refused. A D.2 block never
    # reached E or F, and neither axis is derivable from the other.
    stored = log.append(ev(final_disposition="blocked", layer="D.2",
                           approved_payload_hash=None,
                           action_codes=["NER_UNRESOLVED"]))
    assert stored.layer == "D.2"
    assert log.stages_for(stored) == (
        "Fields selected", "Pseudonymized", "Text screened")


def test_the_request_surface_reached_no_stage_at_all(log):
    stored = log.append(ev(final_disposition="blocked", layer="J",
                           approved_payload_hash=None,
                           action_codes=["ARBITRARY_DICOM_OBJECT_REJECTED"]))
    assert log.stages_for(stored) == ()


def test_the_layer_to_stage_map_is_derived_not_hand_written():
    # One table, one direction of maintenance: an added D.4 has to be given a
    # stage in `STAGE_COMPONENTS`, and the inverse follows without anyone
    # remembering to update it.
    assert LAYER_STAGE == {"A": "Fields selected", "C": "Pseudonymized",
                           "D.1": "Text screened", "D.2": "Text screened",
                           "D.3": "Payload validated", "E": "Policy decision",
                           "F": "Model request"}
    assert set(LAYER_STAGE) == set(LAYERS) - {"J"}
    for stage, components in STAGE_COMPONENTS.items():
        for layer in components:
            assert LAYER_STAGE[layer] == stage


def test_the_stages_projection_covers_every_layer_that_has_one():
    covered = {stages_reached(layer) for layer in LAYERS}
    assert () in covered, "J has no stage and must project to none"
    assert PIPELINE_STAGES in covered, "an approved request reaches every stage"
    for layer in LAYERS:
        stages = stages_reached(layer)
        assert list(stages) == list(PIPELINE_STAGES[: len(stages)]), (
            f"{layer} projects a non-prefix of the pipeline: {stages}"
        )


def test_the_record_carries_a_layer_but_never_a_stored_stage(log):
    # Nothing about the stage list is stored: the chain body is exactly the
    # record's own fields, so adding the projection re-chains nothing.
    stored = log.append(ev(layer="E", final_disposition="blocked",
                           approved_payload_hash=None,
                           action_codes=["UNKNOWN_POLICY_VERSION"]))
    assert set(stored.model_dump()) == ALLOWED_AUDIT_FIELDS
    assert "stages" not in stored.model_dump()
    assert log.verify_chain().ok


def test_a_layer_the_kernel_does_not_have_is_refused(log):
    with pytest.raises(ValueError):
        ev(layer="D")


# -- Concurrency ----------------------------------------------------------------


def test_concurrent_appends_do_not_fork_the_chain(tmp_path):
    # A deferred transaction locks nothing until its first write and the head is
    # *read* before the insert, so without serialisation two appends read the
    # same head and the chain forks. The first round of this component claimed
    # the opposite; the suite reproduced twenty forked records with no error.
    log = AuditLog(f"sqlite:///{tmp_path / 'a.db'}", KEY)
    errors: list[Exception] = []

    def worker(n: int) -> None:
        try:
            for i in range(5):
                log.append(ev(request_id=f"r{n}-{i}",
                              timestamp=NOW + timedelta(seconds=n * 10 + i)))
        except Exception as exc:  # noqa: BLE001 - the assertion is about the chain
            errors.append(exc)

    try:
        threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert not errors, errors
        r = log.verify_chain()
        assert r.ok and r.checked == 20, r
    finally:
        log.close()
