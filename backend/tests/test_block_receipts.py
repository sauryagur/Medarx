"""The block receipt is the only body a blocked caller receives.

Two rules are asserted separately here, because one test asserting both proves
neither: a receipt rejects a field that is not on the contract schema, and it
rejects an action code that carries a raw value.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from medarx.errors import AuthzError, MedarxError, PolicyError
from medarx.models import BlockReceipt


def test_block_receipt_has_exactly_the_five_contract_keys():
    r = BlockReceipt(request_id="req-1", layer="D.2", action_codes=["NER_UNRESOLVED"],
                     policy_version="medarx-policy-1.0.0")
    assert r.status == "blocked"
    assert set(r.model_dump()) == {"status", "request_id", "layer", "action_codes", "policy_version"}


def test_a_receipt_rejects_an_unknown_field():
    with pytest.raises(ValidationError):
        BlockReceipt(request_id="req-1", layer="D.2", action_codes=["NER_UNRESOLVED"],
                     policy_version="medarx-policy-1.0.0", note="Leaked Value")


def test_a_receipt_rejects_an_action_code_that_carries_a_raw_value():
    with pytest.raises(ValidationError):
        BlockReceipt(request_id="req-1", layer="D.2", action_codes=["MRN 4452819"],
                     policy_version="medarx-policy-1.0.0")


def test_policy_error_carries_layer_e():
    err = PolicyError(action_codes=("UNKNOWN_POLICY_VERSION",))
    assert err.layer == "E"
    assert err.action_codes == ("UNKNOWN_POLICY_VERSION",)


def test_a_receipt_rejects_an_empty_action_code_list():
    # The contract sets minItems: 1. An empty list would assert a refusal that
    # names no disposition, which is not what happened.
    with pytest.raises(ValidationError):
        BlockReceipt(request_id="req-1", layer="E", action_codes=[],
                     policy_version="medarx-policy-1.0.0")


def test_authz_error_is_not_a_privacy_block():
    # 403 vs 422 is load-bearing: an authorization failure must never be
    # renderable as a block receipt, so this type stays outside MedarxError and
    # carries no layer and no action codes.
    assert not issubclass(AuthzError, MedarxError)
    err = AuthzError("out of scope")
    assert not hasattr(err, "layer")
    assert not hasattr(err, "action_codes")


def test_a_receipt_rejects_an_action_code_that_carries_a_digit_run():
    # The prefix-plus-digits form is the one that got through before: a medical
    # record number is digits, so a code that permits digits permits PHI wearing
    # a classifier's clothes.
    with pytest.raises(ValidationError):
        BlockReceipt(request_id="req-1", layer="D.2", action_codes=["MRN4452819"],
                     policy_version="medarx-policy-1.0.0")


def test_a_receipt_rejects_a_code_with_a_trailing_newline():
    # A newline inside a code that is logged is a log-injection primitive, and
    # `$` in the pattern used to match before one.
    with pytest.raises(ValidationError):
        BlockReceipt(request_id="req-1", layer="D.2", action_codes=["NER_UNRESOLVED\n"],
                     policy_version="medarx-policy-1.0.0")


def test_a_receipt_accepts_a_real_contract_action_code():
    # So the rejection tests cannot pass by rejecting everything: a genuine
    # member of the contract's ActionCode enum still builds.
    r = BlockReceipt(request_id="req-1", layer="D.3",
                     action_codes=["LEFTOVER_PATTERN_MATCH", "UNSHIFTED_DATE"],
                     policy_version="medarx-policy-1.0.0")
    assert r.action_codes == ["LEFTOVER_PATTERN_MATCH", "UNSHIFTED_DATE"]


def test_an_error_rejects_a_bare_d_layer():
    # There is no bare "D": the three redaction layers are tagged individually.
    # The base class is where that is enforced, so an error cannot be built
    # carrying a layer tag the contract does not have.
    with pytest.raises(ValueError):
        PolicyError(action_codes=("UNRESOLVED_DISPOSITION",), layer="D")


def test_an_error_rejects_an_action_code_that_carries_a_digit_run():
    with pytest.raises(ValueError):
        PolicyError(action_codes=("MRN4452819",))


def test_a_well_formed_error_constructs():
    err = PolicyError(action_codes=("UNKNOWN_POLICY_VERSION",), message="no such policy")
    assert (err.layer, err.action_codes) == ("E", ("UNKNOWN_POLICY_VERSION",))
