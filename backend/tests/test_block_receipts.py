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
