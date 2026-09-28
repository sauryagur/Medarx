"""Component I, the byte-level comparison: observer against observer, and both
against the approved hash.

Two separate questions, deliberately two separate fields, because collapsing
them is the failure this component exists to prevent:

- **Did the two observers see the same bytes?** (`observer_bytes_match`)
- **Were those bytes the approved ones?** (`hash_matches`)

A `True` on the first and a `False` on the second is the whole leak shape of
this project: the observer on disk and the frames on the wire agree perfectly
with each other about a payload nobody approved. That is the state in which a
check written as "do the observers agree?" certifies a leak, and it is why the
second field is not derived from the first.

No container, no socket, no capture: this module is the arithmetic the other
tests rely on, and it has to be checkable on its own or nothing above it is.
"""

from __future__ import annotations

import hashlib

from infra.capture.agreement import compare_bytes_to_payload

#: A body shaped like the one the gateway encodes, including the two messages
#: the orchestrator actually builds — a system prompt and a user message.
BODY = (b'{"model":"medarx-demo-model","messages":[{"role":"system","content":"S"},'
        b'{"role":"user","content":"FINDINGS: 7mm nodule."}],"temperature":0.0,'
        b'"max_tokens":512}')


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# -- The three cases the task specifies --------------------------------------


def test_recorded_bytes_match_the_approved_payload_bytes():
    payload = (b'{"model":"medarx-demo-model","messages":'
               b'[{"role":"user","content":"FINDINGS: 7mm nodule."}]}')
    r = compare_bytes_to_payload(payload, payload, hashlib.sha256(payload).hexdigest())
    assert r.observer_bytes_match is True
    assert r.hash_matches is True
    assert r.differences == []


def test_a_single_extra_byte_fails_the_comparison():
    payload = b'{"model":"medarx-demo-model"}'
    r = compare_bytes_to_payload(payload, payload + b" ", hashlib.sha256(payload).hexdigest())
    assert r.observer_bytes_match is False


def test_hash_mismatch_is_reported_separately():
    r = compare_bytes_to_payload(b"x", b"x", hashlib.sha256(b"different").hexdigest())
    assert r.observer_bytes_match is True and r.hash_matches is False


# -- The two fields must be able to disagree in either direction --------------


def test_observers_that_agree_on_unapproved_bytes_do_not_report_agreement():
    """The leak shape: both observers saw the same wrong thing.

    This is the case the field split exists for. If `hash_matches` were derived
    from `observer_bytes_match`, or if the caller only read the first field,
    this is the input that certifies a substituted payload as approved.
    """
    substituted = BODY.replace(b"7mm nodule", b"12mm mass")
    r = compare_bytes_to_payload(substituted, substituted, digest(BODY))
    assert r.observer_bytes_match is True, "the two observers do agree with each other"
    assert r.hash_matches is False, "and what they agree on is not the approved payload"


def test_a_substitution_is_reported_with_the_offset_of_the_first_difference():
    """A same-length substitution is a byte-level fact and is located as one.

    Length alone cannot report it: a payload with one field replaced by a
    different value of the same width has the same length as the original, and
    a check that compared sizes would call that agreement.
    """
    substituted = BODY.replace(b"7mm nodule", b"9mm nodule")
    assert len(substituted) == len(BODY)
    r = compare_bytes_to_payload(BODY, substituted, digest(BODY))
    assert r.observer_bytes_match is False
    assert r.differences, "a difference must be described, not merely counted"
    reported = " ".join(r.differences)
    assert str(BODY.index(b"7mm nodule")) in reported, (
        f"the reported difference must name the first differing offset, got {r.differences}"
    )


def test_a_length_difference_is_described_and_never_passes():
    r = compare_bytes_to_payload(BODY, BODY + b" ", digest(BODY))
    assert r.observer_bytes_match is False
    assert r.hash_matches is True, (
        "the observer's own bytes are the approved ones; the *capture* is the "
        "one carrying the extra byte, and the two questions are separate"
    )
    assert r.differences


def test_two_empty_observers_agree_but_match_no_approved_hash():
    """Zero bytes on both sides is agreement about emptiness, and nothing more.

    Stated here because it is the shape the blocked-path rule has to special
    case: `observer_bytes_match` is true for two empty records, so any caller
    that reads only that field scores a request that sent nothing as verified.
    """
    r = compare_bytes_to_payload(b"", b"", digest(BODY))
    assert r.observer_bytes_match is True
    assert r.hash_matches is False
    assert r.differences


def test_the_comparison_names_which_side_diverged():
    """`differences` names the diverging side, so a report reads unambiguously.

    Not cosmetic: the blocked-path demo and the substituted-payload demo
    produce opposite asymmetries, and a reader deciding which observer diverged
    should not have to re-derive it from the argument order.
    """
    capture_longer = compare_bytes_to_payload(BODY, BODY + b"x", digest(BODY))
    observer_longer = compare_bytes_to_payload(BODY + b"x", BODY, digest(BODY))
    assert capture_longer.differences != observer_longer.differences
    assert any(d.startswith("capture-only:") for d in capture_longer.differences)
    assert any(d.startswith("observer-only:") for d in observer_longer.differences)
