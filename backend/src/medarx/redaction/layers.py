"""Redaction layers 1–3: the transformations and the checks that police them.

Three layers, three jobs, one direction. Layer 1 deals with the payload's
*structured* content — the references and the dates, which have known shapes
and known correct replacements. Layer 2 deals with free text, where the only
defensible moves are "replace with something the replacer table sanctions" and
"block". Layer 3 does not transform anything: it re-reads the payload the first
two produced and refuses it if it no longer satisfies the contract the earlier
components agreed to.

The one rule the whole module is arranged around:

    **A block comes from the absence of a safe replacement, not from a score.**

Layer 2's scan is called with `min_score=0.0` so a candidate is *seen* rather
than filtered away, and an entity with no registered replacer is unresolved at
any score whatsoever. That is not a stylistic preference. `AMBIGUOUS_REFERENCE`
is detected at 0.30, below `Settings.ner_score_threshold` (0.50), and the
measurement in `recognizers.py` records what happens if a context-aware
enhancer is ever attached to the engine: the same value scores **0.65** in
"ZX-99-ALPHA issued at the counter.", because `ref`, `ticket` and `issued` are
all in that sentence. Enhancement is **not** switched off here, and must never
be assumed to be: `AnalyzerEngine._enhance_using_context` calls the engine's
`LemmaContextAwareEnhancer` unconditionally — the pinned Presidio's
`AnalyzerEngine.__init__` has no `context_aware_config` parameter to pass, and
the shipped engine supplies none. The only thing holding
`AMBIGUOUS_REFERENCE` at its 0.30 floor is the *empty declared context* its
recognizer is built with (`UNENHANCEABLE_CONTEXT`); attach `ref`, `ticket` or
`issued` and the same sentence scores 0.65. The scores observed through
`scan_entities` are therefore **not** the recognizers' floors: measured,
`ACC0000417` returns at 1.00 and `MRN: 4452819` at 1.00, because `acc` and
`mrn` are declared context words occurring inside the value and its field.
Nothing may be keyed on a score. A block keyed on the threshold would have
become a silent pass-through the moment a recognizer gained a context word,
with every test still green. `replacers.has_replacer` is therefore asked
*before* the threshold is consulted, and never after.

`Settings.ner_score_threshold` still has a job: it decides whether a
*replaceable* detection is acted on at all. A hit below it is not replaced,
because applying a replacement on the strength of a detection the engine is not
sure about is redaction by guessing. It is reported and the payload blocks --
under `LOW_CONFIDENCE_NER_UNRESOLVED`, its own wire code, and it is the one
condition in this module that a configuration change can move.

That separate code is not cosmetic. `Disposition.entity` used to be the only
thing distinguishing the two blocks, and it reaches no durable record:
`BlockReceipt` has five fields and none is the entity, and `AuditRecord` has no
such field. A no-replacer block and a sub-threshold block therefore serialised
to byte-identical receipts, which leaves the audit log unable to say whether a
refusal was a coverage gap (needs a replacer) or a tuning problem (needs a
threshold). An audit record that cannot distinguish two refusal reasons is a
false record.

**Relative intervals are passed through.** A count of a named unit, a bare
relative day word, and a clock time name no date, so there is nothing to shift
and nothing to leak -- the interval between now and six weeks is the same for a
shifted patient as for an unshifted one. The recognised shapes are a closed
list, in `replacers.is_relative_interval`; a shape that is not on it is not
passed through, and there is no fallthrough that turns an unrecognised date
into a pass. Measured over 28 sentences of ordinary radiology prose, this took
the approved rate from 14/28 to 24/28, and to 26/28 once `Settings.date_order`
is declared.

**Wire codes versus internal codes.** `Disposition.action_code` carries either.
An *unresolved* or otherwise anomalous disposition carries a member of the
contract's `ActionCode` enum, because it reaches a block receipt and an audit
record. A disposition recording that a replacement *succeeded* carries an
internal code (`REDACT_LAYER1_REPLACED`, `REDACT_LAYER2_REPLACED`) which is
never serialised, and is named without the `ACTION_CODE` substring so the
contract sweep in `tests/test_openapi_contract.py` does not mistake it for an
emission site.

**What a disposition never carries.** No matched value. It names the field and
the entity kind; the text a detector matched stays in the payload and goes out
of scope with it, so the audit log cannot become the second PHI store the
storage policy forbids.

Every layer returns a *new* payload. `StructuredPayload` is frozen, so a layer
cannot mutate its input even by accident, and `model_copy` means a blocked run
leaves the caller's payload exactly as it arrived.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from medarx.config import Settings
from medarx.extraction.allowlists import ALLOWED_FIELDS
from medarx.models import LAYERS, StructuredPayload, payload_hash_of
from medarx.pseudonym.mapping_store import MappingStore
from medarx.pseudonym.pseudonymize import SURROGATE_SHAPE, shift_dicom_date
from medarx.redaction.ner import TRUNCATED_TEXT, EntityHit, scan_entities
from medarx.redaction.recognizers import PATTERNS, REGEX_FLAGS, strip_anchor_labels
from medarx.redaction.replacers import (
    ReplacerContext,
    has_replacer,
    is_absolute_date,
    is_relative_interval,
    replacement_for,
)

__all__ = [
    "Disposition",
    "RedactionContext",
    "layer1_deterministic",
    "layer2_ner",
    "layer3_validation",
]

# -- The action codes this module emits -------------------------------------
#
# Named with `ACTION_CODE` in the identifier so the AST sweep in
# `tests/test_openapi_contract.py` finds them and checks each against the
# contract's `ActionCode` enum. A new code that is not in the contract fails
# there rather than shipping in a receipt.

_ACTION_CODE_NER_UNRESOLVED = "NER_UNRESOLVED"
_ACTION_CODE_LOW_CONFIDENCE = "LOW_CONFIDENCE_NER_UNRESOLVED"
_ACTION_CODE_UNSHIFTED_DATE = "UNSHIFTED_DATE"
_ACTION_CODE_UNRESOLVED_EMPTY_BODY = "UNRESOLVED_EMPTY_BODY"
_ACTION_CODE_DETERMINISTIC_REPLACEMENT_FAILED = "DETERMINISTIC_REPLACEMENT_FAILED"
_ACTION_CODE_MISSING_SURROGATE = "MISSING_SURROGATE"
_ACTION_CODE_FIELD_NOT_ALLOWLISTED = "FIELD_NOT_ALLOWLISTED"
_ACTION_CODE_UNKNOWN_FUNCTION = "UNKNOWN_FUNCTION"
_ACTION_CODE_CONTRACT_VIOLATION = "CONTRACT_VIOLATION"
_ACTION_CODE_LEFTOVER_PATTERN_MATCH = "LEFTOVER_PATTERN_MATCH"

#: Internal, never serialised: these record that a replacement happened.
_REPLACED_LAYER1 = "REDACT_LAYER1_REPLACED"
_REPLACED_LAYER2 = "REDACT_LAYER2_REPLACED"

#: A relative interval, carried through unchanged. Not a replacement: the text
#: that came in is the text that goes out.
_PASSTHROUGH_INTERVAL = "REDACT_LAYER2_INTERVAL_PASSTHROUGH"

#: The payload fields component C shifts, named rather than pattern-matched.
#: Component C holds the same list privately; the check here is against the
#: *contract's* date fields, and a field with a date in it that neither list
#: names is a field whose shift nobody is checking.
_DATE_FIELDS = ("study_date", "prior_study_date")

#: The dicom fields whose values are **prose**, and so are scanned for entities.
#:
#: Named explicitly, like component C's date list, and the omission is measured
#: rather than assumed. Scanning the other allowlisted metadata as free text
#: finds `ORGANIZATION` at 0.85 in the modality `CT` and `PHONE_NUMBER` at 0.40
#: in the age band `040-049` — a layer that scanned them would replace a
#: modality with a redaction mask, which is data corruption wearing a pass.
#: `report_text` is the payload's own top-level field and is handled apart.
_TEXT_DICOM_FIELDS = ("prior_report_text",)

#: The layer-1 deterministic patterns, compiled once. Layer 3 re-runs them over
#: the redacted payload, so the check and the recognizers cannot drift: both
#: read this table.
_DETERMINISTIC_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (entity, re.compile(pattern.regex, REGEX_FLAGS))
    for entity, patterns in sorted(PATTERNS.items())
    for pattern in patterns
)

#: Any character that carries meaning once punctuation and spacing are gone.
_MEANINGFUL = re.compile(r"\w", re.UNICODE)


@dataclass(frozen=True)
class Disposition:
    """What one layer did, or could not do, to one field.

    `layer` is a member of the contract's closed `Layer` enum. There is no bare
    `"D"`: the three redaction layers are tagged individually, because a receipt
    that says only "D" cannot say which check refused the request.

    `entity` is the detected entity *kind* (`"MRN"`, `"AMBIGUOUS_REFERENCE"`) or
    `None` when the disposition is about a field rather than a detection. It is
    never the matched value — see the module docstring.

    `resolved` is the only thing a policy decision needs. A disposition with
    `resolved=False` is a block, and its `action_code` is a contract member
    because it reaches the wire.
    """

    layer: str
    field: str
    entity: str | None
    action_code: str
    resolved: bool

    def __post_init__(self) -> None:
        if self.layer not in LAYERS:
            # Refused at construction, not at the receipt: a disposition built
            # with a tag the contract does not have could not be rendered, and
            # the failure would surface far from its cause.
            raise ValueError(
                f"{self.layer!r} is not a layer tag in the contract enum {LAYERS}"
            )


@dataclass(frozen=True)
class RedactionContext:
    """Everything the three layers need that the payload itself does not carry.

    `replacers` holds the patient's already-derived surrogate and shift, so no
    layer reads the audit key or the mapping store's offsets: component C
    decided them, and this only applies them.

    `source` is the payload **as it arrived from component C**, before any
    redaction. It is what makes two of layer 3's checks computable at all. "The
    date was not shifted" and "redaction did not drop a field" are both
    statements about a *difference*, and a difference needs two sides; a layer
    handed only the transformed payload cannot tell a correctly shifted date
    from an untouched one, because after a shift both are simply valid DICOM
    dates. A check that cannot fire is worse than no check, because the design's
    enforcement table lists these as block conditions and a reader would take
    that as evidence they are enforced.
    """

    store: MappingStore
    settings: Settings
    replacers: ReplacerContext
    source: StructuredPayload

    @classmethod
    def for_patient(
        cls,
        source: StructuredPayload,
        patient_ref: str,
        store: MappingStore,
        settings: Settings,
    ) -> RedactionContext:
        """The context for one patient's payload, with the shift read from the
        store rather than supplied by the caller.

        A caller-passed offset would let a test — or a bug — assert a shifted
        date against an offset the store does not use, and the suite would stay
        green while every date in the approved payload was wrong.
        """
        return cls(
            store=store,
            settings=settings,
            replacers=ReplacerContext(
                patient_surrogate=store.surrogate_for_patient(patient_ref),
                offset=store.offset_for_patient(patient_ref),
                date_order=settings.date_order,
            ),
            source=source,
        )


# -- Layer 1 (D.1): the deterministic pass over structured identifiers --------


def layer1_deterministic(
    payload: StructuredPayload, ctx: RedactionContext
) -> tuple[StructuredPayload, list[Disposition]]:
    """Check every reference, and give every date the patient's shift.

    Layer 1 is the deterministic layer: it touches only fields whose correct
    replacement is known from the field's own shape, so nothing here depends on
    a model, a score, or a threshold. It emits one disposition per field it
    *touched* — a field already in its correct state produces nothing, so the
    disposition list is a record of work done rather than a transcript.

    **References are checked, never minted.** Component C assigns surrogates;
    the mapping store is C's, and D's channels in the design are C, E and G —
    not the re-identification key. A reference that arrives without the
    surrogate shape is therefore an unresolved `MISSING_SURROGATE`: a block,
    and the same condition layer 3 independently checks.

    That branch is unreachable on a well-formed run — measured, after
    `pseudonymize_payload` the reference is `medarx-study-6acddd73` and this
    layer changes nothing — and it is a *check* rather than a repair precisely
    because reaching it means component C was skipped, which is not something a
    later layer should paper over by writing to the one store it was told not
    to touch. An earlier version minted the surrogate here, which both crossed
    that boundary and made design §6 row 5's "missing surrogate for a reference"
    block unreachable, since the condition was repaired before it could be
    observed.

    **Dates are shifted when they still equal the value component C saw.** The
    comparison is skipped entirely when the patient's offset is zero, where
    "unchanged" and "shifted" are the same value and the distinction would be a
    guess.
    """
    fields = dict(payload.dicom_fields)
    updates: dict[str, object] = {}
    dispositions: list[Disposition] = []

    disposition = _check_reference("study_ref", payload.study_ref)
    if disposition is not None:
        dispositions.append(disposition)
    for position, value in enumerate(payload.prior_study_refs):
        disposition = _check_reference(f"prior_study_refs[{position}]", value)
        if disposition is not None:
            dispositions.append(disposition)

    for key, value in payload.dicom_fields.items():
        if key not in _DATE_FIELDS:
            continue
        shifted, disposition = _resolve_date(key, value, ctx)
        if disposition is not None:
            dispositions.append(disposition)
        if shifted != value:
            fields[key] = shifted
    if fields != dict(payload.dicom_fields):
        updates["dicom_fields"] = fields

    if not updates:
        return payload, dispositions
    return payload.model_copy(update=updates), dispositions


def _check_reference(field: str, value: str) -> Disposition | None:
    """The refusal for a reference with no surrogate, or `None`.

    One code for both ways a reference can be unusable — blank, or carrying
    something that is not a surrogate — because a receipt cannot tell them apart
    anyway, and a distinction no consumer can act on is noise. Component C
    already reports its two conditions separately (`MISSING_SURROGATE` and
    `SURROGATE_SHAPED_REFERENCE_REJECTED`); by the time a reference reaches
    this layer the only question left is whether it has a surrogate at all.
    """
    if SURROGATE_SHAPE.fullmatch(value):
        return None
    return Disposition(
        layer="D.1", field=field, entity=None,
        action_code=_ACTION_CODE_MISSING_SURROGATE, resolved=False,
    )


def _resolve_date(
    key: str, value: str, ctx: RedactionContext
) -> tuple[str, Disposition | None]:
    """`value` shifted if it was not shifted already, plus a disposition."""
    if not value.strip():
        # Nothing to shift, and nothing to leak: there is no date here.
        return value, None
    if ctx.replacers.offset == 0:
        # A zero shift makes "unchanged" and "shifted" indistinguishable, so
        # the value is already the one the patient is entitled to.
        return value, None
    before = ctx.source.dicom_fields.get(key)
    if before is None or value != before:
        return value, None
    try:
        return shift_dicom_date(value, ctx.replacers.offset), Disposition(
            layer="D.1", field=key, entity=None,
            action_code=_REPLACED_LAYER1, resolved=True,
        )
    except ValueError:
        return value, Disposition(
            layer="D.1", field=key, entity=None,
            action_code=_ACTION_CODE_DETERMINISTIC_REPLACEMENT_FAILED, resolved=False,
        )


# -- Layer 2 (D.2): entity detection in free text ---------------------------


def layer2_ner(
    payload: StructuredPayload, ctx: RedactionContext
) -> tuple[StructuredPayload, list[Disposition]]:
    """Replace what the replacer table sanctions; block on everything else.

    Each text-bearing field is scanned on its own, with `min_score=0.0` so that
    a low-confidence candidate is *seen* rather than filtered away — an
    invisible candidate cannot be blocked. For each detected span:

    * an entity with **no replacer** is unresolved, at any score;
    * an entity **below** `Settings.ner_score_threshold` is unresolved too, and
      nothing is replaced — applying a replacement on a detection the engine is
      not sure about is redaction by guessing;
    * a replacer that **declines this value** (a date that is not a shiftable
      date) is `UNSHIFTED_DATE`;
    * otherwise the span is replaced and the disposition is resolved.

    Two spans, or two labels on one span, are handled without ever dropping a
    detection: at most one replacement is applied per span, and if any label on
    a span is unresolved then *nothing* on that span is replaced and every label
    is reported. Partial sanitisation is the failure this kernel exists to
    prevent, and a detection that is quietly discarded is a block condition that
    would never reach the receipt.

    A field whose content was entirely identifiers and labels — nothing
    clinical left after redaction — is reported as `UNRESOLVED_EMPTY_BODY`. An
    empty result is not a clean result; it is nothing left. An input that was
    already empty is a real report and is left alone.
    """
    fields: dict[str, str] = {"report_text": payload.report_text}
    for key in _TEXT_DICOM_FIELDS:
        if key in payload.dicom_fields:
            fields[f"dicom_fields.{key}"] = payload.dicom_fields[key]

    updates: dict[str, object] = {}
    dispositions: list[Disposition] = []
    redacted_fields = dict(payload.dicom_fields)
    for field, text in fields.items():
        redacted, field_dispositions = _redact_field(field, text, ctx)
        dispositions.extend(field_dispositions)
        if redacted == text:
            continue
        if field == "report_text":
            updates["report_text"] = redacted
        else:
            # Accumulated onto the copy, never rebuilt from the payload: a
            # second redacted field would otherwise overwrite the first, and
            # the lost redaction would be a value sent in the clear.
            redacted_fields[field.split(".", 1)[1]] = redacted
    if redacted_fields != dict(payload.dicom_fields):
        updates["dicom_fields"] = redacted_fields

    if not updates:
        return payload, dispositions
    return payload.model_copy(update=updates), dispositions


def _redact_field(
    field: str, text: str, ctx: RedactionContext
) -> tuple[str, list[Disposition]]:
    """One text field, scanned, judged, and spliced."""
    # Positional on purpose: `min_score` is this layer's decision to see
    # everything, and passing it as a keyword would make that a matter of the
    # callee's parameter names.
    hits = scan_entities(text, 0.0)

    by_span: dict[tuple[int, int], list[EntityHit]] = {}
    for hit in hits:
        by_span.setdefault((hit.start, hit.end), []).append(hit)

    replacements: list[tuple[int, int, str]] = []
    covered: list[tuple[int, int]] = []
    dispositions: list[Disposition] = []
    for span in sorted(by_span):
        judged = [(hit, _judge(hit, ctx)) for hit in by_span[span]]
        if any(not resolved for _, (resolved, _, _) in judged):
            # An ambiguous span is left exactly as it is. Redacting part of a
            # span the kernel cannot read is the guess this table exists to
            # prevent, and a would-be-resolved label on such a span is reported
            # rather than dropped, so no detection disappears without a trace.
            covered.append(span)
            for hit, (resolved, code, _) in judged:
                dispositions.append(Disposition(
                    layer="D.2", field=field, entity=hit.entity_type,
                    action_code=code if not resolved else _ACTION_CODE_NER_UNRESOLVED,
                    resolved=False,
                ))
            continue
        covered.append(span)
        hit, (_, _, replacement) = judged[0]
        replacements.append((span[0], span[1], replacement))
        dispositions.append(Disposition(
            layer="D.2", field=field, entity=hit.entity_type,
            action_code=_REPLACED_LAYER2, resolved=True,
        ))
        for other, _ in judged[1:]:
            dispositions.append(Disposition(
                layer="D.2", field=field, entity=other.entity_type,
                action_code=_ACTION_CODE_NER_UNRESOLVED, resolved=False,
            ))

    # Right to left, so each splice leaves the offsets to its left valid.
    redacted = text
    for start, end, replacement in sorted(replacements, key=lambda item: -item[0]):
        redacted = redacted[:start] + replacement + redacted[end:]

    if covered and not _has_surviving_content(text, covered):
        dispositions.append(Disposition(
            layer="D.2", field=field, entity=None,
            action_code=_ACTION_CODE_UNRESOLVED_EMPTY_BODY, resolved=False,
        ))
    return redacted, dispositions


def _judge(hit: EntityHit, ctx: RedactionContext) -> tuple[bool, str, str | None]:
    """`(resolved, action_code, replacement)` for one detection.

    Four decisions, in this order, and the order is the module's central claim.

    **A relative interval is not an identifier.** `6 weeks` and `today` name no
    date, so there is nothing to shift and nothing to leak: the interval between
    now and six weeks is the same for a shifted patient as for an unshifted
    one. It is the one shape that passes through untouched, decided by a closed
    list of shapes and asked *before* everything else, so it cannot be moved by
    a score or a threshold. The replacement is the original text, which is what
    makes "passed through" and "replaced" the same operation here.

    **A date is a date whatever the engine called it.** `01/14/2026` comes back
    as `LOCATION` in one sentence and as `DATE_TIME` in another; routing on the
    label would mask a date as a location in the first and shift it in the
    second. So a hit whose *text* is a date goes down the date path regardless,
    which is also what makes an unreadable numeric date a refusal rather than a
    silent mask of its digits.

    **The absent replacer short-circuits everything else.** A detection nothing
    can replace is unresolved at any score, which is what stops a settings
    change from turning a deterministic block into a pass-through.

    **A sub-threshold detection is a different condition** and says so on the
    wire: `LOW_CONFIDENCE_NER_UNRESOLVED` rather than `NER_UNRESOLVED`, because a
    receipt and an audit record are the only durable record of why a request was
    refused, and the two are different problems. One is a coverage gap that
    needs a replacer; the other is a tuning problem that needs a threshold. The
    old behaviour made the two byte-identical on the wire.
    """
    if hit.entity_type == TRUNCATED_TEXT:
        # The scan did not cover the whole field. There is no entity and no
        # value, so there is nothing to replace — and a report whose tail was
        # never read cannot be certified clean.
        return False, _ACTION_CODE_NER_UNRESOLVED, None
    if is_relative_interval(hit.text):
        return True, _PASSTHROUGH_INTERVAL, hit.text
    if is_absolute_date(hit.text) and hit.entity_type != "DATE_TIME":
        # Labelled as something else; treat it as the date its characters say
        # it is, so the outcome does not depend on which recogniser fired.
        shifted = replacement_for(
            EntityHit("DATE_TIME", hit.start, hit.end, hit.score, hit.text), ctx.replacers
        )
        if shifted is None:
            return False, _ACTION_CODE_UNSHIFTED_DATE, None
        return True, _REPLACED_LAYER2, shifted
    if not has_replacer(hit.entity_type):
        return False, _ACTION_CODE_NER_UNRESOLVED, None
    if hit.score < ctx.settings.ner_score_threshold:
        return False, _ACTION_CODE_LOW_CONFIDENCE, None
    replacement = replacement_for(hit, ctx.replacers)
    if replacement is None:
        return False, _ACTION_CODE_UNSHIFTED_DATE, None
    return True, _REPLACED_LAYER2, replacement


def _has_surviving_content(text: str, covered: list[tuple[int, int]]) -> bool:
    """Whether any clinical content is left in `text` outside the covered spans.

    A span is *covered* when the kernel has accounted for it: either it was
    replaced, or it was detected and the payload is blocking on it. A detected
    span is not clinical text — it is an identifier the kernel could not safely
    resolve — so it cannot be what a finding is made of. A field whose every
    character falls inside such a span had nothing clinical in it to begin
    with, and redacting it produces nothing, which is not the same thing as
    producing something clean.

    The residual is read through `strip_anchor_labels`, so a field label does
    not count as content either: a report that was nothing but `MRN: 4452819.`
    has no clinical text once the identifier and its label are both accounted
    for. The blanking is length-preserving, so the spans still index this
    string.

    Where the covering spans are *unresolved*, the payload is already blocked
    and this disposition adds information rather than the decision — it is
    recorded because it is true, not because it is load-bearing. The case it
    decides is the other one: a field whose every span was replaced cleanly,
    which would otherwise be approved as a report with no findings in it.
    """
    residual: list[str] = []
    cursor = 0
    for start, end in sorted(covered):
        residual.append(strip_anchor_labels(text[cursor:start]))
        cursor = end
    residual.append(strip_anchor_labels(text[cursor:]))
    return _MEANINGFUL.search("".join(residual)) is not None


# -- Layer 3 (D.3): the contract check over the transformed payload ----------


def layer3_validation(
    payload: StructuredPayload, ctx: RedactionContext
) -> tuple[StructuredPayload, list[Disposition]]:
    """Check the transformed payload against the contract, and hash it.

    Layer 3 changes nothing except `payload_hash`. Its job is to be the last
    reader of the payload before a policy decision, and to disagree with
    whatever the first two layers let through. Five checks:

    * the function is one the contract names, and no carried field is outside
      its allowlist;
    * no field was dropped between the layers, comparing against `ctx.source`;
    * every date field holds a shiftable date, and none still equals the value
      component C was given;
    * every study reference carries the surrogate shape;
    * no text field still matches a layer-1 deterministic pattern;
    * `payload_hash` is computed over the approved payload.

    The hash **overwrites** the pre-redaction value component A wrote for
    provenance. It does not compare against it and it is not recomputed from the
    old one: layers 1 and 2 transform the payload, so a post-redaction hash
    cannot agree with a pre-redaction one, and a check that demanded agreement
    would refuse every payload the kernel has ever approved.
    """
    dispositions: list[Disposition] = []
    allowed = ALLOWED_FIELDS.get(payload.function)
    if allowed is None:
        dispositions.append(Disposition(
            layer="D.3", field="function", entity=None,
            action_code=_ACTION_CODE_UNKNOWN_FUNCTION, resolved=False,
        ))
        allowed = frozenset()

    for key in sorted(set(payload.dicom_fields) - allowed):
        dispositions.append(Disposition(
            layer="D.3", field=key, entity=None,
            action_code=_ACTION_CODE_FIELD_NOT_ALLOWLISTED, resolved=False,
        ))

    # A field a layer *dropped* is a violation; a field the caller never
    # supplied is not. An earlier version also required the fields the
    # function's allowlist names, which made redaction responsible for input
    # completeness: `pipeline_for` copies only the metadata a request carries,
    # so a legitimate partial-metadata request produced a payload with no
    # `dicom_fields` and layer 3 refused it. That is extraction's concern —
    # layer A already refuses a field outside the allowlist — and a privacy
    # layer that blocks a report for being incomplete is failing at the wrong
    # thing. Removed deliberately; see the task report.
    for key in sorted(set(ctx.source.dicom_fields) - set(payload.dicom_fields)):
        dispositions.append(Disposition(
            layer="D.3", field=key, entity=None,
            action_code=_ACTION_CODE_CONTRACT_VIOLATION, resolved=False,
        ))

    for key in _DATE_FIELDS:
        if key in payload.dicom_fields:
            dispositions.extend(_check_date(key, payload.dicom_fields[key], ctx))

    for field, value in _references(payload):
        if not SURROGATE_SHAPE.fullmatch(value):
            dispositions.append(Disposition(
                layer="D.3", field=field, entity=None,
                action_code=_ACTION_CODE_MISSING_SURROGATE, resolved=False,
            ))

    for field, text in _text_fields(payload).items():
        for entity, pattern in _DETERMINISTIC_PATTERNS:
            if pattern.search(text):
                dispositions.append(Disposition(
                    layer="D.3", field=field, entity=entity,
                    action_code=_ACTION_CODE_LEFTOVER_PATTERN_MATCH, resolved=False,
                ))

    hashed = payload.model_copy(update={"payload_hash": payload_hash_of(payload)})
    return hashed, dispositions


def _check_date(key: str, value: str, ctx: RedactionContext) -> list[Disposition]:
    """One date field: a shiftable date, and one that was actually shifted."""
    if not value.strip():
        return []
    unresolved: list[Disposition] = []
    try:
        shift_dicom_date(value, ctx.replacers.offset)
    except ValueError:
        unresolved.append(Disposition(
            layer="D.3", field=key, entity=None,
            action_code=_ACTION_CODE_UNSHIFTED_DATE, resolved=False,
        ))
    # With a zero offset the shifted value *is* the original, so equality says
    # nothing and is not treated as evidence of anything.
    if ctx.replacers.offset != 0 and value == ctx.source.dicom_fields.get(key):
        unresolved.append(Disposition(
            layer="D.3", field=key, entity=None,
            action_code=_ACTION_CODE_UNSHIFTED_DATE, resolved=False,
        ))
    return unresolved


def _references(payload: StructuredPayload) -> list[tuple[str, str]]:
    """Every study reference in the payload, each with the field that holds it."""
    found = [("study_ref", payload.study_ref)]
    found.extend(
        (f"prior_study_refs[{position}]", value)
        for position, value in enumerate(payload.prior_study_refs)
    )
    return found


def _text_fields(payload: StructuredPayload) -> dict[str, str]:
    """Every field whose value is prose, across both halves of the payload."""
    fields = {"report_text": payload.report_text}
    for key in _TEXT_DICOM_FIELDS:
        if key in payload.dicom_fields:
            fields[f"dicom_fields.{key}"] = payload.dicom_fields[key]
    return fields
