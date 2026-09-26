"""The applier for the PS3.15 Basic Profile held in `profiles.PROFILE`.

`deidentify()` is offline and test-suite-only. It is not on the request path:
nothing in the privacy kernel's live pipeline imports it, and it exists so the
de-identification rules can be exercised against a fixture and inspected.

Four properties matter more than speed here:

* **It never mutates its input.** It returns a deep copy, so a caller's
  dataset is still theirs afterwards and the operation is re-runnable on the
  original.
* **It is idempotent.** A UID already under `root` is left alone, so running
  the de-identifier twice produces the same dataset as running it once.
* **It reaches nested items.** Sequence items are walked recursively, so a
  `PatientName` inside e.g. `RequestAttributesSequence` is removed like any
  other. A structure nested past the depth cap is refused, not passed through.
* **It does not touch pixel data.** There is no rule for `PixelData` and no
  branch that reaches it. Burned-in identifiers survive, which is exactly why
  `CLEAN_PIXEL_DATA_IMPLEMENTED` is `False`.
"""

from __future__ import annotations

import copy
import uuid
from dataclasses import dataclass

from pydicom.dataset import Dataset
from pydicom.sequence import Sequence

from medarx.deident.profiles import PROFILE, Rule

__all__ = ["DeidAction", "deidentify", "make_uid"]

#: Fixed namespace for the surrogate UID derivation. A constant, so the same
#: input UID yields the same surrogate on every machine and every run.
_UID_NAMESPACE = uuid.UUID("6f9619ff-8b86-d011-b42d-00c04fc964ff")

#: PS3.5 caps a whole UID at 64 characters. A UUIDv5 renders as up to 39 decimal
#: digits, which does not fit under a 28-character org root, so the derived
#: value is reduced to the number of digits that remain rather than the full
#: 128 bits being emitted. The cost of that reduction is ~9x10^35 distinct
#: surrogates rather than 2^128: ample for a synthetic conformance fixture, not
#: for production. Revisit the derivation before this is used to de-identify
#: real studies.
_MAX_UID_LENGTH = 64


#: The greatest number of nested levels *below* the top-level dataset that will
#: be walked. Depth counts levels below the top: the top-level dataset is depth
#: 0, a sequence item in it is depth 1, and an item found at depth 33 is refused.
#: Real instances nest a handful of levels; the cap exists so that a pathological
#: or hand-built structure is rejected rather than walked forever.
_MAX_NESTING_DEPTH = 32


def _derived_component(seed: str, root: str) -> str:
    """A decimal component of exactly the right width, under `root`, within 64.

    **Width, not padding.** PS3.5 §9.1: a UID component is a run of decimal
    digits, and one other than the first "shall not have a leading zero". A
    value below `10**(budget-1)` is narrower than the budget, and zero-padding
    it to width — which this used to do — is exactly the leading zero the
    standard forbids: with a 28-character root, `uuid5(...).int % 10**36` lands
    below `10**35` about one time in ten, and every one of those produced a UID
    pydicom warns about on read. So the value is *shifted* into the legal range
    rather than padded into an illegal one.

    Nothing is given up by that. The range `[10**(budget-1), 10**budget)` is
    `9 * 10**(budget-1)` values wide, so the component keeps the full `budget`
    digits; only the leading digit is confined to 1-9, which is the rule.
    """
    budget = _MAX_UID_LENGTH - len(root)
    if budget < 1:
        raise ValueError(f"root {root!r} leaves no room for a UID component")
    return str(uuid.uuid5(_UID_NAMESPACE, seed).int % (9 * 10 ** (budget - 1)) + 10 ** (budget - 1))


@dataclass(frozen=True, slots=True)
class DeidAction:
    """One applied rule.

    `tag` carries the DICOM *keyword* rather than a `(gggg, xxxx)` tag number,
    because a keyword is what a profile table, a conformance report, and a human
    reading a diff can all use. `action` is one of the three kinds in
    `profiles.Rule`.
    """

    tag: str
    keyword: str
    action: str


def make_uid(seed: str, root: str) -> str:
    """Derive a deterministic surrogate UID for `seed` under `root`.

    The result is `root` followed by a decimal component derived from a UUIDv5
    of `seed`, so it sits under the organisation's own OID arc and is
    reproducible: the same seed and root always give the same UID. Distinct
    seeds give distinct surrogates with overwhelming probability, not with
    certainty — the component is a ~9x10^35 reduction of a 128-bit digest, so a
    collision is possible in principle and improbable beyond counting. It is
    deliberately *not* the `2.25.` form: that arc is for UUID-derived UIDs, and
    the org root is what identifies a Medarx-de-identified instance to anyone
    downstream.

    **`seed` is the UID value and nothing else** — no attribute name, no
    keyword. The same source UID in two attributes, or in the dataset and its
    file meta, has to become the same surrogate, or the cross-references the
    profile is remapping in order to preserve stop resolving: PS3.10 requires
    `SOPInstanceUID` and `file_meta.MediaStorageSOPInstanceUID` to be equal, and
    a written file whose file meta points at an instance the dataset does not
    contain is broken. Keying on the value gives that for free; keying on the
    attribute gave each copy its own surrogate and broke it.

    The component is bounded so the whole UID stays within the 64-character
    limit PS3.5 places on a UID; emitting an over-long UID would produce a
    dataset that warns on every read and is invalid on write.
    """
    if not root.endswith("."):
        raise ValueError(f"root {root!r} must end in '.'")
    return f"{root}{_derived_component(seed, root)}"


def _copy(dataset: Dataset) -> Dataset:
    """A deep copy, file meta and nested sequence items included.

    A shallow copy is not enough: the profile is applied to sequence items at
    every nested level, and a shared `Sequence` would let those edits write
    through into the caller's dataset.
    """
    return copy.deepcopy(dataset)


def _apply_to_dataset(
    dataset: Dataset, root: str, actions: list[DeidAction], depth: int = 0
) -> None:
    """Apply the profile to `dataset` in place. `dataset` is always a copy."""
    if depth > _MAX_NESTING_DEPTH:
        # A dataset this deeply nested is not a real one, and recursing further
        # on data we cannot fully inspect would be exactly the silent pass-through
        # this module must not do. Refuse rather than guess.
        raise ValueError(
            f"dataset nests {depth} levels below the top level, more than the "
            f"{_MAX_NESTING_DEPTH} this module will walk; refusing rather than "
            "de-identifying a structure we cannot fully inspect"
        )

    for keyword, rule in PROFILE.items():
        if keyword in dataset:
            _apply_rule(dataset, keyword, rule, root, actions)

    # Nested items. This walks *every* sequence in the dataset, not only the ones
    # the profile names by keyword: a rule that stopped at the top level would
    # leave a `PatientName` inside e.g. `RequestAttributesSequence` in the clear,
    # which is the failure this component is not allowed to have. Recursion, not
    # a single level, so a PHI-bearing item inside a sequence inside a sequence
    # is reached too.
    for element in dataset:
        value = element.value
        if isinstance(value, Sequence):
            for item in value:
                if isinstance(item, Dataset):
                    _apply_to_dataset(item, root, actions, depth + 1)


def _apply_rule(
    container: Dataset, keyword: str, rule: Rule, root: str, actions: list[DeidAction]
) -> None:
    if rule.action == "remove":
        del container[keyword]
        actions.append(DeidAction(tag=keyword, keyword=keyword, action="remove"))
        return

    if rule.action == "empty":
        if rule.vr == "SQ":
            container[keyword].value = Sequence()
        else:
            setattr(container, keyword, "")
        actions.append(DeidAction(tag=keyword, keyword=keyword, action="empty"))
        return

    if rule.action == "replace_uid":
        current = getattr(container, keyword, None)
        if not current:
            return
        # Already under our root: this is a surrogate we produced, and
        # re-deriving it would be what breaks idempotence.
        if str(current).startswith(root):
            return
        setattr(container, keyword, make_uid(str(current), root))
        actions.append(DeidAction(tag=keyword, keyword=keyword, action="replace_uid"))
        return

    raise ValueError(f"unknown profile action: {rule.action!r}")  # pragma: no cover


def deidentify(ds: Dataset, root: str) -> tuple[Dataset, list[DeidAction]]:
    """Return a de-identified copy of `ds` and the actions applied to get it.

    `root` is `Settings.dicom_uid_root`, passed in by the caller rather than
    read from a global, so the dependency on the configuration is explicit and
    the function is testable against any root. `ds` is not modified. Pixel data
    is not read, rewritten, or claimed to be free of burned-in identifiers.
    """
    out = _copy(ds)
    actions: list[DeidAction] = []
    _apply_to_dataset(out, root, actions)

    # MediaStorageSOPInstanceUID lives in the file meta, not the dataset. It is
    # a UID and it is in the profile, so it has to be remapped there too or a
    # written file points back at the original instance.
    file_meta = getattr(out, "file_meta", None)
    if file_meta is not None and "MediaStorageSOPInstanceUID" in file_meta:
        _apply_rule(
            file_meta, "MediaStorageSOPInstanceUID", PROFILE["MediaStorageSOPInstanceUID"],
            root, actions,
        )

    return out, actions
