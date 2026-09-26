"""The PS3.15 Basic Application Level Confidentiality Profile, as data.

The profile is a `dict` of DICOM keyword -> `Rule`, and the de-identifier is a
thin applier over it. Splitting them that way is the point: the profile is
inspectable, and a conformance claim about it is a claim about data that can be
printed and diffed, not about control flow buried in a loop.

**What this profile does not cover.** PS3.15's Clean Pixel Data option is *not*
implemented. Burned-in identifiers in pixel data are therefore still present in
a de-identified dataset, and no code in this package may claim otherwise:
`CLEAN_PIXEL_DATA_IMPLEMENTED` is `False` and no rule anywhere targets
`PixelData`. A dataset passed through here is de-identified in the header sense
only, and must not be described as free of burned-in PHI.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

__all__ = [
    "CLEAN_PIXEL_DATA_IMPLEMENTED",
    "IMPLEMENTED_OPTIONS",
    "PROFILE",
    "Rule",
]

#: Always `False` in v1. The Clean Pixel Data option is not implemented, so no
#: PS3.15 conformance claim may imply that burned-in identifiers are gone.
CLEAN_PIXEL_DATA_IMPLEMENTED: bool = False

#: The PS3.15 *options* this profile implements. The Basic Application Level
#: Confidentiality Profile is the base profile rather than an option, and no
#: option is layered on top of it, so this is empty — and it stays empty until
#: an option has actually been implemented and validated against the fixtures.
#: Populating it speculatively is how an overstated conformance claim ships.
IMPLEMENTED_OPTIONS: frozenset[str] = frozenset()

#: The three things a rule can do to an attribute.
DeidActionKind = Literal["replace_uid", "empty", "remove"]


@dataclass(frozen=True, slots=True)
class Rule:
    """One profile entry: what to do, to which keyword, and its DICOM VR.

    `vr` is the value representation the attribute is expected to carry. It is
    used to type an emptied value correctly rather than to validate the input;
    an attribute whose VR does not match is a malformed dataset and is left for
    the caller to reject, not silently coerced here.
    """

    action: DeidActionKind
    keyword: str
    vr: str | None = None


def _rules(action: DeidActionKind, pairs: dict[str, str]) -> dict[str, Rule]:
    return {keyword: Rule(action=action, keyword=keyword, vr=vr) for keyword, vr in pairs.items()}


#: Attributes deleted outright: the value carries no clinical meaning once the
#: identity is gone, and leaving an empty element behind only invites confusion.
_REMOVE = {
    "PatientName": "PN",
    "OtherPatientIDs": "LO",
    "OtherPatientNames": "PN",
    "PatientAddress": "LO",
    "PatientTelephoneNumbers": "SH",
    "InstitutionAddress": "ST",
    "PerformingPhysicianName": "PN",
    "OperatorsName": "PN",
}

#: Attributes emptied rather than deleted: a clinician or a downstream tool may
#: expect the element to be present, and PS3.15 permits a zero-length value.
#
#: Note `AccessionNumber`, `InstitutionName` and `ReferringPhysicianName` are
#: emptied rather than removed. The task brief listed them under `remove`, but
#: the conformance test in the same brief asserts `out.<keyword> == ""` for each,
#: and a removed DICOM element raises `AttributeError` on attribute access
#: rather than reading back as an empty string. The test states the observable
#: contract, so the test wins; the deviation is recorded in the task report.
_EMPTY = {
    "PatientID": "LO",
    "IssuerOfPatientID": "LO",
    "AccessionNumber": "SH",
    "InstitutionName": "LO",
    "ReferringPhysicianName": "PN",
    "PatientBirthDate": "DA",
    "PatientBirthTime": "TM",
    "PatientSex": "CS",
    "EthnicGroup": "SH",
    "Occupation": "SH",
    "MilitaryRank": "LO",
    "MedicalRecordLocator": "LO",
    "PatientInsurancePlanCodeSequence": "SQ",
    "CountryOfResidence": "LO",
    "RegionOfResidence": "LO",
    "PatientReligiousPreference": "LO",
    "PatientSpeciesDescription": "LO",
    "PatientSexNeutered": "CS",
    "PatientBreedDescription": "LO",
    "ResponsiblePerson": "PN",
    "ResponsibleOrganization": "LO",
}

#: Attributes whose value is an identifier and is remapped to a surrogate under
#: the caller's org root. Replaced rather than removed because cross-references
#: between these attributes have to keep resolving to the same object.
_REPLACE_UID = {
    "StudyInstanceUID": "UI",
    "SeriesInstanceUID": "UI",
    "SOPInstanceUID": "UI",
    "FrameOfReferenceUID": "UI",
    "MediaStorageSOPInstanceUID": "UI",
    "SynchronizationFrameOfReferenceUID": "UI",
}

#: The Basic Application Level Confidentiality Profile. Keys are DICOM keywords
#: so the profile reads the way the standard's tables do.
PROFILE: dict[str, Rule] = {
    **_rules("remove", _REMOVE),
    **_rules("empty", _EMPTY),
    **_rules("replace_uid", _REPLACE_UID),
}
