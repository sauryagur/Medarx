"""DICOM de-identification: the PS3.15 Basic Profile, as data and as an applier.

Offline and test-suite-only. Nothing on the request path imports this package;
see `dicom_deidentifier` for what it does and does not cover.
"""

from medarx.deident.dicom_deidentifier import DeidAction, deidentify, make_uid
from medarx.deident.profiles import (
    CLEAN_PIXEL_DATA_IMPLEMENTED,
    IMPLEMENTED_OPTIONS,
    PROFILE,
    Rule,
)

__all__ = [
    "CLEAN_PIXEL_DATA_IMPLEMENTED",
    "DeidAction",
    "IMPLEMENTED_OPTIONS",
    "PROFILE",
    "Rule",
    "deidentify",
    "make_uid",
]
