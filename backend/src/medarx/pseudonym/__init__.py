"""Component C: pseudonymization — stable surrogates and a per-patient date shift.

**Pseudonymization is not anonymization.** A surrogate is re-identifiable to
anyone holding the mapping store, which is why the mapping store is separate,
access-controlled, and never read by any component on the model path.
"""

from medarx.pseudonym.date_shift import patient_offset, shift_date
from medarx.pseudonym.errors import AuditKeyRequired
from medarx.pseudonym.mapping_store import MappingStore
from medarx.pseudonym.pseudonymize import pseudonymize_payload

__all__ = [
    "AuditKeyRequired",
    "MappingStore",
    "patient_offset",
    "pseudonymize_payload",
]
