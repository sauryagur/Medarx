"""Prose that contains **no identifier at all** — the precision corpus.

This is the other half of the harness, and it is deliberately a *different
artifact* from the planted corpus next door. The planted corpus (`seed_corpus`)
answers "did the detector find the identifiers that were put there?", which is
a recall question and needs a known positive. It cannot answer "did the
detector touch anything it should not have?", because a corpus made of planted
identifiers has a truth on every span and therefore no room for a false
positive to be *observed*. This file is the room: every value here is an
ordinary clinical sentence, so **any** `[REDACTED:...]` mask in an approved
payload is a false positive by construction, and the denominator is a sentence
count rather than an identifier count.

**The two lists below are two lists, and they are never added together.**
`ORDINARY_SENTENCES` is the 28-sentence corpus the project's pass rate and
false-positive rate are quoted over. `KNOWN_FALSE_POSITIVES` is a separate
six-sentence list that names, for each case, the entity label and the ordinary
word that gets masked. An earlier version of this project's record quoted
7/28 by counting the two as one, and the number could not be reproduced from
either list; `tests/test_redaction_layers.py` now imports both from here, and
the harness prints two rows with two denominators.

Every sentence is fabricated. None of it is real patient data.
"""

from __future__ import annotations

__all__ = ["KNOWN_FALSE_POSITIVES", "ORDINARY_SENTENCES", "PROSE_NOTE"]

#: Carried on every one of the two tuples so a reader of a raw measurement can
#: see that the figure is about invented text.
PROSE_NOTE = "Fabricated sentences. No real patient data."

#: 28 sentences of the kind a radiology report is actually made of. They carry
#: no identifiers, and every one was written before the relative-interval work
#: to find out which of them the kernel could process. The pass rate over this
#: list is the project's real usability number.
ORDINARY_SENTENCES: tuple[str, ...] = (
    "May be a small effusion.",
    "Right lower lobe effusion, follow-up 6 weeks.",
    "Aorta 3.2 cm, no dissection.",
    "Dose 2.5 mg today.",
    "Nodule unchanged from 2025-12-01.",
    "Comparison with the prior study shows slight interval growth.",
    "Stable for 6 months.",
    "Follow-up in 3 months.",
    "The patient returns in 2 days.",
    "Seen on 14 January 2026 and again on 2026-03-02.",
    "Previous CT chest on 01/14/2026 for comparison.",
    "Findings discussed at the 4 March 2026 multidisciplinary meeting.",
    "The catheter was removed 2 weeks ago.",
    "DOB 14 January 2026.",
    "No acute osseous abnormality.",
    "Liver enzymes normalised within 3 weeks.",
    "Scan performed 2026-01-14 10:30.",
    "Study dated 20260114.",
    "Recommend follow-up imaging in six weeks.",
    "Apnoea episodes continue, roughly 4 per night.",
    "Mass unchanged in size over 18 months.",
    "Pulmonary embolism, right lower lobe, seen 2025-11-30.",
    "Technical note: breathing artefact present.",
    "Pleural effusion, right side, 15 mm.",
    "Findings as above.",
    "Compared with 02/03/2026 the haematoma has resolved.",
    "The 3 cm nodule seen 14 January 2026 is unchanged.",
    "Density of 120 HU on 2026-02-03.",
)

#: `(text, entity label, the ordinary word that is masked)` for six cases where
#: spaCy reports an ordinary clinical word as a named entity at 0.85 and the
#: replacer table replaces it. A false positive that is merely absent from a
#: report is not acceptable at all, so these are recorded rather than
#: forgotten. Kept apart from the 28 on purpose — see the module docstring.
KNOWN_FALSE_POSITIVES: tuple[tuple[str, str, str], ...] = (
    ("Previous CT chest for comparison.", "ORGANIZATION", "CT"),
    ("Nodule unchanged in size.", "ORGANIZATION", "Nodule"),
    ("Scan performed this morning.", "NRP", "Scan"),
    ("Pulmonary embolism, right lower lobe.", "PERSON", "Pulmonary"),
    ("Pleural effusion, right side.", "LOCATION", "Pleural"),
    ("Density of 120 HU measured.", "PERSON", "HU"),
)
