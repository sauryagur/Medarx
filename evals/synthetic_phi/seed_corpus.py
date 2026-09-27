"""The synthetic PHI corpus: the *known positives* the detector is measured against.

**Every value here is fabricated.** It is invented for this project, it names
no real person, and none of it came from a dataset — not TCIA, not MIMIC, not
anything else. TCIA is in any case not a detection-recall oracle: a corpus that
has already been stripped of its identifiers cannot say how many of them a
pipeline would have caught in the form they arrived in. Synthetic injection is
the only thing that gives a detection figure a denominator, and that is what
this file is for.

**A corpus case and an API request body are the same object.** Each `Case`
renders itself to the `ExecutionRequest` the contract publishes — the wire
function spelling (`Draft`, not `draft`), the `{text, source}` report-text
object, keyword-named DICOM metadata — so the harness measures the surface a
caller can actually reach rather than the kernel's internal call shape. A case
the published schema cannot express is marked `contract_expressible=False` and
carries a `contract_note` saying why; it is still measured, because the
alternative is leaving a whole input source unmeasured, and the note is kept
after the gap closes so the correction has something to be checked against.

**The ground truth is a statement about values, never about spans.** A
`GroundTruth` entry says *this identifier was planted, on this surface*. The
span is derived later, by searching the rendered text, and a value that is
declared but absent is an error (`locate_planted` raises) rather than a silent
false negative. A harness handed a span it wrote itself has nothing left to
falsify; a harness that has to find the value in the text is either right or
loudly wrong.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

__all__ = [
    "ALL_CASES",
    "CASES",
    "CONTRACT_EXPRESSIBLE_CASES",
    "CORPUS_DIR",
    "DICOM_HEADER_CASES",
    "DICOM_PROSE_ATTRIBUTE",
    "INTERNAL_FUNCTION",
    "REPORT_SOURCE",
    "SPELLING_CASES",
    "Case",
    "GroundTruth",
    "GroundTruthError",
    "identifiers",
    "locate_planted",
    "render",
    "templates",
    "write_corpus",
]

#: The directory the corpus artifacts live in, so a test can read
#: `identifiers.json` without re-deriving the path from `__file__`.
CORPUS_DIR = Path(__file__).resolve().parent

#: The one DICOM metadata attribute whose value is *prose* and is therefore
#: scanned for entities by redaction layer 2. Every other allowlisted attribute
#: is a keyword, a date, or an age band, and is handled structurally (dropped,
#: shifted, or banded), never scanned. Naming it here is what lets the harness
#: say "this input source has no NER surface" instead of reporting a recall of
#: 1.00 over zero measurements.
DICOM_PROSE_ATTRIBUTE = "PriorReportText"

#: The `ReportText.source` the contract allows, and the only one that is true of
#: this corpus.
REPORT_SOURCE = "synthetic_corpus"

#: The wire function names the contract publishes, mapped to the internal
#: snake_case spelling the allowlists use. The wire spelling is what an
#: `ExecutionRequest` carries; the internal one is what `pipeline_for` is
#: called with. Two vocabularies exist, and this table is the only place both
#: appear.
INTERNAL_FUNCTION: dict[str, str] = {
    "Draft": "draft",
    "Prior Summary": "prior_summary",
    "Ask": "ask",
}


class GroundTruthError(ValueError):
    """A ground-truth entry the case text does not support."""


def identifiers() -> dict:
    """The fabricated identifier inventory, read from `identifiers.json`."""
    return json.loads((CORPUS_DIR / "identifiers.json").read_text(encoding="utf-8"))


def templates() -> dict[str, str]:
    """The named report skeletons in `report_template.txt`.

    The file is a real input, not decoration: every case body is produced by
    `str.format`-ing one of these, so editing the prose there changes the
    corpus and every measurement taken over it. That is the reason the prose
    lives in a file rather than in a Python string.
    """
    parsed: dict[str, str] = {}
    name: str | None = None
    source = (CORPUS_DIR / "report_template.txt").read_text(encoding="utf-8")
    for line in source.splitlines():
        if line.startswith("--- name: "):
            name = line.removeprefix("--- name: ").strip()
            parsed[name] = ""
        elif name is not None:
            parsed[name] += line
    return parsed


def render(skeleton: str, **slots: str) -> str:
    """One report body, from the named skeleton in `report_template.txt`."""
    return templates()[skeleton].format(**slots).strip()


@dataclass(frozen=True)
class GroundTruth:
    """One planted identifier: what it is, its value, and where it was put.

    `source` is the *input* surface, not a payload field. A value planted in
    DICOM metadata stays a `dicom_header` truth even though what the pipeline
    does about it is to drop the attribute.
    """

    entity_type: str
    value: str
    source: Literal["report_text", "dicom_header"]


@dataclass(frozen=True)
class Case:
    """One corpus case: the request, and what was planted in it.

    `function` is the **contract's** spelling, because the request body carries
    the contract's spelling. `INTERNAL_FUNCTION` translates it at the boundary.
    """

    name: str
    kind: Literal["known_positive", "unresolved", "all_phi"]
    report_text: str
    dicom_metadata: dict[str, str]
    ground_truth: tuple[GroundTruth, ...]
    function: str = "Draft"
    prior_studies: tuple[str, ...] = ()
    #: `False` where the published `ExecutionRequest` schema cannot express this
    #: case. The case is still measured: the code is the truth about what the
    #: kernel does with it, and leaving an input source unmeasured would be the
    #: worse error. The reason travels with it into the printed output.
    contract_expressible: bool = True
    #: A recorded fact about this case's relationship to the contract, kept
    #: whether or not the case is currently expressible. A note rather than a
    #: flag: a contract corrected today still has a history worth naming, and a
    #: note deleted the moment it stops being true is a note nobody can check
    #: the correction against.
    contract_note: str | None = None

    def surface_for(self, truth: GroundTruth) -> tuple[str, str]:
        """`(text, surface_name)` for the input surface `truth` names.

        The surface is *located*, not declared: a `dicom_header` truth resolves
        to the metadata attribute that actually holds the value, so a truth can
        never be graded against the wrong text.
        """
        if truth.source == "report_text":
            return self.report_text, "report_text"
        for attribute, value in self.dicom_metadata.items():
            if truth.value in value:
                return value, f"dicom_header.{attribute}"
        raise GroundTruthError(
            f"{self.name}: {truth.entity_type} {truth.value!r} is declared for "
            f"dicom_header but no metadata attribute in the case holds it; the "
            f"case carries {sorted(self.dicom_metadata)}"
        )

    def to_execution_request(self) -> dict:
        """This case as the `ExecutionRequest` body the contract publishes."""
        body: dict = {
            "function": self.function,
            "study_context": {
                "study_reference": identifiers()["study_reference"],
                "accession_reference": identifiers()["accession"],
                "modality": self.dicom_metadata.get("Modality", "CT"),
            },
            "report_text": {"text": self.report_text, "source": REPORT_SOURCE},
            "dicom_metadata": dict(self.dicom_metadata),
        }
        if self.prior_studies:
            body["prior_studies"] = [
                {"prior_study_reference": ref} for ref in self.prior_studies
            ]
        return body


_IDS = identifiers()

#: The three cases the design names, with the exact fixture strings. Kept as
#: their own tuple so a later task that wants to re-run the original three is
#: not left guessing which of the six are load-bearing.
CASES: tuple[Case, ...] = (
    Case(
        name="known_positive",
        kind="known_positive",
        report_text=render(
            "full_note",
            finding="7mm nodule in the right lower lobe",
            mrn=_IDS["mrn"],
            accession=_IDS["accession"],
            patient_id=_IDS["patient_id"],
            date_of_birth=_IDS["date_of_birth"],
            comparison="Comparison with the prior study shows slight interval growth.",
        ),
        dicom_metadata={
            "Modality": _IDS["modality"],
            "StudyDate": _IDS["study_date"],
            "PatientAge": _IDS["patient_age"],
            "PatientID": _IDS["patient_reference"],
            "AccessionNumber": _IDS["accession"],
        },
        ground_truth=(
            GroundTruth("MRN", str(_IDS["mrn"]), "report_text"),
            GroundTruth("ACCESSION_NUMBER", str(_IDS["accession"]), "report_text"),
            GroundTruth("PATIENT_ID", str(_IDS["patient_id"]), "report_text"),
            GroundTruth("DATE_TIME", str(_IDS["date_of_birth"]), "report_text"),
        ),
    ),
    Case(
        name="unresolved",
        kind="unresolved",
        report_text=render(
            "clinical_then_reference",
            finding="7mm nodule in the right lower lobe",
            ambiguous_reference=_IDS["ambiguous_reference"],
        ),
        dicom_metadata={
            "Modality": _IDS["modality"],
            "StudyDate": _IDS["study_date"],
            "PatientAge": _IDS["patient_age"],
        },
        ground_truth=(),
    ),
    Case(
        name="all_phi",
        kind="all_phi",
        report_text=render(
            "identifier_block",
            mrn=_IDS["mrn"],
            accession=_IDS["accession"],
            patient_id=_IDS["patient_id"],
        ),
        dicom_metadata={
            "Modality": _IDS["modality"],
            "StudyDate": _IDS["study_date"],
            "PatientAge": _IDS["patient_age"],
        },
        ground_truth=(
            GroundTruth("MRN", str(_IDS["mrn"]), "report_text"),
            GroundTruth("ACCESSION_NUMBER", str(_IDS["accession"]), "report_text"),
            GroundTruth("PATIENT_ID", str(_IDS["patient_id"]), "report_text"),
        ),
    ),
)

#: The DICOM-metadata input source. These two carry **no identifier in the free
#: text** — the report body is ordinary clinical prose — so every identifier
#: the case plants is planted in the metadata, and the two sources cannot
#: contaminate each other's numbers. The pipeline's answer to a metadata
#: identifier is structural: component A drops `PatientID`, `AccessionNumber`
#: and `InstitutionName`, component C shifts `StudyDate`, component A bands
#: `PatientAge`. None of that is a *detection*, and the harness reports it in
#: its own row so it is never read as a recall.
DICOM_HEADER_CASES: tuple[Case, ...] = (
    Case(
        name="dicom_header_identifiers",
        kind="known_positive",
        report_text=render(
            "clinical_only",
            finding="6mm nodule in the right upper lobe",
        ),
        dicom_metadata={
            "PatientID": _IDS["mrn"],
            "AccessionNumber": _IDS["accession"],
            "InstitutionName": _IDS["institution_name"],
            "StudyDate": _IDS["study_date"],
            "PatientAge": _IDS["patient_age"],
            "Modality": _IDS["modality"],
        },
        ground_truth=(
            GroundTruth("MRN", str(_IDS["mrn"]), "dicom_header"),
            GroundTruth("ACCESSION_NUMBER", str(_IDS["accession"]), "dicom_header"),
            GroundTruth("ORGANIZATION", str(_IDS["institution_name"]), "dicom_header"),
            GroundTruth("DATE_TIME", str(_IDS["study_date"]), "dicom_header"),
        ),
    ),
    # The only DICOM-metadata value the kernel *scans*. Reached through the
    # `Prior Summary` function, whose allowlist names `prior_report_text`; the
    # contract's `AllowlistedDicomMetadata` declares no `PriorReportText`
    # property, so a caller cannot express this case through the published
    # request schema today. The code is the truth about what happens to the
    # value, and leaving the source unmeasured would be worse than measuring it
    # against a schema that cannot yet reach it.
    Case(
        name="dicom_header_prose",
        kind="known_positive",
        function="Prior Summary",
        report_text=render(
            "clinical_only",
            finding="6mm nodule in the right upper lobe",
        ),
        dicom_metadata={
            DICOM_PROSE_ATTRIBUTE: render(
                "prior_note",
                prior_finding="6mm nodule",
                mrn=_IDS["mrn"],
                accession=_IDS["accession"],
                patient_id=_IDS["patient_id"],
            ),
            "PriorStudyDate": _IDS["prior_study_date"],
            "PatientAge": _IDS["patient_age"],
            "Modality": _IDS["modality"],
        },
        prior_studies=(str(_IDS["prior_study_reference"]),),
        ground_truth=(
            GroundTruth("MRN", str(_IDS["mrn"]), "dicom_header"),
            GroundTruth("ACCESSION_NUMBER", str(_IDS["accession"]), "dicom_header"),
            GroundTruth("PATIENT_ID", str(_IDS["patient_id"]), "dicom_header"),
        ),
        contract_expressible=True,
        # Kept after the contract was corrected, and kept as prose rather than
        # deleted, because the gap was real for a release and because the
        # correction was *additive* in the same place a reader would look first
        # if the property ever went missing again. `contract_expressible` says
        # what is true now; this says what was true, and what would silently
        # come back.
        contract_note=(
            "Until this task, AllowlistedDicomMetadata declared no "
            "PriorReportText property, so the only DICOM metadata value "
            "redaction layer 2 scans could not be supplied by a caller at all. "
            "The property is now declared (strictly additive, alongside "
            "PriorStudyDate), and this case validates against the contract. "
            "The next place to look if it fails is the same one: the "
            "AllowlistedDicomMetadata property list."
        ),
    ),
)

#: One spelling variant, on purpose. The canonical `Patient ID: 774123` is an
#: `ANCHOR_LABELS` entry and is blanked before the analyser runs, which leaves
#: the `PATIENT_ID` pattern with no label to match and no bare-value
#: alternative. `PatientID: 774123` has no space, is therefore not an anchor
#: label, and the pattern's `Patient\s*ID` matches it. Measuring only the
#: canonical spelling would report a recognizer that is dead; measuring only
#: the variant would report one that is fine. Both are in the table.
SPELLING_CASES: tuple[Case, ...] = (
    Case(
        name="patient_id_label_spelling",
        kind="known_positive",
        report_text=render(
            "label_spelling",
            finding="6mm nodule in the right upper lobe",
            patient_id=_IDS["patient_id"],
        ),
        dicom_metadata={
            "Modality": _IDS["modality"],
            "StudyDate": _IDS["study_date"],
            "PatientAge": _IDS["patient_age"],
        },
        ground_truth=(
            GroundTruth("PATIENT_ID", str(_IDS["patient_id"]), "report_text"),
        ),
    ),
)

#: Everything the harness measures, in the order it is printed.
ALL_CASES: tuple[Case, ...] = CASES + DICOM_HEADER_CASES + SPELLING_CASES

#: The subset the published request schema can express, which is the subset the
#: conformance check in the test suite is allowed to validate.
CONTRACT_EXPRESSIBLE_CASES: tuple[Case, ...] = tuple(
    c for c in ALL_CASES if c.contract_expressible
)


def _occurrences(text: str, value: str) -> list[int]:
    """Every index at which `value` occurs in `text`."""
    found: list[int] = []
    start = 0
    while (index := text.find(value, start)) != -1:
        found.append(index)
        start = index + 1
    return found


def locate_planted(case: Case, truth: GroundTruth) -> tuple[str, int, int]:
    """`(surface, start, end)` for one planted value, found by searching.

    The span is derived here rather than stored, which is the whole point: the
    corpus declares *what* it planted and the scorer has to find it in the text
    before it can grade anything. A truth whose value does not occur is a
    corpus defect, and it raises instead of quietly becoming a false negative.
    """
    text, surface = case.surface_for(truth)
    found = _occurrences(text, truth.value)
    if not found:
        raise GroundTruthError(
            f"{case.name}: {truth.entity_type} {truth.value!r} is declared for "
            f"{surface} but does not occur in that surface"
        )
    if len(found) > 1:
        raise GroundTruthError(
            f"{case.name}: {truth.entity_type} {truth.value!r} occurs "
            f"{len(found)} times in {surface}; a span cannot be derived from "
            f"an ambiguous value"
        )
    return surface, found[0], found[0] + len(truth.value)


def write_corpus(out_dir: Path) -> Path:
    """Write `corpus.json` and `study.dcm` into `out_dir`; return the former.

    Byte-identical for identical inputs: there is no randomness anywhere in
    this module, which is what makes two runs of the harness comparable rather
    than merely similar.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "synthetic": True,
        "notice": (
            "Fabricated corpus for the Medarx evaluation harness. No real "
            "patient data, no real dataset, no downloaded images."
        ),
        "identifiers": identifiers(),
        "cases": [
            {
                "name": case.name,
                "kind": case.kind,
                "function": case.function,
                "report_text": case.report_text,
                "dicom_metadata": case.dicom_metadata,
                "prior_studies": list(case.prior_studies),
                "ground_truth": [
                    {"entity_type": g.entity_type, "value": g.value, "source": g.source}
                    for g in case.ground_truth
                ],
                "contract_expressible": case.contract_expressible,
                "contract_note": case.contract_note,
                "execution_request": case.to_execution_request(),
            }
            for case in ALL_CASES
        ],
    }
    corpus_path = out_dir / "corpus.json"
    corpus_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    _write_dicom(out_dir / "study.dcm")
    return corpus_path


def _write_dicom(path: Path) -> None:
    """The corpus's DICOM object, written with `pydicom`.

    The *shape* comes from `gen_dcm` (a realistic identity block and a pixel
    element) and the *values* come from `identifiers.json`, so the file on disk
    and `corpus.json` cannot describe different patients. Every value is
    fabricated; the dataset is a fresh object per call, so nothing here can
    mutate the conformance fixture.
    """
    from evals.synthetic_phi.gen_dcm import make_synthetic_dataset

    dataset = make_synthetic_dataset()
    dataset.PatientID = str(_IDS["mrn"])
    dataset.AccessionNumber = str(_IDS["accession"])
    dataset.OtherPatientIDs = str(_IDS["patient_id"])
    dataset.InstitutionName = str(_IDS["institution_name"])
    dataset.PatientBirthDate = str(_IDS["date_of_birth"]).replace("-", "")
    dataset.StudyDate = str(_IDS["study_date"])
    dataset.PatientAge = str(_IDS["patient_age"])
    dataset.Modality = str(_IDS["modality"])
    # `enforce_file_format=True` is pydicom 3's spelling of "write a conformant
    # Part 10 file"; the older `write_like_original=False` is deprecated and
    # warns on every call, and a harness that emits a deprecation on every
    # corpus write trains its reader to ignore the ones that matter.
    dataset.save_as(path, enforce_file_format=True)
    assert path.read_bytes(), "the DICOM file was written empty"
