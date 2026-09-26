"""Shared error type for the privacy kernel.

`ExtractionError` is raised by the layers that fail closed: this is the
generic, layer-tagged refusal. Layer values come from the closed set
{"J", "A", "D.1", "D.2", "D.3", "E", "F"}; "A" is the structured payload
extractor (Task 2). Action codes are members of the `ActionCode` enumeration
in `.docs/openapi.yaml` and never carry raw values, so a refusal built from
this exception is safe to put in a block receipt.
"""

from __future__ import annotations

__all__ = ["ExtractionError"]


class ExtractionError(Exception):
    """A fail-closed refusal raised by a privacy-kernel layer.

    Attributes:
        layer: closed-set layer tag, e.g. "A" for the payload extractor.
        action_codes: non-empty tuple of contract `ActionCode` values.
    """

    def __init__(self, layer: str, action_codes: tuple[str, ...], message: str = "") -> None:
        if not action_codes:
            raise ValueError("action_codes must not be empty")
        self.layer = layer
        self.action_codes = tuple(action_codes)
        self.message = message
        super().__init__(message or f"{layer}: {', '.join(self.action_codes)}")
