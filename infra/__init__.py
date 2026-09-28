"""Operational infrastructure that is **not** part of the ``medarx`` package.

Nothing here is importable from ``backend/src/medarx/`` and nothing there
imports anything here. The observer is a separate process with its own
dependency file, and the agreement check is a separate tool that reads what the
observer and the capture wrote; keeping them out of the package is what stops
"the thing that checks the egress" from being wired into "the thing that
performs the egress".
"""
