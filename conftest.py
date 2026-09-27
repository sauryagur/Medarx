"""Make the repository root importable, for pytest runs started from it.

`backend/pyproject.toml` sets `pythonpath = ["src", ".."]`, which is what makes
`import medarx` and `import evals` work when pytest is started from `backend/`.
It is applied only when that file is the one pytest reads for configuration.
Naming `../` as the target makes the repository root the rootdir instead, so
that `pythonpath` is never applied and `import evals` fails with
`ModuleNotFoundError` — which it did, from
`backend/tests/test_conformance_profile.py` as well as from the evaluation
harness, before this file existed.

It is loaded only when the rootdir is the repository root. The canonical
`cd backend && uv run pytest` keeps `backend/` as its rootdir and never sees
this file, so the suite it runs is unchanged.
"""

import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
