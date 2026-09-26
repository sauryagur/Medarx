#!/usr/bin/env bash
# Install the pinned spaCy NER model into the project venv without pip.
#
# `python -m spacy download` is unusable here: spaCy shells out to `pip`, `pip`
# is not on PATH, and the `uv` shim intercepts the call with
# "No virtual environment found". Downloading the wheel directly and installing
# it with `uv pip install` is the verified path.
#
# The wheel filename MUST carry the version string; uv rejects an unversioned
# name with: The wheel filename "ensm.whl" is invalid: Must have a version.
#
# Idempotent: exits 0 immediately if the pinned model version is already
# installed. The guard compares the *installed distribution version*, not just
# the model name, so a stale build is reinstalled rather than reported as
# already-present.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
VENV_PYTHON="$BACKEND_DIR/.venv/bin/python"

MODEL_NAME="en_core_web_sm"
MODEL_VERSION="3.8.0"
WHEEL="${MODEL_NAME}-${MODEL_VERSION}-py3-none-any.whl"
WHEEL_URL="https://github.com/explosion/spacy-models/releases/download/${MODEL_NAME}-${MODEL_VERSION}/${WHEEL}"

if [ ! -x "$VENV_PYTHON" ]; then
  echo "venv python not found at $VENV_PYTHON -- run 'uv sync' in backend/ first" >&2
  exit 1
fi

if "$VENV_PYTHON" -c "import importlib.metadata as m, sys; sys.exit(0 if m.version('${MODEL_NAME}') == '${MODEL_VERSION}' else 1)" >/dev/null 2>&1; then
  echo "${MODEL_NAME} ${MODEL_VERSION} is installed at the pinned version -- nothing to do"
  exit 0
fi

cd "$BACKEND_DIR"

# --fail makes a 404/500 abort instead of writing an HTML error page into the
# wheel; the download lands on a temp name so a failed run never leaves a
# corrupt .whl behind for the next one to trip over.
curl -sSL --fail --show-error -o "${WHEEL}.part" "$WHEEL_URL"
mv -f "${WHEEL}.part" "$WHEEL"
uv pip install --python "$VENV_PYTHON" "./$WHEEL"
rm -f "./$WHEEL"

"$VENV_PYTHON" -c "import spacy; spacy.load('${MODEL_NAME}')"
echo "installed ${MODEL_NAME} ${MODEL_VERSION}"
