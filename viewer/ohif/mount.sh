#!/usr/bin/env bash
# Mount the Medarx panel inside a real OHIF mode, against a real Orthanc.
#
# This is the composition root. It does four things and then runs OHIF's own
# dev server:
#
#   1. checks out OHIF at a pinned tag, if it is not already here;
#   2. installs the monorepo's dependencies (once);
#   3. applies the Medarx mount to that checkout — a `pluginConfig.json` entry
#      for the out-of-tree extension, a `resolve.alias` that gives the
#      extension the host's React, and a link to this repo's app config;
#   4. starts the dev server with `APP_CONFIG` pointing at it and the
#      `PROXY_*` variables that route DICOMweb to Orthanc.
#
# ## What "not a fork" means here, exactly
#
# The OHIF checkout is **not modified in any way that changes its behaviour**,
# and this script is the complete list of what it touches:
#
#   * `platform/app/pluginConfig.json` — **one JSON object added** to the
#     `extensions` array. This is OHIF's own documented out-of-tree plugin
#     mechanism: `writePluginImportsFile.js` says so in its own comments ("an
#     external (out-of-tree) package listed here with a `directory` is
#     included"). It turns the package name into a resolve alias and a dynamic
#     import. It is data.
#   * `.webpack/resolveConfig.js` — **one alias added**. An out-of-tree
#     extension has its own `node_modules`; without this the bundle would
#     contain two Reacts (the extension's 19.x and the app's 18.3.1) and every
#     hook in the panel would throw "invalid hook call". This is the same file
#     that exists so the two build pipelines resolve identically.
#   * `platform/app/public/config/medarx.js` — a **symlink** to
#     `viewer/ohif/app-config.js` in this repo, so the configuration is not
#     copied and cannot drift.
#
# `git -C "$OHIF_DIR" diff` shows all three, and the report records it. No OHIF
# source file is edited, nothing is vendored into this repository, and the tag
# is never moved.
#
# ## Usage
#
#   bash viewer/ohif/mount.sh                 # prepare, then serve on :3000
#   OHIF_DIR=/path/to/checkout bash viewer/ohif/mount.sh
#   ORTHANC_URL=http://127.0.0.1:8042 bash viewer/ohif/mount.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OHIF_TAG="v3.13.10"
OHIF_DIR="${OHIF_DIR:-$HOME/Projects/ohif-viewers}"
OHIF_URL="https://github.com/OHIF/Viewers.git"
ORTHANC_URL="${ORTHANC_URL:-http://127.0.0.1:8042}"
PORT="${PORT:-3000}"
MEDARX_PKG="@medarx/viewer"

say() { printf '\n== %s\n' "$*"; }

# -- 0. preflight -------------------------------------------------------------
if [ ! -d "$REPO_ROOT/viewer/src/panels" ]; then
  echo "not a Medarx checkout: $REPO_ROOT" >&2
  exit 1
fi

# The extension is resolved by a `directory` relative to the OHIF repo root
# (see `fromDirectory` in writePluginImportsFile.js), so the checkout has to be
# a sibling of this repository for the default to hold. Anything else works
# with OHIF_DIR set; the relative path is computed below either way.
RELATIVE_TO_OHIF="$(python3 -c "
import os,sys
print(os.path.relpath(sys.argv[1], sys.argv[2]))" "$REPO_ROOT/viewer" "$OHIF_DIR")"

# -- 1. the pinned checkout ---------------------------------------------------
if [ ! -d "$OHIF_DIR/.git" ]; then
  say "cloning OHIF $OHIF_TAG (this is ~190 MB and a few minutes)"
  git clone --depth 1 --branch "$OHIF_TAG" "$OHIF_URL" "$OHIF_DIR"
else
  say "using the existing OHIF checkout at $OHIF_DIR"
  git -C "$OHIF_DIR" describe --tags --exact-match 2>/dev/null || \
    echo "  note: this checkout is not exactly on $OHIF_TAG"
fi

# -- 2. dependencies ----------------------------------------------------------
if [ ! -d "$OHIF_DIR/node_modules" ]; then
  say "installing the OHIF workspace (Cypress and Playwright binaries are skipped)"
  # CYPRESS_INSTALL_BINARY / PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD are not about
  # being tidy: those two downloads are hundreds of megabytes on a filesystem
  # with single-digit gigabytes free, and nothing in this mount uses either.
  ( cd "$OHIF_DIR" && \
    CYPRESS_INSTALL_BINARY=0 PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
    pnpm install --frozen-lockfile )
else
  say "node_modules already present"
fi

# -- 3. the mount -------------------------------------------------------------
say "applying the Medarx mount to the OHIF checkout"

PLUGIN_CONFIG="$OHIF_DIR/platform/app/pluginConfig.json"
python3 - "$PLUGIN_CONFIG" "$MEDARX_PKG" "$RELATIVE_TO_OHIF" <<'PY'
import json, sys
path, package, directory = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path) as fh:
    config = json.load(fh)
entry = {"packageName": package, "directory": f"./{directory}"}
kept = [e for e in config.get("extensions", []) if e.get("packageName") != package]
changed = kept != config.get("extensions", [])
config["extensions"] = kept + [entry]
with open(path, "w") as fh:
    json.dump(config, fh, indent=2)
    fh.write("\n")
print(f"  pluginConfig.json: {'added' if changed else 'already present'} {package} -> ./{directory}")
PY

RESOLVE_CONFIG="$OHIF_DIR/.webpack/resolveConfig.js"
python3 - "$RESOLVE_CONFIG" <<'PY'
import re, sys
path = sys.argv[1]
with open(path) as fh:
    text = fh.read()
anchor = "const alias = {\n"
addition = (
    "  // -- Medarx (out-of-tree extension) --------------------------------------\n"
    "  // An extension outside this repository brings its own `node_modules`, and\n"
    "  // the importer-relative walk-up below would then resolve a *second* React\n"
    "  // into the same bundle: the panel's hooks would run against React 19 while\n"
    "  // the renderer is React 18.3.1, and every hook call throws. One alias per\n"
    "  // host-owned singleton fixes it at the seam. Exact (`$`) matches only.\n"
    "  'react$': require.resolve('react'),\n"
    "  'react-dom$': require.resolve('react-dom'),\n"
    "  'react/jsx-runtime$': require.resolve('react/jsx-runtime'),\n"
    "  'react/jsx-dev-runtime$': require.resolve('react/jsx-dev-runtime'),\n"
)
if "Medarx (out-of-tree extension)" in text:
    print("  resolveConfig.js: the React alias is already there")
else:
    if anchor not in text:
        raise SystemExit("resolveConfig.js: the `const alias = {` anchor moved; re-read it")
    text = text.replace(anchor, anchor + addition, 1)
    with open(path, "w") as fh:
        fh.write(text)
    print("  resolveConfig.js: added the react$ aliases")
PY

APP_CONFIG_LINK="$OHIF_DIR/platform/app/public/config/medarx.js"
rm -f "$APP_CONFIG_LINK"
ln -s "$REPO_ROOT/viewer/ohif/app-config.js" "$APP_CONFIG_LINK"
echo "  public/config/medarx.js -> $REPO_ROOT/viewer/ohif/app-config.js"

# The extension's package entry. `main` is what the generated pluginImports
# dynamic import resolves through, so it has to be the connected module (the
# one that reads the mode's study), not the host-agnostic panel.
python3 - "$REPO_ROOT/viewer/package.json" <<'PY'
import json, sys
path = sys.argv[1]
with open(path) as fh:
    pkg = json.load(fh)
want = "ohif/extension.tsx"
if pkg.get("main") == want:
    print("  viewer/package.json: main already points at the connected module")
else:
    pkg["main"] = want
    ordered = {}
    for key in ("name", "version", "private", "type", "description", "main"):
        if key in pkg:
            ordered[key] = pkg[key]
    ordered.update({k: v for k, v in pkg.items() if k not in ordered})
    with open(path, "w") as fh:
        json.dump(ordered, fh, indent=2)
        fh.write("\n")
    print(f"  viewer/package.json: main -> {want}")
PY

say "what this changed inside the OHIF checkout"
git -C "$OHIF_DIR" --no-pager diff --stat || true

# -- 4. serve -----------------------------------------------------------------
say "starting the OHIF dev server on 127.0.0.1:$PORT"
echo "   open http://127.0.0.1:$PORT/localhost/orthanc/study/1.2.826.0.1.3680043.8.498.1138.900.1.1"
cd "$OHIF_DIR/platform/app"
NODE_ENV=development \
OHIF_PORT="$PORT" \
OHIF_OPEN=false \
APP_CONFIG=config/medarx.js \
PROXY_TARGET="${ORTHANC_URL%/}/dicom-web" \
PROXY_DOMAIN="$ORTHANC_URL" \
PROXY_PATH_REWRITE_FROM=/pacs/dicom-web \
PROXY_PATH_REWRITE_TO=/dicom-web \
exec pnpm exec rspack serve --config .webpack/webpack.pwa.js
