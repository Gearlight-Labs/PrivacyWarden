#!/usr/bin/env bash
# update-collection.sh
# re-encrypts windows.yaml, commits windows.bin to the repo, and pushes.
# the push triggers the deploy-collection workflow which uploads to storage.
#
# usage: bash scripts/update-collection.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
YAML="$REPO_DIR/collections/windows.yaml"
BIN="$REPO_DIR/collections/windows.bin"

# ── check required env vars ───────────────────────────────────────────────────
: "${COLLECTION_SIGNING_KEY:?need COLLECTION_SIGNING_KEY}"
: "${BUILT_IN_FORGE_API_KEY:?need BUILT_IN_FORGE_API_KEY}"
: "${BUILT_IN_FORGE_API_URL:?need BUILT_IN_FORGE_API_URL}"
BLOB_KEY="${COLLECTION_BLOB_KEY:-windows_v380.bin}"

echo "[1/4] encrypting $YAML..."
node "$SCRIPT_DIR/encrypt-collection.mjs" "$YAML" "$BIN"

echo "[2/4] committing windows.bin..."
cd "$REPO_DIR"
git add collections/windows.bin
git commit -m "update collection blob" || echo "nothing to commit"

echo "[3/4] pushing to GitHub (triggers deploy workflow)..."
git push origin main

echo "[4/4] done — the deploy workflow will upload the blob to storage automatically."
echo "      restart the server once the workflow finishes to load the new collection."
