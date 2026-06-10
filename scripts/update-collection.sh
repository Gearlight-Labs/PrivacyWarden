#!/usr/bin/env bash
# update-collection.sh
# re-encrypts windows.yaml and uploads the new blob to private storage.
# run this whenever you edit collections/windows.yaml.
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

echo "[1/3] encrypting $YAML..."
node "$SCRIPT_DIR/encrypt-collection.mjs" "$YAML" "$BIN"

echo "[2/3] uploading as $BLOB_KEY..."
FORGE_BASE="${BUILT_IN_FORGE_API_URL%/}"

PRESIGN_RESP=$(curl -sf \
  -H "Authorization: Bearer $BUILT_IN_FORGE_API_KEY" \
  "${FORGE_BASE}/v1/storage/presign/put?path=${BLOB_KEY}&content_type=application/octet-stream")

SIGNED_URL=$(echo "$PRESIGN_RESP" | node -e \
  "let d=''; process.stdin.on('data',c=>d+=c).on('end',()=>console.log(JSON.parse(d).url))")

[ -z "$SIGNED_URL" ] && { echo "error: couldn't get signed URL"; exit 1; }

STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
  -X PUT \
  -H "Content-Type: application/octet-stream" \
  --data-binary @"$BIN" \
  "$SIGNED_URL")

echo "upload status: $STATUS"
[ "$STATUS" -ge 200 ] && [ "$STATUS" -lt 300 ] || { echo "error: upload failed"; exit 1; }

echo "[3/3] done — restart the server to load the new blob"
