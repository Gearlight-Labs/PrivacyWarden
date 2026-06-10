#!/usr/bin/env node
/**
 * encrypt-collection.mjs
 * PrivacyWarden Collection Encryptor — v2 scheme
 *
 * Blob format (binary):
 *   [4]  magic       "PWCL"
 *   [1]  version     0x02
 *   [16] salt        random, used for PBKDF2-SHA512 key derivation
 *   [12] nonce       random, AES-256-GCM nonce
 *   [64] hmac        HMAC-SHA512 over (salt + nonce + ciphertext+gcmtag)
 *   [N]  ciphertext  AES-256-GCM(plaintext) — includes 16-byte GCM auth tag appended by Node
 *
 * Key derivation:
 *   aesKey = PBKDF2(password=COLLECTION_SIGNING_KEY_hex, salt, iterations=600000, keylen=32, digest=sha512)
 *   macKey = PBKDF2(password=COLLECTION_SIGNING_KEY_hex, salt, iterations=600001, keylen=64, digest=sha512)
 *
 * Usage (local):
 *   COLLECTION_SIGNING_KEY=<64-hex-char-key> node encrypt-collection.mjs \
 *     collections/windows.yaml collections/windows.bin
 *
 * Usage (with Manus storage upload):
 *   COLLECTION_SIGNING_KEY=<key> \
 *   FORGE_API_URL=<url> \
 *   FORGE_API_KEY=<token> \
 *   COLLECTION_BLOB_KEY=<storage-key> \
 *   node encrypt-collection.mjs collections/windows.yaml collections/windows.bin
 *
 * When FORGE_API_URL, FORGE_API_KEY, and COLLECTION_BLOB_KEY are all set,
 * the script automatically uploads the encrypted blob to Manus private storage.
 */
import { createCipheriv, pbkdf2Sync, randomBytes, createHmac } from 'crypto';
import { readFileSync, writeFileSync } from 'fs';
import { resolve } from 'path';

const MAGIC = Buffer.from('PWCL');
const VERSION = 0x02;
const PBKDF2_ITERS_ENC = 600_000;
const PBKDF2_ITERS_MAC = 600_001;

const signingKeyHex = process.env.COLLECTION_SIGNING_KEY;
if (!signingKeyHex || signingKeyHex.length !== 64) {
  console.error('[encrypt] COLLECTION_SIGNING_KEY must be a 64-hex-char (256-bit) secret');
  process.exit(1);
}

const [,, inputPath, outputPath] = process.argv;
if (!inputPath || !outputPath) {
  console.error('[encrypt] Usage: node encrypt-collection.mjs <input.yaml> <output.bin>');
  process.exit(1);
}

const plaintext = readFileSync(resolve(inputPath));
console.log(`[encrypt] Plaintext size: ${plaintext.length} bytes`);

// Derive keys via PBKDF2-SHA512
const salt  = randomBytes(16);
const nonce = randomBytes(12);

console.log('[encrypt] Deriving AES key (PBKDF2-SHA512, 600,000 iterations)…');
const aesKey = pbkdf2Sync(signingKeyHex, salt, PBKDF2_ITERS_ENC, 32, 'sha512');

console.log('[encrypt] Deriving MAC key (PBKDF2-SHA512, 600,001 iterations)…');
const macKey = pbkdf2Sync(signingKeyHex, salt, PBKDF2_ITERS_MAC, 64, 'sha512');

// AES-256-GCM encrypt
const cipher = createCipheriv('aes-256-gcm', aesKey, nonce);
const encryptedBody = Buffer.concat([cipher.update(plaintext), cipher.final()]);
const gcmTag = cipher.getAuthTag(); // 16 bytes
const ciphertext = Buffer.concat([encryptedBody, gcmTag]);
console.log(`[encrypt] Ciphertext size: ${ciphertext.length} bytes (includes 16-byte GCM tag)`);

// HMAC-SHA512 over (salt + nonce + ciphertext) — encrypt-then-MAC
const hmacInput = Buffer.concat([salt, nonce, ciphertext]);
const hmac = createHmac('sha512', macKey).update(hmacInput).digest();
console.log(`[encrypt] HMAC-SHA512: ${hmac.toString('hex').slice(0, 16)}…`);

// Assemble blob
const blob = Buffer.concat([
  MAGIC,                    // 4 bytes
  Buffer.from([VERSION]),   // 1 byte
  salt,                     // 16 bytes
  nonce,                    // 12 bytes
  hmac,                     // 64 bytes
  ciphertext,               // N bytes
]);

writeFileSync(resolve(outputPath), blob);
console.log(`[encrypt] Blob written to ${outputPath} (${blob.length} bytes total)`);

// ── Optional: upload to Manus private storage ──────────────────────────────
const forgeApiUrl = process.env.FORGE_API_URL;
const forgeApiKey = process.env.FORGE_API_KEY;
const blobStorageKey = process.env.COLLECTION_BLOB_KEY;

if (forgeApiUrl && forgeApiKey && blobStorageKey) {
  console.log(`[encrypt] Uploading blob to Manus storage: ${blobStorageKey}`);
  try {
    const forgeBase = forgeApiUrl.replace(/\/+$/, '');

    // Get presigned PUT URL
    const presignUrl = new URL('v1/storage/presign/put', forgeBase + '/');
    presignUrl.searchParams.set('path', blobStorageKey);
    presignUrl.searchParams.set('content_type', 'application/octet-stream');

    const presignRes = await fetch(presignUrl.toString(), {
      headers: { Authorization: `Bearer ${forgeApiKey}` },
      signal: AbortSignal.timeout(10000),
    });

    if (!presignRes.ok) {
      console.error(`[encrypt] Presign failed: HTTP ${presignRes.status}`);
      process.exit(1);
    }

    const { url: signedUrl } = await presignRes.json();
    if (!signedUrl) {
      console.error('[encrypt] No signed URL in presign response');
      process.exit(1);
    }

    // Upload blob
    const uploadRes = await fetch(signedUrl, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: blob,
      signal: AbortSignal.timeout(30000),
    });

    if (uploadRes.ok) {
      console.log(`[encrypt] Upload OK — HTTP ${uploadRes.status}`);
    } else {
      console.error(`[encrypt] Upload failed: HTTP ${uploadRes.status}`);
      process.exit(1);
    }
  } catch (err) {
    console.error('[encrypt] Upload error:', err.message);
    process.exit(1);
  }
} else if (forgeApiUrl || forgeApiKey || blobStorageKey) {
  console.warn('[encrypt] Partial Forge config — skipping upload. Set FORGE_API_URL, FORGE_API_KEY, and COLLECTION_BLOB_KEY to enable.');
} else {
  console.log('[encrypt] Forge env vars not set — skipping storage upload (local mode).');
}

console.log('[encrypt] Done.');
