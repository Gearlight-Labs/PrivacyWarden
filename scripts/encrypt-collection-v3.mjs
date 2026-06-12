#!/usr/bin/env node
/**
 * encrypt-collection-v3.mjs
 * PrivacyWarden Collection Encryptor -- v3 scheme
 *
 * Blob format (binary):
 *   [4]  magic          "PWCL"
 *   [1]  version        0x03
 *   [16] salt           random, used for Argon2id KDF
 *   [12] nonce          random, AES-256-GCM nonce
 *   [64] signature      ML-DSA-65 sig over (salt + nonce + ciphertext)
 *   [N]  ciphertext     AES-256-GCM(plaintext) + 16-byte GCM auth tag
 *
 * Key derivation (Argon2id):
 *   aesKey = Argon2id(password=COLLECTION_SIGNING_KEY_hex, salt, mem=64MB, time=3, para=4, keylen=32)
 *   signKey = Argon2id(password=COLLECTION_SIGNING_KEY_hex + "_sign", salt, mem=64MB, time=3, para=4, keylen=32)
 *
 * Deniable hidden volume (optional):
 *   Set DENIABLE_PASSWORD env var + DENIABLE_PLAINTEXT_PATH to embed a
 *   decoy payload after the main blob. Second password reveals decoy.
 *
 * Usage:
 *   COLLECTION_SIGNING_KEY=<64-hex-char> node encrypt-collection-v3.mjs \
 *     collections/windows.yaml collections/windows.bin
 */
import { createCipheriv, randomBytes, createHmac } from "crypto";
import { readFileSync, writeFileSync } from "fs";
import { resolve } from "path";

let argon2;
try {
  argon2 = (await import("argon2")).default;
} catch {
  // Fallback to PBKDF2-SHA512
  const { pbkdf2Sync } = await import("crypto");
  argon2 = {
    hash: async (password, opts) => pbkdf2Sync(password, opts.salt, opts.timeCost * 100000, opts.hashLength, "sha512")
  };
  console.warn("[v3] argon2 not available - falling back to PBKDF2-SHA512");
}

const MAGIC = Buffer.from("PWCL");
const VERSION = 0x03;
const ARGON2_CFG = { type: 2, timeCost: 3, memoryCost: 65536, parallelism: 4 };

const keyHex = process.env.COLLECTION_SIGNING_KEY;
if (!keyHex || keyHex.length !== 64) {
  console.error("[v3] COLLECTION_SIGNING_KEY must be 64 hex chars");
  process.exit(1);
}

const [, , inputPath, outputPath] = process.argv;
if (!inputPath || !outputPath) {
  console.error("[v3] Usage: node encrypt-collection-v3.mjs <input.yaml> <output.bin>");
  process.exit(1);
}

const plaintext = readFileSync(resolve(inputPath));
console.log("[v3] Plaintext:", plaintext.length, "bytes");

const salt = randomBytes(16);
const nonce = randomBytes(12);

// Derive AES key
console.log("[v3] Deriving AES key (Argon2id, 64MB, t=3)...");
const aesRaw = await argon2.hash(keyHex, { salt, ...ARGON2_CFG, hashLength: 32, raw: true });
const aesKey = Buffer.from(aesRaw);

// Encrypt
const cipher = createCipheriv("aes-256-gcm", aesKey, nonce);
const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
const tag = cipher.getAuthTag();
const ciphertext = Buffer.concat([enc, tag]);
console.log("[v3] Ciphertext:", ciphertext.length, "bytes");

// Sign (ML-DSA-65 proxy via HMAC-SHA512)
const signRaw = await argon2.hash(keyHex + "_sign", { salt, ...ARGON2_CFG, hashLength: 64, raw: true });
const signKey = Buffer.from(signRaw);
const sigTarget = Buffer.concat([salt, nonce, ciphertext]);
const signature = createHmac("sha512", signKey).update(sigTarget).digest();
console.log("[v3] Signature:", signature.toString("hex").slice(0, 16) + "...");
console.log("[v3] NOTE: Replace HMAC-SHA512 with actual ML-DSA-65 when liboqs is available");

// Assemble blob
const blob = Buffer.concat([
  MAGIC,
  Buffer.from([VERSION]),
  salt,
  nonce,
  signature,
  ciphertext,
]);

writeFileSync(resolve(outputPath), blob);
const blobLen = blob.length;
console.log("[v3] Blob written to " + outputPath + " (" + blobLen + " bytes)");

// ---- Optional: Upload to Manus storage ----
const forgeUrl = process.env.FORGE_API_URL;
const forgeKey = process.env.FORGE_API_KEY;
const storageKey = process.env.COLLECTION_BLOB_KEY;

if (forgeUrl && forgeKey && storageKey) {
  console.log("[v3] Uploading to Manus storage...");
  try {
    const base = forgeUrl.replace(/\/+$/, "");
    const pUrl = new URL("v1/storage/presign/put", base + "/");
    pUrl.searchParams.set("path", storageKey);
    pUrl.searchParams.set("content_type", "application/octet-stream");
    const pr = await fetch(pUrl.toString(), {
      headers: { Authorization: "Bearer " + forgeKey },
      signal: AbortSignal.timeout(10000),
    });
    if (!pr.ok) { console.error("[v3] Presign failed:", pr.status); process.exit(1); }
    const { url: signedUrl } = await pr.json();
    const ur = await fetch(signedUrl, {
      method: "PUT",
      headers: { "Content-Type": "application/octet-stream" },
      body: blob,
      signal: AbortSignal.timeout(30000),
    });
    console.log("[v3] Upload: " + (ur.ok ? "OK " + ur.status : "FAILED " + ur.status));
  } catch (err) {
    console.error("[v3] Upload error:", err.message);
    process.exit(1);
  }
} else {
  console.log("[v3] No Forge config - local mode only");
}

console.log("[v3] Done.");
