#!/usr/bin/env node
// scripts/import-key.js — KMS-02 BYOK import CLI.
//
// Imports an Ed25519 PKCS#8 PEM into the configured KMS provider WITHOUT
// touching the backend database. On the next backend boot,
// audit.loadOrInitSigningKey reconciles the provider's pubkey with the DB
// and registerSigningKeyTx inserts the audit_signing_keys row inside the
// genesis transaction. Keeping this CLI DB-free means it works in
// air-gapped / pre-boot staging and avoids two write paths to the same
// table.
//
// Usage:
//   node scripts/import-key.js --source <uri> [--key-id <id>] [--provider <name>]
//
// URIs:
//   file:/absolute/path/to/key.pem    Read PKCS#8 PEM from disk.
//   env:VAR                           Read PKCS#8 PEM from the named env var.
//
// Defaults:
//   --provider  →  $KMS_PROVIDER (or "vault")
//   --key-id    →  $KMS_KEY_ID   (or "audit-signing")
//
// Exit codes:
//   0  successful import (or idempotent skip on fingerprint match)
//   1  unexpected error
//   2  config / parse error
//   3  provider import failure / fingerprint mismatch

const USAGE = `Usage: node scripts/import-key.js --source <uri> [--key-id <id>] [--provider <name>]

URIs:
  file:/absolute/path/to/key.pem    Read PKCS#8 PEM from disk.
  env:VAR                           Read PKCS#8 PEM from the named env var.

Defaults:
  --provider  $KMS_PROVIDER (or "vault")
  --key-id    $KMS_KEY_ID   (or "audit-signing")

The CLI does NOT write to audit_signing_keys. On the next backend boot,
that row is appended atomically inside the genesis transaction.
`;

function parseArgs(argv) {
  const out = { source: null, keyId: null, provider: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--help" || a === "-h") {
      console.log(USAGE);
      process.exit(0);
    } else if (a === "--source") {
      out.source = argv[++i];
    } else if (a === "--key-id") {
      out.keyId = argv[++i];
    } else if (a === "--provider") {
      out.provider = argv[++i];
    } else if (a.startsWith("--source=")) {
      out.source = a.slice("--source=".length);
    } else if (a.startsWith("--key-id=")) {
      out.keyId = a.slice("--key-id=".length);
    } else if (a.startsWith("--provider=")) {
      out.provider = a.slice("--provider=".length);
    } else {
      console.error(`unknown argument: ${a}\n\n${USAGE}`);
      process.exit(2);
    }
  }
  if (!out.source) {
    console.error(`--source is required\n\n${USAGE}`);
    process.exit(2);
  }
  return out;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  // Set KMS_PROVIDER from --provider BEFORE importing kms modules so the
  // getSigner() factory picks it up (it caches the singleton on first call).
  if (args.provider) process.env.KMS_PROVIDER = args.provider;
  if (args.keyId) process.env.KMS_KEY_ID = args.keyId;

  const kmsIndex = await import("../backend/src/services/kms/index.js");
  const byok = await import("../backend/src/services/kms/byok.js");

  let parsed;
  try {
    parsed = await byok.parseByokSource(args.source);
  } catch (e) {
    console.error(`error: ${e.message}`);
    process.exit(2);
  }

  let intendedFp;
  try {
    intendedFp = byok.fingerprintFromPkcs8(parsed.pem);
  } catch (e) {
    console.error(`error: ${e.message}`);
    process.exit(2);
  }

  let signer;
  try {
    signer = await kmsIndex.getSigner();
  } catch (e) {
    console.error(`error: kms provider init failed: ${e.message}`);
    process.exit(2);
  }
  const keyId = kmsIndex.getAuditKeyId();

  // Idempotent check: if the provider already holds a key under this keyId,
  // compare fingerprints. Match → exit 0 (skip). Mismatch → exit 3.
  let existing = null;
  try {
    existing = await signer.getPublicKey(keyId);
  } catch {
    // No key yet; fall through to import.
  }
  if (existing) {
    if (Buffer.compare(existing.fingerprintSha256, intendedFp) === 0) {
      console.log(
        `already present (idempotent) ` +
          `provider=${signer.providerName()} keyId=${keyId} ` +
          `fingerprint=${intendedFp.toString("hex")}`
      );
      process.exit(0);
    }
    console.error(
      `error: provider keyId=${keyId} already holds a key with fingerprint ` +
        `${existing.fingerprintSha256.toString("hex")}, which does not match ` +
        `the BYOK material (${intendedFp.toString("hex")}). ` +
        `Use a different KMS_KEY_ID or rotate the existing key first.`
    );
    process.exit(3);
  }

  try {
    await signer.importKey(keyId, parsed.pem, { alg: "ed25519", source: "pkcs8" });
  } catch (e) {
    console.error(`error: provider import failed: ${e.message}`);
    process.exit(3);
  }

  // Re-fetch the pubkey so the printed fingerprint reflects what the
  // provider actually stored (cheap sanity check; should equal intendedFp).
  let confirmed;
  try {
    confirmed = await signer.getPublicKey(keyId);
  } catch (e) {
    console.error(
      `error: import succeeded but getPublicKey failed afterwards: ${e.message}`
    );
    process.exit(3);
  }
  if (Buffer.compare(confirmed.fingerprintSha256, intendedFp) !== 0) {
    console.error(
      `error: provider stored fingerprint ${confirmed.fingerprintSha256.toString("hex")} ` +
        `but BYOK material was ${intendedFp.toString("hex")} — refusing to claim success`
    );
    process.exit(3);
  }

  console.log(
    `provider=${signer.providerName()} keyId=${keyId} ` +
      `source=${parsed.kind} fingerprint=${confirmed.fingerprintSha256.toString("hex")}`
  );
}

main().catch((e) => {
  console.error(`error: ${e.stack || e.message || e}`);
  process.exit(1);
});
