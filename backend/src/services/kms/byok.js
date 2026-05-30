// kms/byok.js — KMS-02 BYOK source-URI parser + fingerprint helper.
//
// Parses KMS_BYOK_SOURCE (or the CLI --source flag) into a normalized
// PKCS#8 PEM that any KmsSigner with byok=true can ingest via importKey.
// Validates the material is Ed25519 BEFORE touching the provider.
//
// Supported schemes:
//   file:<path>     Read PKCS#8 PEM from disk.
//   env:<VAR>       Read PKCS#8 PEM from the named env var.
//
// Stub schemes (parser refuses with a clear message):
//   pkcs11:<slot/label>   tracked in KMS-04 (HSM path)
//   jwk:<url>             tracked in KMS-05 (JWKS trust-store path)
//
// Cross-cutting rule (FEATURES.md L705): there is no silent fallback.
// Malformed URIs and non-Ed25519 material throw KmsConfigError before the
// caller can hand bytes to a provider.
import crypto from "node:crypto";
import fs from "node:fs";

import { keyFingerprint } from "../auditCrypto.js";
import { ED25519_SPKI_PREFIX, KmsConfigError } from "./index.js";

export const BYOK_SUPPORTED_SCHEMES = ["file", "env"];
export const BYOK_STUB_SCHEMES = ["pkcs11", "jwk"];

function splitScheme(uri) {
  const i = uri.indexOf(":");
  if (i <= 0) {
    throw new KmsConfigError(
      `BYOK source '${uri}' missing scheme; expected one of ` +
        `${BYOK_SUPPORTED_SCHEMES.map((s) => `${s}:`).join(", ")}`
    );
  }
  return { scheme: uri.slice(0, i).toLowerCase(), rest: uri.slice(i + 1) };
}

function readFromFile(path) {
  try {
    return fs.readFileSync(path, "utf8");
  } catch (e) {
    throw new KmsConfigError(`BYOK source file:${path} not readable: ${e.message}`);
  }
}

function readFromEnv(varName) {
  if (!varName) {
    throw new KmsConfigError("BYOK source env: missing variable name (use env:NAME)");
  }
  if (varName === "KMS_BYOK_SOURCE") {
    throw new KmsConfigError(
      "BYOK source env:KMS_BYOK_SOURCE is self-referential; point at a different env var"
    );
  }
  const raw = process.env[varName];
  if (!raw) {
    throw new KmsConfigError(`BYOK source env:${varName} is empty or unset`);
  }
  // docker compose env_file often delivers PEM as a single line with literal
  // backslash-n; convert to real newlines so crypto.createPrivateKey can parse.
  return raw.includes("\n") ? raw : raw.replace(/\\n/g, "\n");
}

function normalizeEd25519Pkcs8(pem, sourceLabel) {
  let priv;
  try {
    priv = crypto.createPrivateKey({ key: pem, format: "pem", type: "pkcs8" });
  } catch (e) {
    throw new KmsConfigError(
      `BYOK material from ${sourceLabel} is not a valid PKCS#8 PEM: ${e.message}`
    );
  }
  if (priv.asymmetricKeyType !== "ed25519") {
    throw new KmsConfigError(
      `BYOK material from ${sourceLabel} is not Ed25519 (got ${priv.asymmetricKeyType})`
    );
  }
  // Re-export to canonical PKCS#8 PEM — strips CRLFs, BOM, trailing junk, and
  // any non-PKCS#8 artefacts a customer's tooling might have introduced.
  return priv.export({ type: "pkcs8", format: "pem" });
}

/**
 * Parse a KMS_BYOK_SOURCE URI and return normalized Ed25519 PKCS#8 material.
 *
 * @param {string} uri  e.g. "file:/etc/secrets/audit.pem" or "env:AUDIT_PEM"
 * @returns {Promise<{pem:string, source:"pkcs8", alg:"ed25519", kind:"file"|"env"}>}
 */
export async function parseByokSource(uri) {
  if (typeof uri !== "string" || uri.trim() === "") {
    throw new KmsConfigError("BYOK source is empty");
  }
  const { scheme, rest } = splitScheme(uri.trim());

  if (scheme === "pkcs11") {
    throw new KmsConfigError(
      "BYOK pkcs11: URIs are not implemented; tracked in KMS-04 (HSM path). " +
        "Use file: or env: with PKCS#8 PEM for now."
    );
  }
  if (scheme === "jwk") {
    throw new KmsConfigError(
      "BYOK jwk: URIs are not implemented; tracked in KMS-05 (JWKS trust store). " +
        "Use file: or env: with PKCS#8 PEM for now."
    );
  }

  let raw, sourceLabel, kind;
  if (scheme === "file") {
    if (!rest) {
      throw new KmsConfigError("BYOK source file: missing path (use file:/absolute/path.pem)");
    }
    raw = readFromFile(rest);
    sourceLabel = `file:${rest}`;
    kind = "file";
  } else if (scheme === "env") {
    raw = readFromEnv(rest);
    sourceLabel = `env:${rest}`;
    kind = "env";
  } else {
    throw new KmsConfigError(
      `BYOK source scheme '${scheme}:' is not supported. Supported: ` +
        BYOK_SUPPORTED_SCHEMES.map((s) => `${s}:`).join(", ")
    );
  }

  const pem = normalizeEd25519Pkcs8(raw, sourceLabel);
  return { pem, source: "pkcs8", alg: "ed25519", kind };
}

/**
 * Compute SHA-256 fingerprint of the SPKI DER for an Ed25519 PKCS#8 PEM.
 * Used at boot to compare BYOK material against the provider's existing key
 * (and the audit_signing_keys row) WITHOUT re-importing.
 *
 * @param {string} pem  Ed25519 PKCS#8 PEM (already validated)
 * @returns {Buffer}    32-byte SHA-256 of the SPKI DER
 */
export function fingerprintFromPkcs8(pem) {
  const priv = crypto.createPrivateKey({ key: pem, format: "pem", type: "pkcs8" });
  if (priv.asymmetricKeyType !== "ed25519") {
    throw new KmsConfigError(
      `fingerprintFromPkcs8: expected ed25519, got ${priv.asymmetricKeyType}`
    );
  }
  const pubkey = crypto.createPublicKey(priv);
  const spkiDer = pubkey.export({ type: "spki", format: "der" });
  // Defensive: confirm the SPKI prefix matches the canonical Ed25519 header
  // so audit_signing_keys.fp computed here is byte-identical to the one
  // providers produce via buildEd25519KeyMaterial(rawPubkey32).
  if (
    spkiDer.length !== ED25519_SPKI_PREFIX.length + 32 ||
    Buffer.compare(spkiDer.subarray(0, ED25519_SPKI_PREFIX.length), ED25519_SPKI_PREFIX) !== 0
  ) {
    throw new KmsConfigError("fingerprintFromPkcs8: unexpected SPKI encoding for Ed25519 key");
  }
  return keyFingerprint(spkiDer);
}
