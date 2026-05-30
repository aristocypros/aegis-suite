// kms/index.js — KmsSigner adapter factory.
//
// Single entry point that selects the signing provider at boot via
// KMS_PROVIDER. The audit chain (audit.js), the policy artifact signer
// (CRY-05), the PEP decision token signer (CRY-04), and any future
// cryptographic consumer talk to KmsSigner — never to a concrete provider.
//
// Adding a provider:
//   1. Create kms/<name>.js exporting `create(): Promise<KmsSigner>`.
//   2. Register it in PROVIDERS below.
//   3. Document its env vars and capabilities in kms/README.md.
//
// Cross-cutting rule (FEATURES.md L700): no provider module may be imported
// from outside kms/. Core code uses `getSigner()` only.
//
// Cross-cutting rule (FEATURES.md L705): there is NO fallback. Misconfigured
// or unimplemented providers fail at instantiation, not at first sign.
import crypto from "node:crypto";

import { keyFingerprint } from "../auditCrypto.js";

import * as vaultProvider from "./vault.js";
import * as fileProvider from "./file.js";
import * as awsProvider from "./aws.js";
import * as gcpProvider from "./gcp.js";
import * as azureProvider from "./azure.js";
import * as pkcs11Provider from "./pkcs11.js";

const PROVIDERS = {
  vault: vaultProvider,
  file: fileProvider,
  aws: awsProvider,
  gcp: gcpProvider,
  azure: azureProvider,
  pkcs11: pkcs11Provider,
};

export class KmsConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = "KmsConfigError";
  }
}

export class KmsProviderNotImplemented extends Error {
  constructor(providerName) {
    super(
      `KMS provider '${providerName}' is not implemented yet. ` +
        `KMS-01 ships 'vault' (production) and 'file' (DEV only). ` +
        `Cloud providers (aws/gcp/azure/pkcs11) land in follow-up tasks.`
    );
    this.name = "KmsProviderNotImplemented";
    this.provider = providerName;
  }
}

let _signer = null;
let _signerProviderName = null;

/**
 * Returns the singleton KmsSigner selected by KMS_PROVIDER (default "vault").
 * Throws KmsConfigError if the provider is unknown or fails its prerequisites.
 * Throws KmsProviderNotImplemented for the stub providers.
 *
 * @typedef {Object} KmsKeyMaterial
 * @property {Buffer} pubkeyDer          SPKI DER bytes (matches audit_signing_keys.pubkey BYTEA)
 * @property {string} pem                PEM-encoded SPKI
 * @property {Object} jwk                JWK form { kty: "OKP", crv: "Ed25519", x }
 * @property {Buffer} fingerprintSha256  SHA-256 of pubkeyDer
 * @property {number} keyVersion         Provider-monotonic key version
 *
 * @typedef {Object} KmsSigner
 * @property {(opts: {keyId:string, algorithm:string}) => Promise<void>} ensureKey
 * @property {(keyId:string) => Promise<KmsKeyMaterial>} getPublicKey
 * @property {(keyId:string, dataBytes:Buffer) => Promise<{sigBytes:Buffer, keyVersion:number, alg:string}>} sign
 * @property {(keyId:string, dataBytes:Buffer, sigBytes:Buffer, opts?:{keyVersion?:number}) => Promise<boolean>} verify
 * @property {(keyId:string) => Promise<{newVersion:number}>} rotate
 * @property {(keyId:string, material:Buffer|string, opts:{alg:string, source:string}) => Promise<void>} importKey
 * @property {() => {algorithms:string[], byok:boolean, rotate:boolean}} capabilities
 * @property {() => string} providerName
 * @property {() => string} signingStoreLabel
 */
export async function getSigner() {
  if (_signer) return _signer;

  const providerName = (process.env.KMS_PROVIDER || "vault").toLowerCase();
  const provider = PROVIDERS[providerName];
  if (!provider) {
    throw new KmsConfigError(
      `unknown KMS_PROVIDER='${providerName}' (expected one of: ${Object.keys(PROVIDERS).join(", ")})`
    );
  }

  const signer = await provider.create();
  const caps = signer.capabilities();
  if (!caps.algorithms.includes("ed25519")) {
    throw new KmsConfigError(
      `KMS provider '${providerName}' does not support ed25519 (capabilities: ${JSON.stringify(caps)})`
    );
  }

  _signer = signer;
  _signerProviderName = providerName;
  return _signer;
}

/**
 * Key identifier for the audit-signing key. Reads KMS_KEY_ID first, falling
 * back to VAULT_TRANSIT_KEY for backward compatibility with deployments
 * predating KMS-01. Default: "audit-signing".
 */
export function getAuditKeyId() {
  return (
    process.env.KMS_KEY_ID ||
    process.env.VAULT_TRANSIT_KEY ||
    "audit-signing"
  );
}

/** Test/reload helper — clears the cached singleton. */
export function _resetForTests() {
  _signer = null;
  _signerProviderName = null;
}

// ─── Shared helpers used by providers ──────────────────────────────────────

// SPKI DER prefix for an Ed25519 public key. Providers that get the raw
// 32-byte ed25519 pubkey (Vault, file) wrap it with this prefix to produce
// the SPKI DER bytes our DB stores.
//   30 2a — SEQUENCE, 42 bytes
//   30 05 — SEQUENCE (AlgorithmIdentifier)
//   06 03 2b 65 70 — OID 1.3.101.112 (Ed25519)
//   03 21 00 — BIT STRING, 33 bytes, 0 unused bits
export const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function base64url(buf) {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function pemFromDer(der) {
  return (
    "-----BEGIN PUBLIC KEY-----\n" +
    der.toString("base64").match(/.{1,64}/g).join("\n") +
    "\n-----END PUBLIC KEY-----\n"
  );
}

/**
 * Build a KmsKeyMaterial from the raw 32-byte Ed25519 public key.
 * Used by providers that natively expose the raw pubkey.
 */
export function buildEd25519KeyMaterial(rawPubkey32, keyVersion) {
  if (!Buffer.isBuffer(rawPubkey32) || rawPubkey32.length !== 32) {
    throw new Error(
      `kms: expected 32-byte ed25519 public key, got ${rawPubkey32?.length} bytes`
    );
  }
  const pubkeyDer = Buffer.concat([ED25519_SPKI_PREFIX, rawPubkey32]);
  return {
    pubkeyDer,
    pem: pemFromDer(pubkeyDer),
    jwk: {
      kty: "OKP",
      crv: "Ed25519",
      x: base64url(rawPubkey32),
    },
    fingerprintSha256: keyFingerprint(pubkeyDer),
    keyVersion,
  };
}

/**
 * Local Ed25519 verify against a KmsKeyMaterial.pubkeyDer. Used by every
 * provider's `verify` implementation — no I/O to the remote KMS.
 */
export function localVerifyEd25519(material, dataBytes, sigBytes) {
  const pubkey = crypto.createPublicKey({
    key: material.pubkeyDer,
    format: "der",
    type: "spki",
  });
  return crypto.verify(null, dataBytes, pubkey, sigBytes);
}
