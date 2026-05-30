// kms/vault.js — KmsSigner backed by HashiCorp Vault's Transit secrets engine.
//
// This is the default provider (KMS_PROVIDER=vault). The Ed25519 private key
// lives inside Vault and never leaves it: sign() POSTs the entry hash to
// /v1/transit/sign and Vault returns the signature.
//
// Env contract:
//   VAULT_ADDR        — Vault HTTP endpoint (e.g. http://vault:8200)
//   VAULT_TOKEN_FILE  — Path to a file containing the Vault token (delivered
//                       by the vault-init sidecar at /vault/secrets/backend_token)
//   KMS_KEY_ID or VAULT_TRANSIT_KEY — Transit key name (default "audit-signing")
//
// Capabilities: ed25519, BYOK via PKCS#8 PEM wrap-and-import, rotate stubbed
// (KMS-04 will wire /transit/keys/<name>/rotate).
import crypto from "node:crypto";
import fs from "node:fs";

import {
  KmsConfigError,
  buildEd25519KeyMaterial,
  localVerifyEd25519,
} from "./index.js";

// AES-KWP default initial value (RFC 5649 §3, "Alternative Initial Value").
// Required by Vault's BYOK import flow.
const AES_KWP_DEFAULT_IV = Buffer.from("a65959a6", "hex");

async function vaultRequest(state, path, { method = "GET", body, expect404 = false } = {}) {
  const url = `${state.addr}/v1/${path.replace(/^\/+/, "")}`;
  const headers = { "X-Vault-Token": state.token };
  if (body !== undefined) headers["Content-Type"] = "application/json";

  let resp;
  try {
    resp = await fetch(url, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch (e) {
    throw new Error(`kms/vault: ${method} ${path} transport error: ${e.message}`);
  }
  if (resp.status === 404 && expect404) return null;
  if (resp.status === 204) return null;
  const text = await resp.text();
  let parsed = null;
  if (text) {
    try { parsed = JSON.parse(text); } catch { /* leave as text */ }
  }
  if (!resp.ok) {
    const errs = parsed?.errors?.join("; ") || text || resp.statusText;
    const err = new Error(`kms/vault: ${method} ${path} → ${resp.status}: ${errs}`);
    err.status = resp.status;
    throw err;
  }
  return parsed;
}

export async function create() {
  const addrRaw = process.env.VAULT_ADDR;
  const tokenFile = process.env.VAULT_TOKEN_FILE;
  if (!addrRaw) {
    throw new KmsConfigError(
      "VAULT_ADDR is required when KMS_PROVIDER=vault"
    );
  }
  if (!tokenFile) {
    throw new KmsConfigError(
      "VAULT_TOKEN_FILE is required when KMS_PROVIDER=vault"
    );
  }

  let token;
  try {
    token = fs.readFileSync(tokenFile, "utf8").trim();
  } catch (e) {
    throw new KmsConfigError(
      `failed to read Vault token file ${tokenFile}: ${e.message}`
    );
  }
  if (!token) {
    throw new KmsConfigError(`Vault token file ${tokenFile} is empty`);
  }

  const state = {
    addr: addrRaw.replace(/\/+$/, ""),
    token,
  };

  // Sanity check: probe seal-status (no auth required) so a misconfigured
  // VAULT_ADDR surfaces with a clear error during boot.
  try {
    const r = await fetch(`${state.addr}/v1/sys/seal-status`);
    if (!r.ok) throw new Error(`vault seal-status returned ${r.status}`);
    const status = await r.json();
    if (status.sealed) throw new Error("vault is sealed");
  } catch (e) {
    throw new KmsConfigError(`Vault unreachable: ${e.message}`);
  }

  // Per-keyId material cache for the local verify path.
  const materialCache = new Map();

  async function fetchPublicKey(keyId) {
    const resp = await vaultRequest(state, `transit/keys/${keyId}`);
    const data = resp?.data;
    if (!data || !data.keys) {
      throw new Error("kms/vault.getPublicKey: malformed response");
    }
    const latest = data.latest_version ?? Math.max(...Object.keys(data.keys).map(Number));
    const entry = data.keys[String(latest)];
    if (!entry?.public_key) {
      throw new Error(`kms/vault.getPublicKey: no public_key for version ${latest}`);
    }
    // For ed25519, Vault returns the raw 32-byte public key as base64.
    const raw = Buffer.from(entry.public_key, "base64");
    const material = buildEd25519KeyMaterial(raw, latest);
    materialCache.set(keyId, material);
    return material;
  }

  return {
    providerName: () => "vault",
    signingStoreLabel: () => "vault://transit",
    capabilities: () => ({ algorithms: ["ed25519"], byok: true, rotate: false }),

    async ensureKey({ keyId, algorithm }) {
      if (algorithm !== "ed25519") {
        throw new Error(
          `kms/vault.ensureKey: only ed25519 supported, got '${algorithm}'`
        );
      }
      const existing = await vaultRequest(state, `transit/keys/${keyId}`, {
        expect404: true,
      });
      if (existing) return;
      await vaultRequest(state, `transit/keys/${keyId}`, {
        method: "POST",
        body: {
          type: "ed25519",
          exportable: false,
          allow_plaintext_backup: false,
        },
      });
    },

    async getPublicKey(keyId) {
      return await fetchPublicKey(keyId);
    },

    async sign(keyId, dataBytes) {
      if (!Buffer.isBuffer(dataBytes)) {
        throw new Error("kms/vault.sign: dataBytes must be a Buffer");
      }
      const resp = await vaultRequest(state, `transit/sign/${keyId}`, {
        method: "POST",
        body: { input: dataBytes.toString("base64") },
      });
      const sig = resp?.data?.signature;
      const keyVersion = resp?.data?.key_version;
      if (typeof sig !== "string" || !sig.startsWith("vault:v")) {
        throw new Error("kms/vault.sign: malformed signature in response");
      }
      // Strip the "vault:v<N>:" prefix and base64-decode the signature bytes.
      const colon = sig.indexOf(":", "vault:".length);
      const sigB64 = sig.slice(colon + 1);
      return {
        sigBytes: Buffer.from(sigB64, "base64"),
        keyVersion: typeof keyVersion === "number" ? keyVersion : 1,
        alg: "ed25519",
      };
    },

    async verify(keyId, dataBytes, sigBytes /*, { keyVersion } = {} */) {
      // Local verification using the cached pubkey. The audit chain
      // verifier (audit.verifyFullChain) does NOT use this path — it reads
      // pubkeys from audit_signing_keys directly. This method is provided
      // for non-audit consumers (CRY-04, CRY-05) that want to spot-check a
      // freshly-signed value without touching the DB.
      let material = materialCache.get(keyId);
      if (!material) material = await fetchPublicKey(keyId);
      return localVerifyEd25519(material, dataBytes, sigBytes);
    },

    async rotate(keyId) {
      // Vault Transit's native rotation: bumps the key version under the
      // same keyId. /transit/sign uses the latest version by default, so
      // future signatures land under the new version automatically. The
      // local pubkey cache is invalidated; the next getPublicKey() returns
      // the new version's pubkey.
      await vaultRequest(state, `transit/keys/${keyId}/rotate`, {
        method: "POST",
      });
      materialCache.delete(keyId);
      const pub = await fetchPublicKey(keyId);
      return { newVersion: pub.keyVersion };
    },

    // BYOK-import a pre-existing Ed25519 private key into Vault Transit.
    // Accepts:
    //   material: PKCS#8 PEM string OR DER Buffer
    //   opts.alg = "ed25519"
    //   opts.source = "pkcs8" (only supported form)
    //
    // Flow (per Vault docs):
    //   1. Fetch the wrapping RSA public key from Vault.
    //   2. Wrap the PKCS#8 DER private-key bytes with an ephemeral AES-256
    //      key using AES-KWP (RFC 5649).
    //   3. Wrap the AES key with the Vault RSA-OAEP-SHA256 wrapping key.
    //   4. POST ciphertext = base64(wrapped_aes || wrapped_key) to
    //      /transit/keys/<name>/import.
    async importKey(keyId, material, { alg, source } = {}) {
      if (alg !== "ed25519") {
        throw new Error(
          `kms/vault.importKey: only alg='ed25519' supported, got '${alg}'`
        );
      }
      if (source !== "pkcs8") {
        throw new Error(
          `kms/vault.importKey: only source='pkcs8' supported, got '${source}'`
        );
      }
      // Normalize material → PKCS#8 DER bytes.
      const keyObj = crypto.createPrivateKey({
        key: material,
        format: Buffer.isBuffer(material) ? "der" : "pem",
        type: "pkcs8",
      });
      const targetPkcs8 = keyObj.export({ type: "pkcs8", format: "der" });

      // Step 1: wrapping key.
      const wrap = await vaultRequest(state, "transit/wrapping_key");
      const wrappingPem = wrap?.data?.public_key;
      if (!wrappingPem) {
        throw new Error("kms/vault.importKey: no wrapping-key from Vault");
      }
      const wrappingKey = crypto.createPublicKey({ key: wrappingPem, format: "pem" });

      // Step 2: ephemeral AES-256 + AES-KWP wrap.
      const aesKey = crypto.randomBytes(32);
      const cipher = crypto.createCipheriv(
        "id-aes256-wrap-pad",
        aesKey,
        AES_KWP_DEFAULT_IV
      );
      const wrappedTarget = Buffer.concat([cipher.update(targetPkcs8), cipher.final()]);

      // Step 3: RSA-OAEP-SHA256 wrap of the AES key.
      const wrappedAes = crypto.publicEncrypt(
        {
          key: wrappingKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: "sha256",
        },
        aesKey
      );

      // Step 4: POST.
      const ciphertext = Buffer.concat([wrappedAes, wrappedTarget]).toString("base64");
      await vaultRequest(state, `transit/keys/${keyId}/import`, {
        method: "POST",
        body: {
          type: "ed25519",
          ciphertext,
          hash_function: "SHA256",
        },
      });

      // Invalidate cache so the next getPublicKey reflects the import.
      materialCache.delete(keyId);
    },
  };
}
