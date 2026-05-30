// kms/file.js — DEV-only KmsSigner that keeps Ed25519 key material in a
// local file. Refuses to start when NODE_ENV=production (FEATURES.md L705:
// "No silent fallbacks for cryptographic operations").
//
// Intended for: laptop development without Vault, CI/test runs, and the
// air-gapped quick-start documented in DEP-05. NEVER for production.
//
// Env contract:
//   NODE_ENV           — MUST NOT be "production"
//   KMS_FILE_KEY_DIR   — Directory holding per-keyId PKCS#8 PEM files
//                        (default: /data/dev_kms). Created with mode 0700.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import {
  KmsConfigError,
  buildEd25519KeyMaterial,
  localVerifyEd25519,
} from "./index.js";

const DEFAULT_KEY_DIR = "/data/dev_kms";

function keyFilePath(dir, keyId) {
  // keyId is operator-supplied — sanitize to avoid path traversal.
  if (!/^[A-Za-z0-9_.-]+$/.test(keyId)) {
    throw new Error(
      `kms/file: invalid keyId '${keyId}' (allowed: alphanumerics, _.-)`
    );
  }
  return path.join(dir, `${keyId}.pkcs8.pem`);
}

function loadKeyMaterial(filePath, versionFn) {
  const pem = fs.readFileSync(filePath, "utf8");
  const privateKey = crypto.createPrivateKey({ key: pem, format: "pem" });
  const publicKey = crypto.createPublicKey(privateKey);
  // Ed25519 raw pubkey lives at the last 32 bytes of the SPKI DER.
  const spki = publicKey.export({ type: "spki", format: "der" });
  const raw = spki.subarray(spki.length - 32);
  const material = buildEd25519KeyMaterial(raw, versionFn());
  return { material, privateKey };
}

export async function create() {
  if ((process.env.NODE_ENV || "production") === "production") {
    throw new KmsConfigError(
      "KMS_PROVIDER=file is DEV-only and refuses to start when NODE_ENV=production. " +
        "Use vault or a cloud KMS provider for production deployments."
    );
  }
  const keyDir = process.env.KMS_FILE_KEY_DIR || DEFAULT_KEY_DIR;
  try {
    fs.mkdirSync(keyDir, { recursive: true, mode: 0o700 });
  } catch (e) {
    throw new KmsConfigError(
      `kms/file: cannot create key directory ${keyDir}: ${e.message}`
    );
  }

  console.warn(
    `[kms/file] DEV-ONLY signer active. NODE_ENV=${process.env.NODE_ENV}, ` +
      `keys in ${keyDir}. Do NOT use in production.`
  );

  // Per-keyId entry: { material, privateKey, version }
  const cache = new Map();

  function readCache(keyId) {
    return cache.get(keyId) || null;
  }
  function writeCache(keyId, material, privateKey, version) {
    cache.set(keyId, { material, privateKey, version });
  }

  return {
    providerName: () => "file",
    signingStoreLabel: () => `file://${keyDir}`,
    capabilities: () => ({ algorithms: ["ed25519"], byok: true, rotate: false }),

    async ensureKey({ keyId, algorithm }) {
      if (algorithm !== "ed25519") {
        throw new Error(
          `kms/file.ensureKey: only ed25519 supported, got '${algorithm}'`
        );
      }
      const filePath = keyFilePath(keyDir, keyId);
      if (fs.existsSync(filePath)) {
        const { material, privateKey } = loadKeyMaterial(filePath, () => 1);
        writeCache(keyId, material, privateKey, 1);
        return;
      }
      const { privateKey } = crypto.generateKeyPairSync("ed25519");
      const pem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
      fs.writeFileSync(filePath, pem, { mode: 0o600 });
      const loaded = loadKeyMaterial(filePath, () => 1);
      writeCache(keyId, loaded.material, loaded.privateKey, 1);
    },

    async getPublicKey(keyId) {
      const entry = readCache(keyId);
      if (entry) return entry.material;
      const filePath = keyFilePath(keyDir, keyId);
      if (!fs.existsSync(filePath)) {
        throw new Error(`kms/file.getPublicKey: no key at ${filePath} — call ensureKey first`);
      }
      const { material, privateKey } = loadKeyMaterial(filePath, () => 1);
      writeCache(keyId, material, privateKey, 1);
      return material;
    },

    async sign(keyId, dataBytes) {
      if (!Buffer.isBuffer(dataBytes)) {
        throw new Error("kms/file.sign: dataBytes must be a Buffer");
      }
      let entry = readCache(keyId);
      if (!entry) {
        const filePath = keyFilePath(keyDir, keyId);
        if (!fs.existsSync(filePath)) {
          throw new Error(`kms/file.sign: no key at ${filePath} — call ensureKey first`);
        }
        const loaded = loadKeyMaterial(filePath, () => 1);
        writeCache(keyId, loaded.material, loaded.privateKey, 1);
        entry = readCache(keyId);
      }
      const sigBytes = crypto.sign(null, dataBytes, entry.privateKey);
      return { sigBytes, keyVersion: entry.version, alg: "ed25519" };
    },

    async verify(keyId, dataBytes, sigBytes /*, { keyVersion } = {} */) {
      let entry = readCache(keyId);
      if (!entry) {
        const filePath = keyFilePath(keyDir, keyId);
        if (!fs.existsSync(filePath)) return false;
        const loaded = loadKeyMaterial(filePath, () => 1);
        writeCache(keyId, loaded.material, loaded.privateKey, 1);
        entry = readCache(keyId);
      }
      return localVerifyEd25519(entry.material, dataBytes, sigBytes);
    },

    async rotate(/* keyId */) {
      throw new Error(
        "kms/file.rotate: key rotation lands in KMS-04"
      );
    },

    async importKey(keyId, material, { alg, source } = {}) {
      if (alg !== "ed25519") {
        throw new Error(
          `kms/file.importKey: only alg='ed25519' supported, got '${alg}'`
        );
      }
      if (source !== "pkcs8") {
        throw new Error(
          `kms/file.importKey: only source='pkcs8' supported, got '${source}'`
        );
      }
      // Validate the material parses as an Ed25519 PKCS#8 key.
      const privateKey = crypto.createPrivateKey({
        key: material,
        format: Buffer.isBuffer(material) ? "der" : "pem",
        type: "pkcs8",
      });
      if (privateKey.asymmetricKeyType !== "ed25519") {
        throw new Error(
          `kms/file.importKey: imported key is not Ed25519 (got ${privateKey.asymmetricKeyType})`
        );
      }
      const filePath = keyFilePath(keyDir, keyId);
      if (fs.existsSync(filePath)) {
        throw new Error(
          `kms/file.importKey: key ${keyId} already exists at ${filePath}`
        );
      }
      const pem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
      fs.writeFileSync(filePath, pem, { mode: 0o600 });
      cache.delete(keyId);
    },
  };
}
