// platformKeys.js — KMS-held signing keys used by the backend (OPA-auth +
// session JWTs) and by the PEP (OPA-auth). Mirrors the structure of
// services/audit.js: the private key never leaves the KMS provider, and the
// DB table `platform_signing_keys` holds only fingerprints + lifecycle
// status. Boot-time reconciliation matches KMS pubkey fingerprints against
// the DB's active rows; mismatch sets a per-purpose "trust broken" flag
// surfaced via `isTrustOk()` and consumed by middleware/authorize.js.
//
// Lifecycle per purpose:
//   pending  — KMS key minted, DB row exists, OPA does not yet trust it.
//   active   — Backend / PEP signs with this key. At most one per purpose.
//   retired  — Previous active key during rotation overlap. Still accepted
//              by OPA so in-flight tokens verify; backend no longer mints.
//   revoked  — Dropped from the next OPA publish. No new tokens accepted.
// No deletion path — same revoke-only invariant as policy_trust_keys.
import crypto from "node:crypto";

import * as kms from "./kms/index.js";
import * as store from "./storage.js";

export const PURPOSES = [
  "opa-auth-signing",
  "session-signing",
  "pep-opa-auth-signing",
];

const DEFAULT_KEY_IDS = {
  "opa-auth-signing": "opa-auth-signing",
  "session-signing": "session-signing",
  "pep-opa-auth-signing": "pep-opa-auth-signing",
};

const KEY_ID_ENV = {
  "opa-auth-signing": "KMS_KEY_ID_OPA_AUTH",
  "session-signing": "KMS_KEY_ID_SESSION",
  "pep-opa-auth-signing": "KMS_KEY_ID_PEP_OPA_AUTH",
};

// Resolve the configured base KMS key id for a purpose. Rotation appends a
// timestamp suffix on top of this so each rotation lands at a fresh KMS
// keyId — see rotate() below. Reads `KMS_KEY_ID_*` overrides first.
export function getBaseKeyId(purpose) {
  return process.env[KEY_ID_ENV[purpose]] || DEFAULT_KEY_IDS[purpose];
}

// Module state. The pubkey cache feeds platformJwt.verifyJwtEdDSA: it's a
// kidHex -> KeyObject map covering active AND retired keys, so tokens
// minted under the previous key continue to verify during overlap.
//
// `_brokenByPurpose` mirrors audit.js's chain-broken flag: a per-purpose
// reconciliation failure freezes mutations through `isTrustOk()`.
const _pubkeyByKid = new Map();
const _activeKeyByPurpose = new Map();
const _brokenByPurpose = new Map();

export function getActivePurposeMeta(purpose) {
  return _activeKeyByPurpose.get(purpose) || null;
}

export function resolvePubkeyByKid(kid) {
  return _pubkeyByKid.get(kid) || null;
}

export function isTrustOk() {
  const out = { ok: true, byPurpose: {} };
  for (const p of PURPOSES) {
    const reason = _brokenByPurpose.get(p);
    out.byPurpose[p] = reason ? { ok: false, reason } : { ok: true };
    if (reason) out.ok = false;
  }
  // Convenience shorthands consumed by middleware/authorize.js + studio.authz.
  const opa = out.byPurpose["opa-auth-signing"];
  const session = out.byPurpose["session-signing"];
  const pep = out.byPurpose["pep-opa-auth-signing"];
  return {
    ok: out.ok,
    opaOk: opa.ok,
    opaReason: opa.reason,
    sessionOk: session.ok,
    sessionReason: session.reason,
    pepOk: pep.ok,
    pepReason: pep.reason,
    byPurpose: out.byPurpose,
  };
}

function _markBroken(purpose, reason) {
  _brokenByPurpose.set(purpose, reason);
  console.error(`[platform-keys] ${purpose}: ${reason}`);
}

function _clearBroken(purpose) {
  _brokenByPurpose.delete(purpose);
}

function _cachePubkey(material) {
  const kid = material.fingerprintSha256.toString("hex");
  const keyObject = crypto.createPublicKey({
    key: material.pubkeyDer, format: "der", type: "spki",
  });
  _pubkeyByKid.set(kid, keyObject);
}

// Bootstrap: for every purpose, ensure the KMS provider holds a key, register
// its fingerprint in the DB on first sight (via withAudit so the act of
// minting is tamper-evident), and reconcile against any existing active row.
// Called once at server boot after audit.loadOrInitSigningKey() so the audit
// chain is available when we record the bootstrap row.
export async function loadOrInitPlatformKeys({ actor } = {}) {
  let signer;
  try {
    signer = await kms.getSigner();
  } catch (e) {
    for (const p of PURPOSES) _markBroken(p, `kms signer init failed: ${e.message}`);
    return { loaded: false };
  }

  for (const purpose of PURPOSES) {
    try {
      await _bootPurpose(signer, purpose, actor);
    } catch (e) {
      _markBroken(purpose, `bootstrap failed: ${e.message}`);
    }
  }
  return { loaded: !_brokenByPurpose.size };
}

async function _bootPurpose(signer, purpose, actor) {
  // Prefer the keyId on the active DB row (so we read the right transit
  // key after a rotation that produced a timestamp-suffixed keyId).
  // Fall back to the base keyId for first-boot / fresh deployments.
  const activeRow = await store.getActivePlatformKey(purpose);
  const keyId = activeRow?.keyId || getBaseKeyId(purpose);
  // 1. Ensure the KMS holds the key (no-op if it does).
  await signer.ensureKey({ keyId, algorithm: "ed25519" });
  const pub = await signer.getPublicKey(keyId);
  const fpHex = pub.fingerprintSha256.toString("hex");

  // 2. Reconcile with the DB.
  if (activeRow) {
    if (activeRow.fpHex !== fpHex) {
      _markBroken(
        purpose,
        `kms pubkey ${fpHex} does not match active DB row ${activeRow.fpHex} ` +
          `(keyId=${keyId})`
      );
      return;
    }
    // Matched — load the pubkey + retired keys into the cache.
    _activeKeyByPurpose.set(purpose, { fpHex, keyId: activeRow.keyId });
    _cachePubkey(pub);
    await _cacheRetiredForPurpose(purpose);
    _clearBroken(purpose);
    return;
  }

  // 3. No active row → register one. Goes through withAudit so the
  // bootstrap is tamper-evident in the chain.
  const auditActor = actor || { id: null, username: "system", role: "system" };
  await store.withAudit(auditActor, {
    action: "platform_key.bootstrap",
    resourceType: "platform_key",
    resourceId: fpHex,
  }, async (client) => {
    const inserted = await store.insertPlatformKeyTx(client, {
      fp: pub.fingerprintSha256,
      pubkey: pub.pubkeyDer,
      algorithm: "ed25519",
      purpose,
      keyId,
      status: "active",
    });
    return {
      response: inserted,
      auditAfter: store.platformKeyRowForAudit({
        fp: pub.fingerprintSha256,
        pubkey: pub.pubkeyDer,
        algorithm: "ed25519",
        purpose,
        key_id: keyId,
        status: "active",
        created_at: new Date(),
        activated_at: new Date(),
        retired_at: null,
        revoked_at: null,
      }),
    };
  });
  _activeKeyByPurpose.set(purpose, { fpHex, keyId });
  _cachePubkey(pub);
  _clearBroken(purpose);
  console.log(
    `[platform-keys] bootstrapped ${purpose} (fp=${fpHex}, keyId=${keyId})`
  );
}

async function _cacheRetiredForPurpose(purpose) {
  const all = await store.listActivePlatformKeys();
  for (const row of all) {
    if (row.purpose !== purpose) continue;
    if (row.status !== "retired") continue;
    const der = Buffer.from(row.pubkeyDerB64, "base64");
    const ko = crypto.createPublicKey({ key: der, format: "der", type: "spki" });
    _pubkeyByKid.set(row.fpHex, ko);
  }
}

// Rotate the active key for a purpose via Vault Transit's native rotation —
// bumps the key version under the SAME keyId, so the on-disk OPA trust file
// stays meaningful across restarts (only the pubkey contents change). The
// new active row stores the same keyId; only the fingerprint differs. The
// prior active row is demoted to 'retired' atomically inside withAudit.
// Caller is responsible for re-publishing data.platform_keys to OPA, then
// calling commitRotation() (see route layer for two-phase wiring).
export async function rotate(purpose, { actor }) {
  if (!PURPOSES.includes(purpose)) {
    throw new Error(`unknown purpose: ${purpose}`);
  }
  const signer = await kms.getSigner();
  const active = _activeKeyByPurpose.get(purpose);
  if (!active) {
    throw new Error(`platform-keys: no active key for purpose ${purpose}; cannot rotate`);
  }
  const keyId = active.keyId;

  await signer.rotate(keyId);
  const newPub = await signer.getPublicKey(keyId);
  const newFpHex = newPub.fingerprintSha256.toString("hex");
  const newKeyId = keyId;

  const result = await store.withAudit(actor, {
    action: "platform_key.rotate",
    resourceType: "platform_key",
    resourceId: newFpHex,
    beforeFetcher: async (c) => {
      const prev = await store.getActivePlatformKeyTx(c, purpose);
      return prev ? store.platformKeyRowForAudit({
        fp: Buffer.from(prev.fpHex, "hex"),
        pubkey: Buffer.from(prev.pubkeyDerB64, "base64"),
        algorithm: prev.algorithm,
        purpose: prev.purpose,
        key_id: prev.keyId,
        status: prev.status,
        created_at: prev.createdAt,
        activated_at: prev.activatedAt,
        retired_at: prev.retiredAt,
        revoked_at: prev.revokedAt,
      }) : null;
    },
  }, async (client) => {
    const prevActive = await store.getActivePlatformKeyTx(client, purpose);
    if (prevActive) {
      await store.retirePlatformKeyTx(client, Buffer.from(prevActive.fpHex, "hex"));
    }
    const inserted = await store.insertPlatformKeyTx(client, {
      fp: newPub.fingerprintSha256,
      pubkey: newPub.pubkeyDer,
      algorithm: "ed25519",
      purpose,
      keyId: newKeyId,
      status: "active",
    });
    return {
      response: { newFpHex, retiredFpHex: prevActive?.fpHex || null },
      auditAfter: inserted,
    };
  });

  // Add the new pubkey to the verification cache so OPA's next publish
  // payload includes it. DO NOT update _activeKeyByPurpose yet — the
  // route must publish to OPA first using the still-active old key, then
  // call commitRotation() to flip the sign-time pointer. Without this
  // two-phase split, publishPlatformKeys() would try to push the new key
  // using a JWT signed by that same not-yet-trusted key and OPA would
  // reject it (chicken-and-egg).
  _cachePubkey(newPub);
  _clearBroken(purpose);
  return { ...result, newKeyId };
}

// Second phase of rotate(): flip the in-memory active pointer so
// subsequent JWTs are signed by the new key. The route calls this AFTER
// publishPlatformKeys() succeeds.
export function commitRotation(purpose, newKeyId, newFpHex) {
  _activeKeyByPurpose.set(purpose, { fpHex: newFpHex, keyId: newKeyId });
}

// Revoke a retired platform key. Refuses on 'active' (rotate first) or
// 'pending' (no such state in current code; defensive). Caller re-publishes
// after the audited txn commits, so OPA drops the key.
export async function revoke(fpHex, { actor }) {
  if (typeof fpHex !== "string" || !/^[0-9a-f]+$/i.test(fpHex)) {
    throw new Error("revoke: fpHex must be a hex string");
  }
  const fp = Buffer.from(fpHex, "hex");
  const before = await store.getPlatformKeyByFp(fpHex);
  if (!before) {
    const e = new Error(`platform key ${fpHex} not found`);
    e.code = "PLATFORM_KEY_NOT_FOUND";
    throw e;
  }
  if (before.status === "active") {
    const e = new Error("cannot revoke an active platform key; rotate first");
    e.code = "PLATFORM_KEY_ACTIVE";
    throw e;
  }
  if (before.status === "revoked") {
    return before;
  }
  await store.withAudit(actor, {
    action: "platform_key.revoke",
    resourceType: "platform_key",
    resourceId: fpHex,
  }, async (client) => {
    const updated = await store.revokePlatformKeyTx(client, fp);
    return { response: updated, auditAfter: updated };
  });
  // Drop the pubkey from the local cache so no further tokens minted under
  // it could verify (defense-in-depth — they would have failed alg/exp anyway).
  _pubkeyByKid.delete(fpHex);
  return await store.getPlatformKeyByFp(fpHex);
}

// Active sign-time helper for callers that don't want to read from the DB
// per request. Throws if the purpose is broken or unbootstrapped.
export function activeKeyId(purpose) {
  const meta = _activeKeyByPurpose.get(purpose);
  if (!meta) {
    throw new Error(`platform-keys: no active key for purpose ${purpose}`);
  }
  return meta.keyId;
}

// Snapshot suitable for publishing to OPA at data.platform_keys. Shape:
//   { "opa-auth-signing": { "<kid>": "<pem>", ... },
//     "pep-opa-auth-signing": { "<kid>": "<pem>" }, ... }
// Includes both 'active' and 'retired' rows so in-flight tokens verify
// during rotation overlap.
export async function buildOpaPublishDocument() {
  const rows = await store.listActivePlatformKeys();
  const out = {};
  for (const row of rows) {
    if (row.status !== "active" && row.status !== "retired") continue;
    const der = Buffer.from(row.pubkeyDerB64, "base64");
    const pem =
      "-----BEGIN PUBLIC KEY-----\n" +
      der.toString("base64").match(/.{1,64}/g).join("\n") +
      "\n-----END PUBLIC KEY-----\n";
    if (!out[row.purpose]) out[row.purpose] = {};
    out[row.purpose][row.fpHex] = pem;
  }
  return out;
}

// Cross-check the file OPA loads at boot against KMS+DB. Returns an array
// of issue strings; empty array means the trust file matches reality.
//
// Used at backend boot and by an admin probe to surface tamper of the
// mounted /opa/trust/platform_keys.json (or its container-side mount).
export async function reconcileWithTrustFile(filePath) {
  const fs = await import("node:fs");
  const issues = [];
  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch (e) {
    return [`failed to read ${filePath}: ${e.message}`];
  }
  // opa-trust-init writes { platform_keys: { <purpose>: { <kid>: <pem> } } }
  // so OPA mounts it at data.platform_keys at boot. Unwrap that here.
  const root = parsed.platform_keys || parsed;
  for (const purpose of ["opa-auth-signing", "pep-opa-auth-signing"]) {
    const inFile = root[purpose] || {};
    const active = await store.getActivePlatformKey(purpose);
    if (!active) {
      if (Object.keys(inFile).length > 0) {
        issues.push(`${purpose}: trust file has keys but DB has no active row`);
      }
      continue;
    }
    if (!inFile[active.fpHex]) {
      issues.push(
        `${purpose}: active fp ${active.fpHex} missing from trust file ${filePath}`
      );
    }
  }
  return issues;
}

// Used by services/auth.js to expose the session-signing pubkey alongside
// the audit pubkey on /.well-known/jwks.json. Returns null until the
// reconciler has run.
export function getSessionSigningPublicJwk() {
  const meta = _activeKeyByPurpose.get("session-signing");
  if (!meta) return null;
  const ko = _pubkeyByKid.get(meta.fpHex);
  if (!ko) return null;
  const jwk = ko.export({ format: "jwk" });
  return { ...jwk, alg: "EdDSA", use: "sig", kid: meta.fpHex };
}

// Verifier-side helper used by middleware/authenticate.js. Returns the
// node:crypto KeyObject for the given kid, or null if unknown / revoked.
export function pubkeyForKid(kid) {
  return _pubkeyByKid.get(kid) || null;
}

// Tiny utility for tests / debug.
export function _resetForTests() {
  _pubkeyByKid.clear();
  _activeKeyByPurpose.clear();
  _brokenByPurpose.clear();
}
