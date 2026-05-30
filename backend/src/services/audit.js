// audit.js — tamper-evident hash chain over backend state mutations.
//
// Signing is delegated to a pluggable KmsSigner adapter (see ./kms/). The
// Ed25519 private key never leaves the provider: every appendAudit() calls
// signer.sign(keyId, hash). Verification is local — public keys live in
// audit_signing_keys (keyed by SHA-256 fingerprint of the SPKI DER) and we
// verify Ed25519 signatures with Node's crypto module via auditCrypto.verify.
//
// Lifecycle:
//   1. At server boot, audit.loadOrInitSigningKey() is called BEFORE the
//      bootstrap pass:
//        a. instantiates the configured KmsSigner (KMS_PROVIDER),
//        b. for the vault provider, migrates any legacy /data/audit_signing_key
//           PEM into Vault via BYOK and deletes it from disk,
//        c. reconciles the provider's active public key against the DB:
//           - if audit_log is empty: ensure the provider has a key (create if not).
//           - if audit_log has rows: assert the provider's pubkey fingerprint
//             matches the active audit_signing_keys row; if not, mark
//             chainBroken (mutations are blocked).
//   2. Bootstrap (fresh deployment) calls audit.registerSigningKeyTx() inside
//      the genesis transaction to insert the pubkey row, then audit.appendAudit()
//      to sign the genesis row via the KmsSigner.
//   3. Every audited mutation goes through storage.withAudit() which invokes
//      audit.appendAudit() inside the transaction it opened.
//   4. The authorize middleware queries headIsValid() before each mutation;
//      OPA studio.authz refuses if input.audit.ok is false.
import fs from "node:fs";

import * as auditCrypto from "./auditCrypto.js";
import * as kms from "./kms/index.js";
import { fingerprintFromPkcs8, parseByokSource } from "./kms/byok.js";
import * as store from "./storage.js";

const DEFAULT_LEGACY_KEY_PATH = "/data/audit_signing_key";

function legacyKeyPath() {
  return process.env.AUDIT_SIGNING_KEY_FILE || DEFAULT_LEGACY_KEY_PATH;
}

// Module-private state. Set exactly once at boot by loadOrInitSigningKey().
// We hold ONLY the public material (pubkey DER + fingerprint + provider key
// version) — never any private key bytes.
let _signer = null;
let _keyId = null;
let signingPubkeyDer = null;
let signingKeyFp = null;
let signingKeyVersion = null;
let chainBroken = false;
let chainBrokenReason = null;

export function getSigningKeyFingerprint() { return signingKeyFp; }
export function getSigningPubkeyDer() { return signingPubkeyDer; }
export function isChainBroken() { return chainBroken; }
export function getChainBrokenReason() { return chainBrokenReason; }

// Human-readable description of where the signing key lives. Used by the
// bootstrap banner. Example: "vault://transit/audit-signing".
export function getSigningStoreLabel() {
  if (!_signer || !_keyId) return "unconfigured";
  return `${_signer.signingStoreLabel()}/${_keyId}`;
}

function _markBroken(reason) {
  chainBroken = true;
  chainBrokenReason = reason;
  console.error(`[audit] chain broken: ${reason}`);
}

function _setActiveKey(material) {
  signingPubkeyDer = material.pubkeyDer;
  signingKeyFp = material.fingerprintSha256;
  signingKeyVersion = material.keyVersion ?? null;
  chainBroken = false;
  chainBrokenReason = null;
}

// Initialize the configured KmsSigner and reconcile its state with the DB.
// Called once at server boot, before bootstrapInitialAdmin().
//
// Side effects:
//   - Instantiates the provider selected by KMS_PROVIDER (default vault).
//   - BYOK (KMS-02): if KMS_BYOK_SOURCE is set, parses the URI (file: or
//     env:) into an Ed25519 PKCS#8 PEM and imports it into the provider
//     before any auto-generation can happen. Idempotent on fingerprint
//     match; fail-closed on mismatch. KMS_BYOK_REQUIRED=true forbids
//     booting without a source.
//   - For the vault provider: if a legacy /data/audit_signing_key PEM is
//     present, imports it into Vault Transit (BYOK) and DELETES the file.
//     Other providers ignore the legacy file (it is a Vault-only migration
//     artifact from pre-KMS-01 builds). BYOK takes precedence over the
//     legacy file when both are present.
//   - Ensures the provider holds an Ed25519 key (creates one on a virgin
//     deployment).
//   - On an existing deployment, verifies the provider's active pubkey
//     fingerprint matches the active audit_signing_keys row. On mismatch
//     marks the chain broken so subsequent mutations are refused.
export async function loadOrInitSigningKey() {
  try {
    _signer = await kms.getSigner();
    _keyId = kms.getAuditKeyId();
  } catch (e) {
    _markBroken(`kms signer init failed: ${e.message}`);
    return { loaded: false };
  }

  const head = await store.getAuditHead();
  const activeKey = await store.getActiveSigningKey(); // may be null
  const isVault = _signer.providerName() === "vault";
  const legacyPath = legacyKeyPath();
  const legacyExists = isVault && fs.existsSync(legacyPath);

  // Step 1: probe whether the provider already holds the key. Needed BEFORE
  // ensureKey so BYOK (KMS-02) can decide whether to import vs. reconcile,
  // and so the legacy PEM migration can tell whether there's a conflict.
  let providerHadKey = true;
  try {
    await _signer.getPublicKey(_keyId);
  } catch {
    providerHadKey = false;
  }

  // Step 2: BYOK import (KMS-02). If KMS_BYOK_SOURCE is set, ingest the
  // customer-supplied Ed25519 PKCS#8 PEM BEFORE ensureKey gets a chance to
  // auto-generate a fresh key. The subsequent ensureKey call short-circuits
  // because the provider now holds a key. Idempotent re-boots are supported
  // via fingerprint comparison against the provider's existing key.
  const byokSource = process.env.KMS_BYOK_SOURCE;
  const byokRequired = process.env.KMS_BYOK_REQUIRED === "true";
  let byokActive = false;
  if (byokRequired && !byokSource) {
    _markBroken("KMS_BYOK_REQUIRED=true but KMS_BYOK_SOURCE is unset");
    return { loaded: false };
  }
  if (byokSource) {
    let parsed;
    try {
      parsed = await parseByokSource(byokSource);
    } catch (e) {
      _markBroken(`byok parse failed: ${e.message}`);
      return { loaded: false };
    }
    let intendedFp;
    try {
      intendedFp = fingerprintFromPkcs8(parsed.pem);
    } catch (e) {
      _markBroken(`byok fingerprint failed: ${e.message}`);
      return { loaded: false };
    }
    if (providerHadKey) {
      let existing;
      try {
        existing = await _signer.getPublicKey(_keyId);
      } catch (e) {
        _markBroken(`byok: getPublicKey failed during reconciliation: ${e.message}`);
        return { loaded: false };
      }
      if (Buffer.compare(existing.fingerprintSha256, intendedFp) === 0) {
        console.log(
          `[audit] BYOK: provider already holds intended key ` +
            `(fp=${intendedFp.toString("hex")}), skipping import`
        );
      } else {
        _markBroken(
          `byok fingerprint ${intendedFp.toString("hex")} does not match ` +
            `provider's existing key ${existing.fingerprintSha256.toString("hex")} ` +
            `for keyId=${_keyId} (operator must rotate or change KMS_KEY_ID)`
        );
        return { loaded: false };
      }
    } else {
      try {
        await _signer.importKey(_keyId, parsed.pem, { alg: "ed25519", source: "pkcs8" });
      } catch (e) {
        _markBroken(`byok import failed: ${e.message}`);
        return { loaded: false };
      }
      providerHadKey = true;
      console.log(
        JSON.stringify({
          event: "byok_import",
          provider: _signer.providerName(),
          keyId: _keyId,
          sourceKind: parsed.kind,
          fingerprint: intendedFp.toString("hex"),
        })
      );
    }
    byokActive = true;
  }

  // Step 3: ensure the provider holds a key. Idempotent when one already
  // exists (after BYOK import, or untouched from a previous boot).
  try {
    await _signer.ensureKey({ keyId: _keyId, algorithm: "ed25519" });
  } catch (e) {
    _markBroken(`kms ensureKey failed: ${e.message}`);
    return { loaded: false };
  }

  // Step 4: handle legacy PEM (vault-only migration). Only attempt if the
  // provider didn't have a key yet — if it did, we trust the provider as the
  // source of truth and verify its fingerprint against the DB below. BYOK
  // takes precedence: if both KMS_BYOK_SOURCE and a legacy file are present,
  // the legacy file is ignored (and not deleted — the operator may want it
  // back).
  if (legacyExists) {
    if (byokActive) {
      console.warn(
        `[audit] legacy ${legacyPath} found AND KMS_BYOK_SOURCE is set — ` +
          `BYOK takes precedence; legacy file is ignored. Remove it to clear ` +
          `this warning.`
      );
    } else if (providerHadKey) {
      console.warn(
        `[audit] legacy ${legacyPath} found AND the signing provider already ` +
          `has a key — ignoring the file. Move it out of the way and restart ` +
          `to clear this warning.`
      );
    } else {
      const pem = fs.readFileSync(legacyPath, "utf8");
      try {
        await _signer.importKey(_keyId, pem, { alg: "ed25519", source: "pkcs8" });
        console.log(`[audit] imported legacy ${legacyPath} into ${_signer.providerName()}`);
        providerHadKey = true;
      } catch (e) {
        _markBroken(`legacy PEM import failed: ${e.message}`);
        return { loaded: false };
      }
    }
  }

  // Step 5: fetch the provider's current public key and reconcile with the DB.
  let pub;
  try {
    pub = await _signer.getPublicKey(_keyId);
  } catch (e) {
    _markBroken(`kms getPublicKey failed: ${e.message}`);
    return { loaded: false };
  }

  if (head && head.seq > 0) {
    // There's existing audit history. The provider's active key MUST match
    // the active row in audit_signing_keys, otherwise we cannot sign new
    // entries that verify under the historical chain.
    if (!activeKey) {
      _markBroken("audit_log has rows but audit_signing_keys is empty");
      return { loaded: false };
    }
    if (Buffer.compare(activeKey.fp, pub.fingerprintSha256) !== 0) {
      _markBroken(
        `kms pubkey fingerprint ${pub.fingerprintSha256.toString("hex")} does ` +
          `not match active audit_signing_keys.fp ${activeKey.fp.toString("hex")}`
      );
      return { loaded: false };
    }
  } else if (activeKey && Buffer.compare(activeKey.fp, pub.fingerprintSha256) !== 0) {
    // Empty chain but a signing key row already exists with a different
    // fingerprint — also a hard error, since bootstrap will try to attest
    // the genesis row under the provider's key.
    _markBroken(
      `audit_signing_keys has a row whose fingerprint ${activeKey.fp.toString("hex")} ` +
        `does not match kms ${pub.fingerprintSha256.toString("hex")}`
    );
    return { loaded: false };
  }

  _setActiveKey(pub);

  // Step 6: legacy PEM cleanup, only after a successful migration (skipped
  // when BYOK is active — the legacy file was deliberately ignored and the
  // operator owns it).
  if (legacyExists && !byokActive) {
    try {
      fs.unlinkSync(legacyPath);
      console.log(`[audit] deleted legacy ${legacyPath} after migration`);
    } catch (e) {
      console.warn(
        `[audit] could not delete legacy ${legacyPath}: ${e.message} (continuing)`
      );
    }
  }

  console.log(
    `[audit] signing via ${getSigningStoreLabel()} ` +
      `(fp=${pub.fingerprintSha256.toString("hex")}, key_version=${pub.keyVersion}, ` +
      `head seq=${head?.seq ?? 0})`
  );

  if (head && head.seq > 0) {
    return { loaded: true, fresh: false };
  }

  // Empty chain. If there are users already but no audit_log rows yet, this
  // is an existing deployment being upgraded to a build with audit support;
  // we need to write a deployment_genesis entry so subsequent mutations have
  // a chain to extend.
  const userCount = await store.countUsers();
  if (userCount > 0) {
    return await _initializeChainForExistingDeployment();
  }

  // Otherwise, leave the chain empty — bootstrapInitialAdmin() is about to
  // create the admin row and the genesis audit entry inside one transaction.
  return { loaded: true, fresh: true };
}

async function _initializeChainForExistingDeployment() {
  const pool = store.getPool();
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await store._setAuditSessionTx(client);
    await client.query(
      `SELECT pg_advisory_xact_lock(hashtext('opa_studio_audit_chain'))`
    );
    // Race-safe re-check: another replica may have initialized it.
    const { rows } = await client.query(
      `SELECT head_seq, head_hash FROM audit_state WHERE id = 1`
    );
    if (rows.length) {
      await client.query("COMMIT");
      return { loaded: true, fresh: false };
    }
    await registerSigningKeyTx(client);

    const payload = {
      ts: new Date().toISOString(),
      type: "deployment_genesis",
      schema_version: 1,
      note: "Audit chain initialized for an existing deployment (no admin row created)",
      pubkey_b64: signingPubkeyDer.toString("base64"),
      signing_key_fp_hex: signingKeyFp.toString("hex"),
    };
    const canonical = auditCrypto.canonicalize(payload);
    const hash = auditCrypto.entryHash(null, canonical);
    const { sigBytes } = await _signer.sign(_keyId, hash);

    const inserted = await store.appendAuditEntryTx(client, {
      prevHash: null,
      entryHash: hash,
      payload,
      payloadCanonical: canonical,
      signature: sigBytes,
      signingKeyFp,
      actorId: null,
      actorUsername: "system",
      action: "genesis",
      resourceType: "system",
      resourceId: null,
    });
    await client.query("COMMIT");
    console.log(
      `[audit] initialized chain for existing deployment (fp=${signingKeyFp.toString("hex")}, seq=${inserted.seq})`
    );
    const bar = "=".repeat(72);
    for (const line of [
      "",
      bar,
      "  AUDIT CHAIN — initialized for an existing deployment",
      bar,
      `  pubkey b64    : ${signingPubkeyDer.toString("base64")}`,
      `  fingerprint   : ${signingKeyFp.toString("hex")}`,
      `  signing store : ${getSigningStoreLabel()}`,
      `  chain head    : seq=${inserted.seq}`,
      "",
      "  The private key lives in the KMS provider. Back up the provider's",
      "  durable storage alongside the database; losing it freezes the chain.",
      bar,
      "",
    ]) console.log(line);
    return { loaded: true, fresh: true };
  } catch (e) {
    try { await client.query("ROLLBACK"); } catch {}
    _markBroken(`failed to initialize audit chain: ${e.message}`);
    return { loaded: false };
  } finally {
    client.release();
  }
}

// Insert the provider's current public key into audit_signing_keys
// (idempotent via ON CONFLICT in storage.insertSigningKeyTx). Called inside
// a transaction by bootstrap (fresh deployment) and by
// _initializeChainForExistingDeployment. Also updates module state so
// subsequent appendAudit calls use the right fp.
export async function registerSigningKeyTx(client) {
  const pub = await _signer.getPublicKey(_keyId);
  await store.insertSigningKeyTx(client, {
    fp: pub.fingerprintSha256,
    pubkey: pub.pubkeyDer,
  });
  _setActiveKey(pub);
  return pub;
}

// Sign an arbitrary entry hash with the configured KmsSigner. Exposed for
// bootstrap.js (which builds its own genesis payload). Caller is responsible
// for canonicalization and for inserting the row.
export async function signEntryHash(hash) {
  if (!_signer || !_keyId) {
    throw new Error("audit.signEntryHash: signing not initialized");
  }
  return await _signer.sign(_keyId, hash);
}

// Builds the canonical payload for an audit entry, signs it via the
// configured KmsSigner, and inserts the row + updates audit_state. Caller
// must already hold the audit advisory lock and pass an open client.
export async function appendAudit(client, {
  actor,
  action,
  resourceType,
  resourceId,
  before,
  after,
}) {
  if (!signingKeyFp) {
    throw new Error("audit.appendAudit: signing key not loaded");
  }
  if (chainBroken) {
    throw new Error(`audit.appendAudit: chain broken (${chainBrokenReason})`);
  }

  // Read the current head FOR UPDATE so concurrent appends serialize on it.
  // Belt-and-suspenders: the advisory lock already enforces this, but the
  // explicit row lock makes the invariant clear.
  const { rows: stateRows } = await client.query(
    `SELECT head_seq, head_hash FROM audit_state WHERE id = 1 FOR UPDATE`
  );
  const prevHash = stateRows[0]?.head_hash || null;

  // The actor object passed by routes is the req.user shape — pick out
  // org_id and is_root so the chained payload preserves a full picture
  // of who acted (root vs sub-admin, which org) for forensic review.
  // Falls back to a "system" actor for background tasks that intentionally
  // run without a human (currently none use withAudit; bootstrap's genesis
  // builds its own payload).
  const payload = {
    ts: new Date().toISOString(),
    actor: actor
      ? {
          id: actor.id,
          username: actor.username,
          role: actor.role,
          org_id: actor.orgId ?? null,
          is_root: !!actor.isRoot,
        }
      : { id: null, username: "system", role: "system", org_id: null, is_root: false },
    action,
    resource: { type: resourceType, id: resourceId ?? null },
    before: before ?? null,
    after: after ?? null,
    signing_key_fp_hex: signingKeyFp.toString("hex"),
  };
  const canonical = auditCrypto.canonicalize(payload);
  const hash = auditCrypto.entryHash(prevHash, canonical);
  const { sigBytes, keyVersion } = await _signer.sign(_keyId, hash);

  // Provider key rotation guard: if the provider returns a key_version
  // different from the one we cached at boot, the public key has changed
  // and we have no matching audit_signing_keys row. Fail loudly rather than
  // insert an unverifiable signature.
  if (signingKeyVersion != null && keyVersion !== signingKeyVersion) {
    throw new Error(
      `audit.appendAudit: kms key rotated (cached version=${signingKeyVersion}, ` +
        `signed version=${keyVersion}) — rotation lands in KMS-04`
    );
  }

  const inserted = await store.appendAuditEntryTx(client, {
    prevHash,
    entryHash: hash,
    payload,
    payloadCanonical: canonical,
    signature: sigBytes,
    signingKeyFp,
    actorId: actor?.id ?? null,
    actorUsername: actor?.username ?? "system",
    actorOrgId: actor?.orgId ?? null,
    action,
    resourceType,
    resourceId: resourceId ?? null,
  });
  return { seq: inserted.seq, hash };
}

// Per-request gate. Returns { ok: boolean, reason?: string }.
//
// All checks read from the DB on every call (no in-memory cache):
//   1. audit_state has a head row.
//   2. The whole chain re-hashes correctly under audit_verify_chain() — a
//      single PL/pgSQL function call. This catches middle-of-chain payload
//      tampering: if any earlier payload_canonical was edited, its
//      recomputed entry_hash diverges and the verifier returns the broken seq.
//   3. The head row's signature verifies under the public key stored in
//      audit_signing_keys (looked up by fingerprint). Verification is local;
//      the KMS provider is not contacted.
export async function headIsValid() {
  if (chainBroken) {
    return { ok: false, reason: chainBrokenReason || "chain broken" };
  }
  const dbHead = await store.getAuditHead();
  if (!dbHead) {
    return { ok: false, reason: "audit_state empty" };
  }

  // Structural verification — walks the whole chain in PL/pgSQL.
  const structural = await store.verifyChainStructural();
  if (!structural.ok) {
    return {
      ok: false,
      reason: structural.seq
        ? `${structural.reason} at seq=${structural.seq}`
        : structural.reason,
    };
  }

  // Signature on the head row, verified locally with the DB-stored pubkey.
  const entry = await store.getAuditEntry(dbHead.seq);
  if (!entry) {
    return { ok: false, reason: "audit_state points at missing audit_log row" };
  }
  const keyRow = await _lookupSigningKey(entry.signingKeyFp);
  if (!keyRow) {
    return { ok: false, reason: "head entry signed by unknown key" };
  }
  const pubkey = auditCrypto.publicKeyFromDer(keyRow.pubkey);
  const sigOk = auditCrypto.verify(pubkey, entry.entryHash, entry.signature);
  if (!sigOk) {
    return { ok: false, reason: `head entry signature invalid at seq=${entry.seq}` };
  }
  return { ok: true };
}

// Look up a single signing key row by fingerprint. We don't cache.
async function _lookupSigningKey(fp) {
  const all = await store.listSigningKeys();
  for (const row of all) {
    if (Buffer.compare(row.fp, fp) === 0) return row;
  }
  return null;
}

// Walks the entire chain and verifies every link + signature. Used by the
// /api/audit/verify endpoint and by an external CLI verifier (which can call
// audit_verify_chain() in Postgres for the structural part).
export async function verifyFullChain() {
  const structural = await store.verifyChainStructural();
  const rows = await store.getAllAuditChainRows();

  if (rows.length === 0) {
    return {
      ok: structural.ok,
      structuralOk: structural.ok,
      reason: structural.reason || "empty chain",
      headSeq: 0,
      signaturesChecked: 0,
    };
  }

  const keyRows = await store.listSigningKeys();
  const keyByFp = new Map();
  for (const k of keyRows) {
    keyByFp.set(k.fp.toString("hex"), auditCrypto.publicKeyFromDer(k.pubkey));
  }

  let signaturesChecked = 0;
  for (const r of rows) {
    const pub = keyByFp.get(r.signing_key_fp.toString("hex"));
    if (!pub) {
      return {
        ok: false,
        structuralOk: structural.ok,
        reason: `unknown signing key fp at seq=${r.seq}`,
        headSeq: Number(rows[rows.length - 1].seq),
        brokenAtSeq: Number(r.seq),
        signaturesChecked,
      };
    }
    const ok = auditCrypto.verify(pub, r.entry_hash, r.signature);
    signaturesChecked++;
    if (!ok) {
      return {
        ok: false,
        structuralOk: structural.ok,
        reason: `signature invalid at seq=${r.seq}`,
        headSeq: Number(rows[rows.length - 1].seq),
        brokenAtSeq: Number(r.seq),
        signaturesChecked,
      };
    }
  }

  return {
    ok: structural.ok,
    structuralOk: structural.ok,
    reason: structural.ok ? "chain verified end-to-end" : structural.reason,
    headSeq: Number(rows[rows.length - 1].seq),
    signaturesChecked,
  };
}

// Wire withAudit() to use this module's appendAudit. Avoids a circular
// import (storage.js needs audit, audit.js needs storage).
store._registerAuditAppend(appendAudit);
