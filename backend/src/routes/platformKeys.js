// routes/platformKeys.js — admin-only CRUD for the platform's KMS-held
// signing keys (separate from the user-managed trust store at trust-keys).
// Lifecycle: pending -> active -> retired -> revoked. No deletion path.
//
// All mutating routes go through:
//   1. authorize() — gated by studio.authz (admin-only, integrity-ok)
//   2. platformKeys.rotate / revoke — emits the audit entry inside withAudit
//   3. publish callback — re-emits data.platform_keys to OPA after commit
import { Router } from "express";

import * as store from "../services/storage.js";
import * as platformKeys from "../services/platformKeys.js";
import * as opa from "../services/opaClient.js";
import * as opaBundle from "../services/opaBundle.js";
import { authorize } from "../middleware/authorize.js";

// How long rotation waits for OPA to ACTIVATE a bundle carrying the new
// pubkey before flipping the in-memory signer. Must comfortably exceed the
// OPA bundle poll's max_delay_seconds (default 20s). Configurable for tests.
const ROTATE_ACTIVATION_TIMEOUT_MS =
  parseInt(process.env.PLATFORM_KEY_ROTATE_TIMEOUT_MS, 10) || 35000;
const ROTATE_POLL_INTERVAL_MS = 2000;

// Poll OPA's live data.platform_keys until it carries `fpHex` under `purpose`,
// i.e. OPA has activated a bundle that trusts the new key. Returns true on
// success, false on timeout. Read-only; never throws (transport errors are
// treated as "not yet").
async function waitForOpaPlatformKey(purpose, fpHex, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      const doc = await opa.getData("platform_keys");
      const live = doc?.result || {};
      if (live[purpose] && live[purpose][fpHex]) return true;
    } catch {
      /* OPA momentarily unreachable / mid-activation — keep polling */
    }
    if (Date.now() >= deadline) return false;
    await new Promise((r) => setTimeout(r, ROTATE_POLL_INTERVAL_MS));
  }
}

// Factory: routes need the publish callback wired from server.js so they
// can re-emit data.platform_keys after the audited mutation commits.
export function createPlatformKeysRouter({ publish }) {
  if (typeof publish !== "function") {
    throw new Error("createPlatformKeysRouter: publish callback required");
  }
  const router = Router();

  router.get("/", authorize("read", "platform_key"), async (_req, res) => {
    const rows = await store.listPlatformKeys();
    const trust = platformKeys.isTrustOk();
    res.json({
      keys: rows,
      trust,
    });
  });

  // Expose a low-privilege check for overall trust chain health (accessible to all authenticated users)
  router.get("/trust-status", async (_req, res) => {
    const trust = platformKeys.isTrustOk();
    res.json({ trust });
  });

  // Compare OPA's live data.platform_keys against the DB's active rows.
  // Surfaces drift caused by an out-of-band write to OPA or a stale boot
  // file. Returns a list of issue strings; empty array means in sync.
  router.get("/opa-state", authorize("read", "platform_key"), async (_req, res) => {
    let live;
    try {
      const doc = await opa.getData("platform_keys");
      live = doc?.result || {};
    } catch (e) {
      return res.status(503).json({ error: `OPA unreachable: ${e.message}` });
    }
    const dbRows = await store.listActivePlatformKeys();
    const issues = [];
    const byPurpose = {};
    for (const row of dbRows) {
      if (row.status !== "active" && row.status !== "retired") continue;
      byPurpose[row.purpose] = byPurpose[row.purpose] || new Set();
      byPurpose[row.purpose].add(row.fpHex);
    }
    for (const purpose of ["opa-auth-signing", "pep-opa-auth-signing"]) {
      const dbKids = byPurpose[purpose] || new Set();
      const opaKids = new Set(Object.keys(live[purpose] || {}));
      for (const kid of dbKids) {
        if (!opaKids.has(kid)) {
          issues.push(`${purpose}: DB kid ${kid} missing from OPA`);
        }
      }
      for (const kid of opaKids) {
        if (!dbKids.has(kid)) {
          issues.push(`${purpose}: OPA kid ${kid} unknown to DB (possible tamper)`);
        }
      }
    }
    res.json({ opaPlatformKeys: live, dbActiveRows: dbRows, issues, inSync: issues.length === 0 });
  });

  router.post("/rotate", authorize("update", "platform_key"), async (req, res) => {
    const purpose = req.body?.purpose;
    if (!platformKeys.PURPOSES.includes(purpose)) {
      return res.status(400).json({
        error: `purpose must be one of: ${platformKeys.PURPOSES.join(", ")}`,
      });
    }
    // Recovery: if a PRIOR rotate already minted the new key but timed out
    // before OPA activated it (202 pending), the active DB row's fingerprint
    // differs from the in-memory signer pointer. Re-issuing rotate must NOT
    // mint yet another key — instead re-check activation of the pending key
    // and commit. (After a backend restart this never trips: boot reconciles
    // the signer pointer to the active DB row.)
    const activeRow = await store.getActivePlatformKey(purpose);
    const inMem = platformKeys.getActivePurposeMeta(purpose);
    const pending =
      activeRow && inMem && activeRow.fpHex !== inMem.fpHex
        ? { newKeyId: activeRow.keyId, newFpHex: activeRow.fpHex, retiredFpHex: inMem.fpHex }
        : null;

    const result = pending || (await platformKeys.rotate(purpose, { actor: req.user }));
    // Two-phase under bundle pull. rotate() registered the new pubkey (active
    // in DB, cached for verification) but did NOT flip the in-memory SIGNING
    // pointer. We must not flip it until OPA actually trusts the new pubkey —
    // otherwise the next backend->OPA (or PEP->OPA for the pep key) JWT, signed
    // by the new key, would fail system_authz until OPA's next poll.
    //
    // So: invalidate + eagerly rebuild the bundle (so the next poll serves the
    // new revision immediately), then WAIT for OPA to activate it, and only
    // then commitRotation(). The old key stays valid throughout (it's retired,
    // not revoked, and buildOpaPublishDocument keeps retired keys), so existing
    // tokens keep verifying during the wait.
    publish("platform_key.rotate");
    try {
      await opaBundle.buildBundle();
    } catch (e) {
      console.warn(`[platform-key.rotate] eager bundle rebuild failed: ${e.message}`);
    }
    const activated = await waitForOpaPlatformKey(
      purpose, result.newFpHex, ROTATE_ACTIVATION_TIMEOUT_MS
    );
    if (!activated) {
      // Do NOT commit — the old key is still the active signer and remains
      // valid, so nothing breaks. The new key is already in the DB + bundle;
      // a follow-up rotate call re-checks activation and commits.
      return res.status(202).json({
        ok: false,
        pending: true,
        newFpHex: result.newFpHex,
        retiredFpHex: result.retiredFpHex,
        detail:
          "Rotated in DB and bundle, but OPA has not yet activated the new " +
          "pubkey within the timeout; the active signer was NOT flipped. " +
          "Re-issue the rotate request to re-check activation and commit.",
      });
    }
    // OPA now trusts the new key — safe to sign with it.
    platformKeys.commitRotation(purpose, result.newKeyId, result.newFpHex);
    if (purpose === "opa-auth-signing") {
      opa.invalidateAuthCache();
    }
    res.json({ ok: true, newFpHex: result.newFpHex, retiredFpHex: result.retiredFpHex });
  });

  router.post("/:fp/revoke", authorize("update", "platform_key"), async (req, res) => {
    try {
      const updated = await platformKeys.revoke(req.params.fp, { actor: req.user });
      await publish("platform_key.revoke");
      res.json(updated);
    } catch (e) {
      if (e.code === "PLATFORM_KEY_ACTIVE") {
        return res.status(400).json({ error: e.message });
      }
      if (e.code === "PLATFORM_KEY_NOT_FOUND") {
        return res.status(404).json({ error: e.message });
      }
      if (e.code === "PLATFORM_KEY_NOT_RETIRED") {
        return res.status(400).json({
          error: e.message,
          detail: "Retire the key first (handled automatically by rotation).",
        });
      }
      throw e;
    }
  });

  return router;
}
