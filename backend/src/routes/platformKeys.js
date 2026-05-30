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
import { authorize } from "../middleware/authorize.js";

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
    const result = await platformKeys.rotate(purpose, { actor: req.user });
    // Publish FIRST with the still-active old signing key, so OPA learns
    // about the new pubkey. THEN flip the in-memory pointer so the next
    // outgoing JWT is signed by the new key. For opa-auth-signing also
    // flush the token cache so the very next call mints under the new
    // key. (For session-signing the cache doesn't matter — issuance
    // picks up activeKeyId per call.)
    await publish("platform_key.rotate");
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
