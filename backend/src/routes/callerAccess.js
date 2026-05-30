// routes/callerAccess.js — admin-managed per-caller policy access list.
//
// Mounted at /api/pep-callers/:callerId/access. Three operations:
//   GET    /                  → list grants for one caller (joined with policy
//                                names/packages so the UI can render them)
//   POST   /  { policyIds }   → bulk grant. Idempotent on each pair; emits a
//                                single audited transaction so partial commits
//                                are impossible.
//   DELETE /:policyId         → revoke one grant. Audit row carries the pair.
//
// Each mutation runs through withAudit so the access list is tamper-evident:
// a DB-trigger refuses out-of-band writes (see ensureSchema), and the audit
// chain freezes mutations on integrity break.
//
// Locked policies are NOT grantable — the admin must unlock first. This keeps
// the runtime invariant "a granted policy is callable" tight; otherwise the
// UI would show a phantom row that the PEP can never service.

import { Router } from "express";
import * as store from "./../services/storage.js";
import { authorize } from "./../middleware/authorize.js";

const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

function badRequest(res, message) {
  res.status(400).json({ error: message });
}

function callerAccessForResponse(row) {
  if (!row) return null;
  const out = {
    callerId:  row.callerId,
    policyId:  row.policyId,
    grantedBy: row.grantedBy,
    grantedAt: row.grantedAt,
  };
  if (row.policyName     !== undefined) out.policyName     = row.policyName;
  if (row.policyPackage  !== undefined) out.policyPackage  = row.policyPackage;
  if (row.policyLocked   !== undefined) out.policyLocked   = row.policyLocked;
  return out;
}

export function createCallerAccessRouter({ publish }) {
  if (typeof publish !== "function") {
    throw new Error("createCallerAccessRouter: publish callback required");
  }
  const router = Router({ mergeParams: true });

  // List grants for the caller in the URL. Returns the joined view so the
  // frontend doesn't have to N+1 the policies list.
  router.get(
    "/",
    authorize("read", "caller_access", { resourceId: (req) => req.params.callerId }),
    async (req, res) => {
      const callerId = req.params.callerId;
      const caller = await store.getPepCaller(callerId, req.user);
      if (!caller) return res.status(404).json({ error: "pep caller not found" });
      const rows = await store.listCallerAccessForCaller(callerId);
      res.json(rows.map(callerAccessForResponse));
    }
  );

  // Bulk grant. Body: { policyIds: ["<uuid>", ...] }. Each pair is upserted
  // idempotently inside a single withAudit transaction.
  router.post(
    "/",
    authorize("create", "caller_access", { resourceId: (req) => req.params.callerId }),
    async (req, res) => {
      const callerId = req.params.callerId;
      const caller = await store.getPepCaller(callerId, req.user);
      if (!caller) return res.status(404).json({ error: "pep caller not found" });
      if (caller.status === "revoked") {
        return res.status(409).json({ error: "pep caller is revoked; cannot grant access" });
      }

      const body = req.body || {};
      const policyIds = Array.isArray(body.policyIds) ? body.policyIds : null;
      if (!policyIds || policyIds.length === 0) {
        return badRequest(res, "policyIds must be a non-empty array of UUIDs");
      }
      if (policyIds.length > 200) {
        return badRequest(res, "policyIds capped at 200 per request");
      }
      const seen = new Set();
      for (const id of policyIds) {
        if (typeof id !== "string" || !UUID_RE.test(id)) {
          return badRequest(res, `invalid policyId: ${id}`);
        }
        if (seen.has(id)) {
          return badRequest(res, `duplicate policyId: ${id}`);
        }
        seen.add(id);
      }

      // Validate every policy exists and is not locked BEFORE granting. We
      // fail the whole transaction on the first invalid id so the audit row
      // doesn't capture grants that the PEP would silently reject. The
      // looked-up name+package travel into the audit body so an admin can
      // read the chain without re-joining against the policies table.
      const policySummaries = [];
      for (const id of policyIds) {
        const policy = await store.getPolicy(id, req.user);
        if (!policy) {
          return res.status(400).json({ error: `policyId not found: ${id}` });
        }
        if (policy.locked) {
          return res.status(400).json({
            error: `policy is locked and cannot be granted: ${policy.name} (${id})`,
          });
        }
        policySummaries.push({
          id: policy.id,
          name: policy.name,
          package: policy.package,
        });
      }

      const createdIds = [];
      const skippedIds = [];
      await store.withAudit(req.user, {
        action: "caller_access.grant",
        resourceType: "caller_access",
        resourceId: callerId,
      }, async (client) => {
        for (const policyId of policyIds) {
          const { created } = await store.grantCallerAccessTx(client, {
            callerId,
            policyId,
            grantedBy: req.user.id,
          });
          (created ? createdIds : skippedIds).push(policyId);
        }
        return {
          response: { createdIds, skippedIds },
          auditAfter: {
            callerId,
            grantedBy: req.user.id,
            policyIds,           // primary keys, kept for replayability
            policies: policySummaries, // human-readable annotation
          },
        };
      });

      await publish("caller_access.grant");
      const grants = await store.listCallerAccessForCaller(callerId);
      res.status(200).json({
        created: createdIds,
        skipped: skippedIds,            // already-granted pairs (no-op)
        access:  grants.map(callerAccessForResponse),
      });
    }
  );

  // Revoke one grant. 200 even if the pair didn't exist (idempotent revoke),
  // but still emits an audit row so an admin can trace the intent.
  router.delete(
    "/:policyId",
    authorize("delete", "caller_access", { resourceId: (req) => req.params.callerId }),
    async (req, res) => {
      const callerId = req.params.callerId;
      const policyId = req.params.policyId;
      if (!UUID_RE.test(policyId)) {
        return badRequest(res, "policyId must be a UUID");
      }
      const caller = await store.getPepCaller(callerId, req.user);
      if (!caller) return res.status(404).json({ error: "pep caller not found" });

      // If the caller currently sees this policy ONLY via tag overlap (no
      // explicit row), a DELETE would silently report `deleted:false` while
      // the caller's published allowlist still contains the policy on the
      // next publish. Surface that clearly so the admin knows to flip the
      // tag instead.
      const policy = await store.getPolicy(policyId, req.user);
      if (policy && Array.isArray(caller.scopeTags) && Array.isArray(policy.tags)) {
        const overlap = policy.tags.filter((t) => caller.scopeTags.includes(t));
        if (overlap.length > 0) {
          // Is there ALSO an explicit row? If yes, fall through to delete
          // it (the tag overlap will keep the policy in scope — that's a
          // separate signal). If no, refuse with 409.
          const explicit = await store.listCallerAccessForCaller(callerId);
          const hasExplicit = explicit.some((r) => r.policyId === policyId);
          if (!hasExplicit) {
            return res.status(409).json({
              error: "derived_from_tag",
              detail:
                "This policy is in the caller's scope via tag overlap; " +
                "remove the matching tag from the policy or the caller's " +
                "scope_tags instead of revoking.",
              tags: overlap,
            });
          }
        }
      }

      // policy was already fetched above for the derived-from-tag guard;
      // pass its name+package through to the audit body so an admin reading
      // the chain sees the human-readable target. Locked / deleted policies
      // can still be revoked (defensive), so guard the optional lookup.
      const policySummary = policy
        ? { id: policy.id, name: policy.name, package: policy.package }
        : { id: policyId };

      let deleted = false;
      await store.withAudit(req.user, {
        action: "caller_access.revoke",
        resourceType: "caller_access",
        resourceId: callerId,
      }, async (client) => {
        const { deleted: didDelete } = await store.revokeCallerAccessTx(client, {
          callerId,
          policyId,
        });
        deleted = didDelete;
        return {
          response: { deleted },
          auditAfter: {
            callerId,
            grantedBy: null,
            policyId,
            policy: policySummary,
          },
        };
      });

      await publish("caller_access.revoke");
      res.json({ deleted });
    }
  );

  return router;
}
