// routes/policyCallers.js — policy-centric view of the per-caller ACL.
//
// Reverse of /api/pep-callers/:callerId/access. Mounted at
// /api/policies/:policyId/access. Same M:N table, same audit actions,
// same publisher — only the URL shape (and the bulk-payload shape) differ.
// One audit row per bulk grant, regardless of which side of the relation
// the admin entered from.

import { Router } from "express";
import * as store from "./../services/storage.js";
import { authorize } from "./../middleware/authorize.js";

const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const CALLER_ID_RE = /^[A-Za-z0-9_.-]{1,64}$/;

function badRequest(res, message) {
  res.status(400).json({ error: message });
}

function callerAccessForResponse(row) {
  if (!row) return null;
  return {
    callerId:  row.callerId,
    policyId:  row.policyId,
    grantedBy: row.grantedBy,
    grantedAt: row.grantedAt,
  };
}

export function createPolicyCallersRouter({ publish }) {
  if (typeof publish !== "function") {
    throw new Error("createPolicyCallersRouter: publish callback required");
  }
  const router = Router({ mergeParams: true });

  // List callers granted access to the policy in the URL. Returns the bare
  // (callerId, policyId, grantedBy, grantedAt) rows; the UI joins against
  // its own caller list for display metadata so we don't refetch the same
  // pep_callers table twice on the same screen.
  router.get(
    "/",
    authorize("read", "caller_access", { resourceId: (req) => req.params.policyId, lookupAs: "policy" }),
    async (req, res) => {
      const policyId = req.params.policyId;
      if (!UUID_RE.test(policyId)) return badRequest(res, "policyId must be a UUID");
      const policy = await store.getPolicy(policyId, req.user);
      if (!policy) return res.status(404).json({ error: "policy not found" });
      const rows = await store.listCallerAccessForPolicy(policyId);
      res.json(rows.map(callerAccessForResponse));
    }
  );

  // Bulk grant a policy to multiple callers in one audited transaction.
  router.post(
    "/",
    authorize("create", "caller_access", { resourceId: (req) => req.params.policyId, lookupAs: "policy" }),
    async (req, res) => {
      const policyId = req.params.policyId;
      if (!UUID_RE.test(policyId)) return badRequest(res, "policyId must be a UUID");
      const policy = await store.getPolicy(policyId, req.user);
      if (!policy) return res.status(404).json({ error: "policy not found" });
      if (policy.locked) {
        return res.status(400).json({ error: "policy is locked; unlock it before granting access" });
      }

      const body = req.body || {};
      const callerIds = Array.isArray(body.callerIds) ? body.callerIds : null;
      if (!callerIds || callerIds.length === 0) {
        return badRequest(res, "callerIds must be a non-empty array");
      }
      if (callerIds.length > 200) {
        return badRequest(res, "callerIds capped at 200 per request");
      }
      const seen = new Set();
      for (const id of callerIds) {
        if (typeof id !== "string" || !CALLER_ID_RE.test(id)) {
          return badRequest(res, `invalid callerId: ${id}`);
        }
        if (seen.has(id)) return badRequest(res, `duplicate callerId: ${id}`);
        seen.add(id);
      }

      // Each callerId must exist and not be revoked. Same fail-closed shape
      // as the caller-centric route — abort the whole tx on the first bad
      // value so the audit row never captures stale grants. Capture summary
      // metadata for the audit body as we validate.
      const callerSummaries = [];
      for (const callerId of callerIds) {
        const caller = await store.getPepCaller(callerId, req.user);
        if (!caller) {
          return res.status(400).json({ error: `callerId not found: ${callerId}` });
        }
        if (caller.status === "revoked") {
          return res.status(400).json({
            error: `cannot grant to a revoked caller: ${callerId}`,
          });
        }
        callerSummaries.push({
          callerId: caller.callerId,
          authMode: caller.authMode,
          tenant: caller.tenant ?? null,
        });
      }
      const policySummary = {
        id: policy.id,
        name: policy.name,
        package: policy.package,
      };

      const createdIds = [];
      const skippedIds = [];
      await store.withAudit(req.user, {
        action: "caller_access.grant",
        resourceType: "caller_access",
        resourceId: policyId,
      }, async (client) => {
        for (const callerId of callerIds) {
          const { created } = await store.grantCallerAccessTx(client, {
            callerId,
            policyId,
            grantedBy: req.user.id,
          });
          (created ? createdIds : skippedIds).push(callerId);
        }
        return {
          response: { createdIds, skippedIds },
          auditAfter: {
            policyId,
            policy: policySummary,
            callerIds,
            callers: callerSummaries,
            grantedBy: req.user.id,
          },
        };
      });

      await publish("caller_access.grant");
      const grants = await store.listCallerAccessForPolicy(policyId);
      res.status(200).json({
        created: createdIds,
        skipped: skippedIds,
        access:  grants.map(callerAccessForResponse),
      });
    }
  );

  // Revoke one caller's grant on this policy.
  router.delete(
    "/:callerId",
    authorize("delete", "caller_access", { resourceId: (req) => req.params.policyId, lookupAs: "policy" }),
    async (req, res) => {
      const policyId = req.params.policyId;
      const callerId = req.params.callerId;
      if (!UUID_RE.test(policyId)) return badRequest(res, "policyId must be a UUID");
      if (!CALLER_ID_RE.test(callerId)) return badRequest(res, "invalid callerId");
      const policy = await store.getPolicy(policyId, req.user);
      if (!policy) return res.status(404).json({ error: "policy not found" });
      const caller = await store.getPepCaller(callerId, req.user);
      if (!caller) return res.status(404).json({ error: "pep caller not found" });

      // Mirror of the caller-side guard: refuse to revoke a "derived"
      // (tag-overlap) grant unless an explicit row also exists.
      if (Array.isArray(policy.tags) && Array.isArray(caller.scopeTags)) {
        const overlap = policy.tags.filter((t) => caller.scopeTags.includes(t));
        if (overlap.length > 0) {
          const explicit = await store.listCallerAccessForPolicy(policyId);
          const hasExplicit = explicit.some((r) => r.callerId === callerId);
          if (!hasExplicit) {
            return res.status(409).json({
              error: "derived_from_tag",
              detail:
                "This caller is in this policy's audience via tag overlap; " +
                "remove the matching tag from the policy or the caller's " +
                "scope_tags instead of revoking.",
              tags: overlap,
            });
          }
        }
      }

      // Both policy and caller were already fetched above for the guard;
      // reuse them to enrich the audit body so the chain reads cleanly.
      const policySummary = {
        id: policy.id,
        name: policy.name,
        package: policy.package,
      };
      const callerSummary = {
        callerId: caller.callerId,
        authMode: caller.authMode,
        tenant: caller.tenant ?? null,
      };

      let deleted = false;
      await store.withAudit(req.user, {
        action: "caller_access.revoke",
        resourceType: "caller_access",
        resourceId: policyId,
      }, async (client) => {
        const { deleted: didDelete } = await store.revokeCallerAccessTx(client, {
          callerId,
          policyId,
        });
        deleted = didDelete;
        return {
          response: { deleted },
          auditAfter: {
            policyId,
            policy: policySummary,
            callerId,
            caller: callerSummary,
            grantedBy: null,
          },
        };
      });

      await publish("caller_access.revoke");
      res.json({ deleted });
    }
  );

  return router;
}
