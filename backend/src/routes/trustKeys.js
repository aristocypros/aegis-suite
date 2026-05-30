// routes/trustKeys.js — admin-only CRUD for the platform trust store (CRY-03).
// All mutating routes go through:
//   1. authorize() — gated by studio.authz (admin-only for trust_key)
//   2. withAudit() — every change recorded in the tamper-evident chain
//   3. publish callback — re-publishes data.studio.keys after the txn commits
//
// Authorization for trust_key resources is handled by the existing admin-CRUD
// allow rule in opa/studio_authz.rego — no new rule is required because that
// rule matches any resource.type. The docstring there has been extended to
// document the new resource type.

import { Router } from "express";
import * as store from "./../services/storage.js";
import {
  normalizeKeyMaterial,
  validateKid,
  validateAlg,
  trustKeyForResponse,
  TrustKeyValidationError,
  HMAC_ALGS,
} from "./../services/trustKeys.js";
import { refreshOne } from "./../services/jwksFetcher.js";
import { authorize } from "./../middleware/authorize.js";

function badRequest(res, message) {
  res.status(400).json({ error: message });
}

// Factory: routes need the publish callback wired from server.js so they can
// re-emit data.studio.keys after the audited mutation commits. Keeping it as
// a factory avoids a circular import (server.js imports this module).
export function createTrustKeysRouter({ publish }) {
  if (typeof publish !== "function") {
    throw new Error("createTrustKeysRouter: publish callback required");
  }
  const router = Router();

  router.get("/", authorize("read", "trust_key"), async (req, res) => {
    const rows = await store.listTrustKeys(req.user);
    res.json(rows.map(trustKeyForResponse));
  });

  router.post("/", authorize("create", "trust_key", {
    targetOrgId: (req) => {
      if (req.user?.isRoot) return req.body?.orgId ?? req.user?.orgId;
      return req.user?.orgId;
    },
  }), async (req, res) => {
    try {
      const body = req.body || {};
      const kid = validateKid(body.kid);
      const alg = validateAlg(body.alg);
      const tenant = typeof body.tenant === "string" && body.tenant.length > 0
        ? body.tenant : null;
      const sourceKind = body.sourceKind === "jwks_url" ? "jwks_url" : "inline";
      // Effective org_id: non-root forced to actor's org; root may opt for
      // null (global) by explicitly setting orgId=null in the body.
      const orgId = req.user.isRoot
        ? (Object.prototype.hasOwnProperty.call(body, "orgId")
            ? body.orgId
            : (req.user.orgId ?? null))
        : req.user.orgId;
      if (!orgId && !req.user.isRoot) {
        return badRequest(res, "non-root caller has no org assigned");
      }

      // kid is globally unique across orgs (PK constraint). Surface the
      // existing row's org info so the admin understands the collision.
      const existing = await store.getTrustKey(kid);
      if (existing) {
        return res.status(409).json({ error: `kid '${kid}' already exists` });
      }

      let normalized;
      let jwksUrl = null;
      let jwksTtlSeconds = null;

      if (sourceKind === "inline") {
        normalized = normalizeKeyMaterial({
          alg,
          jwk: body.jwk ?? null,
          pem: body.pem ?? null,
          secret: body.secret ?? null,
        });
      } else {
        if (HMAC_ALGS.has(alg)) {
          return badRequest(res, "HMAC algorithms cannot use source_kind='jwks_url'");
        }
        if (typeof body.jwksUrl !== "string" || !/^https?:\/\//i.test(body.jwksUrl)) {
          return badRequest(res, "jwks_url is required and must be http(s)");
        }
        jwksUrl = body.jwksUrl;
        jwksTtlSeconds = Number.isInteger(body.jwksTtlSeconds) && body.jwksTtlSeconds > 0
          ? Math.min(body.jwksTtlSeconds, 24 * 3600)
          : null;
        // Leave jwk/pem/secret null on insert; the fetcher will hydrate. We
        // could fail-fast here by trying to fetch synchronously, but a slow
        // upstream would block the CRUD call. The admin can hit /refresh to
        // verify.
        normalized = { jwk: null, pem: null, secret: null };
      }

      const created = await store.withAudit(req.user, {
        action: "trust_key.create",
        resourceType: "trust_key",
        resourceId: kid,
      }, async (client) => {
        const { after } = await store.createTrustKeyTx(client, {
          kid, alg,
          jwk: normalized.jwk,
          pem: normalized.pem,
          secret: normalized.secret,
          x5c: body.x5c ?? null,
          tenant,
          orgId,
          sourceKind,
          jwksUrl,
          jwksTtlSeconds,
        });
        return {
          response: after,
          auditAfter: store.trustKeyRowForAudit(after),
        };
      });

      // Hydrate JWKS-URL rows on first creation so the admin sees material
      // appear in the next publish without waiting a full TTL.
      if (sourceKind === "jwks_url") {
        await refreshOne(kid);
      }
      await publish("trust_key.create");
      res.status(201).json(trustKeyForResponse(await store.getTrustKey(kid)));
    } catch (e) {
      if (e instanceof TrustKeyValidationError) {
        return badRequest(res, e.message);
      }
      throw e;
    }
  });

  router.put("/:kid", authorize("update", "trust_key", { resourceIdParam: "kid" }), async (req, res) => {
    try {
      const kid = validateKid(req.params.kid);
      const existing = await store.getTrustKey(kid);
      if (!existing) return res.status(404).json({ error: "trust key not found" });
      if (existing.status === "revoked") {
        return res.status(409).json({ error: "trust key is revoked; cannot update" });
      }

      const body = req.body || {};
      if (body.kid !== undefined && body.kid !== kid) {
        return badRequest(res, "kid is immutable");
      }
      if (body.sourceKind !== undefined && body.sourceKind !== existing.sourceKind) {
        return badRequest(res, "source_kind is immutable; revoke and recreate to change");
      }

      const patch = {};
      if (existing.sourceKind === "inline") {
        // Re-validate alg + material as a unit. We require the caller to send
        // either fresh material or omit it (in which case alg/tenant can still
        // change). Mixed updates that touch alg without material would lead
        // to silent shape mismatches.
        const alg = body.alg ?? existing.alg;
        validateAlg(alg);
        const hasMaterial =
          body.jwk !== undefined || body.pem !== undefined || body.secret !== undefined;
        if (hasMaterial) {
          const normalized = normalizeKeyMaterial({
            alg,
            jwk: body.jwk ?? null,
            pem: body.pem ?? null,
            secret: body.secret ?? null,
          });
          patch.alg = alg;
          patch.jwk = normalized.jwk;
          patch.pem = normalized.pem;
          patch.secret = normalized.secret;
        } else if (body.alg !== undefined && body.alg !== existing.alg) {
          return badRequest(res, "alg change requires also sending fresh key material");
        }
        if (body.x5c !== undefined) patch.x5c = body.x5c;
      } else {
        // jwks_url row: only the URL and TTL are user-settable (material is
        // refreshed asynchronously).
        if (body.alg !== undefined && body.alg !== existing.alg) {
          validateAlg(body.alg);
          patch.alg = body.alg;
        }
        if (body.jwksUrl !== undefined) {
          if (typeof body.jwksUrl !== "string" || !/^https?:\/\//i.test(body.jwksUrl)) {
            return badRequest(res, "jwks_url must be http(s)");
          }
          patch.jwksUrl = body.jwksUrl;
        }
        if (body.jwksTtlSeconds !== undefined) {
          if (!Number.isInteger(body.jwksTtlSeconds) || body.jwksTtlSeconds <= 0) {
            return badRequest(res, "jwks_ttl_seconds must be a positive integer");
          }
          patch.jwksTtlSeconds = Math.min(body.jwksTtlSeconds, 24 * 3600);
        }
      }
      if (body.tenant !== undefined) {
        patch.tenant = typeof body.tenant === "string" && body.tenant.length > 0
          ? body.tenant : null;
      }

      const updated = await store.withAudit(req.user, {
        action: "trust_key.update",
        resourceType: "trust_key",
        resourceId: kid,
        beforeFetcher: async (c) =>
          store.trustKeyRowForAudit(await store.getTrustKeyTx(c, kid)),
      }, async (client) => {
        const { after } = await store.updateTrustKeyTx(client, kid, patch);
        return {
          response: after,
          auditAfter: store.trustKeyRowForAudit(after),
        };
      });

      // If a jwks_url row's URL changed, hydrate immediately so the next
      // publish reflects the new endpoint.
      if (existing.sourceKind === "jwks_url" && patch.jwksUrl) {
        await refreshOne(kid);
      }
      await publish("trust_key.update");
      res.json(trustKeyForResponse(await store.getTrustKey(kid)));
    } catch (e) {
      if (e instanceof TrustKeyValidationError) {
        return badRequest(res, e.message);
      }
      throw e;
    }
  });

  router.post("/:kid/revoke", authorize("update", "trust_key", { resourceIdParam: "kid" }), async (req, res) => {
    const kid = req.params.kid;
    const existing = await store.getTrustKey(kid);
    if (!existing) return res.status(404).json({ error: "trust key not found" });
    if (existing.status === "revoked") {
      return res.json(trustKeyForResponse(existing));
    }
    const updated = await store.withAudit(req.user, {
      action: "trust_key.revoke",
      resourceType: "trust_key",
      resourceId: kid,
      beforeFetcher: async (c) =>
        store.trustKeyRowForAudit(await store.getTrustKeyTx(c, kid)),
    }, async (client) => {
      const { after } = await store.revokeTrustKeyTx(client, kid);
      return {
        response: after,
        auditAfter: store.trustKeyRowForAudit(after),
      };
    });
    await publish("trust_key.revoke");
    res.json(trustKeyForResponse(updated));
  });

  router.post("/:kid/refresh", authorize("update", "trust_key", { resourceIdParam: "kid" }), async (req, res) => {
    const kid = req.params.kid;
    const existing = await store.getTrustKey(kid);
    if (!existing) return res.status(404).json({ error: "trust key not found" });
    if (existing.sourceKind !== "jwks_url") {
      return badRequest(res, "refresh only applies to source_kind='jwks_url' rows");
    }
    if (existing.status !== "active") {
      return res.status(409).json({ error: "trust key is not active" });
    }

    // Audit the operator action. The actual fetch is performed by refreshOne;
    // the audit entry records the kid and outcome so a chain reviewer can
    // tell apart "admin pressed refresh" from autonomous background ticks.
    let changed = false;
    let error = null;
    await store.withAudit(req.user, {
      action: "trust_key.refresh",
      resourceType: "trust_key",
      resourceId: kid,
      beforeFetcher: async (c) =>
        store.trustKeyRowForAudit(await store.getTrustKeyTx(c, kid)),
    }, async (_client) => {
      try {
        changed = await refreshOne(kid);
      } catch (e) {
        error = e?.message || String(e);
      }
      // The refresh runs OUTSIDE the audit txn (it does its own writes), so
      // we re-fetch the post-refresh state for the after-snapshot.
      const after = await store.getTrustKey(kid);
      return {
        response: { changed, error },
        auditAfter: store.trustKeyRowForAudit(after),
      };
    });

    if (changed) await publish("trust_key.refresh");
    const after = await store.getTrustKey(kid);
    res.json({
      key: trustKeyForResponse(after),
      changed,
      error,
    });
  });

  router.delete("/:kid", authorize("delete", "trust_key", { resourceIdParam: "kid" }), async (req, res) => {
    const kid = req.params.kid;
    try {
      const result = await store.withAudit(req.user, {
        action: "trust_key.delete",
        resourceType: "trust_key",
        resourceId: kid,
        beforeFetcher: async (c) =>
          store.trustKeyRowForAudit(await store.getTrustKeyTx(c, kid)),
      }, async (client) => {
        const { before } = await store.deleteTrustKeyTx(client, kid);
        return {
          response: { ok: true, existed: !!before },
          auditAfter: null,
        };
      });
      await publish("trust_key.delete");
      res.json(result);
    } catch (e) {
      if (e?.code === "TRUST_KEY_NOT_REVOKED") {
        return res.status(409).json({
          error: e.message,
          detail: "Revoke the trust key first; deletion is allowed only on revoked keys.",
        });
      }
      throw e;
    }
  });

  return router;
}
