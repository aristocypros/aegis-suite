// routes/pepCallers.js — admin CRUD for PEP caller identities (PEP-01).
//
// Each row declares ONE auth_mode and identifies a caller permitted to
// invoke the PEP /authorize and /discover endpoints:
//   auth_mode=hmac  → verify X-Studio-Sig against the row's hmac_secret
//   auth_mode=mtls  → verify client cert CN against the row's allowed_cn
//   auth_mode=jwt   → verify bearer JWT (sub matches caller_id or jwt_subject)
//
// auth_mode is set at create time and immutable thereafter — to change
// modes, revoke + create a new caller. This keeps the audit chain honest
// about which credential a given caller_id was issued.
//
// Active rows are published to OPA at data.studio.callers; the PEP reads
// that document on every request via its OPA client. Revocation drops the
// row from the next publish so a stolen caller credential stops working
// within the publish interval. Deletion requires prior revocation, matching
// the trust-keys invariant — the audit chain retains the full history.

import { randomBytes } from "node:crypto";
import { Router } from "express";
import * as store from "./../services/storage.js";
import { authorize } from "./../middleware/authorize.js";

// caller_id is rendered into JSON / OPA data keys; keep it strict so the
// PEP can match it against the X-Studio-Sig header field without surprises.
const CALLER_ID_RE = /^[A-Za-z0-9_.-]{1,64}$/;
const VALID_AUTH_MODES = ["hmac", "mtls", "jwt"];

function badRequest(res, message) {
  res.status(400).json({ error: message });
}

function generateSecret() {
  return randomBytes(32).toString("base64url");
}

function pepCallerForResponse(row) {
  // Always hide the HMAC secret in responses. The plaintext is only emitted
  // by the create/rotate endpoints as a one-shot `generatedSecret` field.
  if (!row) return null;
  const safe = { ...row };
  if (safe.hmacSecret) safe.hmacSecret = "[REDACTED]";
  return safe;
}

function parsePatch(body, { existing } = {}) {
  const patch = {};
  if (body.description !== undefined) {
    if (body.description !== null && typeof body.description !== "string") {
      throw new Error("description must be a string or null");
    }
    patch.description = body.description || null;
  }
  if (body.allowedCn !== undefined) {
    if (existing && existing.authMode !== "mtls") {
      throw new Error("allowedCn is only editable on mtls callers");
    }
    if (body.allowedCn !== null && typeof body.allowedCn !== "string") {
      throw new Error("allowedCn must be a string or null");
    }
    const next = body.allowedCn ? body.allowedCn.trim() : null;
    if (existing && existing.authMode === "mtls" && !next) {
      throw new Error("mtls callers require a non-empty allowedCn");
    }
    patch.allowedCn = next;
  }
  if (body.jwtSubject !== undefined) {
    if (existing && existing.authMode !== "jwt") {
      throw new Error("jwtSubject is only editable on jwt callers");
    }
    if (body.jwtSubject !== null && typeof body.jwtSubject !== "string") {
      throw new Error("jwtSubject must be a string or null");
    }
    patch.jwtSubject = body.jwtSubject ? body.jwtSubject.trim() : null;
  }
  if (body.tenant !== undefined) {
    if (body.tenant !== null && typeof body.tenant !== "string") {
      throw new Error("tenant must be a string or null");
    }
    patch.tenant = body.tenant ? body.tenant.trim() : null;
  }
  // auth_mode is immutable post-create. Reject explicit attempts so admins
  // don't think they switched modes when nothing happened.
  if (body.authMode !== undefined && body.authMode !== existing?.authMode) {
    throw new Error("authMode is immutable; revoke and recreate to change modes");
  }
  // HMAC secret is only rotated via /:id/rotate-secret.
  if (body.hmacSecret !== undefined) {
    throw new Error("hmacSecret is rotated via POST /:id/rotate-secret");
  }
  return patch;
}

export function createPepCallersRouter({ publish, publishAccess }) {
  if (typeof publish !== "function") {
    throw new Error("createPepCallersRouter: publish callback required");
  }
  const router = Router();

  router.get("/", authorize("read", "pep_caller"), async (req, res) => {
    const rows = await store.listPepCallers(req.user);
    res.json(rows.map(pepCallerForResponse));
  });

  router.post("/", authorize("create", "pep_caller", {
    targetOrgId: (req) => {
      if (req.user?.isRoot) return req.body?.orgId ?? req.user?.orgId;
      return req.user?.orgId;
    },
  }), async (req, res) => {
    const body = req.body || {};
    const callerId = typeof body.callerId === "string" ? body.callerId.trim() : "";
    if (!CALLER_ID_RE.test(callerId)) {
      return badRequest(res, "callerId must match /^[A-Za-z0-9_.-]{1,64}$/");
    }
    const authMode = typeof body.authMode === "string" ? body.authMode.trim().toLowerCase() : "";
    if (!VALID_AUTH_MODES.includes(authMode)) {
      return badRequest(res, `authMode must be one of: ${VALID_AUTH_MODES.join(", ")}`);
    }
    // Effective org_id: non-root forced to actor's org; root may explicitly
    // pass orgId=null in body for a global caller.
    const orgId = req.user.isRoot
      ? (Object.prototype.hasOwnProperty.call(body, "orgId")
          ? body.orgId
          : (req.user.orgId ?? null))
      : req.user.orgId;
    if (!orgId && !req.user.isRoot) {
      return badRequest(res, "non-root caller has no org assigned");
    }
    // callerId is globally unique (PK); surface collisions explicitly.
    const existing = await store.getPepCaller(callerId);
    if (existing) {
      return res.status(409).json({ error: `callerId '${callerId}' already exists` });
    }

    const description = typeof body.description === "string" && body.description
      ? body.description : null;
    const tenant = typeof body.tenant === "string" && body.tenant.trim()
      ? body.tenant.trim() : null;

    // Per-mode material. We accept exactly the fields that mode needs and
    // reject the rest so admins can't accidentally provision an mtls caller
    // with a JWT subject pin that will silently never apply.
    let hmacSecret = null;
    let allowedCn = null;
    let jwtSubject = null;
    let generatedSecret = null;

    if (authMode === "hmac") {
      if (body.allowedCn || body.jwtSubject) {
        return badRequest(res, "hmac callers must not carry allowedCn or jwtSubject");
      }
      if (typeof body.hmacSecret === "string" && body.hmacSecret.length > 0) {
        if (body.hmacSecret.length < 16) {
          return badRequest(res, "hmacSecret must be at least 16 characters");
        }
        hmacSecret = body.hmacSecret;
      } else {
        hmacSecret = generateSecret();
        generatedSecret = hmacSecret;
      }
    } else if (authMode === "mtls") {
      if (body.hmacSecret || body.jwtSubject) {
        return badRequest(res, "mtls callers must not carry hmacSecret or jwtSubject");
      }
      if (typeof body.allowedCn !== "string" || !body.allowedCn.trim()) {
        return badRequest(res, "mtls callers require allowedCn");
      }
      allowedCn = body.allowedCn.trim();
    } else if (authMode === "jwt") {
      if (body.hmacSecret || body.allowedCn) {
        return badRequest(res, "jwt callers must not carry hmacSecret or allowedCn");
      }
      // jwtSubject is optional — when absent the dispatcher matches sub==callerId.
      if (body.jwtSubject !== undefined && body.jwtSubject !== null) {
        if (typeof body.jwtSubject !== "string" || !body.jwtSubject.trim()) {
          return badRequest(res, "jwtSubject must be a non-empty string when set");
        }
        jwtSubject = body.jwtSubject.trim();
      }
    }

    try {
      await store.withAudit(req.user, {
        action: "pep_caller.create",
        resourceType: "pep_caller",
        resourceId: callerId,
      }, async (client) => {
        const { after } = await store.createPepCallerTx(client, {
          callerId,
          authMode,
          description,
          hmacSecret,
          allowedCn,
          jwtSubject,
          tenant,
          orgId,
        });
        return {
          response: after,
          auditAfter: store.pepCallerRowForAudit(after),
        };
      });
    } catch (e) {
      // Surface the unique-CN collision as a 409 rather than the generic 500.
      if (e?.code === "23505" &&
          /pep_callers_mtls_cn_uniq/.test(e?.constraint || e?.message || "")) {
        return res.status(409).json({
          error: `another active mtls caller already uses allowedCn '${allowedCn}'`,
        });
      }
      throw e;
    }

    await publish("pep_caller.create");
    const after = await store.getPepCaller(callerId);
    res.status(201).json({
      caller: pepCallerForResponse(after),
      // ONE-SHOT: this is the only place the plaintext leaves the server.
      // Operators must store it now; subsequent reads will see [REDACTED].
      generatedSecret,
    });
  });

  router.put("/:id", authorize("update", "pep_caller"), async (req, res) => {
    const callerId = req.params.id;
    const existing = await store.getPepCaller(callerId);
    if (!existing) return res.status(404).json({ error: "pep caller not found" });
    if (existing.status === "revoked") {
      return res.status(409).json({ error: "pep caller is revoked; cannot update" });
    }
    let patch;
    try {
      patch = parsePatch(req.body || {}, { existing });
    } catch (e) {
      return badRequest(res, e.message);
    }

    await store.withAudit(req.user, {
      action: "pep_caller.update",
      resourceType: "pep_caller",
      resourceId: callerId,
      beforeFetcher: async (c) =>
        store.pepCallerRowForAudit(await store.getPepCallerTx(c, callerId)),
    }, async (client) => {
      const { after } = await store.updatePepCallerTx(client, callerId, patch);
      return {
        response: after,
        auditAfter: store.pepCallerRowForAudit(after),
      };
    });
    await publish("pep_caller.update");
    res.json(pepCallerForResponse(await store.getPepCaller(callerId)));
  });

  router.post("/:id/rotate-secret", authorize("update", "pep_caller"), async (req, res) => {
    const callerId = req.params.id;
    const existing = await store.getPepCaller(callerId);
    if (!existing) return res.status(404).json({ error: "pep caller not found" });
    if (existing.status === "revoked") {
      return res.status(409).json({ error: "pep caller is revoked; cannot rotate" });
    }
    if (existing.authMode !== "hmac") {
      return res.status(409).json({
        error: `cannot rotate secret on a ${existing.authMode} caller; only hmac callers carry a secret`,
      });
    }
    const newSecret = generateSecret();
    await store.withAudit(req.user, {
      action: "pep_caller.rotate_secret",
      resourceType: "pep_caller",
      resourceId: callerId,
      beforeFetcher: async (c) =>
        store.pepCallerRowForAudit(await store.getPepCallerTx(c, callerId)),
    }, async (client) => {
      const { after } = await store.updatePepCallerTx(client, callerId, {
        hmacSecret: newSecret,
      });
      return {
        response: after,
        auditAfter: store.pepCallerRowForAudit(after),
      };
    });
    await publish("pep_caller.rotate_secret");
    res.json({
      caller: pepCallerForResponse(await store.getPepCaller(callerId)),
      generatedSecret: newSecret,
    });
  });

  router.post("/:id/revoke", authorize("update", "pep_caller"), async (req, res) => {
    const callerId = req.params.id;
    const existing = await store.getPepCaller(callerId);
    if (!existing) return res.status(404).json({ error: "pep caller not found" });
    if (existing.status === "revoked") {
      return res.json(pepCallerForResponse(existing));
    }
    const updated = await store.withAudit(req.user, {
      action: "pep_caller.revoke",
      resourceType: "pep_caller",
      resourceId: callerId,
      beforeFetcher: async (c) =>
        store.pepCallerRowForAudit(await store.getPepCallerTx(c, callerId)),
    }, async (client) => {
      const { after } = await store.revokePepCallerTx(client, callerId);
      return {
        response: after,
        auditAfter: store.pepCallerRowForAudit(after),
      };
    });
    await publish("pep_caller.revoke");
    res.json(pepCallerForResponse(updated));
  });

  router.delete("/:id", authorize("delete", "pep_caller"), async (req, res) => {
    const callerId = req.params.id;
    try {
      const result = await store.withAudit(req.user, {
        action: "pep_caller.delete",
        resourceType: "pep_caller",
        resourceId: callerId,
        beforeFetcher: async (c) =>
          store.pepCallerRowForAudit(await store.getPepCallerTx(c, callerId)),
      }, async (client) => {
        const { before } = await store.deletePepCallerTx(client, callerId);
        return {
          response: { ok: true, existed: !!before },
          auditAfter: null,
        };
      });
      await publish("pep_caller.delete");
      res.json(result);
    } catch (e) {
      if (e?.code === "PEP_CALLER_NOT_REVOKED") {
        return res.status(409).json({
          error: e.message,
          detail: "Revoke the caller first; deletion is allowed only on revoked rows.",
        });
      }
      throw e;
    }
  });

  // PATCH /:id/scope-tags — admin-edited list of tags this caller is in
  // scope for. The PEP-ACL publisher unions `policies whose tags overlap
  // scope_tags` into the published allowlist on the next publish, so a
  // single tag here can grant access to many policies at once.
  router.patch(
    "/:id/scope-tags",
    authorize("update", "pep_caller"),
    async (req, res) => {
      const callerId = req.params.id;
      const existing = await store.getPepCaller(callerId);
      if (!existing) return res.status(404).json({ error: "pep caller not found" });
      if (existing.status === "revoked") {
        return res.status(409).json({ error: "pep caller is revoked; cannot edit scope tags" });
      }

      const body = req.body || {};
      let add, remove, nextTags;
      try {
        add = store.normaliseTags(body.add ?? []);
        remove = store.normaliseTags(body.remove ?? []);
        nextTags = store.applyTagDelta(existing.scopeTags, { add, remove });
      } catch (e) {
        return badRequest(res, e.message);
      }

      const result = await store.withAudit(req.user, {
        action: "pep_caller.scope_tags.update",
        resourceType: "pep_caller",
        resourceId: callerId,
        beforeFetcher: async (_c) => ({ callerId, scopeTags: existing.scopeTags }),
      }, async (client) => {
        const { after } = await store.updateCallerScopeTagsTx(client, callerId, nextTags);
        return {
          response: after,
          auditAfter: { callerId, add, remove, scopeTags: nextTags },
        };
      });

      // pep_callers.scope_tags is informational on the callers doc; the
      // *effective* allowlist for /authorize lives in caller_access. Republish
      // both so the PEP sees a consistent view.
      await publish("pep_caller.scope_tags.update");
      if (typeof publishAccess === "function") {
        await publishAccess("pep_caller.scope_tags.update");
      }
      res.json({ callerId, scopeTags: result?.scopeTags ?? nextTags });
    }
  );

  return router;
}
