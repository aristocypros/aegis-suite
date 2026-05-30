// authorize.js — application authz middleware. Calls OPA's studio.authz
// policy on every mutating request. Default-deny: if OPA is unreachable or
// the policy denies, the request is rejected.
//
// In addition to the user/action/resource, every call passes the current
// audit-chain status as input.audit. studio.authz refuses any mutating
// action when the chain is broken. This wires the tamper-evident audit
// chain into the policy engine so a corrupted DB can't be further mutated.
//
// Usage:
//   app.post("/api/policies", authorize("create", "policy"), handler);
//   app.delete("/api/users/:id", authorize("delete", "user"), handler);
//
// For routes whose resource id lives in a non-default URL param (e.g. :kid,
// :callerId), pass resourceIdParam. For routes where the id is derived from
// something other than req.params (e.g. req.user.id for self-service), pass
// an explicit resourceId resolver.
//
//   authorize("update", "trust_key", { resourceIdParam: "kid" })
//   authorize("update", "password",  { resourceId: (req) => req.user.id })
//
// Cross-org enforcement: when an org-scoped resource id is present, the
// middleware loads the row's org_id from the DB and passes it to OPA as
// input.resource.org_id (or input.resource.is_global=true when the row
// has no org). Routes that perform an "create" against a specific target
// org should pass a targetOrgId resolver so studio_authz can match it
// against the actor's org.
//
//   authorize("create", "user", { targetOrgId: (req) => req.body.orgId })
//
// When the resource id refers to a row in a DIFFERENT table than what the
// resource type would normally key off — e.g. /policies/:policyId/callers
// uses resource type "caller_access" but the id is a policy id — pass
// lookupAs so the org-info dispatcher reads from the right table.
//
//   authorize("read", "caller_access", {
//     resourceId: (req) => req.params.policyId,
//     lookupAs:   "policy",
//   })
import * as opa from "../services/opaClient.js";
import * as audit from "../services/audit.js";
import * as platformKeys from "../services/platformKeys.js";
import * as store from "../services/storage.js";

export function authorize(action, resourceType, opts = {}) {
  return async function authorizeMiddleware(req, res, next) {
    if (!req.user) {
      return res.status(401).json({ error: "Authentication required" });
    }
    const resource = { type: resourceType };
    const idParam = opts.resourceIdParam || "id";
    const id = typeof opts.resourceId === "function"
      ? opts.resourceId(req)
      : req.params?.[idParam];
    if (id !== undefined && id !== null) resource.id = id;

    // Load the row's org_id when this resource type supports org scoping
    // and an id is present. studio_authz uses input.resource.org_id (or
    // is_global) to enforce cross-org isolation; without this lookup,
    // non-root callers would match the "no specific org context" path
    // and bypass the check. Resource types without org scoping
    // (audit, password, evaluation, template, platform_key) return null
    // here and skip the dispatch.
    if (id !== undefined && id !== null) {
      try {
        const lookupType = opts.lookupAs || resourceType;
        const info = await store.getResourceOrgInfo(lookupType, id);
        if (info && info.found) {
          if (info.orgId === null) {
            resource.is_global = true;
          } else {
            resource.org_id = info.orgId;
          }
        }
        // info.found === false → row doesn't exist; let the route 404.
        // OPA still evaluates with no org info, so root sees the same
        // "allow" it always would; non-root falls into the "no org
        // context" branch which is acceptable for a non-existent row
        // (the route handler returns 404 next).
      } catch (e) {
        console.error(
          `[authorize] org-info lookup failed for ${resourceType}/${id}: ${e.message}`
        );
        return res.status(503).json({
          error: "Authorization preflight failed",
          detail: "Could not load resource ownership for the authz decision.",
        });
      }
    }

    // Target org for create actions. The resolver typically reads
    // req.body.orgId; if it returns null/undefined the middleware just
    // doesn't set target_org_id and OPA falls into the "no org context"
    // path (acceptable for root and for sub-admin self-targeted creates
    // that the route handler will further constrain).
    if (typeof opts.targetOrgId === "function") {
      const targetOrg = opts.targetOrgId(req);
      if (targetOrg !== undefined && targetOrg !== null) {
        resource.target_org_id = targetOrg;
      }
    }

    // Integrity signals. Read endpoints don't require any of them to be ok,
    // but studio.authz expects them in input so it can decide per-action.
    let auditStatus;
    try {
      auditStatus = await audit.headIsValid();
    } catch (e) {
      console.error(`[authorize] audit.headIsValid failed: ${e.message}`);
      auditStatus = { ok: false, reason: `audit check failed: ${e.message}` };
    }
    const trustStatus = platformKeys.isTrustOk();
    const opaTrust = trustStatus.opaOk
      ? { ok: true }
      : { ok: false, reason: trustStatus.opaReason || "opa trust broken" };
    const jwtSigner = trustStatus.sessionOk
      ? { ok: true }
      : { ok: false, reason: trustStatus.sessionReason || "session signer broken" };

    let decision;
    try {
      decision = await opa.authorize({
        user: {
          id: req.user.id,
          username: req.user.username,
          role: req.user.role,
          role_name: req.user.roleName ?? null,
          org_id: req.user.orgId ?? null,
          role_id: req.user.roleId ?? null,
          is_root: !!req.user.isRoot,
          permissions: req.user.permissions || {},
          disabled: false, // authenticate middleware already 401s disabled users
        },
        action,
        resource,
        audit: auditStatus,
        opaTrust,
        jwtSigner,
      });
    } catch (e) {
      console.error(`[authorize] OPA call failed: ${e.message}`);
      return res.status(503).json({
        error: "Authorization service unavailable",
        detail: "Could not reach OPA to evaluate studio.authz.",
      });
    }

    if (!decision.allow) {
      return res.status(403).json({
        error: "Forbidden",
        action,
        resource: resource.type,
        reason: decision.reason,
      });
    }
    next();
  };
}
