// roles.js — RBAC role management.
//
// Three visibility classes:
//   - built-in (is_builtin=true, org_id NULL) — shipped by bootstrap,
//     visible to all, editable by NONE (root included; the seed is the
//     spec). Refused at the route layer with 409.
//   - global custom (is_builtin=false, org_id NULL) — root-only.
//   - org-local (org_id=<uuid>) — org admins within that org, plus root.
//
// Listing: non-root callers see global roles + their org's locals; root
// sees everything. studio.authz handles cross-org per-row enforcement on
// update/delete via the middleware's org_id preflight (resource type
// "role"). Create routes set the target_org_id resolver so a non-root
// caller cannot create a role in another org.
//
// Delete is hard, but refused if any user still has role_id pointing at
// it (storage returns blockers; route returns 409 with the count).
import { Router } from "express";
import * as store from "../services/storage.js";
import { authorize } from "../middleware/authorize.js";

// Built-in roles share the same name format; keep tight to avoid weird
// chars in JSON payloads or Rego-side string comparisons.
const ROLE_NAME_RE = /^[a-z][a-z0-9_]{1,63}$/;

// Recognized resource-type discriminators in studio.authz. We refuse
// permission keys outside this set so a typo can't silently grant
// nothing — better to 400.
const PERMISSION_RESOURCE_TYPES = new Set([
  "policy", "user", "trust_key", "pep_caller", "audit",
  "evaluation", "template", "password", "platform_key",
  "caller_access", "org", "role",
]);
// Same idea for actions. studio.authz uses these verbs in its grant rules.
const PERMISSION_ACTIONS = new Set([
  "read", "create", "update", "delete", "lock", "unlock",
  "revoke", "manage",
]);

function badRequest(res, msg) {
  return res.status(400).json({ error: msg });
}

// Insider-threat guard: refuse any role create/update where the proposed
// permission set contains an (action, resourceType) pair the actor's own
// role does not grant. Without this, an org_admin holding role:create or
// role:update could escalate by minting a new role with arbitrary perms
// (and later assigning it to themselves) or by widening an existing role
// they intend to grab. Root bypasses (already trusted, has all perms by
// is_root).
//
// Returns { ok: true } on success, { ok: false, missing: { resourceType,
// action } } on the first refused grant so the caller can show which
// specific permission was the problem.
function checkPermissionSubset(proposed, actor) {
  if (!proposed || actor?.isRoot) return { ok: true };
  for (const [resType, actions] of Object.entries(proposed)) {
    if (!Array.isArray(actions) || actions.length === 0) continue;
    const allowed = actor?.permissions?.[resType];
    if (!Array.isArray(allowed)) {
      return { ok: false, missing: { resourceType: resType, action: actions[0] } };
    }
    for (const action of actions) {
      if (!allowed.includes(action)) {
        return { ok: false, missing: { resourceType: resType, action } };
      }
    }
  }
  return { ok: true };
}

function validatePermissions(perms) {
  if (perms === undefined) return undefined; // not provided
  if (perms === null || typeof perms !== "object" || Array.isArray(perms)) {
    return { error: "permissions must be an object { resourceType: [action,...] }" };
  }
  const out = {};
  for (const [resType, actions] of Object.entries(perms)) {
    if (!PERMISSION_RESOURCE_TYPES.has(resType)) {
      return { error: `unknown resource type in permissions: ${resType}` };
    }
    if (!Array.isArray(actions)) {
      return { error: `permissions.${resType} must be an array of action strings` };
    }
    const seen = new Set();
    for (const a of actions) {
      if (typeof a !== "string" || !PERMISSION_ACTIONS.has(a)) {
        return { error: `unknown action in permissions.${resType}: ${a}` };
      }
      seen.add(a);
    }
    out[resType] = [...seen]; // de-duplicated, preserves insertion order
  }
  return { value: out };
}

export function createRolesRouter() {
  const router = Router();

  router.get("/", authorize("read", "role"), async (req, res) => {
    // Root → all roles. Non-root → globals + own org's locals.
    const orgScope = req.user.isRoot ? undefined : req.user.orgId;
    const rows = await store.listRoles({ orgId: orgScope });
    res.json(rows);
  });

  router.post("/", authorize("create", "role", {
    // Non-root callers may only create roles in their own org. Root may
    // pass orgId=null in the body to create a global custom role. The
    // OPA rule reads target_org_id; on null/undefined it falls into the
    // "no specific org context" branch (root passes via is_root bypass).
    targetOrgId: (req) => req.body?.orgId,
  }), async (req, res) => {
    const body = req.body || {};
    const name = typeof body.name === "string" ? body.name.trim() : "";
    if (!ROLE_NAME_RE.test(name)) {
      return badRequest(res, "name must match /^[a-z][a-z0-9_]{1,63}$/");
    }
    const description = typeof body.description === "string" ? body.description : "";
    const permsResult = validatePermissions(body.permissions);
    if (permsResult && permsResult.error) return badRequest(res, permsResult.error);

    // Self-escalation guard: the new role's permissions must be a subset
    // of the actor's own. Root bypasses inside the helper.
    if (permsResult) {
      const subset = checkPermissionSubset(permsResult.value, req.user);
      if (!subset.ok) {
        return res.status(403).json({
          error: "permissions would exceed your own role",
          code: "PERMISSION_ESCALATION_REFUSED",
          missing: subset.missing,
        });
      }
    }

    // Non-root callers always create in their own org regardless of body.
    let orgId;
    if (req.user.isRoot) {
      // Root may explicitly pass null/omit for a global role, or a uuid
      // for an org-local role.
      orgId = body.orgId === undefined ? null : body.orgId;
    } else {
      if (!req.user.orgId) {
        return res.status(403).json({ error: "non-root caller has no org assigned" });
      }
      orgId = req.user.orgId;
    }

    try {
      const created = await store.withAudit(req.user, {
        action: "role.create",
        resourceType: "role",
      }, async (client) => {
        const dup = await store.getRoleByNameTx(client, name, orgId);
        if (dup) {
          const err = new Error(`role '${name}' already exists in scope`);
          err.status = 409;
          throw err;
        }
        const row = await store.insertRoleTx(client, {
          orgId,
          name,
          description,
          permissions: permsResult ? permsResult.value : {},
          isBuiltin: false, // built-ins are only seeded by bootstrap
        });
        return { response: row, auditAfter: row };
      });
      res.status(201).json(created);
    } catch (e) {
      if (e.status === 409) return res.status(409).json({ error: e.message });
      if (/duplicate key/i.test(e.message || "")) {
        return res.status(409).json({ error: "role name already in use" });
      }
      throw e;
    }
  });

  router.put("/:id", authorize("update", "role"), async (req, res) => {
    const id = req.params.id;

    // Self-targeting guard: an actor cannot edit the role they currently
    // hold (even name/description). Root bypasses. Prevents the trivial
    // "narrow my role to nothing then re-widen" escalation path and keeps
    // the invariant easy to reason about: your own role is read-only to
    // you; another admin must change it.
    if (!req.user.isRoot && req.user.roleId === id) {
      return res.status(409).json({
        error: "you cannot edit the role you currently hold; ask another admin to update it",
        code: "SELF_ROLE_EDIT_REFUSED",
      });
    }

    const body = req.body || {};
    const name = body.name !== undefined ? String(body.name).trim() : undefined;
    const description = body.description !== undefined ? String(body.description) : undefined;
    const permsResult = validatePermissions(body.permissions);
    if (permsResult && permsResult.error) return badRequest(res, permsResult.error);

    if (name !== undefined && !ROLE_NAME_RE.test(name)) {
      return badRequest(res, "name must match /^[a-z][a-z0-9_]{1,63}$/");
    }
    if (name === undefined && description === undefined && permsResult === undefined) {
      return badRequest(res, "supply at least one of name, description, permissions");
    }

    try {
      const updated = await store.withAudit(req.user, {
        action: "role.update",
        resourceType: "role",
        resourceId: id,
        beforeFetcher: (c) => store.getRoleByIdTx(c, id),
      }, async (client) => {
        const before = await store.getRoleByIdTx(client, id);
        if (!before) {
          const err = new Error("role not found");
          err.status = 404;
          throw err;
        }
        if (before.isBuiltin) {
          const err = new Error("built-in roles cannot be edited; create a custom role instead");
          err.status = 409;
          throw err;
        }
        // Self-escalation guard on the proposed perms (only when supplied;
        // metadata-only edits skip this). Runs inside the txn so we've
        // already confirmed the role exists and is editable — failures
        // give the caller "not found → built-in → escalation" in that
        // order, which is the right disclosure ladder.
        if (permsResult) {
          const subset = checkPermissionSubset(permsResult.value, req.user);
          if (!subset.ok) {
            const err = new Error("permissions would exceed your own role");
            err.status = 403;
            err.code = "PERMISSION_ESCALATION_REFUSED";
            err.missing = subset.missing;
            throw err;
          }
        }
        const row = await store.updateRoleTx(client, id, {
          name,
          description,
          permissions: permsResult ? permsResult.value : undefined,
        });
        return { response: row, auditAfter: row };
      });
      res.json(updated);
    } catch (e) {
      if (e.status === 403 && e.code === "PERMISSION_ESCALATION_REFUSED") {
        return res.status(403).json({
          error: e.message,
          code: e.code,
          missing: e.missing,
        });
      }
      if (e.status === 404) return res.status(404).json({ error: e.message });
      if (e.status === 409) return res.status(409).json({ error: e.message });
      if (/duplicate key/i.test(e.message || "")) {
        return res.status(409).json({ error: "role name already in use in scope" });
      }
      throw e;
    }
  });

  router.delete("/:id", authorize("delete", "role"), async (req, res) => {
    const id = req.params.id;
    try {
      const outcome = await store.withAudit(req.user, {
        action: "role.delete",
        resourceType: "role",
        resourceId: id,
        beforeFetcher: (c) => store.getRoleByIdTx(c, id),
      }, async (client) => {
        const before = await store.getRoleByIdTx(client, id);
        if (!before) {
          const err = new Error("role not found");
          err.status = 404;
          throw err;
        }
        if (before.isBuiltin) {
          const err = new Error("built-in roles cannot be deleted");
          err.status = 409;
          throw err;
        }
        const result = await store.deleteRoleTx(client, id);
        if (!result.deleted) {
          const err = new Error("role is still assigned to users; reassign them first");
          err.status = 409;
          err.blockers = result.blockers;
          throw err;
        }
        return { response: { ok: true, deleted: before }, auditAfter: { deleted: before } };
      });
      res.json(outcome);
    } catch (e) {
      if (e.status === 404) return res.status(404).json({ error: e.message });
      if (e.status === 409) {
        return res.status(409).json({ error: e.message, blockers: e.blockers });
      }
      throw e;
    }
  });

  return router;
}
