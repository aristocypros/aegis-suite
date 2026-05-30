// orgs.js — root-only CRUD on the orgs table.
//
// Orgs are managed exclusively by root. The default 'platform' org is
// seeded by bootstrap.ensurePlatformDefaults; everything else is created
// through this route. Non-root callers receive 403 via studio.authz (the
// `org` resource type isn't in any built-in permission map).
//
// Deletes are hard, but refused when the org still owns users, policies,
// trust keys, PEP callers, or custom roles — the route returns 409 with
// the blocker counts so an admin can clear them or reassign first. The
// audit chain preserves the history of every mutation regardless.
import { Router } from "express";
import * as store from "../services/storage.js";
import { authorize } from "../middleware/authorize.js";

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$/;
const SLUG_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;

function badRequest(res, msg) {
  return res.status(400).json({ error: msg });
}

export function createOrgsRouter() {
  const router = Router();

  router.get("/", authorize("read", "org"), async (req, res) => {
    // Non-root reads are denied at the OPA layer; root sees every row.
    const rows = await store.listOrgs();
    res.json(rows);
  });

  router.post("/", authorize("create", "org"), async (req, res) => {
    const body = req.body || {};
    const name = typeof body.name === "string" ? body.name.trim() : "";
    const slug = typeof body.slug === "string" ? body.slug.trim().toLowerCase() : "";
    if (!NAME_RE.test(name)) {
      return badRequest(res, "name must be 1-64 chars: [A-Za-z0-9 _.-]");
    }
    if (!SLUG_RE.test(slug)) {
      return badRequest(res, "slug must be 1-64 chars: lowercase [a-z0-9_-]");
    }
    try {
      const created = await store.withAudit(req.user, {
        action: "org.create",
        resourceType: "org",
      }, async (client) => {
        const existing = await store.getOrgBySlugTx(client, slug);
        if (existing) {
          const err = new Error(`org with slug '${slug}' already exists`);
          err.status = 409;
          throw err;
        }
        const row = await store.insertOrgTx(client, { name, slug });
        return { response: row, auditAfter: row };
      });
      res.status(201).json(created);
    } catch (e) {
      if (e.status === 409) return res.status(409).json({ error: e.message });
      if (/duplicate key/i.test(e.message || "")) {
        return res.status(409).json({ error: "org with that slug already exists" });
      }
      throw e;
    }
  });

  router.put("/:id", authorize("update", "org"), async (req, res) => {
    const id = req.params.id;
    const body = req.body || {};
    const name = body.name !== undefined ? String(body.name).trim() : undefined;
    const slug = body.slug !== undefined ? String(body.slug).trim().toLowerCase() : undefined;
    if (name !== undefined && !NAME_RE.test(name)) {
      return badRequest(res, "name must be 1-64 chars: [A-Za-z0-9 _.-]");
    }
    if (slug !== undefined && !SLUG_RE.test(slug)) {
      return badRequest(res, "slug must be 1-64 chars: lowercase [a-z0-9_-]");
    }
    if (name === undefined && slug === undefined) {
      return badRequest(res, "supply at least one of name or slug");
    }
    try {
      const updated = await store.withAudit(req.user, {
        action: "org.update",
        resourceType: "org",
        resourceId: id,
        beforeFetcher: (c) => store.getOrgByIdTx(c, id),
      }, async (client) => {
        const row = await store.updateOrgTx(client, id, { name, slug });
        if (!row) {
          const err = new Error("org not found");
          err.status = 404;
          throw err;
        }
        return { response: row, auditAfter: row };
      });
      res.json(updated);
    } catch (e) {
      if (e.status === 404) return res.status(404).json({ error: e.message });
      if (/duplicate key/i.test(e.message || "")) {
        return res.status(409).json({ error: "org with that slug already exists" });
      }
      throw e;
    }
  });

  router.delete("/:id", authorize("delete", "org"), async (req, res) => {
    const id = req.params.id;
    try {
      const outcome = await store.withAudit(req.user, {
        action: "org.delete",
        resourceType: "org",
        resourceId: id,
        beforeFetcher: (c) => store.getOrgByIdTx(c, id),
      }, async (client) => {
        const before = await store.getOrgByIdTx(client, id);
        if (!before) {
          const err = new Error("org not found");
          err.status = 404;
          throw err;
        }
        const result = await store.deleteOrgTx(client, id);
        if (!result.deleted) {
          const err = new Error("org has dependent rows; clear them first");
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
