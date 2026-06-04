// server.js — Express HTTP API for the policy studio.
//
// `express-async-errors` MUST be imported before express itself: the package
// is a side-effect module that monkey-patches express 4's Layer.handle_request
// so async route handlers' rejected promises are forwarded to the terminal
// error-handling middleware (registered just before app.listen). Without it,
// throwing inside an `async (req, res) => {...}` handler — which happens
// e.g. when Vault is sealed and audit.appendAudit throws — closes the TCP
// connection with no response body.
import "express-async-errors";
import { randomUUID, randomBytes, createPublicKey, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import express from "express";
import cors from "cors";

import { compile, validate } from "./services/regoCompiler.js";
import * as opa from "./services/opaClient.js";
import * as opaBundle from "./services/opaBundle.js";
import * as store from "./services/storage.js";
import * as auth from "./services/auth.js";
import * as bootstrap from "./services/bootstrap.js";
import * as audit from "./services/audit.js";
import * as platformKeys from "./services/platformKeys.js";
import { startJwksFetcher } from "./services/jwksFetcher.js";
import { createTrustKeysRouter } from "./routes/trustKeys.js";
import { createPepCallersRouter } from "./routes/pepCallers.js";
import { createCallerAccessRouter } from "./routes/callerAccess.js";
import { createPolicyCallersRouter } from "./routes/policyCallers.js";
import { createPlatformKeysRouter } from "./routes/platformKeys.js";
import { createOrgsRouter } from "./routes/orgs.js";
import { createRolesRouter } from "./routes/roles.js";
import { authenticate } from "./middleware/authenticate.js";
import { authorize } from "./middleware/authorize.js";
// getPolicyVersions and getPolicyVersion are accessed via store.*
import { templates as daTemplates, sampleInputs as daInputs } from "./templates/digitalAssets.js";
import { templates as mtTemplates, sampleInputs as mtInputs } from "./templates/saasMultitenant.js";
import { templates as chTemplates, sampleInputs as chInputs } from "./templates/custodyHierarchy.js";
import { templates as taTemplates, sampleInputs as taInputs } from "./templates/trustedAuth.js";

const templates = [...daTemplates, ...mtTemplates, ...chTemplates, ...taTemplates];
const sampleInputs = { ...daInputs, ...mtInputs, ...chInputs, ...taInputs };

const app = express();
app.set("trust proxy", 1);
app.use(cors());
app.use(express.json({ limit: "1mb" }));

function generatePassword() {
  return randomBytes(18).toString("base64url");
}

function validateNewPassword(newPassword, { username, currentPassword } = {}) {
  if (typeof newPassword !== "string" || newPassword.length < 12) {
    return "New password must be at least 12 characters";
  }
  if (username && newPassword.toLowerCase() === username.toLowerCase()) {
    return "New password must not equal the username";
  }
  if (currentPassword && newPassword === currentPassword) {
    return "New password must differ from the current password";
  }
  return null;
}

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function isUuid(s) {
  return typeof s === "string" && UUID_RE.test(s);
}

const PORT = process.env.PORT || 3001;

// Flipped true at the end of the boot sequence. The container healthcheck
// (GET /healthz) gates on it so OPA — which now depends_on the backend and
// pulls its bundle from us — doesn't start before we can serve one.
let _ready = false;

// ─── Health ────────────────────────────────────────────────────────────────
app.get("/api/health", async (_req, res) => {
  const opaHealth = await opa.health();
  res.json({ ok: true, opa: opaHealth });
});

// Container readiness probe (machine-to-machine, unauthenticated). 200 once
// boot (schema + KMS + platform keys + initial bundle warm) has completed.
app.get("/healthz", (_req, res) => {
  res.status(_ready ? 200 : 503).json({ ready: _ready });
});

// ─── OPA bundle endpoint (machine-to-machine; bearer-authed) ────────────────
// Every OPA replica polls this to pull the policy/data bundle (see
// services/opaBundle.js). It replaces the old push model so a fleet of
// stateless OPA replicas all converge to the same revision.
//
// SECURITY: the bundle carries cleartext HMAC secrets (caller + trust-key
// secrets). This endpoint is therefore bearer-authed with a constant-time
// compare and MUST stay on the internal network — it is mounted before
// app.use(authenticate) (the puller is OPA, not a user) and must NEVER be
// proxied through nginx. Fail-closed: with no token configured we refuse.
const BUNDLE_TOKEN = (() => {
  const f = process.env.BUNDLE_TOKEN_FILE;
  if (f) {
    try {
      return readFileSync(f, "utf8").trim();
    } catch (e) {
      console.error(`[opa-bundle] could not read BUNDLE_TOKEN_FILE ${f}: ${e.message}`);
    }
  }
  if (process.env.BUNDLE_TOKEN) return process.env.BUNDLE_TOKEN.trim();
  return null;
})();

function bundleAuthOk(req) {
  if (!BUNDLE_TOKEN) return false;
  const m = /^Bearer\s+(.+)$/i.exec(req.get("authorization") || "");
  if (!m) return false;
  const presented = Buffer.from(m[1].trim(), "utf8");
  const expected = Buffer.from(BUNDLE_TOKEN, "utf8");
  // timingSafeEqual requires equal lengths; bail (still constant-ish) if not.
  if (presented.length !== expected.length) return false;
  return timingSafeEqual(presented, expected);
}

app.get("/bundle/aegis.tar.gz", async (req, res) => {
  if (!BUNDLE_TOKEN) {
    return res.status(503).json({ error: "bundle endpoint not configured (no BUNDLE_TOKEN)" });
  }
  if (!bundleAuthOk(req)) {
    res.set("WWW-Authenticate", "Bearer");
    return res.status(401).json({ error: "unauthorized" });
  }
  let bundle;
  try {
    bundle = await opaBundle.getBundle();
  } catch (e) {
    console.error(`[opa-bundle] build failed: ${e.message}`);
    return res.status(500).json({ error: "bundle build failed" });
  }
  const etag = `"${bundle.revision}"`;
  res.set("ETag", etag);
  res.set("Cache-Control", "no-store");
  // OPA sends If-None-Match once it holds a revision; 304 skips re-download.
  if ((req.get("if-none-match") || "") === etag) {
    return res.status(304).end();
  }
  res.set("Content-Type", "application/gzip");
  res.status(200).send(bundle.tarGz);
});

// Public JWKS exposing the platform Ed25519 signing keys:
//   - the audit chain key (for downstream verification of audit attestations)
//   - the session-signing key (so the frontend or any verifier can validate
//     EdDSA-signed session JWTs offline)
//   - the opa-auth-signing key (so external auditors can verify the JWTs
//     the backend sends to OPA)
// PEP-01 callers in jwt mode also fetch this endpoint. No authentication:
// only public material is returned. Returns 503 when the audit signing key
// has not been loaded yet (e.g. KMS unreachable).
app.get("/.well-known/jwks.json", async (_req, res) => {
  const der = audit.getSigningPubkeyDer();
  const fp = audit.getSigningKeyFingerprint();
  if (!der || !fp) {
    return res.status(503).json({ error: "audit signing key not loaded" });
  }
  try {
    const keys = [];
    const auditKey = createPublicKey({ key: der, format: "der", type: "spki" });
    keys.push({
      ...auditKey.export({ format: "jwk" }),
      alg: "EdDSA",
      use: "sig",
      kid: fp.toString("hex"),
    });
    const sessionJwk = platformKeys.getSessionSigningPublicJwk();
    if (sessionJwk) keys.push(sessionJwk);
    for (const purpose of ["opa-auth-signing", "pep-opa-auth-signing"]) {
      const meta = platformKeys.getActivePurposeMeta(purpose);
      if (!meta) continue;
      const ko = platformKeys.pubkeyForKid(meta.fpHex);
      if (!ko) continue;
      keys.push({
        ...ko.export({ format: "jwk" }),
        alg: "EdDSA",
        use: "sig",
        kid: meta.fpHex,
      });
    }
    res.json({ keys });
  } catch (e) {
    res.status(500).json({ error: `jwk export failed: ${e.message}` });
  }
});

// ─── Auth — public login ───────────────────────────────────────────────────
// Mounted BEFORE app.use(authenticate). Always runs a bcrypt compare (against
// a dummy hash on user-miss) to keep timing constant and avoid user enumeration.
app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== "string" || typeof password !== "string") {
    return res.status(400).json({ error: "username and password are required" });
  }
  const row = await store.getUserByUsernameWithHash(username);
  let ok = false;
  if (!row || row.disabled) {
    await auth.constantTimeMissCompare(password);
  } else {
    ok = await auth.verifyPassword(password, row.password_hash);
  }
  if (!row || row.disabled || !ok) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  await store.touchUserLogin(row.id);
  // Resolve the full auth context (org, role_id, is_root, permissions)
  // so both the JWT and the login response carry it. The frontend reads
  // the response payload for first-paint UI gating; subsequent screens
  // can refresh via /api/auth/me.
  const ctx = await store.getUserAuthContext(row.id);
  const token = await auth.signToken(ctx);
  res.json({
    token,
    user: {
      id: ctx.id,
      username: ctx.username,
      email: ctx.email,
      role: ctx.role,
      orgId: ctx.orgId,
      roleId: ctx.roleId,
      roleName: ctx.roleName,
      isRoot: ctx.isRoot,
      permissions: ctx.permissions,
      mustChangePassword: ctx.mustChangePassword,
      lastLoginAt: ctx.lastLoginAt,
    },
  });
});

// ─── Authenticated zone ────────────────────────────────────────────────────
// Everything after this line requires a valid Bearer token (except the public
// paths whitelisted inside the middleware).
app.use(authenticate);

// ─── Auth — authenticated ──────────────────────────────────────────────────
app.get("/api/auth/me", async (req, res) => {
  // Always return a fresh copy from the DB so role/permissions/disabled
  // reflect the current state — the JWT may be stale if the actor's role
  // was rotated since login. The frontend uses this to refresh the
  // permission map for live UI gating without forcing a re-login.
  const ctx = await store.getUserAuthContext(req.user.id);
  if (!ctx) return res.status(401).json({ error: "User no longer exists" });
  res.json({
    user: {
      id: ctx.id,
      username: ctx.username,
      email: ctx.email,
      role: ctx.role,
      orgId: ctx.orgId,
      roleId: ctx.roleId,
      roleName: ctx.roleName,
      isRoot: ctx.isRoot,
      permissions: ctx.permissions,
      mustChangePassword: ctx.mustChangePassword,
      lastLoginAt: ctx.lastLoginAt,
    },
  });
});

app.post(
  "/api/auth/change-password",
  authorize("update", "password", { resourceId: (req) => req.user.id }),
  async (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (typeof currentPassword !== "string" || typeof newPassword !== "string") {
    return res.status(400).json({ error: "currentPassword and newPassword are required" });
  }
  const fresh = await store.getUserById(req.user.id);
  if (!fresh) return res.status(401).json({ error: "User no longer exists" });

  const ok = await auth.verifyPassword(currentPassword, fresh.passwordHash);
  if (!ok) return res.status(400).json({ error: "Current password is incorrect" });

  const reason = validateNewPassword(newPassword, {
    username: fresh.username,
    currentPassword,
  });
  if (reason) return res.status(400).json({ error: reason });

  const wasBootstrappedAdmin = fresh.mustChangePassword && fresh.role === "admin";
  const newHash = await auth.hashPassword(newPassword);

  await store.withAudit(req.user, {
    action: "user.password.change",
    resourceType: "user",
    resourceId: req.user.id,
    beforeFetcher: async (c) => {
      const r = await store.getUserByIdTx(c, req.user.id);
      return store.userRowForAudit(r);
    },
  }, async (client) => {
    const updated = await store.updateUserPasswordTx(
      client, req.user.id, newHash, false
    );
    return {
      response: { ok: true },
      auditAfter: store.userRowForAudit(updated),
    };
  });

  if (wasBootstrappedAdmin) {
    bootstrap.deleteInitialAdminPasswordFile();
  }
  res.json({ ok: true });
  }
);

app.post("/api/auth/logout", (_req, res) => {
  // Stateless JWT — client drops the token. Endpoint exists as a stable hook.
  res.status(204).end();
});

// ─── Users — admin only ────────────────────────────────────────────────────
// Authorization is delegated to OPA's studio.authz policy. The default
// policy grants the admin role full CRUD on the `user` resource.
app.get("/api/users", authorize("read", "user"), async (req, res) => {
  const users = await store.listUsers(req.user);
  res.json(users);
});

app.post("/api/users", authorize("create", "user", {
  // The OPA rule compares target_org_id with actor.org_id. Root bypasses;
  // non-root creators are confined to their own org via this resolver
  // even if they try to set body.orgId — see the override below.
  targetOrgId: (req) => {
    if (req.user?.isRoot) return req.body?.orgId ?? req.user?.orgId;
    return req.user?.orgId;
  },
}), async (req, res) => {
  const body = req.body || {};
  const username = typeof body.username === "string" ? body.username.trim() : "";
  const email = typeof body.email === "string" && body.email.length > 0 ? body.email : null;
  if (!username) {
    return res.status(400).json({ error: "username is required" });
  }
  if (typeof body.roleId !== "string" || body.roleId.length === 0) {
    return res.status(400).json({ error: "roleId is required" });
  }

  // Effective scope. Non-root callers ALWAYS create users in their own
  // org regardless of body; root may pass body.orgId to target any org
  // (defaults to root's own platform org). isRoot is root-only.
  const effectiveOrgId = req.user.isRoot
    ? (body.orgId ?? req.user.orgId ?? null)
    : req.user.orgId;
  if (!effectiveOrgId) {
    return res.status(400).json({
      error: "orgId is required (non-root caller has no org and none provided)",
    });
  }
  const effectiveIsRoot = req.user.isRoot ? !!body.isRoot : false;

  // Validate the role exists AND is visible to this caller (root sees
  // every role; non-root only sees globals + their own org's locals).
  const role = await store.getRoleById(body.roleId);
  if (!role) {
    return res.status(400).json({ error: "roleId does not match any role" });
  }
  if (!req.user.isRoot) {
    if (role.orgId !== null && role.orgId !== req.user.orgId) {
      return res.status(403).json({ error: "roleId is in another org" });
    }
  }
  // Cross-check: assigning the built-in `root` role implies is_root=true.
  // We don't auto-set; we just require the caller to be explicit so the
  // audit row captures intent.
  if (role.name === "root" && !effectiveIsRoot) {
    return res.status(400).json({
      error: "assigning the root role requires isRoot=true",
    });
  }
  if (effectiveIsRoot && !req.user.isRoot) {
    // Defense in depth — the body block above already forces isRoot=false
    // for non-root callers, so this is unreachable.
    return res.status(403).json({ error: "only root may create root users" });
  }

  // Validate org exists (best-effort; FK would catch it but a 400 here
  // is friendlier than a 500 from the constraint).
  const targetOrg = await store.getOrgById(effectiveOrgId);
  if (!targetOrg) {
    return res.status(400).json({ error: "orgId does not match any org" });
  }

  let plain = body.password;
  let generated = false;
  if (typeof plain !== "string" || plain.length === 0) {
    plain = generatePassword();
    generated = true;
  } else {
    const reason = validateNewPassword(plain, { username });
    if (reason) return res.status(400).json({ error: reason });
  }

  try {
    const passwordHash = await auth.hashPassword(plain);
    const user = await store.withAudit(req.user, {
      action: "user.create",
      resourceType: "user",
    }, async (client) => {
      const row = await store.createUserTx(client, {
        username,
        email,
        passwordHash,
        role: role.name,                   // legacy display column
        roleId: role.id,                   // authoritative RBAC link
        orgId: effectiveOrgId,
        isRoot: effectiveIsRoot,
        mustChangePassword: true,
      });
      const safe = store.userRowForAudit(row);
      return { response: safe, auditAfter: safe };
    });
    res.status(201).json({
      user,
      generatedPassword: generated ? plain : undefined,
    });
  } catch (e) {
    if (/duplicate key/i.test(e.message || "")) {
      return res.status(409).json({ error: "username or email already exists" });
    }
    throw e;
  }
});

app.put("/api/users/:id", authorize("update", "user"), async (req, res) => {
  const { role, disabled } = req.body || {};
  const target = await store.getUserById(req.params.id);
  if (!target) return res.status(404).json({ error: "User not found" });

  if (target.id === req.user.id && (role !== undefined || disabled === true)) {
    return res.status(400).json({ error: "You cannot modify your own role or disable yourself" });
  }
  if (role !== undefined && role !== "admin") {
    return res.status(400).json({ error: "Only the 'admin' role is supported in v1" });
  }
  if (disabled === true && target.role === "admin") {
    const admins = await store.countAdmins();
    if (admins <= 1) {
      return res.status(400).json({ error: "Cannot disable the last active admin" });
    }
  }

  const fresh = await store.withAudit(req.user, {
    action: "user.update",
    resourceType: "user",
    resourceId: target.id,
    beforeFetcher: async (c) =>
      store.userRowForAudit(await store.getUserByIdTx(c, target.id)),
  }, async (client) => {
    let row = null;
    if (role !== undefined) row = await store.updateUserRoleTx(client, target.id, role);
    if (disabled !== undefined) row = await store.setUserDisabledTx(client, target.id, !!disabled);
    if (!row) row = await store.getUserByIdTx(client, target.id);
    const safe = store.userRowForAudit(row);
    return { response: safe, auditAfter: safe };
  });
  res.json({ user: fresh });
});

app.post("/api/users/:id/reset-password", authorize("update", "user"), async (req, res) => {
  const target = await store.getUserById(req.params.id);
  if (!target) return res.status(404).json({ error: "User not found" });

  let plain = req.body?.newPassword;
  let generated = false;
  if (typeof plain !== "string" || plain.length === 0) {
    plain = generatePassword();
    generated = true;
  } else {
    const reason = validateNewPassword(plain, { username: target.username });
    if (reason) return res.status(400).json({ error: reason });
  }
  const newHash = await auth.hashPassword(plain);
  await store.withAudit(req.user, {
    action: "user.password.reset",
    resourceType: "user",
    resourceId: target.id,
    beforeFetcher: async (c) =>
      store.userRowForAudit(await store.getUserByIdTx(c, target.id)),
  }, async (client) => {
    const row = await store.updateUserPasswordTx(client, target.id, newHash, true);
    const safe = store.userRowForAudit(row);
    return { response: { ok: true }, auditAfter: safe };
  });
  res.json({ ok: true, generatedPassword: generated ? plain : undefined });
});

app.delete("/api/users/:id", authorize("delete", "user"), async (req, res) => {
  const target = await store.getUserById(req.params.id);
  if (!target) return res.json({ ok: true, existed: false });

  if (target.id === req.user.id) {
    return res.status(400).json({ error: "You cannot delete yourself" });
  }
  if (target.role === "admin") {
    const admins = await store.countAdmins();
    if (admins <= 1) {
      return res.status(400).json({ error: "Cannot delete the last active admin" });
    }
  }
  const result = await store.withAudit(req.user, {
    action: "user.delete",
    resourceType: "user",
    resourceId: target.id,
    beforeFetcher: async (c) =>
      store.userRowForAudit(await store.getUserByIdTx(c, target.id)),
  }, async (client) => {
    const row = await store.deleteUserTx(client, target.id);
    return {
      response: { ok: true, existed: !!row },
      auditAfter: null,
    };
  });
  res.json(result);
});

// ─── Audit log ─────────────────────────────────────────────────────────────
// Read-only. Visible to admins (gated by studio.authz). Always works even
// when the chain is broken, so an operator can investigate.

function serializeAuditEntry(entry) {
  if (!entry) return null;
  return {
    seq: entry.seq,
    prevHashHex: entry.prevHash ? entry.prevHash.toString("hex") : null,
    entryHashHex: entry.entryHash.toString("hex"),
    payload: entry.payload,
    payloadCanonical: entry.payloadCanonical,
    signatureB64: entry.signature.toString("base64"),
    signingKeyFpHex: entry.signingKeyFp.toString("hex"),
    actorId: entry.actorId,
    actorUsername: entry.actorUsername,
    actorOrgId: entry.actorOrgId ?? null,
    action: entry.action,
    resourceType: entry.resourceType,
    resourceId: entry.resourceId,
    createdAt: entry.createdAt,
  };
}

app.get("/api/audit", authorize("read", "audit"), async (req, res) => {
  const limit = Math.max(1, Math.min(500, parseInt(req.query.limit, 10) || 50));
  const beforeSeq = req.query.beforeSeq != null
    ? parseInt(req.query.beforeSeq, 10)
    : undefined;
  const action = typeof req.query.action === "string" ? req.query.action : undefined;
  const resourceId = typeof req.query.resourceId === "string" ? req.query.resourceId : undefined;
  const entries = await store.listAudit({ limit, beforeSeq, action, resourceId, actor: req.user });
  const head = await store.getAuditHead();
  const status = await audit.headIsValid();
  res.json({
    head: head ? { seq: head.seq, hashHex: head.hash.toString("hex") } : null,
    chainStatus: status,
    entries: entries.map(serializeAuditEntry),
  });
});

app.get("/api/audit/verify", authorize("read", "audit"), async (_req, res) => {
  const result = await audit.verifyFullChain();
  res.json(result);
});

app.get("/api/audit/pubkey", async (_req, res) => {
  const der = audit.getSigningPubkeyDer();
  const fp = audit.getSigningKeyFingerprint();
  if (!der || !fp) {
    return res.status(503).json({ error: "audit signing key not loaded" });
  }
  res.json({
    algorithm: "ed25519",
    pubkeyDerB64: der.toString("base64"),
    fingerprintHex: fp.toString("hex"),
  });
});

app.get("/api/audit/:seq", authorize("read", "audit"), async (req, res) => {
  const seq = parseInt(req.params.seq, 10);
  if (!Number.isFinite(seq) || seq < 1) {
    return res.status(400).json({ error: "Invalid seq" });
  }
  const entry = await store.getAuditEntry(seq);
  if (!entry) return res.status(404).json({ error: "Not found" });
  res.json(serializeAuditEntry(entry));
});

// ─── Templates ─────────────────────────────────────────────────────────────
app.get("/api/templates", (_req, res) => {
  res.json(
    templates.map((t) => ({
      id: t.id,
      name: t.name,
      category: t.category,
      description: t.description,
      package: t.package,
    }))
  );
});

app.get("/api/templates/:id", (req, res) => {
  const t = templates.find((x) => x.id === req.params.id);
  if (!t) return res.status(404).json({ error: "Template not found" });
  res.json({ template: t, sampleInput: sampleInputs[t.id] || {} });
});

// ─── Compile (no-op preview, doesn't persist) ──────────────────────────────
app.post("/api/compile", (req, res) => {
  const spec = req.body;
  const v = validate(spec);
  if (!v.valid) return res.status(400).json({ error: "Validation failed", details: v.errors });
  try {
    const rego = compile(spec);
    res.json({ rego });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// ─── Validate ──────────────────────────────────────────────────────────────
app.post("/api/validate", (req, res) => {
  const v = validate(req.body);
  res.json(v);
});

// ─── Policies CRUD ─────────────────────────────────────────────────────────
app.get("/api/policies", async (req, res) => {
  const all = await store.listPolicies(req.user);
  res.json(all);
});

app.get("/api/policies/:id", async (req, res) => {
  if (!isUuid(req.params.id)) return res.status(400).json({ error: "Invalid policy id" });
  // Pass the actor so cross-org lookups return null → 404 (don't leak existence).
  const p = await store.getPolicy(req.params.id, req.user);
  if (!p) return res.status(404).json({ error: "Not found" });
  res.json(p);
});

app.get("/api/policies/:id/versions", async (req, res) => {
  if (!isUuid(req.params.id)) return res.status(400).json({ error: "Invalid policy id" });
  const versions = await store.getPolicyVersions(req.params.id);
  if (versions === null) return res.status(404).json({ error: "Not found" });
  res.json(versions);
});

app.get("/api/policies/:id/versions/:versionNum", async (req, res) => {
  if (!isUuid(req.params.id)) return res.status(400).json({ error: "Invalid policy id" });
  const versionNum = parseInt(req.params.versionNum, 10);
  if (Number.isNaN(versionNum)) return res.status(400).json({ error: "versionNum must be an integer" });
  const entry = await store.getPolicyVersion(req.params.id, versionNum);
  if (!entry) return res.status(404).json({ error: "Version not found" });
  res.json(entry);
});

// ─── OPA state distribution: bundle pull, not push ──────────────────────────
// Policies and data documents (policy_index / keys / callers / caller_access /
// platform_keys) are NO LONGER pushed to OPA. They are assembled into a bundle
// (services/opaBundle.js) that every OPA replica pulls from GET /bundle. A
// mutation just invalidates the cached bundle; the next poll rebuilds and the
// whole fleet converges. `invalidateBundle` is the single replacement for the
// old publish* functions and keeps the same fire-and-forget call shape.
const invalidateBundle = (reason) => opaBundle.invalidateBundle(reason);

// Bundle-safety probe: a compiled policy that OPA can't parse would, under
// bundle mode, fail activation of the WHOLE bundle (blast radius: the entire
// fleet stops updating). The JS compiler is the security boundary and is
// trusted to emit valid Rego, but we additionally probe each new/updated
// policy against the backend's live OPA by pushing a throwaway module under a
// reserved `__validate_` package (outside every bundle root, so the write is
// allowed) and deleting it. OPA actively rejecting it → 400 to the author so
// the bad module never reaches the DB or the bundle. OPA unreachable / 5xx →
// skip (don't block authoring; the bundle remains the source of truth).
async function assertRegoCompilesInOpa(spec) {
  const tempId = `__validate_${Date.now()}`;
  let tempRego;
  try {
    tempRego = compile({ ...spec, package: tempId });
  } catch {
    return; // JS compile error is handled by the caller's own compile() call
  }
  try {
    await opa.putPolicy(tempId, tempRego);
    await opa.deletePolicy(tempId).catch(() => {});
  } catch (e) {
    await opa.deletePolicy(tempId).catch(() => {});
    if (e.status && e.status >= 400 && e.status < 500) {
      const err = new Error(e.message);
      err.code = "OPA_REGO_REJECTED";
      err.body = e.body;
      throw err;
    }
    console.warn(`[policy] OPA validation probe skipped (${e.message})`);
  }
}

// Render the "policy is locked" 409 consistently for both POST and PUT paths.
function handlePolicyLockedError(e, res) {
  if (e?.code === "POLICY_LOCKED") {
    res.status(409).json({
      error: "Policy is locked",
      detail:
        "Unlock the policy via POST /api/policies/:id/unlock before modifying its content.",
    });
    return true;
  }
  return false;
}

app.post("/api/policies", authorize("create", "policy", {
  // Non-root creators are pinned to their own org. Root may pass body.orgId
  // to create a global (null) or any-org policy; otherwise it defaults to
  // the actor's own platform org.
  targetOrgId: (req) => {
    if (req.user?.isRoot) return req.body?.orgId ?? req.user?.orgId;
    return req.user?.orgId;
  },
}), async (req, res) => {
  const spec = { ...req.body, id: randomUUID() };
  if (!spec.package || !spec.name) {
    return res.status(400).json({ error: "Missing name or package" });
  }
  // Effective org_id: non-root forced to actor's org; root may opt for
  // null (global) by explicitly passing orgId=null in the body.
  const orgId = req.user.isRoot
    ? (Object.prototype.hasOwnProperty.call(req.body || {}, "orgId")
        ? req.body.orgId
        : (req.user.orgId ?? null))
    : req.user.orgId;
  if (!orgId && !req.user.isRoot) {
    return res.status(400).json({
      error: "non-root caller has no org assigned; cannot create policy",
    });
  }
  const v = validate(spec);
  if (!v.valid) return res.status(400).json({ error: "Validation failed", details: v.errors });

  let rego;
  try {
    rego = compile(spec);
  } catch (e) {
    return res.status(400).json({ error: `Compile failed: ${e.message}` });
  }

  // Probe the compiled Rego against OPA so a module OPA can't parse is
  // rejected here (400) rather than later bricking the whole bundle.
  try {
    await assertRegoCompilesInOpa(spec);
  } catch (e) {
    if (e.code === "OPA_REGO_REJECTED") {
      return res.status(400).json({
        error: `OPA rejected the policy: ${e.message}`,
        opaResponse: e.body,
      });
    }
    throw e;
  }

  let savedId;
  try {
    savedId = await store.withAudit(req.user, {
      action: "policy.create",
      resourceType: "policy",
      resourceId: spec.id,
    }, async (client) => {
      const { after } = await store.savePolicyTx(client, { ...spec, rego, orgId });
      return { response: after.id, auditAfter: after };
    });
  } catch (e) {
    if (handlePolicyLockedError(e, res)) return;
    throw e;
  }
  // Reload as the actor so the response respects the same scoping the
  // list endpoint would (root sees the row regardless; the org-admin
  // creator always sees their own org's row).
  const saved = await store.getPolicy(savedId, req.user);
  invalidateBundle("policy.create");
  res.json(saved);
});

app.put("/api/policies/:id", authorize("update", "policy"), async (req, res) => {
  if (!isUuid(req.params.id)) return res.status(400).json({ error: "Invalid policy id" });
  const spec = { ...req.body, id: req.params.id };
  const v = validate(spec);
  if (!v.valid) return res.status(400).json({ error: "Validation failed", details: v.errors });

  let rego;
  try {
    rego = compile(spec);
  } catch (e) {
    return res.status(400).json({ error: `Compile failed: ${e.message}` });
  }

  // Probe the compiled Rego against OPA (see create route) before persisting.
  try {
    await assertRegoCompilesInOpa(spec);
  } catch (e) {
    if (e.code === "OPA_REGO_REJECTED") {
      return res.status(400).json({
        error: `OPA rejected the policy: ${e.message}`,
        opaResponse: e.body,
      });
    }
    throw e;
  }

  let savedId;
  try {
    savedId = await store.withAudit(req.user, {
      action: "policy.update",
      resourceType: "policy",
      resourceId: spec.id,
      beforeFetcher: async (c) => {
        const r = await c.query(
          `SELECT id, name, package, description, rules, rego, version, locked, created_at, updated_at
             FROM policies WHERE id = $1`,
          [spec.id]
        );
        return store.policyRowForAudit(r.rows[0]);
      },
    }, async (client) => {
      const { after } = await store.savePolicyTx(client, { ...spec, rego });
      return { response: after.id, auditAfter: after };
    });
  } catch (e) {
    if (handlePolicyLockedError(e, res)) return;
    throw e;
  }
  const saved = await store.getPolicy(savedId);
  invalidateBundle("policy.update");
  res.json(saved);
});

// Lock / unlock — admins cannot delete policies; they lock or unlock instead.
// Both actions:
//   - bump the policy's version
//   - emit a policy_versions snapshot
//   - audit as policy.lock / policy.unlock
//   - rebuild the bundle: buildPolicyIndex / the bundle module list both drop
//     locked policies, so on the next OPA poll the locked policy stops being
//     served (default-deny) fleet-wide; unlock re-includes it.
// NOTE on propagation: under bundle pull, lock is EVENTUAL — it takes effect
// within one OPA poll interval (~10-20s) plus the PEP's own caller cache TTL,
// not instantly. A bundle-owned policy module cannot be REST-deleted from OPA
// (OPA owns bundle roots), so there is no instant per-replica kill-switch as
// there was under the push model; shorten the poll if a faster kill matters.
// Idempotent: relocking a locked policy or unlocking an unlocked policy
// returns the current state with version unchanged and no audit entry.
async function handleSetLocked(req, res, locked) {
  if (!isUuid(req.params.id)) return res.status(400).json({ error: "Invalid policy id" });

  const action = locked ? "policy.lock" : "policy.unlock";
  let result;
  try {
    result = await store.withAudit(req.user, {
      action,
      resourceType: "policy",
      resourceId: req.params.id,
      beforeFetcher: async (c) => {
        const r = await c.query(
          `SELECT id, name, package, description, rules, rego, version, locked, created_at, updated_at
             FROM policies WHERE id = $1`,
          [req.params.id]
        );
        return store.policyRowForAudit(r.rows[0]);
      },
    }, async (client) => {
      const { before, after, changed } = await store.setPolicyLockedTx(
        client, req.params.id, locked
      );
      if (!before) {
        // 404 path. Throw a sentinel that the caller turns into 404 — we
        // can't return the response from inside withAudit's fn cleanly.
        const err = new Error("not found");
        err.code = "POLICY_NOT_FOUND";
        throw err;
      }
      // If nothing changed, skip emitting an audit entry by throwing a
      // sentinel; the outer catch turns it into a normal response.
      if (!changed) {
        const err = new Error("no-op");
        err.code = "POLICY_LOCK_NOOP";
        err.policy = after;
        throw err;
      }
      return { response: after, auditAfter: after };
    });
  } catch (e) {
    if (e.code === "POLICY_NOT_FOUND") {
      return res.status(404).json({ error: "Policy not found" });
    }
    if (e.code === "POLICY_LOCK_NOOP") {
      return res.json(e.policy);
    }
    throw e;
  }

  // The audit entry committed; now reflect the change in the bundle. The
  // rebuild drops (lock) or restores (unlock) the policy module AND updates
  // policy_index + caller_access (both filter out locked policies), so the
  // PEP stops/starts admitting calls against it on the next poll.
  invalidateBundle(locked ? "policy.lock" : "policy.unlock");
  res.json(result);
}

app.post("/api/policies/:id/lock", authorize("update", "policy"), (req, res) => {
  return handleSetLocked(req, res, true);
});

app.post("/api/policies/:id/unlock", authorize("update", "policy"), (req, res) => {
  return handleSetLocked(req, res, false);
});

// PATCH /api/policies/:id/tags — admin-managed labels. Doesn't bump
// `policies.version` (tags are metadata, not part of the rule snapshot
// stored in policy_versions). Audit row carries the {add, remove} delta
// so a replay is unambiguous.
app.patch("/api/policies/:id/tags", authorize("update", "policy"), async (req, res) => {
  if (!isUuid(req.params.id)) {
    return res.status(400).json({ error: "Invalid policy id" });
  }
  const before = await store.getPolicy(req.params.id);
  if (!before) return res.status(404).json({ error: "policy not found" });

  const body = req.body || {};
  let add, remove, nextTags;
  try {
    add = store.normaliseTags(body.add ?? []);
    remove = store.normaliseTags(body.remove ?? []);
    nextTags = store.applyTagDelta(before.tags, { add, remove });
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }

  const result = await store.withAudit(req.user, {
    action: "policy.tags.update",
    resourceType: "policy",
    resourceId: req.params.id,
    beforeFetcher: async (_c) => ({ policyId: req.params.id, tags: before.tags }),
  }, async (client) => {
    const { after } = await store.updatePolicyTagsTx(client, req.params.id, nextTags);
    return {
      response: after,
      auditAfter: { policyId: req.params.id, add, remove, tags: nextTags },
    };
  });

  invalidateBundle("policy.tags.update");
  res.json({ id: req.params.id, tags: result?.tags ?? nextTags });
});

// All tags currently in use across policies + callers. Used for the
// chip-input autocomplete. No audit (read-only).
app.get("/api/tags", authorize("read", "policy"), async (_req, res) => {
  res.json({ tags: await store.listAllTags() });
});

// Hard-delete is intentionally NOT exposed. Admins lock policies instead so
// the audit chain retains the full content and history. We reject the verb
// up front so misbehaving clients see a clear 405 rather than a 404.
app.all("/api/policies/:id", (req, res, next) => {
  if (req.method === "DELETE") {
    return res.status(405).json({
      error: "Method Not Allowed",
      detail:
        "Policies cannot be deleted. Use POST /api/policies/:id/lock to deactivate.",
    });
  }
  next();
});

// ─── Trust keys (CRY-03) ───────────────────────────────────────────────────
// Admin-managed public-key trust store carried in the bundle at
// data.studio.keys. Policies reference it via verify conditions with
// keyRef.source="data.studio.keys". Mutations invalidate the bundle.
app.use("/api/trust-keys", createTrustKeysRouter({ publish: invalidateBundle }));

// ─── PEP callers (PEP-01) ──────────────────────────────────────────────────
// Admin-managed caller identities for the PEP's /authorize and /discover
// surfaces. Active rows are carried in the bundle at data.studio.callers; the
// PEP reads that doc on every request to authenticate the caller.
app.use("/api/pep-callers", createPepCallersRouter({
  publish: invalidateBundle,
  publishAccess: invalidateBundle,
}));

// ─── Caller access list (PEP ACL) ──────────────────────────────────────────
// Per-caller policy allowlist nested under each pep caller. Granted policies
// are carried in the bundle at data.studio.caller_access; the PEP enforces
// both /authorize and /discover against this document.
app.use(
  "/api/pep-callers/:callerId/access",
  createCallerAccessRouter({ publish: invalidateBundle })
);

// Reverse view of the same M:N relation, scoped to one policy. Shares the
// same audit actions and bundle invalidation as the caller-centric route.
app.use(
  "/api/policies/:policyId/access",
  createPolicyCallersRouter({ publish: invalidateBundle })
);

// ─── Platform signing keys ─────────────────────────────────────────────────
// Admin-managed lifecycle for the KMS-held keys that the backend uses to
// authenticate to OPA and sign session JWTs (plus the PEP's OPA-auth key).
// Rotation/revoke carry data.platform_keys in the bundle. NOTE: rotation is
// special — it must CONFIRM OPA has activated the new pubkey before flipping
// the active signer (the route handles this poll-aware sequence itself), so
// here we only wire bundle invalidation.
app.use("/api/platform-keys", createPlatformKeysRouter({ publish: invalidateBundle }));

app.use("/api/orgs",  createOrgsRouter());
app.use("/api/roles", createRolesRouter());

// ─── Evaluate (sandbox) ────────────────────────────────────────────────────
app.post("/api/evaluate/:id", async (req, res) => {
  const policyId = req.params.id;
  const { input, ruleName } = req.body || {};

  const p = await store.getPolicy(policyId);
  if (!p) return res.status(404).json({ error: "Policy not found" });

  const target = ruleName
    ? `${p.package}.${ruleName}`
    : p.package; // evaluate the whole package

  const start = Date.now();
  try {
    const result = await opa.evaluatePackage(target, input || {});
    const elapsed = Date.now() - start;
    res.json({ result, elapsedMs: elapsed, evaluatedPath: target });
  } catch (e) {
    res.status(500).json({ error: e.message, elapsedMs: Date.now() - start });
  }
});

// ─── Compile-and-eval (without persisting) — useful for live preview testing
app.post("/api/preview-evaluate", async (req, res) => {
  const { spec, input, ruleName } = req.body || {};
  const v = validate(spec);
  if (!v.valid) return res.status(400).json({ error: "Validation failed", details: v.errors });

  // Use a unique package name so the temp policy never conflicts with the
  // already-deployed version of the same policy in OPA. Duplicate default
  // declarations in the same package cause OPA to reject the module.
  const tempId = `__preview_${Date.now()}`;
  const tempPkg = tempId;
  let rego;
  try { rego = compile({ ...spec, package: tempPkg }); } catch (e) {
    return res.status(400).json({ error: `Compile failed: ${e.message}` });
  }

  try {
    await opa.putPolicy(tempId, rego);
    const target = ruleName ? `${tempPkg}.${ruleName}` : tempPkg;
    const result = await opa.evaluatePackage(target, input || {});
    await opa.deletePolicy(tempId);
    res.json({ result, rego });
  } catch (e) {
    await opa.deletePolicy(tempId).catch(() => {});
    res.status(400).json({ error: e.message });
  }
});

// ─── Seeding (idempotent) ──────────────────────────────────────────────────
async function seedTemplates() {
  const seeds = templates.map((t) => {
    let rego;
    try {
      rego = compile(t);
    } catch (e) {
      console.error(`Failed to compile template ${t.id}: ${e.message}`);
      return null;
    }
    return { ...t, slug: t.id, rego };
  }).filter(Boolean);

  // OPA push is handled by the restore block below, which uses DB UUIDs as
  // policy IDs. Pushing here with slug IDs would create duplicate modules.
  const added = await store.bulkSeed(seeds);
  console.log(`Seeded ${added} templates into storage`);
}

// ─── Terminal error handler ────────────────────────────────────────────────
// Runs last in the middleware chain. With express-async-errors imported at
// the top of this file, any throw or rejected promise from an async route
// (or async middleware) is forwarded here instead of becoming an unhandled
// rejection. The DB transaction was already rolled back by withAudit's
// catch block, so the audit chain stays intact; this middleware just turns
// the throw into a stable 500 JSON body for the client.
app.use((err, _req, res, _next) => {
  console.error(`[express] unhandled error: ${err?.stack || err?.message || err}`);
  if (res.headersSent) {
    res.destroy(err);
    return;
  }
  res.status(500).json({
    error: "Internal server error",
    detail: err?.message || "unknown",
  });
});

// Belt-and-suspenders: rejections that originate OUTSIDE a request lifecycle
// (e.g. fire-and-forget invalidateBundle calls, the JWKS background fetcher)
// wouldn't hit the express error middleware. Log and keep the process alive
// so the next request can succeed.
process.on("unhandledRejection", (err) => {
  console.error(`[unhandledRejection] ${err?.stack || err?.message || err}`);
});

// ─── Bootstrap ─────────────────────────────────────────────────────────────
app.listen(PORT, async () => {
  console.log(`Aegis Core (backend) listening on :${PORT}`);
  console.log(`OPA target: ${process.env.OPA_URL || "http://localhost:8181"}`);

  // 1. DB schema + KMS reconciliation + admin bootstrap run first so login
  //    works even if OPA is down. The audit signing key lives in the
  //    configured KMS provider (KMS_PROVIDER, default vault);
  //    audit.loadOrInitSigningKey() instantiates the provider, reconciles
  //    its active key with audit_signing_keys, and (for the vault provider
  //    on upgrade) migrates any legacy on-disk PEM into Vault via BYOK.
  //    Bootstrap then creates the admin row + genesis audit entry (signed
  //    via the KMS provider) on a fresh DB.
  try {
    await store.ensureSchema();
    await audit.loadOrInitSigningKey();
    if (!audit.isChainBroken()) {
      // Seed platform org + built-in roles, and promote any pre-RBAC
      // admins to is_root. Idempotent; safe to call before bootstrap on
      // both fresh and upgrade boots.
      await bootstrap.ensurePlatformDefaults();
      await bootstrap.bootstrapInitialAdmin();
    }
    if (audit.isChainBroken()) {
      console.error(
        `[startup] AUDIT CHAIN BROKEN: ${audit.getChainBrokenReason()}. ` +
          `Mutating routes will be denied until restored.`
      );
    } else {
      // Platform signing keys: reconcile KMS pubkeys against
      // platform_signing_keys; create rows on first sight; mark
      // per-purpose trust broken on fingerprint mismatch.
      await platformKeys.loadOrInitPlatformKeys();
      // (Pre-bundle builds cross-checked a boot-time /opa-trust/platform_keys.json
      // written by the opa-trust-init sidecar. That sidecar + file are gone —
      // platform_keys now travels in the bundle the backend builds from KMS+DB.
      // Live drift between the DB and what OPA serves is surfaced on demand by
      // GET /api/platform-keys/opa-state.)
      const trust = platformKeys.isTrustOk();
      if (!trust.ok) {
        console.error(
          `[startup] PLATFORM TRUST BROKEN: ` +
            Object.entries(trust.byPurpose)
              .filter(([, v]) => !v.ok)
              .map(([p, v]) => `${p}: ${v.reason}`)
              .join("; ")
        );
      }
    }
  } catch (e) {
    console.error("Schema / bootstrap failed:", e.message);
  }

  // 2. Seed templates (optional) and WARM the bundle. We no longer wait for
  //    OPA or push policies into it — under bundle pull, OPA depends_on this
  //    backend and pulls GET /bundle on its own. Warming the cache here means
  //    OPA's first poll gets an immediate 200 at the right revision rather
  //    than paying a cold-build latency spike.
  try {
    if (process.env.SEED_TEMPLATES === "true") {
      await seedTemplates();
    } else {
      console.log("Template seeding disabled (SEED_TEMPLATES != true). Skipping.");
    }
    try {
      const { revision } = await opaBundle.buildBundle();
      console.log(`[startup] OPA bundle warmed at revision ${revision.slice(0, 12)}`);
    } catch (e) {
      // Non-fatal: the bundle is lazily (re)built on the next GET /bundle.
      // OPA stays fail-closed (denies all) until it activates a bundle.
      console.error(`[startup] initial bundle build failed (will retry on poll): ${e.message}`);
    }
    // CRY-03: background poller for jwks_url-sourced trust keys. On a change
    // it invalidates the bundle so the refreshed key reaches OPA on the next
    // poll. The handle is not retained — unref() inside the fetcher keeps it
    // from holding the event loop open.
    const intervalMs = parseInt(process.env.TRUST_KEYS_FETCH_INTERVAL_MS, 10) || 30000;
    startJwksFetcher({ publish: invalidateBundle, intervalMs });
  } catch (e) {
    console.error("Seeding failed:", e.message);
  }

  // Boot complete — flip readiness so the container healthcheck (and thus
  // OPA's depends_on) goes green and OPA can start pulling the bundle.
  _ready = true;
});
