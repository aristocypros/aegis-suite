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
import { randomUUID, randomBytes, createPublicKey } from "node:crypto";
import express from "express";
import cors from "cors";

import { compile, validate } from "./services/regoCompiler.js";
import * as opa from "./services/opaClient.js";
import * as store from "./services/storage.js";
import * as auth from "./services/auth.js";
import * as bootstrap from "./services/bootstrap.js";
import * as audit from "./services/audit.js";
import * as platformKeys from "./services/platformKeys.js";
import { buildPolicyIndex } from "./services/policyIndex.js";
import { publishValueFromRow } from "./services/trustKeys.js";
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

// ─── Health ────────────────────────────────────────────────────────────────
app.get("/api/health", async (_req, res) => {
  const opaHealth = await opa.health();
  res.json({ ok: true, opa: opaHealth });
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

// Publish the discovery index to OPA at data.studio.policy_index. Read by the
// PEP's /discover endpoint. Best-effort: a transient failure here does not
// fail the calling request — the next successful publish brings it back into
// sync (and the startup restore loop also republishes on every boot).
async function publishPolicyIndex(reason) {
  try {
    const all = await store.listPolicies();
    const index = buildPolicyIndex(all);
    await opa.putData("studio/policy_index", index);
    console.log(
      `[policy-index] published ${index.policies.length} active policies (${reason})`
    );
  } catch (e) {
    console.warn(`[policy-index] publish failed (${reason}): ${e.message}`);
  }
}

// CRY-03: publish the platform trust store to OPA at data.studio.keys. The
// compiler emits `data.studio.keys[kid]` directly as the cert: argument to
// io.jwt.decode_verify (asymmetric) or as the HMAC secret arg, so the
// document is a flat { [kid]: string } map of PEM/secret values. Revoked
// rows are dropped from the publish; the next successful re-publish takes
// effect on the next OPA evaluation. Same best-effort policy as
// publishPolicyIndex — transport errors are logged and the next call
// converges.
async function publishTrustKeys(reason) {
  try {
    const rows = await store.listTrustKeys();
    const out = {};
    let skipped = 0;
    for (const row of rows) {
      const v = publishValueFromRow(row);
      if (typeof v === "string" && v.length > 0) out[row.kid] = v;
      else if (row.status === "active") skipped++;
    }
    await opa.putData("studio/keys", out);
    const note = skipped > 0 ? ` (skipped ${skipped} unhydrated)` : "";
    console.log(`[trust-keys] published ${Object.keys(out).length} keys${note} (${reason})`);
  } catch (e) {
    console.warn(`[trust-keys] publish failed (${reason}): ${e.message}`);
  }
}

// PEP-01: publish the active PEP caller set to OPA at data.studio.callers.
// The PEP reads this document to authenticate inbound requests (caller_id
// lookup for hmac mode, CN allowlist for mtls, subject pin for jwt). Same
// best-effort policy as the other publishers — transport errors are logged
// and the next call converges; the startup restore loop republishes.
//
// Revoked rows are intentionally omitted: the PEP stops accepting them on
// the next publish (within ~30s), without needing to track per-row status.
async function publishPepCallers(reason) {
  try {
    const rows = await store.listPepCallers();
    const out = {};
    for (const r of rows) {
      if (r.status !== "active") continue;
      // auth_mode is the contract between the studio and the PEP dispatcher:
      // the PEP rejects a request whose presented credential kind disagrees
      // with the row's declared mode. We always emit it so the PEP never has
      // to infer the mode from which fields happen to be present.
      const entry = { auth_mode: r.authMode };
      if (r.authMode === "hmac" && r.hmacSecret) entry.hmac_secret = r.hmacSecret;
      if (r.authMode === "mtls" && r.allowedCn) entry.allowed_cn = r.allowedCn;
      if (r.authMode === "jwt" && r.jwtSubject) entry.jwt_subject = r.jwtSubject;
      if (r.tenant) entry.tenant = r.tenant;
      // org_id ties the caller to its org. The PEP uses this to filter
      // /discover results: a caller in org A only sees policies in org A
      // (or global policies with org_id=null). Always emitted so the PEP
      // doesn't have to default on missing-field semantics.
      entry.org_id = r.orgId ?? null;
      out[r.callerId] = entry;
    }
    await opa.putData("studio/callers", out);
    console.log(`[pep-callers] published ${Object.keys(out).length} callers (${reason})`);
  } catch (e) {
    console.warn(`[pep-callers] publish failed (${reason}): ${e.message}`);
  }
}

// Per-caller policy access list — the PEP filters /discover and rejects
// /authorize against this document. Shape: { [callerId]: [policyId, ...] }.
//
// The published allowlist is computed at publish time as the UNION of two
// sources, so the PEP only ever sees the final answer:
//
//   1) Explicit grants in pep_caller_policy_access (audit-logged).
//   2) Tag matches: every active policy whose `tags` overlap the caller's
//      `scope_tags`. New policies tagged later auto-appear in the caller's
//      allowlist on the next publish without an admin action.
//
// Locked policies are filtered out of BOTH sources so the published doc
// never advertises a policy the PEP can't currently service. Underlying
// DB rows stay; the next publish after unlock restores them.
async function publishCallerAccess(reason) {
  try {
    const [grants, policies, callers] = await Promise.all([
      store.listAllCallerAccess(),
      store.listPolicies(),
      store.listPepCallers(),
    ]);
    const activePolicyById = new Map(
      policies.filter((p) => !p.locked).map((p) => [p.id, p])
    );

    // Per-caller Set of granted policy ids — Set dedupes the overlap
    // between explicit grants and tag matches.
    const allowed = new Map();
    const explicitCount = new Map();
    const tagCount = new Map();
    function add(callerId, policyId, source) {
      let set = allowed.get(callerId);
      if (!set) { set = new Set(); allowed.set(callerId, set); }
      const newlyAdded = !set.has(policyId);
      set.add(policyId);
      if (newlyAdded || source === "explicit") {
        if (source === "explicit") {
          explicitCount.set(callerId, (explicitCount.get(callerId) ?? 0) + 1);
        } else {
          tagCount.set(callerId, (tagCount.get(callerId) ?? 0) + 1);
        }
      }
    }

    // 1) Explicit grants — drop any pointing at locked policies.
    for (const g of grants) {
      if (!activePolicyById.has(g.policyId)) continue;
      add(g.callerId, g.policyId, "explicit");
    }

    // 2) Tag matches — only for active callers with non-empty scope_tags.
    for (const c of callers) {
      if (c.status !== "active") continue;
      if (!c.scopeTags || c.scopeTags.length === 0) continue;
      const scope = new Set(c.scopeTags);
      for (const [pid, p] of activePolicyById) {
        if (!p.tags || p.tags.length === 0) continue;
        if (p.tags.some((t) => scope.has(t))) {
          add(c.callerId, pid, "tag");
        }
      }
    }

    const out = Object.fromEntries(
      [...allowed.entries()].map(([cid, set]) => [cid, [...set]])
    );
    await opa.putData("studio/caller_access", out);
    const totalGrants = Object.values(out).reduce((n, arr) => n + arr.length, 0);
    const explicitTotal = [...explicitCount.values()].reduce((a, b) => a + b, 0);
    const tagTotal = totalGrants - explicitTotal;
    console.log(
      `[caller-access] published ${Object.keys(out).length} caller scopes ` +
        `(${totalGrants} grants: ${explicitTotal} explicit, ${tagTotal} via tags) (${reason})`
    );
  } catch (e) {
    console.warn(`[caller-access] publish failed (${reason}): ${e.message}`);
  }
}

// Publish the active + retired platform signing keys to OPA at
// data.platform_keys. system_authz.rego reads this document to verify the
// JWTs the backend and PEP attach to every request. Same best-effort
// semantics as the other publishers: a transport failure here is logged
// and the next call (or startup restore) brings OPA back in sync.
async function publishPlatformKeys(reason) {
  try {
    const doc = await platformKeys.buildOpaPublishDocument();
    await opa.putData("platform_keys", doc);
    const counts = Object.entries(doc)
      .map(([p, m]) => `${p}=${Object.keys(m).length}`)
      .join(", ");
    console.log(`[platform-keys] published (${counts}) (${reason})`);
  } catch (e) {
    console.warn(`[platform-keys] publish failed (${reason}): ${e.message}`);
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

  try {
    await opa.putPolicy(spec.id, rego);
  } catch (e) {
    return res.status(400).json({
      error: `OPA rejected the policy: ${e.message}`,
      opaResponse: e.body,
    });
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
  publishPolicyIndex("policy.create");
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

  try {
    await opa.putPolicy(spec.id, rego);
  } catch (e) {
    return res.status(400).json({
      error: `OPA rejected the policy: ${e.message}`,
      opaResponse: e.body,
    });
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
  publishPolicyIndex("policy.update");
  res.json(saved);
});

// Lock / unlock — admins cannot delete policies; they lock or unlock instead.
// Both actions:
//   - bump the policy's version
//   - emit a policy_versions snapshot
//   - audit as policy.lock / policy.unlock
//   - mutate OPA: lock → opa.deletePolicy (module unloaded; default-deny);
//                 unlock → opa.putPolicy (module re-pushed; enforcement resumes)
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

  // The audit entry committed; now reflect the change in OPA.
  // OPA mutations happen AFTER the DB commit, so a transient OPA outage
  // doesn't poison the chain — the next backend boot's restore loop will
  // bring OPA back in sync (unless the policy is now locked, in which case
  // it's intentionally absent from OPA).
  if (locked) {
    await opa.deletePolicy(req.params.id).catch((e) => {
      console.warn(`[lock] OPA delete failed for ${req.params.id}: ${e.message}`);
    });
  } else if (result?.rego) {
    try {
      await opa.putPolicy(req.params.id, result.rego);
    } catch (e) {
      console.warn(`[unlock] OPA put failed for ${req.params.id}: ${e.message}`);
    }
  }
  publishPolicyIndex(locked ? "policy.lock" : "policy.unlock");
  // Locked policies are filtered out of the published caller_access doc so
  // the PEP stops admitting calls against them within the next refresh.
  publishCallerAccess(locked ? "policy.lock" : "policy.unlock");
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

  publishCallerAccess("policy.tags.update");
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
// Admin-managed public-key trust store published to OPA at data.studio.keys.
// Policies reference it via verify conditions with keyRef.source="data.studio.keys".
app.use("/api/trust-keys", createTrustKeysRouter({ publish: publishTrustKeys }));

// ─── PEP callers (PEP-01) ──────────────────────────────────────────────────
// Admin-managed caller identities for the PEP's /authorize and /discover
// surfaces. Active rows are published to OPA at data.studio.callers; the
// PEP reads that doc on every request to authenticate the caller.
app.use("/api/pep-callers", createPepCallersRouter({
  publish: publishPepCallers,
  publishAccess: publishCallerAccess,
}));

// ─── Caller access list (PEP ACL) ──────────────────────────────────────────
// Per-caller policy allowlist nested under each pep caller. Granted policies
// are published to OPA at data.studio.caller_access; the PEP enforces both
// /authorize and /discover against this document.
app.use(
  "/api/pep-callers/:callerId/access",
  createCallerAccessRouter({ publish: publishCallerAccess })
);

// Reverse view of the same M:N relation, scoped to one policy. Shares the
// same audit actions and publisher as the caller-centric route.
app.use(
  "/api/policies/:policyId/access",
  createPolicyCallersRouter({ publish: publishCallerAccess })
);

// ─── Platform signing keys ─────────────────────────────────────────────────
// Admin-managed lifecycle for the KMS-held keys that the backend uses to
// authenticate to OPA and sign session JWTs (plus the PEP's OPA-auth key).
// Rotation re-publishes data.platform_keys; revoke flips a retired row to
// revoked and re-publishes (dropping it from OPA's accepted set).
app.use("/api/platform-keys", createPlatformKeysRouter({ publish: publishPlatformKeys }));

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
// (e.g. fire-and-forget publishPolicyIndex calls, the startup OPA-restore
// loop) wouldn't hit the express error middleware. Log and keep the process
// alive so the next request can succeed.
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
      // Cross-check against the file OPA loaded at boot. Pure read; logs
      // any drift but doesn't fail startup — the data-publish loop below
      // will re-converge OPA's view after every restart.
      const trustFilePath =
        process.env.OPA_TRUST_FILE || "/opa-trust/platform_keys.json";
      try {
        const issues = await platformKeys.reconcileWithTrustFile(trustFilePath);
        if (issues.length) {
          console.warn(
            `[platform-keys] OPA trust file drift detected:\n  - ${issues.join("\n  - ")}`
          );
        }
      } catch (e) {
        console.warn(`[platform-keys] trust-file probe skipped: ${e.message}`);
      }
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

  // 2. Wait for OPA to be reachable.
  let tries = 0;
  while (tries < 30) {
    const h = await opa.health();
    if (h.ok) break;
    await new Promise((r) => setTimeout(r, 1000));
    tries++;
  }

  // 3. Seeding + restoring policies into OPA.
  try {
    if (process.env.SEED_TEMPLATES === "true") {
      await seedTemplates();
    } else {
      console.log("Template seeding disabled (SEED_TEMPLATES != true). Skipping.");
    }
    const stored = await store.listPolicies();
    let pushed = 0;
    let skippedLocked = 0;
    for (const p of stored) {
      if (p.locked) { skippedLocked++; continue; }
      if (p.rego) {
        try { await opa.putPolicy(p.id, p.rego); pushed++; }
        catch (e) { console.error(`Failed to restore ${p.id}: ${e.message}`); }
      }
    }
    console.log(
      `Restored ${pushed} policies to OPA` +
        (skippedLocked ? ` (skipped ${skippedLocked} locked)` : "")
    );
    await publishPolicyIndex("startup.restore");
    await publishTrustKeys("startup.restore");
    await publishPepCallers("startup.restore");
    await publishCallerAccess("startup.restore");
    await publishPlatformKeys("startup.restore");
    // CRY-03: background poller for jwks_url-sourced trust keys. The handle
    // is not retained — Node will tear it down on process exit, and unref()
    // inside the fetcher keeps it from holding the event loop open.
    const intervalMs = parseInt(process.env.TRUST_KEYS_FETCH_INTERVAL_MS, 10) || 30000;
    startJwksFetcher({ publish: publishTrustKeys, intervalMs });
  } catch (e) {
    console.error("Seeding failed:", e.message);
  }
});
