// opaBundle.js — assembles the OPA *bundle* the whole PDP fleet pulls.
//
// We replaced the old push model (PUT /v1/policies + PUT /v1/data to a single
// OPA) with OPA's idiomatic bundle-pull: the backend serves ONE gzipped tar at
// GET /bundle/aegis.tar.gz, and every OPA replica polls it and converges. This
// is what makes horizontal scaling correct — a mutation no longer lands on one
// replica and leaves the rest stale.
//
// The bundle is the SOLE source of OPA's state (pure-bundle mode — OPA boots
// with only config.yaml). It carries:
//   - system_authz.rego  (the inbound REST gate, data.system.authz)
//   - studio_authz.rego  (backend RBAC, data.studio.authz)
//   - every active (non-locked) compiled policy module
//   - data.studio.policy_index / keys / callers / caller_access
//   - data.platform_keys  (the pubkeys system_authz verifies JWTs against)
//
// The `.manifest` declares explicit `roots` so the bundle owns exactly its
// paths and nothing else — crucially leaving the `__preview_*` namespace free
// so /api/preview-evaluate can still PUSH transient modules outside the bundle.
//
// SECURITY: the data.json docs contain cleartext HMAC secrets (caller secrets,
// HMAC trust keys). The HTTP endpoint that serves this bundle MUST authenticate
// the puller (see the /bundle route in server.js) and stay on the internal
// network — never proxy it through nginx.
import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import * as store from "./storage.js";
import * as platformKeys from "./platformKeys.js";
import { buildPolicyIndex } from "./policyIndex.js";
import { buildCallerAccess } from "./callerAccess.js";
import { publishValueFromRow } from "./trustKeys.js";
import * as opaTracker from "./opaTracker.js";

// Fixed data/authz roots the bundle always owns. Granular (not bare `studio`)
// so the reserved-prefix guard in regoCompiler.js is the only thing user
// packages can collide with — and that guard refuses system/studio/platform_keys.
const FIXED_ROOTS = [
  "system/authz",
  "studio/authz",
  "studio/policy_index",
  "studio/keys",
  "studio/callers",
  "studio/caller_access",
  "platform_keys",
];

// ─── ustar tar writer (no dependency) ───────────────────────────────────────
// An OPA bundle is a gzipped POSIX (ustar) tar. The file set here is tiny,
// fixed, ASCII-named and well under 8 GB, so a minimal writer is enough and
// keeps a third-party tar lib off a secret-bearing artifact.
function tarHeader(name, size) {
  const buf = Buffer.alloc(512, 0);
  buf.write(name, 0, "utf8");                 // name (100)
  buf.write("0000644\0", 100, "ascii");       // mode (8)
  buf.write("0000000\0", 108, "ascii");       // uid (8)
  buf.write("0000000\0", 116, "ascii");       // gid (8)
  buf.write(size.toString(8).padStart(11, "0") + "\0", 124, "ascii"); // size (12)
  buf.write("00000000000\0", 136, "ascii");   // mtime (12) — fixed 0 for determinism
  buf.write("        ", 148, "ascii");        // chksum placeholder: 8 spaces
  buf.write("0", 156, "ascii");               // typeflag: regular file
  buf.write("ustar\0", 257, "ascii");         // magic (6)
  buf.write("00", 263, "ascii");              // version (2)
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += buf[i];
  // chksum field: 6 octal digits, NUL, space
  buf.write(sum.toString(8).padStart(6, "0") + "\0 ", 148, "ascii");
  return buf;
}

export function buildTar(entries) {
  const chunks = [];
  for (const { name, content } of entries) {
    if (name.length > 100) throw new Error(`tar entry name too long: ${name}`);
    const body = Buffer.isBuffer(content) ? content : Buffer.from(content, "utf8");
    chunks.push(tarHeader(name, body.length));
    chunks.push(body);
    const pad = (512 - (body.length % 512)) % 512;
    if (pad) chunks.push(Buffer.alloc(pad, 0));
  }
  chunks.push(Buffer.alloc(1024, 0)); // two zero blocks terminate the archive
  return Buffer.concat(chunks);
}

// ─── source of the bundled authz Rego ───────────────────────────────────────
// system_authz.rego / studio_authz.rego are the security gate; they are NOT
// user-editable. OPA no longer mounts ./opa — the backend reads them and puts
// them in the bundle. Mount ./opa into the backend (default /app/opa) or set
// OPA_AUTHZ_DIR. Re-read per build so `node --watch` dev picks up edits.
function readAuthzRego() {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const candidates = [
    process.env.OPA_AUTHZ_DIR,
    "/app/opa",
    path.resolve(here, "../../../opa"), // local dev: backend/src/services -> repo/opa
  ].filter(Boolean);
  for (const dir of candidates) {
    try {
      const system = fs.readFileSync(path.join(dir, "system_authz.rego"), "utf8");
      const studio = fs.readFileSync(path.join(dir, "studio_authz.rego"), "utf8");
      return { system, studio, dir };
    } catch {
      /* try next candidate */
    }
  }
  throw new Error(
    "opaBundle: could not locate system_authz.rego / studio_authz.rego " +
      "(set OPA_AUTHZ_DIR or mount ./opa into the backend)"
  );
}

// ─── deterministic helpers ──────────────────────────────────────────────────
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    const out = {};
    for (const k of Object.keys(value).sort()) out[k] = canonical(value[k]);
    return out;
  }
  return value;
}

function packageToRoot(pkg) {
  return String(pkg).split(".").join("/");
}

// Reduce to non-overlapping roots: drop any path that is a descendant of one
// already kept (OPA rejects overlapping roots within a bundle, which would
// happen if a user had packages `acme.billing` and `acme.billing.v2`).
function minimalRoots(paths) {
  const sorted = [...new Set(paths)].sort();
  const kept = [];
  for (const p of sorted) {
    if (kept.some((k) => p === k || p.startsWith(k + "/"))) continue;
    kept.push(p);
  }
  return kept;
}

// Gather every input the bundle is derived from. Mirrors the old publish*
// functions exactly so OPA sees identical documents — just delivered via pull.
async function collect(orgId) {
  const [policies, trustRows, callerRows, grants, platform] = await Promise.all([
    store.listPolicies(),
    store.listTrustKeys(),
    store.listPepCallers(),
    store.listAllCallerAccess(),
    platformKeys.buildOpaPublishDocument(),
  ]);

  // If orgId is provided, filter the DB results so we only bundle this org's
  // resources (or global ones where orgId is null).
  const filteredPolicies = orgId
    ? policies.filter((p) => p.orgId === orgId || p.orgId === null)
    : policies;
  const filteredTrustRows = orgId
    ? trustRows.filter((r) => r.orgId === orgId || r.orgId === null)
    : trustRows;
  const filteredCallerRows = orgId
    ? callerRows.filter((r) => r.orgId === orgId || r.orgId === null)
    : callerRows;
  const filteredGrants = orgId
    ? grants.filter((g) => {
        const policy = filteredPolicies.find((p) => p.id === g.policyId);
        const caller = filteredCallerRows.find((c) => c.callerId === g.callerId);
        return policy && caller;
      })
    : grants;

  const policyIndex = buildPolicyIndex(filteredPolicies); // deterministic (no wall-clock)

  // data.studio.keys — flat { kid: pem|secret }, revoked rows dropped.
  const keys = {};
  for (const row of filteredTrustRows) {
    const v = publishValueFromRow(row);
    if (typeof v === "string" && v.length > 0) keys[row.kid] = v;
  }

  // data.studio.callers — active rows only (mirrors publishPepCallers).
  const callers = {};
  for (const r of filteredCallerRows) {
    if (r.status !== "active") continue;
    const entry = { auth_mode: r.authMode };
    if (r.authMode === "hmac" && r.hmacSecret) entry.hmac_secret = r.hmacSecret;
    if (r.authMode === "mtls" && r.allowedCn) entry.allowed_cn = r.allowedCn;
    if (r.authMode === "jwt" && r.jwtSubject) entry.jwt_subject = r.jwtSubject;
    if (r.tenant) entry.tenant = r.tenant;
    entry.org_id = r.orgId ?? null;
    callers[r.callerId] = entry;
  }

  // data.studio.caller_access — union of explicit grants + tag matches.
  const { access: callerAccess } = buildCallerAccess({
    grants: filteredGrants,
    policies: filteredPolicies,
    callers: filteredCallerRows,
  });

  // Active (non-locked) compiled policy modules, sorted for a stable revision.
  const modules = filteredPolicies
    .filter((p) => !p.locked && p.rego && p.package)
    .map((p) => ({ id: p.id, package: p.package, rego: p.rego, name: p.name, version: p.version }))
    .sort((a, b) => String(a.id).localeCompare(String(b.id)));

  return { policyIndex, keys, callers, callerAccess, platform, modules };
}

// ─── cache ───────────────────────────────────────────────────────────────────
const _caches = new Map();     // orgId -> { tarGz, revision, builtAt }
const _buildings = new Map();  // orgId -> in-flight build promise (coalesce concurrent polls)

// Build the bundle fresh and cache it. Pure read of DB + KMS-derived pubkeys.
export async function buildBundle(orgId = null) {
  const authz = readAuthzRego();
  const data = await collect(orgId);

  const roots = minimalRoots([
    ...FIXED_ROOTS,
    ...data.modules.map((m) => packageToRoot(m.package)),
  ]);

  // Revision = sha256 over the LOGICAL inputs (not tar bytes). generatedAt is
  // excluded by construction (buildPolicyIndex emits null), so an unchanged
  // policy set yields an unchanged revision → OPA gets a clean 304.
  const revision = createHash("sha256")
    .update(
      JSON.stringify(
        canonical({
          systemAuthz: authz.system,
          studioAuthz: authz.studio,
          policyIndex: data.policyIndex,
          keys: data.keys,
          callers: data.callers,
          callerAccess: data.callerAccess,
          platform: data.platform,
          modules: data.modules.map((m) => ({ id: m.id, rego: m.rego })),
          roots,
        })
      )
    )
    .digest("hex");

  const entries = [
    { name: ".manifest", content: JSON.stringify({ revision, roots }) },
    { name: "system/authz/policy.rego", content: authz.system },
    { name: "studio/authz/policy.rego", content: authz.studio },
    { name: "studio/policy_index/data.json", content: JSON.stringify(data.policyIndex) },
    { name: "studio/keys/data.json", content: JSON.stringify(data.keys) },
    { name: "studio/callers/data.json", content: JSON.stringify(data.callers) },
    { name: "studio/caller_access/data.json", content: JSON.stringify(data.callerAccess) },
    { name: "platform_keys/data.json", content: JSON.stringify(data.platform) },
    ...data.modules.map((m) => ({ name: `policies/${m.id}.rego`, content: m.rego })),
  ];

  const tarGz = gzipSync(buildTar(entries), { level: 9 });
  const cacheObj = { tarGz, revision, builtAt: Date.now() };
  _caches.set(orgId, cacheObj);

  // Record the policies in this revision
  const revisionPolicies = data.modules.map((m) => ({
    id: m.id,
    name: m.name || "Unknown",
    package: m.package,
    version: m.version || 1,
  }));
  opaTracker.recordRevisionPolicies(revision, revisionPolicies);

  console.log(
    `[opa-bundle] built revision ${revision.slice(0, 12)} for org ${orgId || "global"} ` +
      `(${data.modules.length} policies, ${Object.keys(data.callers).length} callers, ` +
      `${Object.keys(data.keys).length} trust keys, ${tarGz.length} bytes gz)`
  );
  return cacheObj;
}

// Return the cached bundle, building (and coalescing) on a cold cache.
export async function getBundle(orgId = null) {
  const cached = _caches.get(orgId);
  if (cached) return cached;
  let promise = _buildings.get(orgId);
  if (!promise) {
    promise = buildBundle(orgId).finally(() => {
      _buildings.delete(orgId);
    });
    _buildings.set(orgId, promise);
  }
  return promise;
}

export function getCachedBundle(orgId = null) {
  return _caches.get(orgId);
}

// Drop the cache so the next poll rebuilds. Lazy on purpose: bursts of
// mutations batch into a single rebuild on the next OPA poll. Cheap and
// fire-and-forget-safe — replaces all the old publish* calls.
export function invalidateBundle(reason, orgId = null) {
  if (orgId) {
    _caches.delete(orgId);
    console.log(`[opa-bundle] invalidated org ${orgId} cache (${reason || "unspecified"})`);
  } else {
    _caches.clear();
    console.log(`[opa-bundle] cleared entire bundle cache (${reason || "unspecified"})`);
  }
}
