// opaClient.js
// Thin wrapper around OPA's Data + Policy REST APIs.
// https://www.openpolicyagent.org/docs/rest-api
//
// Auth: every request carries a short-lived EdDSA JWT minted by the KMS-held
// `opa-auth-signing` key (see services/platformKeys.js + platformJwt.js).
// `opa/system_authz.rego` accepts the JWT when its signature verifies under
// a pubkey loaded into OPA's `data.platform_keys` tree at boot, the iss is
// `opa-policy-studio`, and the aud is `opa-studio-backend` (mutating paths)
// or one of the read-allowed auds (GET / HEAD).
//
// The JWT is cached in-process for ~30s to avoid per-call KMS round-trips.
import * as platformJwt from "./platformJwt.js";
import * as platformKeys from "./platformKeys.js";

const OPA_URL = process.env.OPA_URL || "http://localhost:8181";

const TOKEN_TTL_SECONDS = 30;
const TOKEN_REFRESH_BUFFER_SECONDS = 5;

let _cachedToken = null;
let _cachedExp = 0;
let _cachedFp = null;

// Export so platformKeys.rotate() can flush the cache after a rotation —
// otherwise we'd keep using the retired key for up to TOKEN_TTL_SECONDS.
export function invalidateAuthCache() {
  _cachedToken = null;
  _cachedExp = 0;
  _cachedFp = null;
}

async function authHeaders(extra = {}) {
  const now = Math.floor(Date.now() / 1000);
  const activeFp = platformKeys.getActivePurposeMeta("opa-auth-signing")?.fpHex;
  // If the active key rotated underneath us, drop the cached token.
  if (activeFp && _cachedFp && _cachedFp !== activeFp) invalidateAuthCache();
  if (!_cachedToken || _cachedExp - now < TOKEN_REFRESH_BUFFER_SECONDS) {
    const keyId = platformKeys.activeKeyId("opa-auth-signing");
    _cachedToken = await platformJwt.signJwtEdDSA({
      keyId,
      payload: {
        iss: "opa-policy-studio",
        aud: "opa-studio-backend",
        sub: "backend",
        iat: now,
        exp: now + TOKEN_TTL_SECONDS,
      },
    });
    _cachedExp = now + TOKEN_TTL_SECONDS;
    _cachedFp = activeFp || null;
  }
  return { Authorization: `Bearer ${_cachedToken}`, ...extra };
}

async function fetchJson(url, options = {}) {
  const res = await fetch(url, {
    ...options,
    headers: await authHeaders(options.headers || {}),
  });
  const text = await res.text();
  let body;
  try {
    body = text ? JSON.parse(text) : {};
  } catch {
    body = { raw: text };
  }
  if (!res.ok) {
    const err = new Error(`OPA ${res.status}: ${body.message || body.raw || text}`);
    err.status = res.status;
    err.body = body;
    throw err;
  }
  return body;
}

// PUT a Rego module under a policy ID. OPA compiles it and rejects on parse error.
export async function putPolicy(policyId, regoSource) {
  const url = `${OPA_URL}/v1/policies/${encodeURIComponent(policyId)}`;
  const res = await fetch(url, {
    method: "PUT",
    headers: await authHeaders({ "Content-Type": "text/plain" }),
    body: regoSource,
  });
  const text = await res.text();
  if (!res.ok) {
    let body;
    try { body = JSON.parse(text); } catch { body = { message: text }; }
    const err = new Error(`OPA rejected policy: ${body.message || text}`);
    err.status = res.status;
    err.body = body;
    throw err;
  }
  return { ok: true };
}

export async function deletePolicy(policyId) {
  const url = `${OPA_URL}/v1/policies/${encodeURIComponent(policyId)}`;
  const res = await fetch(url, {
    method: "DELETE",
    headers: await authHeaders(),
  });
  if (!res.ok && res.status !== 404) {
    throw new Error(`OPA delete failed: ${res.status}`);
  }
  return { ok: true };
}

export async function listPolicies() {
  return fetchJson(`${OPA_URL}/v1/policies`);
}

// Evaluate a policy: POST input to /v1/data/<package-path>/<rule-name>
// rulePath is dot-separated, e.g. "digital_assets.tx_limits.allow"
export async function evaluate(rulePath, input) {
  const dataPath = rulePath.replace(/\./g, "/");
  const url = `${OPA_URL}/v1/data/${dataPath}`;
  return fetchJson(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ input }),
  });
}

// Evaluate the whole package and return all rule results
export async function evaluatePackage(packagePath, input) {
  const dataPath = packagePath.replace(/\./g, "/");
  const url = `${OPA_URL}/v1/data/${dataPath}`;
  return fetchJson(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ input }),
  });
}

// PUT a JSON document into OPA's data tree at the given path.
// dataPath is dot- or slash-separated (e.g. "studio/policy_index" or
// "studio.policy_index"). Used to publish the discovery index for the PEP.
export async function putData(dataPath, value) {
  const path = String(dataPath).replace(/\./g, "/").replace(/^\/+/, "");
  const url = `${OPA_URL}/v1/data/${path}`;
  const res = await fetch(url, {
    method: "PUT",
    headers: await authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(value),
  });
  if (!res.ok && res.status !== 204) {
    const text = await res.text().catch(() => "");
    const err = new Error(`OPA put-data failed (${res.status}): ${text}`);
    err.status = res.status;
    throw err;
  }
  return { ok: true };
}

// GET an arbitrary document from OPA's data tree. Used by the platform-keys
// admin UI to compare DB state against what OPA is currently serving.
export async function getData(dataPath) {
  const path = String(dataPath).replace(/\./g, "/").replace(/^\/+/, "");
  const url = `${OPA_URL}/v1/data/${path}`;
  return fetchJson(url, { method: "GET" });
}

// OPA `/health` is allowlisted in system_authz.rego so liveness probes don't
// need a JWT — keep this call unauthenticated to break a chicken-and-egg at
// boot, where the backend hasn't loaded its signing key yet but still wants
// to confirm OPA is reachable.
export async function health() {
  try {
    const res = await fetch(`${OPA_URL}/health`);
    return { ok: res.ok, status: res.status };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

// ─── Studio authz ─────────────────────────────────────────────────────────
// Evaluate `data.studio.authz` for a given user/action/resource plus the
// audit-chain status. Returns `{ allow: boolean, reason?: string }`.
// Throws on transport / OPA errors.
export async function authorize({ user, action, resource, audit, opaTrust, jwtSigner }) {
  const url = `${OPA_URL}/v1/data/studio/authz`;
  const input = { user, action, resource };
  if (audit !== undefined) input.audit = audit;
  if (opaTrust !== undefined) input.opa_trust = opaTrust;
  if (jwtSigner !== undefined) input.jwt_signer = jwtSigner;
  const body = await fetchJson(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ input }),
  });
  const result = body.result || {};
  return {
    allow: result.allow === true,
    reason: typeof result.reason === "string" ? result.reason : undefined,
  };
}
