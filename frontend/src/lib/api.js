// lib/api.js — frontend API client for the policy studio backend.
import { getToken, clearToken } from "./auth.js";

const BASE = "/api";

async function req(path, options = {}) {
  const token = getToken();
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {}),
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  const res = await fetch(BASE + path, { ...options, headers });
  const text = await res.text();
  let body;
  try { body = text ? JSON.parse(text) : {}; }
  catch { body = { raw: text }; }

  if (res.status === 401) {
    // Token rejected by server — drop it so App rerenders to LoginPage.
    // (clearToken emits auth-change which App is subscribed to.)
    clearToken();
  }

  if (!res.ok) {
    const err = new Error(body.error || `HTTP ${res.status}`);
    err.status = res.status;
    err.body = body;
    throw err;
  }
  return body;
}

export const api = {
  health: () => req("/health"),

  // ── Auth ────────────────────────────────────────────────────────────────
  login: (username, password) =>
    req("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
  me: () => req("/auth/me"),
  changePassword: (currentPassword, newPassword) =>
    req("/auth/change-password", {
      method: "POST",
      body: JSON.stringify({ currentPassword, newPassword }),
    }),
  logout: () => req("/auth/logout", { method: "POST" }).catch(() => {}),

  // ── Users (admin only) ──────────────────────────────────────────────────
  listUsers: () => req("/users"),
  createUser: (payload) =>
    req("/users", { method: "POST", body: JSON.stringify(payload) }),
  updateUser: (id, payload) =>
    req(`/users/${id}`, { method: "PUT", body: JSON.stringify(payload) }),
  resetUserPassword: (id, payload = {}) =>
    req(`/users/${id}/reset-password`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  deleteUser: (id) => req(`/users/${id}`, { method: "DELETE" }),

  // ── Orgs (root-only) ────────────────────────────────────────────────────
  listOrgs: () => req("/orgs"),
  createOrg: (payload) =>
    req("/orgs", { method: "POST", body: JSON.stringify(payload) }),
  updateOrg: (id, payload) =>
    req(`/orgs/${id}`, { method: "PUT", body: JSON.stringify(payload) }),
  deleteOrg: (id) => req(`/orgs/${id}`, { method: "DELETE" }),

  // ── Roles (root globals + org-admin locals) ─────────────────────────────
  listRoles: () => req("/roles"),
  createRole: (payload) =>
    req("/roles", { method: "POST", body: JSON.stringify(payload) }),
  updateRole: (id, payload) =>
    req(`/roles/${id}`, { method: "PUT", body: JSON.stringify(payload) }),
  deleteRole: (id) => req(`/roles/${id}`, { method: "DELETE" }),

  // ── Templates ──────────────────────────────────────────────────────────
  listTemplates: () => req("/templates"),
  getTemplate: (id) => req(`/templates/${id}`),

  // ── Policies ───────────────────────────────────────────────────────────
  listPolicies: () => req("/policies"),
  getPolicy: (id) => req(`/policies/${id}`),
  savePolicy: (spec) =>
    req("/policies", { method: "POST", body: JSON.stringify(spec) }),
  updatePolicy: (id, spec) =>
    req(`/policies/${id}`, { method: "PUT", body: JSON.stringify(spec) }),
  // Policies cannot be deleted — only locked / unlocked. Both bump version
  // and append a signed audit entry. A locked policy is removed from OPA so
  // it stops enforcing; unlock re-pushes it.
  lockPolicy: (id) =>
    req(`/policies/${id}/lock`, { method: "POST" }),
  unlockPolicy: (id) =>
    req(`/policies/${id}/unlock`, { method: "POST" }),

  compile: (spec) =>
    req("/compile", { method: "POST", body: JSON.stringify(spec) }),
  validate: (spec) =>
    req("/validate", { method: "POST", body: JSON.stringify(spec) }),

  evaluate: (id, input, ruleName) =>
    req(`/evaluate/${id}`, {
      method: "POST",
      body: JSON.stringify({ input, ruleName }),
    }),

  previewEvaluate: (spec, input, ruleName) =>
    req("/preview-evaluate", {
      method: "POST",
      body: JSON.stringify({ spec, input, ruleName }),
    }),

  listVersions: (id) => req(`/policies/${id}/versions`),
  getVersion: (id, versionNum) => req(`/policies/${id}/versions/${versionNum}`),

  // ── PEP callers (admin only, PEP-01) ────────────────────────────────────
  listPepCallers: () => req("/pep-callers"),
  createPepCaller: (payload) =>
    req("/pep-callers", { method: "POST", body: JSON.stringify(payload) }),
  updatePepCaller: (id, payload) =>
    req(`/pep-callers/${encodeURIComponent(id)}`, {
      method: "PUT",
      body: JSON.stringify(payload),
    }),
  rotatePepCallerSecret: (id) =>
    req(`/pep-callers/${encodeURIComponent(id)}/rotate-secret`, { method: "POST" }),
  revokePepCaller: (id) =>
    req(`/pep-callers/${encodeURIComponent(id)}/revoke`, { method: "POST" }),
  deletePepCaller: (id) =>
    req(`/pep-callers/${encodeURIComponent(id)}`, { method: "DELETE" }),

  // ── Per-caller policy ACL ───────────────────────────────────────────────
  listCallerAccess: (id) =>
    req(`/pep-callers/${encodeURIComponent(id)}/access`),
  grantCallerAccess: (id, policyIds) =>
    req(`/pep-callers/${encodeURIComponent(id)}/access`, {
      method: "POST",
      body: JSON.stringify({ policyIds }),
    }),
  revokeCallerAccess: (id, policyId) =>
    req(
      `/pep-callers/${encodeURIComponent(id)}/access/${encodeURIComponent(policyId)}`,
      { method: "DELETE" }
    ),

  // ── Policy-centric ACL (reverse view) ───────────────────────────────────
  listPolicyCallers: (policyId) => req(`/policies/${policyId}/access`),
  grantPolicyCallers: (policyId, callerIds) =>
    req(`/policies/${policyId}/access`, {
      method: "POST",
      body: JSON.stringify({ callerIds }),
    }),
  revokePolicyCaller: (policyId, callerId) =>
    req(
      `/policies/${policyId}/access/${encodeURIComponent(callerId)}`,
      { method: "DELETE" }
    ),

  // ── Tags (policy.tags + pep_caller.scope_tags) ─────────────────────────
  listTags: () => req("/tags"),
  updatePolicyTags: (policyId, { add = [], remove = [] }) =>
    req(`/policies/${policyId}/tags`, {
      method: "PATCH",
      body: JSON.stringify({ add, remove }),
    }),
  updateCallerScopeTags: (callerId, { add = [], remove = [] }) =>
    req(`/pep-callers/${encodeURIComponent(callerId)}/scope-tags`, {
      method: "PATCH",
      body: JSON.stringify({ add, remove }),
    }),

  // ── Trust keys (admin only, CRY-03) ─────────────────────────────────────
  listTrustKeys: () => req("/trust-keys"),
  createTrustKey: (payload) =>
    req("/trust-keys", { method: "POST", body: JSON.stringify(payload) }),
  updateTrustKey: (kid, payload) =>
    req(`/trust-keys/${encodeURIComponent(kid)}`, {
      method: "PUT",
      body: JSON.stringify(payload),
    }),
  revokeTrustKey: (kid) =>
    req(`/trust-keys/${encodeURIComponent(kid)}/revoke`, { method: "POST" }),
  refreshTrustKey: (kid) =>
    req(`/trust-keys/${encodeURIComponent(kid)}/refresh`, { method: "POST" }),
  deleteTrustKey: (kid) =>
    req(`/trust-keys/${encodeURIComponent(kid)}`, { method: "DELETE" }),

  // ── Platform signing keys (admin only) ──────────────────────────────────
  listPlatformKeys: () => req("/platform-keys"),
  rotatePlatformKey: (purpose) =>
    req("/platform-keys/rotate", {
      method: "POST",
      body: JSON.stringify({ purpose }),
    }),
  revokePlatformKey: (fp) =>
    req(`/platform-keys/${encodeURIComponent(fp)}/revoke`, { method: "POST" }),
  getPlatformKeysOpaState: () => req("/platform-keys/opa-state"),
  getPlatformKeysTrustStatus: () => req("/platform-keys/trust-status"),
  getOpaFleet: () => req("/opa-fleet"),

  // ── Audit (admin only) ──────────────────────────────────────────────────
  listAudit: ({ limit, beforeSeq, action, resourceId } = {}) => {
    const qs = new URLSearchParams();
    if (limit != null) qs.set("limit", String(limit));
    if (beforeSeq != null) qs.set("beforeSeq", String(beforeSeq));
    if (action) qs.set("action", action);
    if (resourceId) qs.set("resourceId", resourceId);
    const s = qs.toString();
    return req("/audit" + (s ? "?" + s : ""));
  },
  getAuditEntry: (seq) => req(`/audit/${seq}`),
  verifyAudit: () => req("/audit/verify"),
  getAuditPubkey: () => req("/audit/pubkey"),
};
