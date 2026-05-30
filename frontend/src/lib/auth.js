// auth.js — frontend token storage + pub-sub for 401-driven logout.
const KEY = "opa_studio_token";

export const getToken = () => {
  try { return localStorage.getItem(KEY); } catch { return null; }
};
export const setToken = (t) => {
  try { localStorage.setItem(KEY, t); } catch { /* ignore */ }
  emitAuthChange();
};
export const clearToken = () => {
  try { localStorage.removeItem(KEY); } catch { /* ignore */ }
  emitAuthChange();
};

// UI-hint decode of the JWT payload. Never trust this for authorization —
// the server re-validates the token on every request and applies its own
// RBAC + cross-org checks. The decode here just lets the SPA render the
// right menu on first paint without an extra /api/auth/me round trip.
export function decodeUser(token = getToken()) {
  if (!token) return null;
  try {
    const [, b64] = token.split(".");
    const json = JSON.parse(
      atob(b64.replace(/-/g, "+").replace(/_/g, "/"))
    );
    return {
      id: json.sub,
      username: json.username,
      role: json.role,
      roleName: json.role_name ?? null,
      orgId: json.org_id ?? null,
      roleId: json.role_id ?? null,
      isRoot: !!json.is_root,
      permissions: json.permissions || {},
      mustChangePassword: !!json.mcp,
      exp: json.exp,
    };
  } catch {
    return null;
  }
}

// can(user, action, resourceType) — frontend permission check used to gate
// UI affordances (menu items, action buttons, page guards). Mirrors the
// is_effective_root + permission-map logic of opa/studio_authz.rego so
// the UI doesn't show buttons the backend would 403. The backend remains
// the source of truth; never rely on this for security.
//
//   can(user, "read",   "user")       → boolean
//   can(user, "create", "policy")     → boolean
//   can(user, "manage", "platform_key") → false unless explicitly granted
//
// Returns false on missing user, disabled user (caller's responsibility
// to detect — we don't carry disabled in JWT), or unknown action/type.
export function can(user, action, resourceType) {
  if (!user) return false;
  // Root bypass (matches studio_authz.is_effective_root).
  if (user.isRoot) return true;
  if (user.role === "admin") return true; // legacy admin compat
  const perms = user.permissions || {};
  const actions = perms[resourceType];
  if (!Array.isArray(actions)) return false;
  return actions.includes(action);
}

const listeners = new Set();
export const onAuthChange = (fn) => {
  listeners.add(fn);
  return () => listeners.delete(fn);
};
export const emitAuthChange = () => {
  for (const fn of listeners) {
    try { fn(); } catch { /* ignore listener errors */ }
  }
};
