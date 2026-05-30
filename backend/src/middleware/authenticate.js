// authenticate.js — Bearer token middleware for the policy studio API.
import * as auth from "../services/auth.js";
import * as store from "../services/storage.js";

const PUBLIC_PATHS = new Set(["/api/health", "/api/auth/login"]);
const MUST_CHANGE_ALLOWED = new Set([
  "/api/auth/me",
  "/api/auth/change-password",
  "/api/auth/logout",
]);
const BEARER_RE = /^Bearer (.+)$/i;

export async function authenticate(req, res, next) {
  if (PUBLIC_PATHS.has(req.path)) return next();

  const header = req.get("authorization") || "";
  const m = header.match(BEARER_RE);
  if (!m) {
    return res.status(401).json({ error: "Missing or malformed Authorization header" });
  }

  let payload;
  try {
    payload = auth.verifyToken(m[1]);
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }

  // Resolve from DB on every request so role/permissions/disabled reflect
  // the current state. The JWT carries claims for the frontend's first-paint
  // UI gating, but the backend (and the input we pass to OPA) only trusts
  // these freshly-loaded values.
  const ctx = await store.getUserAuthContext(payload.sub);
  if (!ctx || ctx.disabled) {
    return res.status(401).json({ error: "User no longer valid" });
  }

  req.user = {
    id: ctx.id,
    username: ctx.username,
    role: ctx.role,
    orgId: ctx.orgId,
    roleId: ctx.roleId,
    roleName: ctx.roleName,
    isRoot: ctx.isRoot,
    permissions: ctx.permissions,
    mustChangePassword: ctx.mustChangePassword,
  };

  if (req.user.mustChangePassword && !MUST_CHANGE_ALLOWED.has(req.path)) {
    return res.status(403).json({
      error: "PASSWORD_CHANGE_REQUIRED",
      message: "You must change your password before continuing.",
    });
  }
  next();
}

export function requireAdmin(req, res, next) {
  if (req.user?.role !== "admin") {
    return res.status(403).json({ error: "Admin role required" });
  }
  next();
}
