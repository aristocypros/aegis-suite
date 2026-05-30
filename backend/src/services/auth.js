// auth.js — bcrypt password hashing + EdDSA session-JWT issuance.
//
// Session tokens are signed with the KMS-held `session-signing` key (see
// services/platformKeys.js) using EdDSA. The private key never leaves the
// KMS provider; verification is local against the public key the reconciler
// cached at boot.
//
// The legacy HS256 path (`JWT_SECRET`) is gone — the explicit algorithms
// whitelist in verifyToken refuses anything other than `EdDSA`, and the
// `kid` header pins the verifier to a specific platform_signing_keys row.
import crypto from "node:crypto";
import bcrypt from "bcryptjs";

import * as platformJwt from "./platformJwt.js";
import * as platformKeys from "./platformKeys.js";

const BCRYPT_ROUNDS = 12;
const SESSION_TTL_SECONDS = 12 * 60 * 60;
const ISS = "opa-policy-studio";
const AUD = "opa-policy-studio-session";

// Pre-computed dummy hash to keep login timing constant on user-miss / disabled.
const DUMMY_HASH = bcrypt.hashSync(
  "not-a-password-" + crypto.randomBytes(8).toString("hex"),
  BCRYPT_ROUNDS
);

export function hashPassword(plain) {
  return bcrypt.hash(plain, BCRYPT_ROUNDS);
}

export function verifyPassword(plain, hash) {
  return bcrypt.compare(plain, hash);
}

export async function constantTimeMissCompare(plain) {
  await bcrypt.compare(plain || "", DUMMY_HASH);
  return false;
}

// Sign a session JWT. The `user` argument should be the auth-context shape
// returned by store.getUserAuthContext() so the token carries the RBAC
// claims (org_id, role_id, is_root, permissions) the frontend needs for
// UI gating. The backend doesn't trust these claims for authorization —
// authenticate.js re-resolves from the DB on every request — but baking
// them in lets the SPA render the right menu on first paint without an
// extra round trip. Older callers that pass a thinner user object still
// work: missing fields become null/false/{}.
export async function signToken(user) {
  const keyId = platformKeys.activeKeyId("session-signing");
  const now = Math.floor(Date.now() / 1000);
  return platformJwt.signJwtEdDSA({
    keyId,
    payload: {
      iss: ISS,
      aud: AUD,
      sub: user.id,
      username: user.username,
      role: user.role,
      org_id: user.orgId ?? null,
      role_id: user.roleId ?? null,
      role_name: user.roleName ?? null,
      is_root: !!user.isRoot,
      permissions: user.permissions || {},
      mcp: !!user.mustChangePassword,
      iat: now,
      exp: now + SESSION_TTL_SECONDS,
    },
  });
}

export function verifyToken(token) {
  return platformJwt.verifyJwtEdDSA(token, {
    pubkeyResolver: platformKeys.pubkeyForKid,
    issuer: ISS,
    audience: AUD,
  });
}
