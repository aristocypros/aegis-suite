// jwt.js — JWT verifier reached by the dispatcher when Authorization:
// Bearer is present. Verifies the signature offline against the platform's
// published JWKS (default /.well-known/jwks.json on the backend), then
// looks up the caller in the pep_callers document and asserts the row's
// auth_mode is "jwt".
//
// The JWT's `sub` claim is the caller identity. A caller row may override
// the expected `sub` via jwt_subject; otherwise the sub must match the
// caller_id directly. Issuer and audience are enforced against PEP_JWT_*.

import { jwtVerify } from "jose";

export function createJwtAuth({
  jwks,
  callerStore,
  issuer,
  audience,
  algorithms = ["EdDSA"],
  logger = console,
}) {
  if (!jwks || typeof jwks.getKeySet !== "function") {
    throw new Error("createJwtAuth: jwks cache is required");
  }
  if (typeof issuer !== "string" || !issuer) {
    throw new Error("createJwtAuth: issuer is required");
  }
  if (typeof audience !== "string" || !audience) {
    throw new Error("createJwtAuth: audience is required");
  }

  return async function jwtAuth(req, res, next) {
    const header = req.headers["authorization"];
    if (typeof header !== "string" || !header.toLowerCase().startsWith("bearer ")) {
      return res.status(401).json({ error: "missing_bearer_token" });
    }
    const token = header.slice("bearer ".length).trim();
    if (!token) return res.status(401).json({ error: "missing_bearer_token" });

    let payload;
    try {
      ({ payload } = await jwtVerify(token, jwks.getKeySet(), {
        issuer,
        audience,
        algorithms,
      }));
    } catch (e) {
      logger.warn?.(`[pep-auth] jwt reject: ${e?.code || e?.message || e}`);
      return res.status(401).json({ error: "invalid_jwt", reason: e?.code || "verify_failed" });
    }

    if (typeof payload.sub !== "string" || payload.sub.length === 0) {
      return res.status(401).json({ error: "jwt_missing_sub" });
    }

    const match = await callerStore.findByJwtSubject(payload.sub);
    if (!match) {
      logger.warn?.(`[pep-auth] jwt reject: sub='${payload.sub}' not allowed`);
      return res.status(401).json({ error: "caller_not_allowed" });
    }
    if (match.row?.auth_mode !== "jwt") {
      logger.warn?.(`[pep-auth] jwt reject: caller '${match.callerId}' is auth_mode=${match.row?.auth_mode}`);
      return res.status(401).json({ error: "auth_mode_mismatch" });
    }

    req.caller = {
      id: match.callerId,
      mode: "jwt",
      sub: payload.sub,
      tenant: match.row?.tenant,
      orgId: match.row?.org_id ?? null,
    };
    next();
  };
}
