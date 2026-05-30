// auth/index.js — per-request auth dispatcher (PEP-01, multi-mode).
//
// The PEP no longer runs in a single global auth mode. Every pep_callers
// row declares its own auth_mode (hmac | mtls | jwt); the dispatcher picks
// which verifier to run by inspecting the credential the request presents:
//
//   X-Studio-Sig header               → candidate mode: hmac
//   Authorization: Bearer <token>     → candidate mode: jwt
//   client TLS certificate            → candidate mode: mtls
//
// Rules:
//   - exactly zero credentials → 401 (or admit anon when devAllowAnon=true)
//   - more than one credential → 401 ambiguous_credentials (we don't try to
//     guess precedence; pick one scheme per request)
//   - exactly one credential   → look up the caller, assert
//     row.auth_mode == presented mode, run the matching verifier
//
// Per-mode modules under ./modes/ each accept the request, validate the
// credential, and populate req.caller on success.

import { createCallerStore } from "./callerStore.js";
import { createNonceCache } from "./nonceCache.js";
import { createJwksCache } from "./jwksCache.js";
import { createHmacAuth } from "./modes/hmac.js";
import { createMtlsAuth } from "./modes/mtls.js";
import { createJwtAuth } from "./modes/jwt.js";

export const VALID_AUTH_MODES = ["hmac", "mtls", "jwt"];

function detectCredentialKinds(req, { tlsEnabled }) {
  const kinds = [];
  if (typeof req.headers["x-studio-sig"] === "string" &&
      req.headers["x-studio-sig"].length > 0) {
    kinds.push("hmac");
  }
  const auth = req.headers["authorization"];
  if (typeof auth === "string" && /^bearer\s+\S/i.test(auth)) {
    kinds.push("jwt");
  }
  if (tlsEnabled) {
    // getPeerCertificate() returns {} for "no cert presented". A populated
    // object (even with authorized=false) means the client offered one — we
    // surface that as an mtls attempt so the mtls verifier can emit the
    // specific reason (e.g. untrusted_client_cert) rather than a generic
    // "no credentials".
    let cert = null;
    try {
      cert = typeof req.socket?.getPeerCertificate === "function"
        ? req.socket.getPeerCertificate(false)
        : null;
    } catch (_e) { /* not a TLS socket */ }
    if (cert && Object.keys(cert).length > 0) {
      kinds.push("mtls");
    }
  }
  return kinds;
}

export async function createAuthDispatcher({
  pdp,
  config,
  tlsEnabled,
  devAllowAnon = false,
  logger = console,
}) {
  const callerStore = createCallerStore({
    pdp,
    ttlMs: config.callerTtlMs,
    logger,
  });
  try {
    await callerStore.warmUp();
  } catch (e) {
    logger.warn?.(`[pep-auth] initial caller store warm-up failed: ${e?.message || e}`);
  }

  const nonceCache = createNonceCache({
    maxEntries: config.nonceCacheMax,
    ttlMs: config.hmacWindowMs * 2,
  });
  const hmacVerifier = createHmacAuth({
    callerStore,
    nonceCache,
    windowMs: config.hmacWindowMs,
    logger,
  });
  const mtlsVerifier = createMtlsAuth({
    allowedCns: config.allowedCns,
    callerStore,
    logger,
  });

  // JWT is only wired when the platform-level iss/aud/jwks are configured.
  // A JWT-mode caller row is unusable without them; reject at dispatch time
  // rather than crash mid-verification.
  let jwtVerifier = null;
  if (config.jwksUrl && config.jwtIssuer && config.jwtAudience) {
    const jwks = createJwksCache({ url: config.jwksUrl });
    jwtVerifier = createJwtAuth({
      jwks,
      callerStore,
      issuer: config.jwtIssuer,
      audience: config.jwtAudience,
      logger,
    });
  }

  const verifiers = {
    hmac: hmacVerifier,
    mtls: mtlsVerifier,
    jwt: jwtVerifier,
  };

  return async function authDispatch(req, res, next) {
    const kinds = detectCredentialKinds(req, { tlsEnabled });

    if (kinds.length === 0) {
      if (devAllowAnon) {
        req.caller = { id: "anonymous", mode: "none" };
        return next();
      }
      return res.status(401).json({ error: "no_credentials" });
    }
    if (kinds.length > 1) {
      logger.warn?.(`[pep-auth] reject: multiple credentials presented: ${kinds.join(",")}`);
      return res.status(401).json({
        error: "ambiguous_credentials",
        presented: kinds,
      });
    }

    const mode = kinds[0];
    const verifier = verifiers[mode];
    if (!verifier) {
      // mtls when tlsEnabled is false is unreachable (we wouldn't detect a
      // cert), but jwt mode without jwks/iss/aud is reachable: a caller
      // sends a Bearer token, but the PEP wasn't configured to verify any.
      logger.warn?.(`[pep-auth] reject: ${mode} verifier not configured`);
      return res.status(401).json({
        error: "mode_not_configured",
        mode,
      });
    }

    // The per-mode verifier owns the actual credential check AND the
    // row.auth_mode == mode assertion. It populates req.caller on success
    // or sends a 4xx and returns without calling next() on failure.
    return verifier(req, res, next);
  };
}
