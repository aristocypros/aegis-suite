// trustKeys.js — validation and material conversion for CRY-03.
//
// Responsibilities:
//   - normalizeKeyMaterial(): given any of { jwk, pem, secret } plus the alg,
//     return the canonical row shape { jwk, pem, secret, publishValue } where
//     publishValue is the string emitted to OPA at data.studio.keys[kid].
//   - validateKid(): refuse kids the compiler couldn't address as a quoted
//     literal in `data.studio.keys["<kid>"]`.
//   - ALG_KTY_MAP / SUPPORTED_ALGS: a single source of truth shared with the
//     compiler so a key uploaded here is guaranteed referenceable from a spec.
//
// The compiler emits `data.studio.keys[<kid>]` directly as the cert: argument
// to io.jwt.decode_verify and as the HMAC secret arg to crypto.hmac.<fn>.
// Those arguments are strings: PEM for asymmetric, raw secret for HMAC. So the
// publish format MUST be { [kid]: string }, never an object.

import { createPublicKey } from "node:crypto";
import { JWT_ALGS, HMAC_ALGS, SELECTOR_LITERAL_RE } from "./regoCompiler.js";

export { JWT_ALGS, HMAC_ALGS };

// Mapping from JOSE alg names to the JWK kty (and crv where relevant) we
// expect. Used to fail loudly when an admin uploads a JWK whose kty doesn't
// match the declared alg.
const ALG_TO_JWK_SHAPE = {
  EdDSA: { kty: "OKP", crv: "Ed25519" },
  ES256: { kty: "EC",  crv: "P-256"   },
  ES384: { kty: "EC",  crv: "P-384"   },
  ES512: { kty: "EC",  crv: "P-521"   },
  RS256: { kty: "RSA" },
  RS384: { kty: "RSA" },
  RS512: { kty: "RSA" },
  PS256: { kty: "RSA" },
  PS384: { kty: "RSA" },
  PS512: { kty: "RSA" },
  HS256: { kty: "oct" },
  HS384: { kty: "oct" },
  HS512: { kty: "oct" },
};

const MAX_PEM_LEN = 16384;
const MAX_SECRET_LEN = 4096;

export class TrustKeyValidationError extends Error {
  constructor(message) {
    super(message);
    this.code = "TRUST_KEY_INVALID";
  }
}

function fail(msg) {
  throw new TrustKeyValidationError(msg);
}

export function validateKid(kid) {
  if (typeof kid !== "string" || kid.length === 0) {
    fail("kid is required");
  }
  if (kid.length > 256) {
    fail("kid must be <= 256 chars");
  }
  if (!SELECTOR_LITERAL_RE.test(kid)) {
    fail("kid must match [A-Za-z0-9_.-]+ (so policies can reference it as a string literal)");
  }
  return kid;
}

export function validateAlg(alg) {
  if (typeof alg !== "string" || !JWT_ALGS.has(alg)) {
    fail(`alg must be one of: ${[...JWT_ALGS].join(", ")}`);
  }
  return alg;
}

function checkJwkShape(jwk, alg) {
  if (!jwk || typeof jwk !== "object" || Array.isArray(jwk)) {
    fail("jwk must be an object");
  }
  const expected = ALG_TO_JWK_SHAPE[alg];
  if (!expected) return; // already validated by validateAlg, defensive
  if (typeof jwk.kty !== "string" || jwk.kty !== expected.kty) {
    fail(`jwk.kty must be '${expected.kty}' for alg '${alg}' (got '${jwk.kty}')`);
  }
  if (expected.crv && jwk.crv !== expected.crv) {
    fail(`jwk.crv must be '${expected.crv}' for alg '${alg}' (got '${jwk.crv}')`);
  }
}

function jwkToPublicPem(jwk) {
  // Node's createPublicKey accepts a JWK directly. The output PEM is SPKI,
  // which is exactly what OPA's io.jwt.decode_verify expects in cert:.
  const key = createPublicKey({ key: jwk, format: "jwk" });
  return key.export({ type: "spki", format: "pem" });
}

function pemToPublicJwk(pem) {
  const key = createPublicKey(pem);
  return key.export({ format: "jwk" });
}

function isLikelyPem(s) {
  return /-----BEGIN [A-Z ]+-----[\s\S]+-----END [A-Z ]+-----/.test(s);
}

// Given a user-supplied set of fields, produce the canonical storage row plus
// the value the publisher will write to OPA. Throws TrustKeyValidationError
// on any inconsistency so the route can return a 400 with the message.
//
// Inputs (one of):
//   asymmetric: { alg, jwk }  OR  { alg, pem }  (one is required, the other is derived)
//   hmac:       { alg, secret }                  (jwk derivable; pem unused)
//
// Returns: { jwk, pem, secret, publishValue }
export function normalizeKeyMaterial({ alg, jwk = null, pem = null, secret = null } = {}) {
  validateAlg(alg);
  const isHmac = HMAC_ALGS.has(alg);

  if (isHmac) {
    let raw = secret;
    if (!raw && jwk && typeof jwk.k === "string") {
      // RFC 7518 §6.4: the secret is base64url in the "k" parameter.
      try {
        raw = Buffer.from(jwk.k, "base64url").toString("utf8");
      } catch {
        fail("jwk.k must be base64url-encoded");
      }
    }
    if (typeof raw !== "string" || raw.length === 0) {
      fail("HMAC algs require 'secret' (or a JWK with 'k')");
    }
    if (raw.length > MAX_SECRET_LEN) {
      fail(`secret exceeds ${MAX_SECRET_LEN} chars`);
    }
    const finalJwk = jwk || {
      kty: "oct",
      alg,
      k: Buffer.from(raw, "utf8").toString("base64url"),
    };
    checkJwkShape(finalJwk, alg);
    return { jwk: finalJwk, pem: null, secret: raw, publishValue: raw };
  }

  // Asymmetric path: need either jwk or pem; derive the missing one.
  let finalJwk = jwk;
  let finalPem = pem;

  if (finalJwk) {
    checkJwkShape(finalJwk, alg);
    if (!finalPem) {
      try { finalPem = jwkToPublicPem(finalJwk); }
      catch (e) { fail(`could not derive PEM from JWK: ${e.message}`); }
    }
  } else if (finalPem) {
    if (typeof finalPem !== "string" || finalPem.length === 0) {
      fail("pem must be a non-empty string");
    }
    if (finalPem.length > MAX_PEM_LEN) {
      fail(`pem exceeds ${MAX_PEM_LEN} chars`);
    }
    if (!isLikelyPem(finalPem)) {
      fail("pem is not a recognizable PEM block");
    }
    try { finalJwk = pemToPublicJwk(finalPem); }
    catch (e) { fail(`could not parse PEM: ${e.message}`); }
    checkJwkShape(finalJwk, alg);
  } else {
    fail(`alg '${alg}' requires 'jwk' or 'pem'`);
  }

  // Stamp alg into JWK if absent so consumers can self-describe.
  if (!finalJwk.alg) finalJwk = { ...finalJwk, alg };

  return { jwk: finalJwk, pem: finalPem, secret: null, publishValue: finalPem };
}

// Pluck the publish value from a stored row. Pure — does not touch the DB or
// the network. Returns null if the row is not publishable (revoked, or
// jwks_url row not yet hydrated).
export function publishValueFromRow(row) {
  if (!row || row.status !== "active") return null;
  if (HMAC_ALGS.has(row.alg)) {
    return typeof row.secret === "string" && row.secret.length > 0 ? row.secret : null;
  }
  return typeof row.pem === "string" && row.pem.length > 0 ? row.pem : null;
}

// Fetch a JWKS document at `url`, find the entry whose kid matches, and
// normalize it into our row shape. Throws on transport, parse, or kid-miss.
// Bounded response size (256 KiB), 5s abort timeout, JSON content-type check.
export async function fetchJwksEntry(url, kid, alg) {
  if (typeof url !== "string" || !/^https?:\/\//i.test(url)) {
    fail("jwks_url must be an http(s) URL");
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  let res;
  try {
    res = await fetch(url, {
      signal: controller.signal,
      headers: { Accept: "application/json" },
    });
  } finally {
    clearTimeout(timer);
  }
  if (!res.ok) {
    throw new Error(`JWKS fetch ${url} -> HTTP ${res.status}`);
  }
  const ct = res.headers.get("content-type") || "";
  if (!/json/i.test(ct)) {
    throw new Error(`JWKS fetch ${url} -> unexpected content-type '${ct}'`);
  }
  // Bound the body. fetch doesn't expose a content-length cap; we read the
  // whole text and reject anything over 256 KiB, which is enormous for a JWKS.
  const text = await res.text();
  if (text.length > 256 * 1024) {
    throw new Error("JWKS response exceeds 256 KiB");
  }
  let doc;
  try { doc = JSON.parse(text); }
  catch { throw new Error(`JWKS response is not valid JSON`); }
  if (!doc || !Array.isArray(doc.keys)) {
    throw new Error("JWKS document missing .keys array");
  }
  const jwk = doc.keys.find((k) => k && k.kid === kid);
  if (!jwk) {
    throw new Error(`kid '${kid}' not present in JWKS document`);
  }
  // Reuse the normalizer so the derived PEM matches inline-upload semantics
  // exactly. Will throw TrustKeyValidationError on kty/crv mismatch.
  return normalizeKeyMaterial({ alg, jwk });
}

// Hide the secret column when echoing back to API consumers. The route layer
// uses store.trustKeyRowForAudit() for audit payloads; this helper is for
// non-audited reads (GET /api/trust-keys) where we still don't want the
// shared HMAC secret on the wire.
export function trustKeyForResponse(row) {
  if (!row) return null;
  const safe = { ...row };
  if (safe.secret) safe.secret = "[REDACTED]";
  // Don't echo the JWK 'k' member (also the HMAC secret).
  if (safe.jwk && typeof safe.jwk === "object" && typeof safe.jwk.k === "string") {
    safe.jwk = { ...safe.jwk, k: "[REDACTED]" };
  }
  return safe;
}
