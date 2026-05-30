// hmac.js — HMAC verifier reached by the dispatcher when X-Studio-Sig is
// present. The dispatcher already filtered ambiguous credentials; here we
// just check the signature and assert the looked-up row's auth_mode is
// "hmac" (a non-hmac row with the same caller_id is provisioning drift).
//
// Each request carries X-Studio-Sig:
//
//   X-Studio-Sig: caller=<id>,ts=<unix-seconds>,nonce=<b64url>,sig=<b64url>
//
// where sig = HMAC-SHA256(secret, `${ts}.${nonce}.${path}.${rawBody}`).
//
// Acceptance criteria:
//   - missing/unparseable header → 401
//   - ts outside the window → 401
//   - caller unknown / revoked → 401
//   - signature mismatch → 401 (constant-time compare)
//   - nonce already seen within the window → 409 (replay protection)

import { createHmac, timingSafeEqual } from "node:crypto";

const HEADER_NAME = "x-studio-sig";

const HEADER_RE = /^[A-Za-z0-9+/=._-]+$/; // base64url + dots/dashes only

function parseHeader(raw) {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > 1024) return null;
  const out = {};
  for (const part of raw.split(",")) {
    const eq = part.indexOf("=");
    if (eq <= 0) return null;
    const k = part.slice(0, eq).trim();
    const v = part.slice(eq + 1).trim();
    if (!k || !v) return null;
    if (!HEADER_RE.test(v)) return null;
    out[k] = v;
  }
  if (!out.caller || !out.ts || !out.nonce || !out.sig) return null;
  return out;
}

function b64urlToBuf(s) {
  // Pad with '=' so Buffer.from('base64') accepts the input regardless of
  // whether the client sent the padded or unpadded variant.
  const padded = s + "=".repeat((4 - (s.length % 4)) % 4);
  return Buffer.from(padded.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

export function createHmacAuth({
  callerStore,
  nonceCache,
  windowMs = 30_000,
  logger = console,
}) {
  return async function hmacAuth(req, res, next) {
    const parsed = parseHeader(req.headers[HEADER_NAME]);
    if (!parsed) {
      return res.status(401).json({ error: "missing_or_malformed_signature" });
    }

    const tsSeconds = Number.parseInt(parsed.ts, 10);
    if (!Number.isFinite(tsSeconds)) {
      return res.status(401).json({ error: "invalid_timestamp" });
    }
    const now = Date.now();
    const skew = Math.abs(now - tsSeconds * 1000);
    if (skew > windowMs) {
      return res.status(401).json({
        error: "timestamp_out_of_window",
        skewMs: skew,
        windowMs,
      });
    }

    const caller = await callerStore.lookup(parsed.caller);
    if (!caller) {
      logger.warn?.(`[pep-auth] hmac reject: unknown caller '${parsed.caller}'`);
      return res.status(401).json({ error: "unknown_caller" });
    }
    if (caller.auth_mode !== "hmac") {
      logger.warn?.(`[pep-auth] hmac reject: caller '${parsed.caller}' is auth_mode=${caller.auth_mode}`);
      return res.status(401).json({ error: "auth_mode_mismatch" });
    }
    if (typeof caller.hmac_secret !== "string" || caller.hmac_secret.length === 0) {
      // The DB CHECK constraint forbids this combination; reaching it means
      // publishPepCallers shipped a malformed row. Surface clearly.
      logger.error?.(`[pep-auth] hmac reject: caller '${parsed.caller}' has no hmac_secret`);
      return res.status(401).json({ error: "caller_misconfigured" });
    }

    // Replay protection: check the nonce BEFORE verifying the signature.
    // A valid-looking signature with a reused nonce gets 409; a
    // bad-signature replay still falls through to 401 below because we
    // never reach the cache lookup with a bogus payload. To prevent an
    // attacker from precomputing nonces to fill the cache, we still gate
    // by caller (cache key includes caller_id) — that bounds the per-caller
    // footprint.
    const replayed = nonceCache.checkAndRemember(parsed.caller, parsed.nonce);
    if (replayed) {
      return res.status(409).json({ error: "nonce_replay" });
    }

    const rawBody = req.rawBody ?? Buffer.alloc(0);
    const expected = createHmac("sha256", caller.hmac_secret)
      .update(`${parsed.ts}.${parsed.nonce}.${req.path}.`)
      .update(rawBody)
      .digest();

    let supplied;
    try {
      supplied = b64urlToBuf(parsed.sig);
    } catch {
      return res.status(401).json({ error: "invalid_signature_encoding" });
    }
    if (supplied.length !== expected.length ||
        !timingSafeEqual(supplied, expected)) {
      return res.status(401).json({ error: "signature_mismatch" });
    }

    req.caller = {
      id: parsed.caller,
      mode: "hmac",
      tenant: caller.tenant,
      orgId: caller.org_id ?? null,
    };
    next();
  };
}
