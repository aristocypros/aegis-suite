// jwksCache.js — JWKS fetcher used by the jwt-mode verifier.
//
// We use jose's createRemoteJWKSet, which:
//   - fetches the JWKS lazily on the first verify call,
//   - caches the document for `cacheMaxAge` ms,
//   - cooldowns between forced refreshes when an unknown kid is presented.
//
// The platform publishes its Ed25519 signing key at /.well-known/jwks.json
// on the backend. In production the PEP should hit that URL through the
// internal network (default http://backend:3001/.well-known/jwks.json).

import { createRemoteJWKSet } from "jose";

export function createJwksCache({ url, cooldownMs = 30_000, cacheMaxAgeMs = 600_000 }) {
  if (typeof url !== "string" || !/^https?:\/\//i.test(url)) {
    throw new Error("createJwksCache: url must be http(s)");
  }
  const remoteSet = createRemoteJWKSet(new URL(url), {
    cooldownDuration: cooldownMs,
    cacheMaxAge: cacheMaxAgeMs,
  });
  return {
    // jose's JWKS object is a callable used by jwtVerify; expose it directly.
    getKeySet() { return remoteSet; },
    url,
  };
}
