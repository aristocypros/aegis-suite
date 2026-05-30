// nonceCache.js — replay protection for HMAC-mode requests.
//
// Key = `${callerId}:${nonce}`. TTL is set to twice the timestamp-skew
// window so that any request still within the validity window cannot be
// replayed even if it was first seen at the very edge of the window.
//
// The cache is in-memory. Multi-replica PEP deployments need a shared store
// (Redis) — wired in once AUTH-01's RATE_LIMIT_STORE adapter lands. For
// single-replica deployments (the laptop default and most on-prem setups)
// in-memory is fine.

import { LRUCache } from "lru-cache";

export function createNonceCache({ maxEntries = 50000, ttlMs }) {
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
    throw new Error("createNonceCache: ttlMs must be a positive number");
  }
  const cache = new LRUCache({
    max: maxEntries,
    ttl: ttlMs,
    ttlAutopurge: true,
  });

  return {
    // Returns true if the nonce was already seen; false otherwise.
    // Insertion is performed atomically with the check so concurrent
    // requests with the same nonce both see "seen" after the first.
    checkAndRemember(callerId, nonce) {
      const key = `${callerId}:${nonce}`;
      if (cache.has(key)) return true;
      cache.set(key, 1);
      return false;
    },
    size() { return cache.size; },
  };
}
