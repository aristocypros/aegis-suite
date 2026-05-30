// callerStore.js — reads the PEP caller table from OPA at data.studio.callers.
//
// The backend's publishPepCallers writes the active caller set to OPA on
// every CRUD mutation and at startup. We cache the document in-memory with
// a short TTL so a /authorize call doesn't need a round-trip to OPA on the
// hot path; revocation propagates within the TTL.
//
// Shape of data.studio.callers (per PEP-01, multi-mode):
//   {
//     "<caller_id>": {
//       "auth_mode":   "hmac" | "mtls" | "jwt",   // REQUIRED — declared mode
//       "hmac_secret": "<base64url>",             // hmac-mode rows only
//       "allowed_cn":  "<CN>",                    // mtls-mode rows only
//       "jwt_subject": "<sub>",                   // jwt-mode rows, optional pin
//       "tenant":      "<tenant>",                // optional, informational
//       "org_id":      "<uuid>"|null              // RBAC org ownership — the
//                                                 // PEP filters /discover by
//                                                 // this so a caller in org A
//                                                 // only sees policies in
//                                                 // org A (or global policies
//                                                 // with org_id=null).
//     }, ...
//   }
//
// The dispatcher uses auth_mode to assert the presented credential kind
// matches the row's declared mode; the lookup helpers below scope by mode
// so an mtls row's CN can't accidentally satisfy a jwt lookup, etc.

const DEFAULT_TTL_MS = 30_000;

export function createCallerStore({ pdp, ttlMs = DEFAULT_TTL_MS, logger = console }) {
  if (!pdp || typeof pdp.fetchData !== "function") {
    throw new Error("createCallerStore: pdp client with fetchData() is required");
  }

  let cache = null;       // { fetchedAt, callers }
  let inflight = null;    // promise to dedupe concurrent refreshes

  async function refresh() {
    if (inflight) return inflight;
    inflight = (async () => {
      try {
        const data = await pdp.fetchData("studio.callers");
        const callers = (data && typeof data === "object" && !Array.isArray(data))
          ? data : {};
        cache = { fetchedAt: Date.now(), callers };
        return callers;
      } catch (e) {
        // Keep the previous cache on transport failure so a momentary OPA
        // hiccup doesn't lock every caller out. The startup load is the
        // only place a failure surfaces as "no callers yet" — anywhere else
        // we fall back to the last known-good map.
        logger.error?.(`[pep-auth] caller refresh failed: ${e?.message || e}`);
        if (!cache) cache = { fetchedAt: Date.now(), callers: {} };
        return cache.callers;
      } finally {
        inflight = null;
      }
    })();
    return inflight;
  }

  async function getAll() {
    if (!cache || Date.now() - cache.fetchedAt > ttlMs) {
      await refresh();
    }
    return cache.callers;
  }

  return {
    async lookup(callerId) {
      if (typeof callerId !== "string" || callerId.length === 0) return null;
      const all = await getAll();
      const row = all[callerId];
      return row && typeof row === "object" ? row : null;
    },
    async findByAllowedCn(cn) {
      // Returns the first row whose allowed_cn matches, regardless of mode.
      // The mtls verifier separately asserts row.auth_mode === 'mtls', so
      // a non-mtls row that happens to carry a stray allowed_cn surfaces as
      // an explicit auth_mode_mismatch rather than silently being admitted.
      if (typeof cn !== "string" || cn.length === 0) return null;
      const all = await getAll();
      for (const [callerId, row] of Object.entries(all)) {
        if (row && row.allowed_cn === cn) {
          return { callerId, row };
        }
      }
      return null;
    },
    async findByJwtSubject(sub) {
      // Only jwt-mode rows participate in jwt-sub lookup. An hmac row whose
      // caller_id happens to equal a JWT sub must not be matched here.
      if (typeof sub !== "string" || sub.length === 0) return null;
      const all = await getAll();
      for (const [callerId, row] of Object.entries(all)) {
        if (!row || row.auth_mode !== "jwt") continue;
        const expected = row.jwt_subject || callerId;
        if (expected === sub) return { callerId, row };
      }
      return null;
    },
    async warmUp() { await refresh(); },
  };
}
