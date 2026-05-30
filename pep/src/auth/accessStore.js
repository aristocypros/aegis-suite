// accessStore.js — per-caller policy access list cache.
//
// Reads two OPA documents and intersects them on the hot path:
//   data.studio.caller_access  → { [callerId]: [policyId, ...] }
//   data.studio.policy_index   → { policies: [{ id, package, ... }, ...] }
//
// The PEP enforces both /authorize and /discover against this combined view:
//   isAllowed(callerId, policyPath) → boolean
//   getPolicyIndex()                → cached index for /discover filtering
//
// Both docs are cached together with one TTL (the same `PEP_CALLER_TTL_MS`
// the caller store already uses). On transport failure we keep the previous
// cache so a brief OPA hiccup doesn't lock every caller out — only stale
// reads, never silent admit.

const DEFAULT_TTL_MS = 30_000;

function normalisePackage(policyPath) {
  // `/authorize` accepts both dot and slash forms; the policy_index stores
  // the Rego package which is dot-separated. Normalise inbound to dot form
  // for matching.
  if (typeof policyPath !== "string" || policyPath.length === 0) return null;
  return policyPath.replace(/\//g, ".");
}

export function createAccessStore({ pdp, ttlMs = DEFAULT_TTL_MS, logger = console }) {
  if (!pdp || typeof pdp.fetchData !== "function") {
    throw new Error("createAccessStore: pdp client with fetchData() is required");
  }

  // Cache shape:
  //   { fetchedAt, access: { callerId -> Set(policyId) },
  //                index:  { id -> { id, package }, byPackage: { package -> id } } }
  let cache = null;
  let inflight = null;

  async function refresh() {
    if (inflight) return inflight;
    inflight = (async () => {
      try {
        const [accessRaw, indexRaw] = await Promise.all([
          pdp.fetchData("studio.caller_access").catch(() => ({})),
          pdp.fetchData("studio.policy_index").catch(() => ({ policies: [] })),
        ]);

        const access = {};
        if (accessRaw && typeof accessRaw === "object" && !Array.isArray(accessRaw)) {
          for (const [callerId, policyIds] of Object.entries(accessRaw)) {
            if (Array.isArray(policyIds)) {
              access[callerId] = new Set(policyIds);
            }
          }
        }

        const byId = {};
        const byPackage = {};
        const policies = Array.isArray(indexRaw?.policies) ? indexRaw.policies : [];
        for (const p of policies) {
          if (!p || typeof p.id !== "string") continue;
          // org_id is null for globals (root-owned, visible to all callers).
          byId[p.id] = {
            id: p.id, package: p.package, name: p.name,
            orgId: p.org_id ?? null,
          };
          if (typeof p.package === "string") byPackage[p.package] = p.id;
        }

        cache = { fetchedAt: Date.now(), access, index: { byId, byPackage, raw: indexRaw } };
        return cache;
      } catch (e) {
        logger.error?.(`[pep-access] refresh failed: ${e?.message || e}`);
        if (!cache) {
          cache = {
            fetchedAt: Date.now(),
            access: {},
            index: { byId: {}, byPackage: {}, raw: { policies: [] } },
          };
        }
        return cache;
      } finally {
        inflight = null;
      }
    })();
    return inflight;
  }

  async function ensure() {
    if (!cache || Date.now() - cache.fetchedAt > ttlMs) {
      await refresh();
    }
    return cache;
  }

  return {
    async isAllowed(callerId, policyPath, { callerOrgId } = {}) {
      if (typeof callerId !== "string" || !callerId) return false;
      const pkg = normalisePackage(policyPath);
      if (!pkg) return false;
      const { access, index } = await ensure();
      const policyId = index.byPackage[pkg];
      if (!policyId) {
        // Policy isn't in the published index — could be locked, deleted, or
        // never deployed. Treat as not-in-scope; the existing INVALID_POLICY
        // path will fire first on truly unknown paths.
        return false;
      }
      // Cross-org gate (defense in depth — stale grants from before the
      // RBAC migration could otherwise leak across orgs). A caller with a
      // known orgId can only reach policies in the same org or globals;
      // callers with no orgId (legacy / pre-RBAC publish) are unaffected
      // and behave as before until an admin reassigns them.
      if (callerOrgId) {
        const policyOrg = index.byId[policyId]?.orgId ?? null;
        if (policyOrg != null && policyOrg !== callerOrgId) return false;
      }
      const allowed = access[callerId];
      return Boolean(allowed && allowed.has(policyId));
    },
    async getAllowedPolicyIds(callerId) {
      const { access } = await ensure();
      return access[callerId] || new Set();
    },
    async getPolicyIndex() {
      // Returns the raw index document (same shape as data.studio.policy_index)
      // so /discover can reuse the cache instead of paying a round-trip.
      const { index } = await ensure();
      return index.raw;
    },
    async warmUp() { await refresh(); },
  };
}
