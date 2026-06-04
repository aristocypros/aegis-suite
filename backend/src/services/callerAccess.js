// callerAccess.js — pure computation of the per-caller policy allowlist that
// the PEP enforces on /authorize and filters /discover against.
//
// The published doc (data.studio.caller_access) shape is
// { [callerId]: [policyId, ...] }, computed as the UNION of two sources so
// the PEP only ever sees the final answer:
//
//   1) Explicit grants in pep_caller_policy_access (audit-logged).
//   2) Tag matches: every active policy whose `tags` overlap the caller's
//      `scope_tags`. New policies tagged later auto-appear in the caller's
//      allowlist on the next build without an admin action.
//
// Locked policies are filtered out of BOTH sources so the published doc never
// advertises a policy the PEP can't currently service. Underlying DB rows
// stay; the next build after unlock restores them.
//
// Extracted from server.js's old publishCallerAccess so the bundle builder
// (services/opaBundle.js) and any legacy publisher share one implementation.

// Returns { access, stats } where:
//   access = { [callerId]: [policyId, ...] }  (deterministic key/element order)
//   stats  = { callers, totalGrants, explicitTotal, tagTotal }
export function buildCallerAccess({ grants = [], policies = [], callers = [] } = {}) {
  const activePolicyById = new Map(
    (Array.isArray(policies) ? policies : [])
      .filter((p) => p && !p.locked)
      .map((p) => [p.id, p])
  );

  // Per-caller Set of granted policy ids — Set dedupes the overlap between
  // explicit grants and tag matches.
  const allowed = new Map();
  let explicitTotal = 0;
  let tagTotal = 0;

  function add(callerId, policyId, source) {
    let set = allowed.get(callerId);
    if (!set) { set = new Set(); allowed.set(callerId, set); }
    if (!set.has(policyId)) {
      set.add(policyId);
      if (source === "explicit") explicitTotal++;
      else tagTotal++;
    }
  }

  // 1) Explicit grants — drop any pointing at locked / missing policies.
  for (const g of Array.isArray(grants) ? grants : []) {
    if (!activePolicyById.has(g.policyId)) continue;
    add(g.callerId, g.policyId, "explicit");
  }

  // 2) Tag matches — only for active callers with non-empty scope_tags.
  for (const c of Array.isArray(callers) ? callers : []) {
    if (c.status !== "active") continue;
    if (!c.scopeTags || c.scopeTags.length === 0) continue;
    const scope = new Set(c.scopeTags);
    for (const [pid, p] of activePolicyById) {
      if (!p.tags || p.tags.length === 0) continue;
      if (p.tags.some((t) => scope.has(t))) add(c.callerId, pid, "tag");
    }
  }

  // Deterministic ordering so the bundle revision hash is stable when the
  // underlying set hasn't changed. Sort caller ids and the policy id arrays.
  const access = {};
  for (const cid of [...allowed.keys()].sort()) {
    access[cid] = [...allowed.get(cid)].sort();
  }
  const totalGrants = Object.values(access).reduce((n, arr) => n + arr.length, 0);
  return {
    access,
    stats: { callers: Object.keys(access).length, totalGrants, explicitTotal, tagTotal },
  };
}
