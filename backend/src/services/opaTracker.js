// opaTracker.js — in-memory registry for active OPA replicas.
//
// OPA replicas poll /bundle/aegis.tar.gz dynamically. By recording every poll,
// we can discover the fleet shape in-memory without persistent DB state or extra
// configuration. Replicas that stop polling are automatically pruned after 60s.

const replicas = new Map(); // ip -> status object
const revisionPoliciesCache = new Map(); // revision -> array of policy metadata

/**
 * Record a poll request from an OPA replica.
 * Computes the replica's poll interval by checking the elapsed time since the previous poll.
 */
export function recordPoll(ip, userAgent, ifNoneMatch, activeRevision, responseStatus, orgId = null) {
  const now = Date.now();
  const existing = replicas.get(ip);
  let pollingInterval = null;

  if (existing) {
    // Calculate seconds elapsed since last request
    pollingInterval = Math.round((now - existing.lastPollAt) / 1000);
  }

  // Clean up any double quotes in ETag headers
  const reportedRevision = ifNoneMatch ? ifNoneMatch.replace(/"/g, "") : null;
  const target = activeRevision ? activeRevision.replace(/"/g, "") : null;
  const inSync = reportedRevision === target;

  replicas.set(ip, {
    ip,
    userAgent,
    lastPollAt: now,
    // Keep dynamic interval if calculated, or fallback to previously calculated value
    pollingInterval: (pollingInterval && pollingInterval > 0) ? pollingInterval : (existing ? existing.pollingInterval : null),
    reportedRevision,
    targetRevision: target,
    inSync,
    lastResponseStatus: responseStatus,
    orgId: orgId || null,
  });
}

/**
 * Returns a list of active OPA replicas. Prunes stale ones (> 60s since last poll).
 */
export function getReplicas() {
  const now = Date.now();
  for (const [ip, data] of replicas.entries()) {
    if (now - data.lastPollAt > 60000) {
      replicas.delete(ip);
    }
  }
  return Array.from(replicas.values());
}

/**
 * Cache the policies active at a specific bundle revision.
 */
export function recordRevisionPolicies(revision, policies) {
  const rev = revision ? revision.replace(/"/g, "") : "";
  if (!rev) return;

  revisionPoliciesCache.set(rev, policies);

  // Limit cache size to 50 to prevent memory exhaustion
  if (revisionPoliciesCache.size > 50) {
    const firstKey = revisionPoliciesCache.keys().next().value;
    revisionPoliciesCache.delete(firstKey);
  }
}

/**
 * Look up the policies that were bundled in a given revision.
 */
export function getPoliciesForRevision(revision) {
  const rev = revision ? revision.replace(/"/g, "") : "";
  return revisionPoliciesCache.get(rev) || null;
}
