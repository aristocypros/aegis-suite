// jwksFetcher.js — background poller for trust-store rows whose source_kind
// is 'jwks_url'. On each tick it fetches every due URL, picks the matching
// kid out of the JWKS document, derives PEM, and updates the row in place.
// If anything changed, it invalidates the OPA bundle so the refreshed
// material reaches the fleet on the next bundle poll.
//
// Refresh is deliberately NOT routed through withAudit: the JWKS-URL BYO
// path is a high-volume background refresh, comparable to AUD-07's PEP
// decision logs, and routing every minute's tick through the audit chain
// would dwarf the actual mutation events. Admin-initiated refresh via
// POST /api/trust-keys/:kid/refresh IS audited.

import * as store from "./storage.js";
import { fetchJwksEntry, TrustKeyValidationError } from "./trustKeys.js";

const DEFAULT_TTL_SECONDS = 300;

function isDue(row, nowMs) {
  const ttl = (row.jwksTtlSeconds && row.jwksTtlSeconds > 0)
    ? row.jwksTtlSeconds
    : DEFAULT_TTL_SECONDS;
  if (!row.jwksLastFetchedAt) return true;
  const last = new Date(row.jwksLastFetchedAt).getTime();
  if (!Number.isFinite(last)) return true;
  return nowMs - last >= ttl * 1000;
}

// Refresh exactly one row. Returns true iff anything changed (publish-worthy).
// Used both by the periodic tick and by the admin `/refresh` route.
export async function refreshOne(kid) {
  const row = await store.getTrustKey(kid);
  if (!row) return false;
  if (row.sourceKind !== "jwks_url") return false;
  if (!row.jwksUrl) {
    await store.recordTrustKeyJwksError(kid, "jwks_url not set");
    return false;
  }
  try {
    const { jwk, pem } = await fetchJwksEntry(row.jwksUrl, row.kid, row.alg);
    const prevPem = row.pem || null;
    const updated = await store.touchTrustKeyJwks(kid, {
      jwk, pem, x5c: null, error: null,
    });
    return updated && updated.pem !== prevPem;
  } catch (e) {
    const msg = e instanceof TrustKeyValidationError
      ? `validation: ${e.message}`
      : (e?.message || String(e));
    await store.recordTrustKeyJwksError(kid, msg).catch(() => {});
    return false;
  }
}

async function tick({ publish, log }) {
  let rows;
  try {
    rows = await store.listActiveJwksUrlTrustKeys();
  } catch (e) {
    log.warn(`[jwks-fetcher] list failed: ${e.message}`);
    return;
  }
  if (rows.length === 0) return;
  const nowMs = Date.now();
  let changed = false;
  for (const row of rows) {
    if (!isDue(row, nowMs)) continue;
    try {
      const did = await refreshOne(row.kid);
      if (did) changed = true;
    } catch (e) {
      log.warn(`[jwks-fetcher] refresh ${row.kid} failed: ${e.message}`);
    }
  }
  if (changed) {
    try { await publish("jwks.refresh"); }
    catch (e) { log.warn(`[jwks-fetcher] post-refresh publish failed: ${e.message}`); }
  }
}

// Start the periodic poller. Returns a handle with stop() so callers can
// dispose during tests / shutdown. Logs to the given logger (defaults to
// console) so tests can capture output.
export function startJwksFetcher({ publish, intervalMs = 30000, log = console } = {}) {
  if (typeof publish !== "function") {
    throw new Error("startJwksFetcher: publish callback required");
  }
  const safeLog = {
    info: log.info?.bind(log) || log.log?.bind(log) || (() => {}),
    warn: log.warn?.bind(log) || log.error?.bind(log) || (() => {}),
  };
  const handle = setInterval(() => {
    tick({ publish, log: safeLog }).catch((e) => {
      safeLog.warn(`[jwks-fetcher] tick crashed: ${e?.message || e}`);
    });
  }, intervalMs);
  // Don't keep Node alive solely because of this timer.
  if (typeof handle.unref === "function") handle.unref();
  safeLog.info(`[jwks-fetcher] started (interval=${intervalMs}ms)`);
  return {
    stop() { clearInterval(handle); },
    tickNow: () => tick({ publish, log: safeLog }),
  };
}
