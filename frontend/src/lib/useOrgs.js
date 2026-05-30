// useOrgs — small hook that fetches the visible orgs list once and exposes
// { orgs, lookup(id) } so admin modals can render org NAMES instead of
// opaque UUIDs in their lists/selectors.
//
// Sub-admins get a 403 from /api/orgs (root-only route), which we swallow
// and treat as "no orgs loaded" — those screens fall back to displaying
// the bare orgId. Root gets the full list and a Map of id → name.
//
// Cached per component instance; if a modal needs cross-instance sharing
// later we can lift this into a singleton, but for v1 the call is cheap
// enough (one row per org, infrequently opened).
import { useEffect, useState, useCallback } from "react";
import { api } from "./api.js";

export function useOrgs() {
  const [orgs, setOrgs] = useState([]);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    let cancelled = false;
    api.listOrgs()
      .then((list) => { if (!cancelled) { setOrgs(list); setLoaded(true); } })
      .catch(() => { if (!cancelled) setLoaded(true); });
    return () => { cancelled = true; };
  }, []);

  const lookup = useCallback((id) => {
    if (!id) return "(global)";
    const hit = orgs.find((o) => o.id === id);
    if (hit) return hit.name;
    // Fallback for sub-admins (who can't list orgs) or stale ids — show
    // a short prefix so the column isn't empty/useless.
    return typeof id === "string" ? id.slice(0, 8) + "…" : String(id);
  }, [orgs]);

  return { orgs, lookup, loaded };
}
