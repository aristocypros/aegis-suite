import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../lib/api.js";
import { useOrgs } from "../lib/useOrgs.js";

// Compact relative-time formatter for the "last modified … ago" hint shown
// under each sidebar item (root view). Falls back to a locale string for
// anything older than a week — keeps the line short.
function formatRelative(iso) {
  if (!iso) return "";
  const then = new Date(iso).getTime();
  if (!Number.isFinite(then)) return "";
  const diffSec = Math.max(0, Math.floor((Date.now() - then) / 1000));
  if (diffSec < 45) return "just now";
  if (diffSec < 90) return "1m ago";
  const min = Math.floor(diffSec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.floor(hr / 24);
  if (day < 7) return `${day}d ago`;
  try { return new Date(iso).toLocaleDateString(); }
  catch { return ""; }
}

// Group key derived from the Rego package: first two segments when the
// package has 3+ levels (e.g. "digital_assets.compliance.blackout" →
// "digital_assets.compliance"), else the first segment ("studio.foo" →
// "studio"). This produces ~10–15 groups across the 55 bundled templates,
// granular enough to scan but coarse enough to be useful.
function groupKey(pkg) {
  if (!pkg) return "(no package)";
  const parts = pkg.split(".");
  if (parts.length >= 3) return `${parts[0]}.${parts[1]}`;
  return parts[0] || "(no package)";
}

const FILTERS = [
  { key: "all", label: "All" },
  { key: "active", label: "Active" },
  { key: "locked", label: "Locked" },
];

// Split the search box into `tag:foo` tokens + remaining fuzzy text.
// Multiple tag: tokens are ANDed against the policy's tags array; the
// fuzzy text continues to match name/package/description as before.
function parseSearchQuery(raw) {
  const tagTerms = new Set();
  const rest = [];
  for (const token of (raw || "").split(/\s+/)) {
    if (!token) continue;
    const m = token.match(/^tag:([A-Za-z0-9_-]+)$/i);
    if (m) tagTerms.add(m[1].toLowerCase());
    else rest.push(token);
  }
  return { tagTerms, fuzzy: rest.join(" ") };
}

// Cap items rendered at once so the DOM stays small no matter how many
// policies the backend serves. 50 is comfortable to scroll inside the
// sidebar viewport without becoming a wall of text.
const PAGE_SIZE = 50;

export default function Sidebar({ policies, activeId, onSelect, onNew, onShowTemplates, collapsed, onToggleCollapsed, currentUser, templates = [], onSelectTemplate, policyHealth = {}, onClone }) {
  const isRoot = !!currentUser?.isRoot;
  if (collapsed) {
    return (
      <aside className="sidebar sidebar--collapsed">
        <button
          type="button"
          className="sidebar-toggle sidebar-toggle--expand"
          onClick={onToggleCollapsed}
          title="Expand sidebar"
          aria-label="Expand sidebar"
          aria-expanded="false"
        >
          ›
        </button>
      </aside>
    );
  }
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("all");
  const [tagFilter, setTagFilter] = useState(() => new Set());
  
  // Three-level navigation state
  const [selectedOrgId, setSelectedOrgId] = useState(null);
  const [selectedPackage, setSelectedPackage] = useState(null);
  
  const [page, setPage] = useState(1);
  const [newMenuOpen, setNewMenuOpen] = useState(false);
  const dropdownRef = useRef(null);

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setNewMenuOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const presets = useMemo(() => {
    if (!templates || templates.length === 0) return [];
    const picked = [];
    const cats = new Set();
    for (const t of templates) {
      if (!cats.has(t.category)) {
        cats.add(t.category);
        picked.push(t);
      }
      if (picked.length >= 5) break;
    }
    if (picked.length < 5) {
      for (const t of templates) {
        if (!picked.some(p => p.id === t.id)) {
          picked.push(t);
        }
        if (picked.length >= 5) break;
      }
    }
    return picked;
  }, [templates]);

  const searchRef = useRef(null);

  const { lookup: orgName } = useOrgs();
  const [lastMod, setLastMod] = useState({}); // { [policyId]: { actorUsername, action, createdAt } }
  const policyIdsKey = useMemo(
    () => policies.map((p) => p.id).sort().join(","),
    [policies]
  );
  useEffect(() => {
    if (!isRoot || policies.length === 0) return undefined;
    let cancelled = false;
    (async () => {
      const entries = await Promise.all(
        policies.map(async (p) => {
          try {
            const list = await api.listAudit({ resourceId: p.id, limit: 1 });
            const e = Array.isArray(list?.entries) ? list.entries[0] : (Array.isArray(list) ? list[0] : null);
            if (!e) return [p.id, null];
            return [p.id, {
              actorUsername: e.actorUsername,
              action: e.action,
              createdAt: e.createdAt,
            }];
          } catch {
            return [p.id, null];
          }
        })
      );
      if (cancelled) return;
      const next = {};
      for (const [id, v] of entries) if (v) next[id] = v;
      setLastMod(next);
    })();
    return () => { cancelled = true; };
  }, [isRoot, policyIdsKey, policies]);

  // ⌘K / Ctrl+K focuses the search; Escape inside it clears + blurs.
  useEffect(() => {
    const onKey = (e) => {
      const meta = e.metaKey || e.ctrlKey;
      if (meta && (e.key === "k" || e.key === "K")) {
        e.preventDefault();
        searchRef.current?.focus();
        searchRef.current?.select();
      } else if (e.key === "Escape" && document.activeElement === searchRef.current) {
        if (query) setQuery("");
        else searchRef.current?.blur();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [query]);

  // Reset pagination whenever the visible set changes shape.
  useEffect(() => {
    setPage(1);
  }, [query, filter, selectedOrgId, selectedPackage, tagFilter]);

  // Auto-expand/drill to active policy folders when selected
  useEffect(() => {
    if (activeId && policies.length > 0) {
      const activePolicy = policies.find(p => p.id === activeId);
      if (activePolicy) {
        if (isRoot) {
          setSelectedOrgId(activePolicy.orgId || "global");
        }
        setSelectedPackage(activePolicy.package);
      }
    }
  }, [activeId, policies, isRoot]);

  // Parse the search box once per render: split into `tag:foo` AND-terms
  // and a fuzzy remainder. Reused below in `filtered` and `mode`.
  const { tagTerms: searchTagTerms, fuzzy } = useMemo(
    () => parseSearchQuery(query),
    [query]
  );
  const fuzzyLc = fuzzy.trim().toLowerCase();

  const catalogueTags = useMemo(() => {
    const all = new Set();
    for (const p of policies) for (const t of (p.tags || [])) all.add(t);
    return [...all].sort();
  }, [policies]);

  const filtered = useMemo(() => {
    return policies.filter((p) => {
      if (filter === "active" && p.locked) return false;
      if (filter === "locked" && !p.locked) return false;
      const tags = Array.isArray(p.tags) ? p.tags : [];
      if (tagFilter.size > 0 && !tags.some((t) => tagFilter.has(t))) return false;
      for (const t of searchTagTerms) if (!tags.includes(t)) return false;
      if (!fuzzyLc) return true;
      const haystack = `${p.name || ""} ${p.package || ""} ${p.description || ""}`.toLowerCase();
      return haystack.includes(fuzzyLc);
    });
  }, [policies, fuzzyLc, searchTagTerms, filter, tagFilter]);

  // View modes
  const isSearching = fuzzyLc.length > 0 || searchTagTerms.size > 0;
  const mode = isSearching 
    ? "search" 
    : isRoot 
      ? (selectedOrgId === null ? "org" : (selectedPackage === null ? "package" : "policy"))
      : (selectedPackage === null ? "package" : "policy");

  const orgGroups = useMemo(() => {
    if (mode !== "org") return [];
    const map = new Map();
    for (const p of filtered) {
      const key = p.orgId || "global";
      if (!map.has(key)) map.set(key, []);
      map.get(key).push(p);
    }
    return [...map.entries()].sort(([a], [b]) => {
      if (a === "global") return -1;
      if (b === "global") return 1;
      return orgName(a).localeCompare(orgName(b));
    });
  }, [filtered, mode, orgName]);

  const packageGroups = useMemo(() => {
    if (mode !== "package") return [];
    const policiesInOrg = isRoot 
      ? filtered.filter(p => (selectedOrgId === "global" ? !p.orgId : p.orgId === selectedOrgId))
      : filtered;
    const map = new Map();
    for (const p of policiesInOrg) {
      const key = p.package || "(no package)";
      if (!map.has(key)) map.set(key, []);
      map.get(key).push(p);
    }
    return [...map.entries()].sort(([a], [b]) => a.localeCompare(b));
  }, [filtered, mode, selectedOrgId, isRoot]);

  const flatItems = useMemo(() => {
    if (mode === "search") {
      return filtered.slice().sort((a, b) => (a.name || "").localeCompare(b.name || ""));
    }
    if (mode === "policy") {
      const policiesInOrg = isRoot 
        ? filtered.filter(p => (selectedOrgId === "global" ? !p.orgId : p.orgId === selectedOrgId))
        : filtered;
      return policiesInOrg
        .filter(p => p.package === selectedPackage)
        .slice()
        .sort((a, b) => (a.name || "").localeCompare(b.name || ""));
    }
    return [];
  }, [mode, filtered, selectedOrgId, selectedPackage, isRoot]);

  const totalPages = Math.max(1, Math.ceil(flatItems.length / PAGE_SIZE));
  const safePage = Math.min(page, totalPages);
  const pageStart = (safePage - 1) * PAGE_SIZE;
  const pagedItems = flatItems.slice(pageStart, pageStart + PAGE_SIZE);

  const totalShown =
    mode === "search"
      ? flatItems.length
      : mode === "policy"
        ? flatItems.length
        : mode === "package"
          ? packageGroups.reduce((s, [, arr]) => s + arr.length, 0)
          : orgGroups.reduce((s, [, arr]) => s + arr.length, 0);

  const headerLabel =
    totalShown === policies.length
      ? `Policies — ${policies.length}`
      : `Policies — ${totalShown} of ${policies.length}`;

  const toggleTagFilter = (tag) => {
    setTagFilter((prev) => {
      const next = new Set(prev);
      if (next.has(tag)) next.delete(tag); else next.add(tag);
      return next;
    });
  };

  const renderItem = (p) => {
    const health = policyHealth[p.id];
    const hasIssues = health && ((health.errors || []).length > 0 || (health.warnings || []).length > 0);
    const tooltipText = hasIssues 
      ? [...(health.errors || []), ...(health.warnings || [])].join("\n")
      : "";

    return (
      <div
        key={p.id}
        className={`sidebar-item ${p.id === activeId ? "active" : ""} ${p.locked ? "locked" : ""}`}
        onClick={() => onSelect(p.id)}
      >
        <div className="sidebar-item-top-row">
          <div className="sidebar-item-name">{p.name}</div>
          {onClone && (
            <button
              type="button"
              className="sidebar-item-clone-action"
              onClick={(e) => {
                e.stopPropagation();
                onClone(p.id);
              }}
              title="Clone policy"
            >
              Clone
            </button>
          )}
          {hasIssues && (
            <span
              className="policy-warning-dot"
              title={`Issues detected:\n${tooltipText}`}
              style={{ marginLeft: "6px" }}
            >
              ⚠️
            </span>
          )}
          {p.locked && (
            <span className="locked-badge sm" title="Not enforcing — locked">Locked</span>
          )}
          {p.version && <span className="sidebar-item-version">v{p.version}</span>}
        </div>
        <div className="sidebar-item-pkg">{p.package}</div>
        {isRoot && (
          <div className="sidebar-item-attrib">
            <span className="sidebar-item-org" title={p.orgId ? `org_id: ${p.orgId}` : "global (no org)"}>
              {orgName(p.orgId)}
            </span>
            <span className="sidebar-item-attrib-sep" aria-hidden="true">·</span>
            {lastMod[p.id] ? (
              <>
                <span className="sidebar-item-author" title={`last ${lastMod[p.id].action || "change"} by ${lastMod[p.id].actorUsername}`}>
                  {lastMod[p.id].actorUsername || "—"}
                </span>
                <span className="sidebar-item-attrib-sep" aria-hidden="true">·</span>
                <span className="sidebar-item-when" title={lastMod[p.id].createdAt || ""}>
                  {formatRelative(lastMod[p.id].createdAt)}
                </span>
              </>
            ) : (
              <span className="sidebar-item-author">—</span>
            )}
          </div>
        )}
        {Array.isArray(p.tags) && p.tags.length > 0 && (
          <div className="sidebar-item-tags" onClick={(e) => e.stopPropagation()}>
            {p.tags.map((t) => (
              <button
                key={t}
                type="button"
                className={`sidebar-item-tag ${tagFilter.has(t) ? "active" : ""}`}
                onClick={() => toggleTagFilter(t)}
                title={tagFilter.has(t) ? `Remove ${t} from filter` : `Filter to ${t}`}
              >
                {t}
              </button>
            ))}
          </div>
        )}
      </div>
    );
  };

  return (
    <aside className="sidebar">
      <div className="sidebar-head">
        <div className="sidebar-title-row">
          <div className="sidebar-title">{headerLabel}</div>
          <button
            type="button"
            className="sidebar-toggle"
            onClick={onToggleCollapsed}
            title="Collapse sidebar"
            aria-label="Collapse sidebar"
            aria-expanded="true"
          >
            ‹
          </button>
        </div>
        <div className="sidebar-actions" ref={dropdownRef} style={{ position: "relative" }}>
          <div className="btn-group-split">
            <button
              className="btn btn-primary btn-sm btn-split-main"
              onClick={() => {
                onNew();
                setNewMenuOpen(false);
              }}
              title="New blank policy"
            >
              + New
            </button>
            <button
              className={`btn btn-primary btn-sm btn-split-arrow ${newMenuOpen ? "active" : ""}`}
              onClick={() => setNewMenuOpen(!newMenuOpen)}
              title="New policy options"
              aria-expanded={newMenuOpen}
            >
              ▼
            </button>
          </div>

          {newMenuOpen && (
            <div className="preset-dropdown-menu">
              <div className="menu-header">CREATE NEW</div>
              <button
                type="button"
                className="menu-item"
                onClick={() => {
                  onNew();
                  setNewMenuOpen(false);
                }}
              >
                <span className="menu-item-icon">📄</span>
                <div className="menu-item-text">
                  <div className="menu-item-title">New Blank Policy</div>
                  <div className="menu-item-desc">Start a clean policy from scratch</div>
                </div>
              </button>

              {presets.length > 0 && (
                <>
                  <div className="menu-divider" />
                  <div className="menu-header">POPULAR PRESETS</div>
                  <div className="presets-list">
                    {presets.map((t) => (
                      <button
                        key={t.id}
                        type="button"
                        className="menu-item preset-item"
                        onClick={() => {
                          onSelectTemplate(t.id);
                          setNewMenuOpen(false);
                        }}
                      >
                        <span className="menu-item-icon">⚡</span>
                        <div className="menu-item-text">
                          <div className="menu-item-title">{t.name}</div>
                          <div className="menu-item-desc">{t.description?.length > 60 ? t.description.slice(0, 57) + "..." : t.description}</div>
                          <div className="menu-item-meta">{t.category}</div>
                        </div>
                      </button>
                    ))}
                  </div>
                </>
              )}

              <div className="menu-divider" />
              <button
                type="button"
                className="menu-item menu-item-footer"
                onClick={() => {
                  onShowTemplates();
                  setNewMenuOpen(false);
                }}
              >
                <span className="menu-item-icon">📂</span>
                <div className="menu-item-text">
                  <div className="menu-item-title footer-title">Browse template gallery...</div>
                </div>
              </button>
            </div>
          )}
        </div>
      </div>

      <div className="sidebar-search-row">
        <input
          ref={searchRef}
          type="search"
          className="sidebar-search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search name, package, description…"
          spellCheck="false"
        />
        {query ? (
          <button
            className="sidebar-search-clear"
            type="button"
            onClick={() => setQuery("")}
            title="Clear"
            aria-label="Clear search"
          >
            ×
          </button>
        ) : (
          <kbd className="sidebar-search-kbd" aria-hidden="true">⌘K</kbd>
        )}
      </div>

      <div className="sidebar-filters" role="tablist" aria-label="Filter policies">
        {FILTERS.map((f) => {
          const count =
            f.key === "all"
              ? policies.length
              : f.key === "locked"
                ? policies.filter((p) => p.locked).length
                : policies.filter((p) => !p.locked).length;
          return (
            <button
              key={f.key}
              type="button"
              role="tab"
              aria-selected={filter === f.key}
              className={`sidebar-filter ${filter === f.key ? "active" : ""}`}
              onClick={() => setFilter(f.key)}
            >
              {f.label}
              <span className="sidebar-filter-count">{count}</span>
            </button>
          );
        })}
      </div>

      {catalogueTags.length > 0 && (
        <div
          className="sidebar-tag-filters"
          role="group"
          aria-label="Filter by tag"
        >
          {catalogueTags.map((t) => {
            const active = tagFilter.has(t);
            return (
              <button
                key={t}
                type="button"
                className={`sidebar-tag-chip ${active ? "active" : ""}`}
                onClick={() => toggleTagFilter(t)}
                aria-pressed={active}
                title={active ? `Remove ${t} filter` : `Filter to ${t}`}
              >
                {t}
              </button>
            );
          })}
          {tagFilter.size > 0 && (
            <button
              type="button"
              className="sidebar-tag-clear"
              onClick={() => setTagFilter(new Set())}
              title="Clear tag filter"
            >
              clear
            </button>
          )}
        </div>
      )}

      {mode !== "search" && (isRoot ? (selectedOrgId !== null) : (selectedPackage !== null)) && (
        <div className="sidebar-crumbs">
          {isRoot ? (
            <>
              <button
                type="button"
                className="sidebar-crumb-back"
                onClick={() => {
                  setSelectedOrgId(null);
                  setSelectedPackage(null);
                }}
                title="Back to all Orgs"
              >
                Orgs
              </button>
              <span className="sidebar-crumb-sep" aria-hidden="true">/</span>
              {selectedPackage ? (
                <>
                  <button
                    type="button"
                    className="sidebar-crumb-back"
                    onClick={() => setSelectedPackage(null)}
                    title="Back to packages"
                  >
                    {selectedOrgId === "global" ? "Global" : orgName(selectedOrgId)}
                  </button>
                  <span className="sidebar-crumb-sep" aria-hidden="true">/</span>
                  <span className="sidebar-crumb-current" title={selectedPackage}>{selectedPackage}</span>
                </>
              ) : (
                <span className="sidebar-crumb-current">
                  {selectedOrgId === "global" ? "Global" : orgName(selectedOrgId)}
                </span>
              )}
            </>
          ) : (
            <>
              <button
                type="button"
                className="sidebar-crumb-back"
                onClick={() => setSelectedPackage(null)}
                title="Back to all Packages"
              >
                Packages
              </button>
              <span className="sidebar-crumb-sep" aria-hidden="true">/</span>
              <span className="sidebar-crumb-current" title={selectedPackage}>{selectedPackage}</span>
            </>
          )}
        </div>
      )}

      {mode === "search" && (
        <div className="sidebar-crumbs">
          <span className="sidebar-crumb-current">
            {flatItems.length} {flatItems.length === 1 ? "match" : "matches"}
            {fuzzyLc && <> for “{fuzzy.trim()}”</>}
            {searchTagTerms.size > 0 && (
              <> with {[...searchTagTerms].map((t) => `tag:${t}`).join(" ")}</>
            )}
          </span>
        </div>
      )}

      <div className="sidebar-list">
        {policies.length === 0 ? (
          <div className="sidebar-empty">
            <p>No policies yet.</p>
            <p style={{ fontSize: 11, opacity: 0.7 }}>
              Start from a template or create a blank one.
            </p>
          </div>
        ) : mode === "org" ? (
          orgGroups.length === 0 ? (
            <div className="sidebar-empty">
              <p>No matches.</p>
              <p style={{ fontSize: 11, opacity: 0.7 }}>Try a different filter.</p>
            </div>
          ) : (
            orgGroups.map(([key, arr]) => {
              const hasActive = arr.some((p) => p.id === activeId);
              return (
                <button
                  key={key}
                  type="button"
                  className={`sidebar-grouprow ${hasActive ? "has-active" : ""}`}
                  onClick={() => setSelectedOrgId(key)}
                  title={`Open ${key === "global" ? "Global" : orgName(key)}`}
                >
                  <span className="sidebar-grouprow-name">{key === "global" ? "Global" : orgName(key)}</span>
                  <span className="sidebar-grouprow-meta">
                    <span className="sidebar-grouprow-count">{arr.length}</span>
                    <span className="sidebar-grouprow-chevron" aria-hidden="true">›</span>
                  </span>
                </button>
              );
            })
          )
        ) : mode === "package" ? (
          packageGroups.length === 0 ? (
            <div className="sidebar-empty">
              <p>No matches.</p>
              <p style={{ fontSize: 11, opacity: 0.7 }}>Try a different filter.</p>
            </div>
          ) : (
            packageGroups.map(([key, arr]) => {
              const hasActive = arr.some((p) => p.id === activeId);
              return (
                <button
                  key={key}
                  type="button"
                  className={`sidebar-grouprow ${hasActive ? "has-active" : ""}`}
                  onClick={() => setSelectedPackage(key)}
                  title={`Open ${key}`}
                >
                  <span className="sidebar-grouprow-name">{key}</span>
                  <span className="sidebar-grouprow-meta">
                    <span className="sidebar-grouprow-count">{arr.length}</span>
                    <span className="sidebar-grouprow-chevron" aria-hidden="true">›</span>
                  </span>
                </button>
              );
            })
          )
        ) : flatItems.length === 0 ? (
          <div className="sidebar-empty">
            <p>No matches.</p>
            <p style={{ fontSize: 11, opacity: 0.7 }}>
              Try a different search or filter.
            </p>
          </div>
        ) : (
          pagedItems.map(renderItem)
        )}
      </div>

      {(mode === "policy" || mode === "search") && totalPages > 1 && (
        <div className="sidebar-pagination">
          <button
            type="button"
            className="sidebar-page-btn"
            onClick={() => setPage((n) => Math.max(1, n - 1))}
            disabled={safePage === 1}
            aria-label="Previous page"
          >
            ‹
          </button>
          <span className="sidebar-page-label">
            {pageStart + 1}–{Math.min(pageStart + PAGE_SIZE, flatItems.length)} of {flatItems.length}
          </span>
          <button
            type="button"
            className="sidebar-page-btn"
            onClick={() => setPage((n) => Math.min(totalPages, n + 1))}
            disabled={safePage === totalPages}
            aria-label="Next page"
          >
            ›
          </button>
        </div>
      )}
    </aside>
  );
}
