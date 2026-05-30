import { useEffect, useMemo, useState, useCallback } from "react";
import { api } from "../lib/api.js";
import TagChipInput from "./TagChipInput.jsx";

// Caller-centric ACL pane. Opened from the PepCallers "Manage access" action.
// Renders the full policy catalogue with checkboxes; pre-checks rows the
// caller currently has. Save diffs against the initial set and issues a bulk
// grant (POST) plus per-removed-row revokes (DELETE).
//
// Also surfaces the caller's `scope_tags` — admin-edited tag chips that the
// PEP-ACL publisher unions into the allowlist at publish time. Policies in
// scope via tag overlap (rather than an explicit grant) are shown with a
// dim "via tag" annotation and a non-toggleable checkbox.
export default function CallerAccessPane({ caller, onClose }) {
  const [policies, setPolicies] = useState([]);
  const [selected, setSelected] = useState(() => new Set());
  const [initial, setInitial] = useState(() => new Set());
  // scope_tags edits buffer locally until Save — same gate as the checkbox
  // grants, so an admin can stage tag-driven access changes and confirm
  // them deliberately. Persisted only by handleSave().
  const [scopeTags, setScopeTags] = useState(() => caller.scopeTags || []);
  const [initialScopeTags, setInitialScopeTags] = useState(() => caller.scopeTags || []);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);
  const [info, setInfo] = useState(null);
  const [prefix, setPrefix] = useState("");

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [allPolicies, currentAccess, freshCaller] = await Promise.all([
        api.listPolicies(),
        api.listCallerAccess(caller.callerId),
        // Pull the canonical caller row so scope_tags reflects DB truth, not
        // a stale snapshot from the parent list.
        api.listPepCallers().then((rows) => rows.find((c) => c.callerId === caller.callerId)),
      ]);
      setPolicies(allPolicies);
      const granted = new Set(currentAccess.map((r) => r.policyId));
      setSelected(new Set(granted));
      setInitial(granted);
      const persistedTags = freshCaller?.scopeTags || [];
      setScopeTags(persistedTags);
      setInitialScopeTags(persistedTags);
    } catch (e) {
      setError(e?.body?.error || e.message || "Failed to load policy access");
    } finally {
      setLoading(false);
    }
  }, [caller.callerId]);

  useEffect(() => { refresh(); }, [refresh]);

  const toggleOne = (policyId) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(policyId)) next.delete(policyId); else next.add(policyId);
      return next;
    });
  };

  const selectByPrefix = () => {
    if (!prefix.trim()) return;
    const pfx = prefix.trim();
    setSelected((prev) => {
      const next = new Set(prev);
      for (const p of policies) {
        if (!p.locked && typeof p.package === "string" && p.package.startsWith(pfx)) {
          next.add(p.id);
        }
      }
      return next;
    });
  };

  const clearByPrefix = () => {
    if (!prefix.trim()) return;
    const pfx = prefix.trim();
    setSelected((prev) => {
      const next = new Set(prev);
      for (const p of policies) {
        if (typeof p.package === "string" && p.package.startsWith(pfx)) {
          next.delete(p.id);
        }
      }
      return next;
    });
  };

  const diff = useMemo(() => {
    const toGrant = [];
    const toRevoke = [];
    for (const id of selected) if (!initial.has(id)) toGrant.push(id);
    for (const id of initial) if (!selected.has(id)) toRevoke.push(id);
    return { toGrant, toRevoke };
  }, [selected, initial]);

  // Tag-derived map: for each policy whose tags overlap the caller's
  // scope_tags, capture the matching tag(s) so the UI can annotate.
  const tagDerived = useMemo(() => {
    const out = new Map();
    if (!scopeTags || scopeTags.length === 0) return out;
    const scope = new Set(scopeTags);
    for (const p of policies) {
      if (!Array.isArray(p.tags) || p.tags.length === 0) continue;
      const overlap = p.tags.filter((t) => scope.has(t));
      if (overlap.length > 0) out.set(p.id, overlap);
    }
    return out;
  }, [policies, scopeTags]);

  // Local-only chip mutation. Persistence is deferred to handleSave() so
  // tag-driven access changes go through the same explicit confirmation
  // as the checkbox grants — no implicit writes.
  function handleScopeTagsCommit(next) {
    setScopeTags([...next].sort());
  }

  // Tag-side diff against initialScopeTags. Mirrors the grant/revoke diff.
  const tagsDiff = useMemo(() => {
    const cur = new Set(initialScopeTags);
    const nxt = new Set(scopeTags);
    const add = [...nxt].filter((t) => !cur.has(t));
    const remove = [...cur].filter((t) => !nxt.has(t));
    return { add, remove };
  }, [initialScopeTags, scopeTags]);

  // Group policies by their package prefix (the portion before the first dot
  // or slash) so the list is skimmable for admins managing many policies.
  const grouped = useMemo(() => {
    const groups = new Map();
    for (const p of policies) {
      const key = (typeof p.package === "string" ? p.package : "")
        .split(/[./]/)[0] || "(uncategorised)";
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(p);
    }
    return [...groups.entries()].sort(([a], [b]) => a.localeCompare(b));
  }, [policies]);

  async function handleSave() {
    if (saving) return;
    const { toGrant, toRevoke } = diff;
    const { add: tagsAdd, remove: tagsRemove } = tagsDiff;
    if (
      toGrant.length === 0 &&
      toRevoke.length === 0 &&
      tagsAdd.length === 0 &&
      tagsRemove.length === 0
    ) {
      setInfo("No changes to save.");
      return;
    }
    setSaving(true);
    setError(null);
    setInfo(null);
    try {
      // Tag delta runs first so the publisher's union view (explicit ∪
      // tag-overlap) is consistent by the time the grant/revoke fires the
      // next caller_access publish.
      if (tagsAdd.length > 0 || tagsRemove.length > 0) {
        await api.updateCallerScopeTags(caller.callerId, {
          add: tagsAdd,
          remove: tagsRemove,
        });
      }
      if (toGrant.length > 0) {
        await api.grantCallerAccess(caller.callerId, toGrant);
      }
      // Revokes run serially — small N in practice; if a future scale ask
      // arrives, expose a bulk DELETE on the backend.
      for (const policyId of toRevoke) {
        await api.revokeCallerAccess(caller.callerId, policyId);
      }
      const parts = [];
      if (toGrant.length > 0) parts.push(`${toGrant.length} granted`);
      if (toRevoke.length > 0) parts.push(`${toRevoke.length} revoked`);
      if (tagsAdd.length > 0) parts.push(`+${tagsAdd.length} scope tag${tagsAdd.length === 1 ? "" : "s"}`);
      if (tagsRemove.length > 0) parts.push(`−${tagsRemove.length} scope tag${tagsRemove.length === 1 ? "" : "s"}`);
      setInfo(`Saved: ${parts.join(", ")}.`);
      await refresh();
    } catch (e) {
      setError(e?.body?.error || e.message || "Save failed");
    } finally {
      setSaving(false);
    }
  }

  const hasChanges =
    diff.toGrant.length > 0 ||
    diff.toRevoke.length > 0 ||
    tagsDiff.add.length > 0 ||
    tagsDiff.remove.length > 0;

  return (
    <div className="modal-overlay" role="dialog" aria-modal="true">
      <div className="modal" style={{ maxWidth: 980 }}>
        <div className="modal-head">
          <h2 className="modal-title">
            Access for <em>{caller.callerId}</em>
          </h2>
          <button className="modal-close" type="button" onClick={onClose} aria-label="Close">×</button>
        </div>
        <div className="modal-body">
          {error && <div className="auth-error">{error}</div>}
          {info && !error && (
            <div className="access-pane-info">{info}</div>
          )}

          <div className="auth-help" style={{ marginBottom: 8 }}>
            Tick the policies this caller is allowed to invoke through Aegis Sentry. Locked policies are listed but not selectable — unlock them first. Changes apply on Save; revocations take effect on Aegis Sentry within ~30s.
          </div>

          <div className="access-pane-section">
            <div className="field-label" style={{ marginBottom: 6 }}>
              Scope tags
              {(tagsDiff.add.length > 0 || tagsDiff.remove.length > 0) && (
                <span className="auth-help" style={{ marginLeft: 8 }}>
                  (unsaved: {tagsDiff.add.length > 0 ? `+${tagsDiff.add.length}` : ""}
                  {tagsDiff.add.length > 0 && tagsDiff.remove.length > 0 ? ", " : ""}
                  {tagsDiff.remove.length > 0 ? `−${tagsDiff.remove.length}` : ""})
                </span>
              )}
            </div>
            <TagChipInput
              value={scopeTags}
              onCommit={handleScopeTagsCommit}
              placeholder="add a tag to auto-grant matching policies…"
            />
            <div className="auth-help" style={{ marginTop: 6 }}>
              Any policy whose own tags include one of these scope tags is automatically in this caller's allowlist (no explicit checkbox needed). Changes apply on Save like the rest of this pane.
            </div>
          </div>

          <div className="row" style={{ alignItems: "flex-end", gap: 8, marginBottom: 12 }}>
            <div className="field" style={{ marginBottom: 0, flex: 1 }}>
              <label className="field-label" htmlFor="prefix-input">Select by package prefix</label>
              <input
                id="prefix-input"
                className="field-input"
                type="text"
                value={prefix}
                onChange={(e) => setPrefix(e.target.value)}
                placeholder="e.g. payments."
                disabled={loading || saving}
              />
            </div>
            <button
              className="btn btn-sm"
              type="button"
              onClick={selectByPrefix}
              disabled={loading || saving || !prefix.trim()}
            >
              Select matching
            </button>
            <button
              className="btn btn-sm"
              type="button"
              onClick={clearByPrefix}
              disabled={loading || saving || !prefix.trim()}
            >
              Clear matching
            </button>
          </div>

          {loading ? (
            <div className="diff-empty">Loading policies…</div>
          ) : policies.length === 0 ? (
            <div className="diff-empty">No policies have been created yet.</div>
          ) : (
            <div className="access-pane-list">
              <table className="users-table" style={{ margin: 0 }}>
                <thead>
                  <tr>
                    <th style={{ width: 32 }}></th>
                    <th>Policy</th>
                    <th>Package</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {grouped.flatMap(([groupName, rows]) => [
                    <tr key={`group-${groupName}`} className="access-pane-group">
                      <td colSpan={4}>{groupName}</td>
                    </tr>,
                    ...rows.map((p) => {
                      const checked = selected.has(p.id);
                      const dirty = checked !== initial.has(p.id);
                      const derivedTags = tagDerived.get(p.id);
                      const inScopeViaTag = !!derivedTags;
                      return (
                        <tr key={p.id} className={dirty ? "access-pane-row-dirty" : ""}>
                          <td>
                            <input
                              type="checkbox"
                              checked={checked || inScopeViaTag}
                              disabled={p.locked || saving || inScopeViaTag}
                              onChange={() => toggleOne(p.id)}
                              aria-label={`Grant ${p.name}`}
                              title={
                                inScopeViaTag
                                  ? `In scope via tag: ${derivedTags.join(", ")} — remove the matching tag to revoke.`
                                  : undefined
                              }
                            />
                          </td>
                          <td>
                            <strong>{p.name}</strong>
                            {p.description && (
                              <div className="auth-help" style={{ marginTop: 2 }}>{p.description}</div>
                            )}
                            {inScopeViaTag && (
                              <div className="auth-help" style={{ marginTop: 2 }}>
                                via tag: {derivedTags.map((t) => (
                                  <span key={t} className="role-badge" style={{ marginRight: 4 }}>{t}</span>
                                ))}
                              </div>
                            )}
                          </td>
                          <td>
                            <code style={{ fontSize: 12 }}>{p.package}</code>
                          </td>
                          <td>
                            <span className={`status-pill ${p.locked ? "disabled" : ""}`}>
                              {p.locked ? "Locked" : "Active"}
                            </span>
                          </td>
                        </tr>
                      );
                    }),
                  ])}
                </tbody>
              </table>
            </div>
          )}

          <div className="row" style={{ marginTop: 12, justifyContent: "space-between" }}>
            <div className="auth-help">
              {hasChanges
                ? (
                  <>
                    Pending: +{diff.toGrant.length} grant, −{diff.toRevoke.length} revoke
                    {(tagsDiff.add.length > 0 || tagsDiff.remove.length > 0) && (
                      <>
                        , {tagsDiff.add.length > 0 ? `+${tagsDiff.add.length} scope tag${tagsDiff.add.length === 1 ? "" : "s"}` : ""}
                        {tagsDiff.add.length > 0 && tagsDiff.remove.length > 0 ? ", " : ""}
                        {tagsDiff.remove.length > 0 ? `−${tagsDiff.remove.length} scope tag${tagsDiff.remove.length === 1 ? "" : "s"}` : ""}
                      </>
                    )}
                  </>
                )
                : `${selected.size} policies granted`}
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <button className="btn btn-sm" type="button" onClick={onClose} disabled={saving}>
                Close
              </button>
              <button
                className="btn btn-primary btn-sm"
                type="button"
                onClick={handleSave}
                disabled={!hasChanges || saving}
              >
                {saving ? "Saving…" : "Save changes"}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
