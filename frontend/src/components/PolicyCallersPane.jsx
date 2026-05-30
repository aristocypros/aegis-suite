import { useEffect, useMemo, useState, useCallback } from "react";
import { api } from "../lib/api.js";

// Policy-centric reverse view of the M:N caller-access table. Listed as a
// tab inside the policy editor; lets the admin grant/revoke this policy
// for multiple callers in one audited transaction (mirror of the bulk-grant
// path on the caller-centric pane).
export default function PolicyCallersPane({ policy, isNew }) {
  const [callers, setCallers] = useState([]);
  const [selected, setSelected] = useState(() => new Set());
  const [initial, setInitial] = useState(() => new Set());
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);
  const [info, setInfo] = useState(null);

  const refresh = useCallback(async () => {
    if (isNew || !policy?.id) {
      // Brand-new policy that hasn't been saved yet — no id to fetch grants
      // for. Show a stub so the admin knows to save first.
      setLoading(false);
      setCallers([]);
      setInitial(new Set());
      setSelected(new Set());
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const [allCallers, currentAccess] = await Promise.all([
        api.listPepCallers(),
        api.listPolicyCallers(policy.id),
      ]);
      setCallers(allCallers);
      const granted = new Set(currentAccess.map((r) => r.callerId));
      setInitial(granted);
      setSelected(new Set(granted));
    } catch (e) {
      setError(e?.body?.error || e.message || "Failed to load policy callers");
    } finally {
      setLoading(false);
    }
  }, [policy?.id, isNew]);

  useEffect(() => { refresh(); }, [refresh]);

  const toggleOne = (callerId) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(callerId)) next.delete(callerId); else next.add(callerId);
      return next;
    });
  };

  // Reverse of the caller-side tagDerived: callers whose scope_tags overlap
  // this policy's tags are auto-allowlisted by the OPA publisher. They show
  // as read-only checked rows here — the grant lives on the caller's chips,
  // not in pep_caller_policy_access, so this pane can't revoke them.
  const tagDerived = useMemo(() => {
    const out = new Map();
    const policyTags = Array.isArray(policy?.tags) ? policy.tags : [];
    if (policyTags.length === 0) return out;
    const pset = new Set(policyTags);
    for (const c of callers) {
      if (!Array.isArray(c.scopeTags) || c.scopeTags.length === 0) continue;
      const overlap = c.scopeTags.filter((t) => pset.has(t));
      if (overlap.length > 0) out.set(c.callerId, overlap);
    }
    return out;
  }, [callers, policy?.tags]);

  const diff = useMemo(() => {
    const toGrant = [];
    const toRevoke = [];
    // Tag-derived rows are read-only here; they never participate in diffs.
    for (const id of selected) {
      if (tagDerived.has(id)) continue;
      if (!initial.has(id)) toGrant.push(id);
    }
    for (const id of initial) {
      if (tagDerived.has(id)) continue;
      if (!selected.has(id)) toRevoke.push(id);
    }
    return { toGrant, toRevoke };
  }, [selected, initial, tagDerived]);

  async function handleSave() {
    if (saving) return;
    const { toGrant, toRevoke } = diff;
    if (toGrant.length === 0 && toRevoke.length === 0) {
      setInfo("No changes to save.");
      return;
    }
    setSaving(true);
    setError(null);
    setInfo(null);
    try {
      if (toGrant.length > 0) {
        await api.grantPolicyCallers(policy.id, toGrant);
      }
      for (const callerId of toRevoke) {
        await api.revokePolicyCaller(policy.id, callerId);
      }
      setInfo(`Saved: ${toGrant.length} granted, ${toRevoke.length} revoked.`);
      await refresh();
    } catch (e) {
      setError(e?.body?.error || e.message || "Save failed");
    } finally {
      setSaving(false);
    }
  }

  const hasChanges = diff.toGrant.length > 0 || diff.toRevoke.length > 0;

  if (isNew || !policy?.id) {
    return (
      <div className="diff-empty">
        Save the policy first — caller grants can only be set on a deployed policy.
      </div>
    );
  }
  if (policy.locked) {
    return (
      <div className="diff-empty">
        This policy is locked. Unlock it before granting access to new callers; existing grants stay in the audit chain but the policy is not currently enforced.
      </div>
    );
  }

  return (
    <div>
      {error && <div className="auth-error">{error}</div>}
      {info && !error && (
        <div className="access-pane-info">{info}</div>
      )}

      <div className="auth-help" style={{ marginBottom: 8 }}>
        Tick the Aegis Sentry callers that should be able to invoke <code>{policy.package}</code>. Revoked callers are listed but disabled. Callers whose scope tags overlap this policy's tags are shown as read-only (manage them from the caller's scope tags). Changes propagate to Aegis Sentry within ~30s of Save.
      </div>

      {loading ? (
        <div className="diff-empty">Loading callers…</div>
      ) : callers.length === 0 ? (
        <div className="diff-empty">
          No Aegis Sentry callers yet. Provision one from the <strong>Manage Aegis Sentry callers</strong> menu first.
        </div>
      ) : (
        <div className="access-pane-list">
          <table className="users-table" style={{ margin: 0 }}>
            <thead>
              <tr>
                <th style={{ width: 32 }}></th>
                <th>Caller ID</th>
                <th>Mode</th>
                <th>Tenant</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {callers.map((c) => {
                const revoked = c.status === "revoked";
                const derivedTags = tagDerived.get(c.callerId);
                const inScopeViaTag = !!derivedTags;
                const checked = selected.has(c.callerId);
                const dirty = !inScopeViaTag && checked !== initial.has(c.callerId);
                return (
                  <tr key={c.callerId} className={dirty ? "access-pane-row-dirty" : ""}>
                    <td>
                      <input
                        type="checkbox"
                        checked={checked || inScopeViaTag}
                        disabled={revoked || saving || inScopeViaTag}
                        onChange={() => toggleOne(c.callerId)}
                        aria-label={`Grant ${c.callerId}`}
                        title={
                          inScopeViaTag
                            ? `In scope via tag: ${derivedTags.join(", ")} — remove the matching scope tag from the caller to revoke.`
                            : undefined
                        }
                      />
                    </td>
                    <td>
                      <strong>{c.callerId}</strong>
                      {c.description && (
                        <div className="auth-help" style={{ marginTop: 2 }}>{c.description}</div>
                      )}
                      {inScopeViaTag && (
                        <div className="auth-help" style={{ marginTop: 2 }}>
                          via tag: {derivedTags.map((t) => (
                            <span key={t} className="role-badge" style={{ marginRight: 4 }}>{t}</span>
                          ))}
                        </div>
                      )}
                    </td>
                    <td><span className="role-badge">{c.authMode}</span></td>
                    <td><span className="auth-help">{c.tenant || "—"}</span></td>
                    <td>
                      <span className={`status-pill ${revoked ? "disabled" : ""}`}>
                        {revoked ? "Revoked" : "Active"}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      <div className="row" style={{ marginTop: 12, justifyContent: "space-between" }}>
        <div className="auth-help">
          {hasChanges
            ? `Pending: +${diff.toGrant.length} grant, −${diff.toRevoke.length} revoke`
            : (() => {
                const effective = new Set(selected);
                for (const id of tagDerived.keys()) effective.add(id);
                const viaTag = tagDerived.size;
                return viaTag > 0
                  ? `${effective.size} callers granted (${viaTag} via tag)`
                  : `${effective.size} callers granted`;
              })()}
        </div>
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
  );
}
