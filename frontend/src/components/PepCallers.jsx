import { useEffect, useState, useCallback } from "react";
import { api } from "../lib/api.js";
import { useOrgs } from "../lib/useOrgs.js";
import CallerAccessPane from "./CallerAccessPane.jsx";

const AUTH_MODES = ["hmac", "mtls", "jwt"];

function formatDate(s) {
  if (!s) return "—";
  try { return new Date(s).toLocaleString(); }
  catch { return s; }
}

export default function PepCallers({ currentUser, onClose }) {
  const [callers, setCallers] = useState([]);
  const [scopeCounts, setScopeCounts] = useState({}); // callerId -> N policies
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [accessFor, setAccessFor] = useState(null); // open access pane for this caller

  const isRoot = !!currentUser?.isRoot;
  const { orgs, lookup: orgName } = useOrgs();

  const [newCallerId, setNewCallerId] = useState("");
  const [newAuthMode, setNewAuthMode] = useState("hmac");
  const [newDescription, setNewDescription] = useState("");
  const [newAllowedCn, setNewAllowedCn] = useState("");
  const [newJwtSubject, setNewJwtSubject] = useState("");
  const [newTenant, setNewTenant] = useState("");
  const [newOrgId, setNewOrgId] = useState("");
  const [creating, setCreating] = useState(false);
  const [revealedSecret, setRevealedSecret] = useState(null); // {callerId, secret}

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [list, allPolicies] = await Promise.all([
        api.listPepCallers(),
        api.listPolicies().catch(() => []),
      ]);
      setCallers(list);
      // Effective ACL = explicit grants ∪ policies whose tags overlap the
      // caller's scope_tags. The explicit-grants call is the source of truth
      // for failure semantics (a "—" badge) — tag-derived counts alone don't
      // suffice to call the row "loaded".
      const counts = await Promise.all(
        list.map(async (c) => {
          const scope = new Set(Array.isArray(c.scopeTags) ? c.scopeTags : []);
          const tagMatched = scope.size === 0 ? [] : allPolicies.filter(
            (p) => Array.isArray(p.tags) && p.tags.some((t) => scope.has(t))
          );
          try {
            const rows = await api.listCallerAccess(c.callerId);
            const union = new Set(rows.map((r) => r.policyId));
            for (const p of tagMatched) union.add(p.id);
            return [c.callerId, {
              total: union.size,
              explicit: rows.length,
              viaTag: tagMatched.length,
            }];
          } catch {
            return [c.callerId, null];
          }
        })
      );
      setScopeCounts(Object.fromEntries(counts));
    } catch (e) {
      setError(e?.body?.error || e.message || "Failed to load Aegis Sentry callers");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  function resetForm() {
    setNewCallerId("");
    setNewAuthMode("hmac");
    setNewDescription("");
    setNewAllowedCn("");
    setNewJwtSubject("");
    setNewTenant("");
  }

  async function handleCreate(e) {
    e.preventDefault();
    if (creating) return;
    if (!newCallerId.trim()) { setError("callerId is required"); return; }
    if (newAuthMode === "mtls" && !newAllowedCn.trim()) {
      setError("mtls callers require an Allowed CN");
      return;
    }
    setCreating(true);
    setError(null);
    try {
      const payload = {
        callerId: newCallerId.trim(),
        authMode: newAuthMode,
      };
      if (newDescription.trim()) payload.description = newDescription.trim();
      if (newTenant.trim()) payload.tenant = newTenant.trim();
      // Only root can target another org; sub-admins are pinned to their
      // own by the backend regardless of what the body says.
      if (isRoot && newOrgId) payload.orgId = newOrgId;
      if (newAuthMode === "mtls") payload.allowedCn = newAllowedCn.trim();
      if (newAuthMode === "jwt" && newJwtSubject.trim()) {
        payload.jwtSubject = newJwtSubject.trim();
      }
      const res = await api.createPepCaller(payload);
      if (res?.generatedSecret) {
        setRevealedSecret({
          callerId: res.caller.callerId,
          secret: res.generatedSecret,
        });
      }
      resetForm();
      await refresh();
    } catch (e) {
      setError(e?.body?.error || e.message || "Create failed");
    } finally {
      setCreating(false);
    }
  }

  async function handleRotate(c) {
    if (!confirm(`Rotate HMAC secret for "${c.callerId}"? The current secret will stop working immediately.`)) return;
    try {
      const res = await api.rotatePepCallerSecret(c.callerId);
      if (res?.generatedSecret) {
        setRevealedSecret({
          callerId: c.callerId,
          secret: res.generatedSecret,
        });
      }
      await refresh();
    } catch (e) {
      setError(e?.body?.error || e.message || "Rotate failed");
    }
  }

  async function handleRevoke(c) {
    if (!confirm(`Revoke caller "${c.callerId}"? Aegis Sentry will stop accepting requests from this caller within ~30s.`)) return;
    try {
      await api.revokePepCaller(c.callerId);
      await refresh();
    } catch (e) {
      setError(e?.body?.error || e.message || "Revoke failed");
    }
  }

  async function handleDelete(c) {
    if (!confirm(`Permanently delete revoked caller "${c.callerId}"? This cannot be undone.`)) return;
    try {
      await api.deletePepCaller(c.callerId);
      await refresh();
    } catch (e) {
      setError(e?.body?.error || e.message || "Delete failed");
    }
  }

  return (
    <div className="modal-overlay" role="dialog" aria-modal="true">
      <div className="modal" style={{ maxWidth: 1080 }}>
        <div className="modal-head">
          <h2 className="modal-title">
            Manage <em>Aegis Sentry callers</em>
          </h2>
          <button className="modal-close" type="button" onClick={onClose} aria-label="Close">×</button>
        </div>
        <div className="modal-body">
          {error && <div className="auth-error">{error}</div>}

          {revealedSecret && (
            <div className="auth-error" style={{ background: "#fffae6", color: "#5a4500" }}>
              <strong>HMAC secret for {revealedSecret.callerId}:</strong>
              <code style={{ display: "block", marginTop: 4, wordBreak: "break-all" }}>
                {revealedSecret.secret}
              </code>
              <div className="auth-help">
                Copy this now — it will never be shown again. The server only stores a hashed reference for redaction purposes; rotate it via the table action if it leaks.
              </div>
              <button
                type="button"
                className="btn btn-sm"
                style={{ marginTop: 6 }}
                onClick={() => setRevealedSecret(null)}
              >
                Dismiss
              </button>
            </div>
          )}

          <form className="user-create-form" onSubmit={handleCreate} autoComplete="off">
            <div className="row" style={{ marginBottom: 8 }}>
              <div className="field" style={{ marginBottom: 0 }}>
                <label className="field-label" htmlFor="pc-id">Caller ID</label>
                <input
                  id="pc-id"
                  className="field-input"
                  type="text"
                  value={newCallerId}
                  onChange={(e) => setNewCallerId(e.target.value)}
                  required
                  disabled={creating}
                  placeholder="e.g. checkout-service"
                />
              </div>
              <div className="field" style={{ marginBottom: 0 }}>
                <label className="field-label" htmlFor="pc-mode">Auth mode</label>
                <select
                  id="pc-mode"
                  className="field-input"
                  value={newAuthMode}
                  onChange={(e) => setNewAuthMode(e.target.value)}
                  disabled={creating}
                >
                  {AUTH_MODES.map((m) => (
                    <option key={m} value={m}>{m}</option>
                  ))}
                </select>
              </div>
              <div className="field" style={{ marginBottom: 0 }}>
                <label className="field-label" htmlFor="pc-tenant">Tenant (optional)</label>
                <input
                  id="pc-tenant"
                  className="field-input"
                  type="text"
                  value={newTenant}
                  onChange={(e) => setNewTenant(e.target.value)}
                  disabled={creating}
                />
              </div>
              {isRoot && (
                <div className="field" style={{ marginBottom: 0 }}>
                  <label className="field-label" htmlFor="pc-org">Org</label>
                  <select
                    id="pc-org"
                    className="field-input"
                    value={newOrgId}
                    onChange={(e) => setNewOrgId(e.target.value)}
                    disabled={creating}
                  >
                    <option value="">(your platform org)</option>
                    {orgs.map((o) => (
                      <option key={o.id} value={o.id}>{o.name}</option>
                    ))}
                  </select>
                </div>
              )}
            </div>

            <div className="field">
              <label className="field-label" htmlFor="pc-desc">Description (optional)</label>
              <input
                id="pc-desc"
                className="field-input"
                type="text"
                value={newDescription}
                onChange={(e) => setNewDescription(e.target.value)}
                disabled={creating}
              />
            </div>

            {newAuthMode === "mtls" && (
              <div className="field">
                <label className="field-label" htmlFor="pc-cn">Allowed CN (required)</label>
                <input
                  id="pc-cn"
                  className="field-input"
                  type="text"
                  value={newAllowedCn}
                  onChange={(e) => setNewAllowedCn(e.target.value)}
                  required
                  disabled={creating}
                  placeholder="e.g. checkout.service.local"
                />
                <div className="auth-help">
                  The CN on the client certificate the caller will present. Aegis Sentry must be running with TLS material configured (PEP_TLS_CERT/KEY/CA) for mtls callers to be admitted.
                </div>
              </div>
            )}

            {newAuthMode === "jwt" && (
              <div className="field">
                <label className="field-label" htmlFor="pc-sub">JWT subject pin (optional)</label>
                <input
                  id="pc-sub"
                  className="field-input"
                  type="text"
                  value={newJwtSubject}
                  onChange={(e) => setNewJwtSubject(e.target.value)}
                  disabled={creating}
                  placeholder="leave blank to accept sub == caller ID"
                />
                <div className="auth-help">
                  Aegis Sentry verifies the bearer JWT offline against the platform JWKS and matches its <code>sub</code> claim against this pin (or against the Caller ID when unset).
                </div>
              </div>
            )}

            {newAuthMode === "hmac" && (
              <div className="auth-help" style={{ marginTop: 8 }}>
                A fresh HMAC secret is generated on create and shown once. Sign each request as <code>HMAC-SHA256(secret, ts.nonce.path.body)</code> in the <code>X-Studio-Sig</code> header.
              </div>
            )}

            <div className="row" style={{ marginTop: 8 }}>
              <button className="btn btn-primary" type="submit" disabled={creating || !newCallerId.trim()}>
                {creating ? "Adding…" : "Add caller"}
              </button>
            </div>
            <div className="auth-help">
              Auth mode is immutable after create — revoke and re-add to switch modes. The active set publishes to OPA at <code>data.studio.callers</code>; Aegis Sentry reads it on every request.
            </div>
          </form>

          {loading ? (
            <div className="diff-empty">Loading Aegis Sentry callers…</div>
          ) : callers.length === 0 ? (
            <div className="diff-empty">No Aegis Sentry callers yet. Add one above.</div>
          ) : (
            <table className="users-table">
              <thead>
                <tr>
                  <th>Caller ID</th>
                  <th>Mode</th>
                  {isRoot && <th>Org</th>}
                  <th>Material</th>
                  <th>Access</th>
                  <th>Scope tags</th>
                  <th>Status</th>
                  <th>Created</th>
                  <th style={{ textAlign: "right" }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {callers.map((c) => {
                  const revoked = c.status === "revoked";
                  return (
                    <tr key={c.callerId}>
                      <td>
                        <strong>{c.callerId}</strong>
                        {c.tenant && (
                          <div className="auth-help" style={{ marginTop: 2 }}>tenant: {c.tenant}</div>
                        )}
                        {c.description && (
                          <div className="auth-help" style={{ marginTop: 2 }}>{c.description}</div>
                        )}
                      </td>
                      <td>
                        <span className="role-badge">{c.authMode}</span>
                      </td>
                      {isRoot && (
                        <td>
                          <span className="auth-help">{orgName(c.orgId)}</span>
                        </td>
                      )}
                      <td>
                        {c.authMode === "hmac" && (
                          <span className="auth-help">secret on file</span>
                        )}
                        {c.authMode === "mtls" && (
                          <span className="auth-help">CN: {c.allowedCn || "—"}</span>
                        )}
                        {c.authMode === "jwt" && (
                          <span className="auth-help">
                            sub: {c.jwtSubject || `(matches caller ID)`}
                          </span>
                        )}
                      </td>
                      <td>
                        {(() => {
                          const entry = scopeCounts[c.callerId];
                          if (entry === undefined) {
                            return <span className="role-badge">… policies</span>;
                          }
                          if (entry === null) {
                            return <span className="auth-help">—</span>;
                          }
                          const { total, explicit, viaTag } = entry;
                          const tooltip = viaTag > 0
                            ? `${explicit} explicit + ${viaTag} via tag`
                            : undefined;
                          if (total === 0) {
                            return <span className="status-pill disabled">0 policies</span>;
                          }
                          return (
                            <span className="role-badge" title={tooltip}>
                              {total} policies
                            </span>
                          );
                        })()}
                      </td>
                      <td>
                        {Array.isArray(c.scopeTags) && c.scopeTags.length > 0 ? (
                          c.scopeTags.map((t) => (
                            <span key={t} className="role-badge" style={{ marginRight: 4 }}>{t}</span>
                          ))
                        ) : (
                          <span className="auth-help">—</span>
                        )}
                      </td>
                      <td>
                        <span className={`status-pill ${revoked ? "disabled" : ""}`}>
                          {revoked ? "Revoked" : "Active"}
                        </span>
                      </td>
                      <td><span className="auth-help">{formatDate(c.createdAt)}</span></td>
                      <td>
                        <div className="row-actions">
                          {!revoked && (
                            <button className="btn btn-sm" type="button" onClick={() => setAccessFor(c)}>
                              Manage access
                            </button>
                          )}
                          {!revoked && c.authMode === "hmac" && (
                            <button className="btn btn-sm" type="button" onClick={() => handleRotate(c)}>
                              Rotate secret
                            </button>
                          )}
                          {!revoked && (
                            <button className="btn btn-sm" type="button" onClick={() => handleRevoke(c)}>
                              Revoke
                            </button>
                          )}
                          {revoked && (
                            <button
                              className="btn btn-sm btn-danger"
                              type="button"
                              onClick={() => handleDelete(c)}
                            >
                              Delete
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
      {accessFor && (
        <CallerAccessPane
          caller={accessFor}
          onClose={() => {
            setAccessFor(null);
            // Refresh scope counts so the badge reflects any changes.
            refresh();
          }}
        />
      )}
    </div>
  );
}
