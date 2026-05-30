import { useEffect, useState, useCallback } from "react";
import { api } from "../lib/api.js";

function formatDate(s) {
  if (!s) return "—";
  try { return new Date(s).toLocaleString(); }
  catch { return s; }
}

// Orgs panel — root-only CRUD. Non-root users never reach this modal
// because the TopBar entry is gated on can(user, "read", "org"), but we
// still render an inline "permission denied" if a non-root opens it via
// some other path (defense in depth — backend still 403s).
export default function Orgs({ currentUser, onClose }) {
  const [orgs, setOrgs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [newName, setNewName] = useState("");
  const [newSlug, setNewSlug] = useState("");
  const [creating, setCreating] = useState(false);

  const isRoot = !!currentUser?.isRoot;

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setOrgs(await api.listOrgs());
    } catch (e) {
      setError(e?.body?.error || e.message || "Failed to load orgs");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  async function handleCreate(e) {
    e.preventDefault();
    if (creating || !newName.trim() || !newSlug.trim()) return;
    setCreating(true);
    setError(null);
    try {
      await api.createOrg({ name: newName.trim(), slug: newSlug.trim().toLowerCase() });
      setNewName("");
      setNewSlug("");
      await refresh();
    } catch (e) {
      setError(e?.body?.error || e.message || "Create failed");
    } finally {
      setCreating(false);
    }
  }

  async function handleDelete(org) {
    if (!confirm(`Permanently delete org "${org.name}"? Refused if any users, policies, trust keys, Aegis Sentry callers, or custom roles still belong to it.`)) return;
    try {
      await api.deleteOrg(org.id);
      await refresh();
    } catch (e) {
      const detail = e?.body?.blockers
        ? ` (blockers: ${Object.entries(e.body.blockers).map(([k, v]) => `${k}=${v}`).join(", ")})`
        : "";
      setError((e?.body?.error || e.message || "Delete failed") + detail);
    }
  }

  if (!isRoot && currentUser) {
    return (
      <div className="modal-overlay" role="dialog" aria-modal="true">
        <div className="modal" style={{ maxWidth: 480 }}>
          <div className="modal-head">
            <h2 className="modal-title">Organizations</h2>
            <button className="modal-close" type="button" onClick={onClose} aria-label="Close">×</button>
          </div>
          <div className="modal-body">
            <div className="auth-error">
              Only root may manage organizations.
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="modal-overlay" role="dialog" aria-modal="true">
      <div className="modal" style={{ maxWidth: 800 }}>
        <div className="modal-head">
          <h2 className="modal-title">
            Manage <em>organizations</em>
          </h2>
          <button className="modal-close" type="button" onClick={onClose} aria-label="Close">×</button>
        </div>
        <div className="modal-body">
          {error && <div className="auth-error">{error}</div>}

          <form className="user-create-form" onSubmit={handleCreate} autoComplete="off">
            <div className="row">
              <div className="field" style={{ marginBottom: 0 }}>
                <label className="field-label" htmlFor="no-name">Name</label>
                <input
                  id="no-name"
                  className="field-input"
                  type="text"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  placeholder="Acme Corp"
                  required
                  disabled={creating}
                />
              </div>
              <div className="field" style={{ marginBottom: 0 }}>
                <label className="field-label" htmlFor="no-slug">Slug</label>
                <input
                  id="no-slug"
                  className="field-input"
                  type="text"
                  value={newSlug}
                  onChange={(e) => setNewSlug(e.target.value.toLowerCase())}
                  placeholder="acme"
                  pattern="^[a-z0-9][a-z0-9_-]{0,63}$"
                  required
                  disabled={creating}
                />
              </div>
              <button className="btn btn-primary" type="submit" disabled={creating || !newName.trim() || !newSlug.trim()}>
                {creating ? "Creating…" : "Create org"}
              </button>
            </div>
            <div className="auth-help">
              Resources (users, policies, trust keys, Aegis Sentry callers) belong to one org. Sub-admins only see resources in their own org.
            </div>
          </form>

          {loading ? (
            <div className="diff-empty">Loading orgs…</div>
          ) : (
            <table className="users-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Slug</th>
                  <th>Created</th>
                  <th style={{ textAlign: "right" }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {orgs.map((o) => (
                  <tr key={o.id}>
                    <td><strong>{o.name}</strong></td>
                    <td><span className="role-badge">{o.slug}</span></td>
                    <td><span className="auth-help">{formatDate(o.createdAt)}</span></td>
                    <td>
                      <div className="row-actions">
                        <button
                          className="btn btn-sm btn-danger"
                          type="button"
                          onClick={() => handleDelete(o)}
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
