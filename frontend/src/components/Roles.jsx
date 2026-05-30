import { useEffect, useState, useCallback } from "react";
import { api } from "../lib/api.js";
import { can } from "../lib/auth.js";

// Discriminators recognised by opa/studio_authz.rego. We surface them as
// checkbox columns so building a permission matrix is a click-grid rather
// than hand-edited JSON. Keep in sync with PERMISSION_RESOURCE_TYPES in
// backend/src/routes/roles.js (the backend re-validates).
const RESOURCE_TYPES = [
  "policy", "user", "trust_key", "pep_caller",
  "audit", "role", "caller_access",
];
const ACTIONS = ["read", "create", "update", "delete"];

function emptyMatrix() {
  const out = {};
  for (const rt of RESOURCE_TYPES) out[rt] = [];
  return out;
}

function permHas(perms, rt, action) {
  return Array.isArray(perms?.[rt]) && perms[rt].includes(action);
}

function togglePerm(perms, rt, action) {
  const next = { ...perms };
  const current = Array.isArray(next[rt]) ? [...next[rt]] : [];
  const idx = current.indexOf(action);
  if (idx >= 0) current.splice(idx, 1);
  else current.push(action);
  next[rt] = current;
  return next;
}

// Roles panel. Root sees every role (built-ins + globals + every org's
// locals). Sub-admins see globals + their own org's locals. Built-in roles
// are read-only; the route refuses edits and we render them with the
// inputs disabled for clarity.
export default function Roles({ currentUser, onClose }) {
  const [roles, setRoles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [newName, setNewName] = useState("");
  const [newDescription, setNewDescription] = useState("");
  const [newPermissions, setNewPermissions] = useState(emptyMatrix);
  const [creating, setCreating] = useState(false);

  const canManage = can(currentUser, "create", "role");

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setRoles(await api.listRoles());
    } catch (e) {
      setError(e?.body?.error || e.message || "Failed to load roles");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  async function handleCreate(e) {
    e.preventDefault();
    if (creating || !newName.trim()) return;
    setCreating(true);
    setError(null);
    try {
      // Strip empty action arrays so the API payload stays compact.
      const perms = {};
      for (const [rt, acts] of Object.entries(newPermissions)) {
        if (acts.length > 0) perms[rt] = acts;
      }
      await api.createRole({
        name: newName.trim().toLowerCase(),
        description: newDescription.trim(),
        permissions: perms,
      });
      setNewName("");
      setNewDescription("");
      setNewPermissions(emptyMatrix());
      await refresh();
    } catch (e) {
      setError(e?.body?.error || e.message || "Create failed");
    } finally {
      setCreating(false);
    }
  }

  async function handleDelete(role) {
    if (role.isBuiltin) return;
    if (!confirm(`Delete role "${role.name}"? Refused if any user still has this role.`)) return;
    try {
      await api.deleteRole(role.id);
      await refresh();
    } catch (e) {
      const detail = e?.body?.blockers
        ? ` (blockers: ${Object.entries(e.body.blockers).map(([k, v]) => `${k}=${v}`).join(", ")})`
        : "";
      setError((e?.body?.error || e.message || "Delete failed") + detail);
    }
  }

  return (
    <div className="modal-overlay" role="dialog" aria-modal="true">
      <div className="modal" style={{ maxWidth: 1080 }}>
        <div className="modal-head">
          <h2 className="modal-title">
            Manage <em>roles</em>
          </h2>
          <button className="modal-close" type="button" onClick={onClose} aria-label="Close">×</button>
        </div>
        <div className="modal-body">
          {error && <div className="auth-error">{error}</div>}

          {canManage && (
            <form className="user-create-form" onSubmit={handleCreate} autoComplete="off">
              <div className="row">
                <div className="field" style={{ marginBottom: 0 }}>
                  <label className="field-label" htmlFor="nr-name">Role name</label>
                  <input
                    id="nr-name"
                    className="field-input"
                    type="text"
                    value={newName}
                    onChange={(e) => setNewName(e.target.value)}
                    placeholder="e.g. policy_reviewer"
                    pattern="^[a-z][a-z0-9_]{1,63}$"
                    required
                    disabled={creating}
                  />
                </div>
                <div className="field" style={{ marginBottom: 0, flex: 2 }}>
                  <label className="field-label" htmlFor="nr-desc">Description</label>
                  <input
                    id="nr-desc"
                    className="field-input"
                    type="text"
                    value={newDescription}
                    onChange={(e) => setNewDescription(e.target.value)}
                    placeholder="What can holders of this role do?"
                    disabled={creating}
                  />
                </div>
              </div>

              <div style={{ marginTop: 12, marginBottom: 8, fontWeight: 600 }}>
                Permissions
              </div>
              <table className="users-table">
                <thead>
                  <tr>
                    <th>Resource</th>
                    {ACTIONS.map((a) => (
                      <th key={a} style={{ textAlign: "center" }}>{a}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {RESOURCE_TYPES.map((rt) => (
                    <tr key={rt}>
                      <td><strong>{rt}</strong></td>
                      {ACTIONS.map((a) => (
                        <td key={a} style={{ textAlign: "center" }}>
                          <input
                            type="checkbox"
                            checked={permHas(newPermissions, rt, a)}
                            onChange={() => setNewPermissions((p) => togglePerm(p, rt, a))}
                            disabled={creating}
                          />
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>

              <div className="row" style={{ marginTop: 12 }}>
                <button className="btn btn-primary" type="submit" disabled={creating || !newName.trim()}>
                  {creating ? "Creating…" : "Create role"}
                </button>
                <div className="auth-help">
                  {currentUser?.isRoot
                    ? "Created in your platform org by default. To create a global role, omit org via the API."
                    : "Created in your own org and visible only to its members."}
                </div>
              </div>
            </form>
          )}

          {loading ? (
            <div className="diff-empty">Loading roles…</div>
          ) : (
            <table className="users-table" style={{ marginTop: 16 }}>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Scope</th>
                  <th>Description</th>
                  <th>Permissions</th>
                  <th style={{ textAlign: "right" }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {roles.map((r) => {
                  const grants = Object.entries(r.permissions || {})
                    .filter(([, acts]) => Array.isArray(acts) && acts.length > 0)
                    .map(([rt, acts]) => `${rt}:${acts.join("/")}`)
                    .join("  ·  ");
                  return (
                    <tr key={r.id}>
                      <td>
                        <strong>{r.name}</strong>
                        {r.isBuiltin && (
                          <span className="auth-help" style={{ marginLeft: 8 }}>built-in</span>
                        )}
                      </td>
                      <td>
                        <span className="role-badge">
                          {r.orgId ? "org-local" : (r.isBuiltin ? "global (built-in)" : "global")}
                        </span>
                      </td>
                      <td><span className="auth-help">{r.description || "—"}</span></td>
                      <td><span className="auth-help" style={{ fontSize: "0.85em" }}>{grants || "(no permissions)"}</span></td>
                      <td>
                        <div className="row-actions">
                          <button
                            className="btn btn-sm btn-danger"
                            type="button"
                            onClick={() => handleDelete(r)}
                            disabled={r.isBuiltin}
                            title={r.isBuiltin ? "Built-in roles cannot be deleted" : ""}
                          >
                            Delete
                          </button>
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
    </div>
  );
}
