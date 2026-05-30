import { useEffect, useState, useCallback } from "react";
import { api } from "../lib/api.js";

function formatDate(s) {
  if (!s) return "—";
  try { return new Date(s).toLocaleString(); }
  catch { return s; }
}

export default function UserManagement({ currentUser, onClose }) {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const isRoot = !!currentUser?.isRoot;
  const actorOrgId = currentUser?.orgId ?? "";

  // RBAC dropdowns. Root sees every org and every role; org-admins see
  // only their own org and the roles they may assign (globals + org-locals).
  // Empty arrays until first fetch; lookup fails are surfaced inline.
  const [orgs, setOrgs] = useState([]);
  const [roles, setRoles] = useState([]);
  const [newUsername, setNewUsername] = useState("");
  const [newEmail, setNewEmail] = useState("");
  const [newOrgId, setNewOrgId] = useState("");
  const [newRoleId, setNewRoleId] = useState("");
  const [newIsRoot, setNewIsRoot] = useState(false);
  const [creating, setCreating] = useState(false);

  // Banner shown once after creating a user or resetting a password.
  const [pwBanner, setPwBanner] = useState(null); // { username, password }

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [list, orgList, roleList] = await Promise.all([
        api.listUsers(),
        isRoot ? api.listOrgs().catch(() => []) : Promise.resolve([]),
        api.listRoles().catch(() => []),
      ]);
      setUsers(list);
      setOrgs(orgList);
      setRoles(roleList);
      // Auto-populate selectors so the form is submit-ready on first paint.
      if (!newOrgId) {
        setNewOrgId(isRoot ? (orgList[0]?.id || "") : actorOrgId);
      }
      if (!newRoleId) {
        const defaultRole =
          roleList.find((r) => r.name === "org_admin") || roleList[0];
        if (defaultRole) setNewRoleId(defaultRole.id);
      }
    } catch (e) {
      setError(e?.body?.error || e.message || "Failed to load users");
    } finally {
      setLoading(false);
    }
    // newOrgId/newRoleId intentionally excluded — we only seed them on
    // first successful load to avoid clobbering an in-progress edit.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isRoot, actorOrgId]);

  useEffect(() => { refresh(); }, [refresh]);

  async function handleCreate(e) {
    e.preventDefault();
    if (creating || !newUsername.trim()) return;
    if (!newRoleId) {
      setError("Pick a role for the new user");
      return;
    }
    setCreating(true);
    setError(null);
    try {
      const payload = {
        username: newUsername.trim(),
        email: newEmail.trim() || undefined,
        roleId: newRoleId,
        isRoot: isRoot ? newIsRoot : false,
      };
      // Root may explicitly target another org; org-admins are pinned to
      // their own (the backend re-enforces this regardless).
      if (isRoot && newOrgId) payload.orgId = newOrgId;
      const { user, generatedPassword } = await api.createUser(payload);
      setNewUsername("");
      setNewEmail("");
      setNewIsRoot(false);
      if (generatedPassword) {
        setPwBanner({ username: user.username, password: generatedPassword });
      }
      await refresh();
    } catch (e) {
      setError(e?.body?.error || e.message || "Create failed");
    } finally {
      setCreating(false);
    }
  }

  async function handleResetPassword(user) {
    if (!confirm(`Generate a new temporary password for "${user.username}"?`)) return;
    try {
      const { generatedPassword } = await api.resetUserPassword(user.id);
      if (generatedPassword) {
        setPwBanner({ username: user.username, password: generatedPassword });
      }
      await refresh();
    } catch (e) {
      setError(e?.body?.error || e.message || "Reset failed");
    }
  }

  async function handleToggleDisabled(user) {
    const verb = user.disabled ? "enable" : "disable";
    if (!confirm(`${verb[0].toUpperCase() + verb.slice(1)} "${user.username}"?`)) return;
    try {
      await api.updateUser(user.id, { disabled: !user.disabled });
      await refresh();
    } catch (e) {
      setError(e?.body?.error || e.message || "Update failed");
    }
  }

  async function handleDelete(user) {
    if (!confirm(`Permanently delete "${user.username}"?`)) return;
    try {
      await api.deleteUser(user.id);
      await refresh();
    } catch (e) {
      setError(e?.body?.error || e.message || "Delete failed");
    }
  }

  return (
    <div className="modal-overlay" role="dialog" aria-modal="true">
      <div className="modal" style={{ maxWidth: 920 }}>
        <div className="modal-head">
          <h2 className="modal-title">
            Manage <em>users</em>
          </h2>
          <button className="modal-close" type="button" onClick={onClose} aria-label="Close">×</button>
        </div>
        <div className="modal-body">
          {error && <div className="auth-error">{error}</div>}

          {pwBanner && (
            <div className="generated-pw-banner">
              <strong>Temporary password for {pwBanner.username} — copy now, shown once</strong>
              {pwBanner.password}
              <div style={{ marginTop: 8 }}>
                <button className="btn btn-sm" type="button" onClick={() => setPwBanner(null)}>
                  Got it
                </button>
              </div>
            </div>
          )}

          <form className="user-create-form" onSubmit={handleCreate} autoComplete="off">
            <div className="row">
              <div className="field" style={{ marginBottom: 0 }}>
                <label className="field-label" htmlFor="nu-name">New username</label>
                <input
                  id="nu-name"
                  className="field-input"
                  type="text"
                  value={newUsername}
                  onChange={(e) => setNewUsername(e.target.value)}
                  required
                  disabled={creating}
                />
              </div>
              <div className="field" style={{ marginBottom: 0 }}>
                <label className="field-label" htmlFor="nu-email">Email (optional)</label>
                <input
                  id="nu-email"
                  className="field-input"
                  type="email"
                  value={newEmail}
                  onChange={(e) => setNewEmail(e.target.value)}
                  disabled={creating}
                />
              </div>
            </div>
            <div className="row" style={{ marginTop: 8 }}>
              <div className="field" style={{ marginBottom: 0 }}>
                <label className="field-label" htmlFor="nu-org">Organization</label>
                <select
                  id="nu-org"
                  className="field-input"
                  value={newOrgId}
                  onChange={(e) => setNewOrgId(e.target.value)}
                  disabled={creating || !isRoot}
                  title={isRoot ? "" : "Only root can create users in another org"}
                >
                  {isRoot
                    ? orgs.map((o) => (
                        <option key={o.id} value={o.id}>{o.name} ({o.slug})</option>
                      ))
                    : <option value={actorOrgId}>{currentUser?.roleName ? "Your org" : actorOrgId}</option>}
                </select>
              </div>
              <div className="field" style={{ marginBottom: 0 }}>
                <label className="field-label" htmlFor="nu-role">Role</label>
                <select
                  id="nu-role"
                  className="field-input"
                  value={newRoleId}
                  onChange={(e) => {
                    setNewRoleId(e.target.value);
                    // If they pick the built-in `root` role, hint that
                    // it requires isRoot=true (validated by backend too).
                    const r = roles.find((x) => x.id === e.target.value);
                    if (r?.name === "root") setNewIsRoot(true);
                  }}
                  disabled={creating}
                  required
                >
                  <option value="">Select role…</option>
                  {roles.map((r) => (
                    <option key={r.id} value={r.id}>
                      {r.name}{r.isBuiltin ? " (built-in)" : ""}{r.orgId ? " (org-local)" : ""}
                    </option>
                  ))}
                </select>
              </div>
              {isRoot && (
                <div className="field" style={{ marginBottom: 0, alignSelf: "end" }}>
                  <label className="field-label" htmlFor="nu-isroot">
                    <input
                      id="nu-isroot"
                      type="checkbox"
                      checked={newIsRoot}
                      onChange={(e) => setNewIsRoot(e.target.checked)}
                      disabled={creating}
                      style={{ marginRight: 6 }}
                    />
                    Grant super-admin (is_root)
                  </label>
                </div>
              )}
              <button className="btn btn-primary" type="submit" disabled={creating || !newUsername.trim() || !newRoleId}>
                {creating ? "Creating…" : "Create user"}
              </button>
            </div>
            <div className="auth-help">
              A temporary password is generated and shown once; the new user will be required to change it on first login.
            </div>
          </form>

          {loading ? (
            <div className="diff-empty">Loading users…</div>
          ) : (
            <table className="users-table">
              <thead>
                <tr>
                  <th>Username</th>
                  <th>Role</th>
                  {isRoot && <th>Org</th>}
                  <th>Status</th>
                  <th>Last login</th>
                  <th style={{ textAlign: "right" }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => {
                  const isSelf = u.id === currentUser?.id;
                  const status = u.disabled
                    ? <span className="status-pill disabled">Disabled</span>
                    : u.mustChangePassword
                      ? <span className="status-pill">Pending password change</span>
                      : <span className="status-pill">Active</span>;
                  // Org name from the pre-fetched orgs list (loaded by
                  // refresh() for root only — sub-admins see only their
                  // own org and don't need the column).
                  const orgRow = orgs.find((o) => o.id === u.orgId);
                  return (
                    <tr key={u.id}>
                      <td>
                        <strong>{u.username}</strong>
                        {isSelf && <span className="auth-help" style={{ marginLeft: 8 }}>(you)</span>}
                        {u.email && <div className="auth-help" style={{ marginTop: 2 }}>{u.email}</div>}
                      </td>
                      <td>
                        <span className="role-badge">{u.role}</span>
                        {u.isRoot && (
                          <span className="auth-help" style={{ marginLeft: 6 }}>root</span>
                        )}
                      </td>
                      {isRoot && (
                        <td>
                          <span className="auth-help">
                            {orgRow ? orgRow.name : (u.orgId ? u.orgId.slice(0, 8) + "…" : "—")}
                          </span>
                        </td>
                      )}
                      <td>{status}</td>
                      <td><span className="auth-help">{formatDate(u.lastLoginAt)}</span></td>
                      <td>
                        <div className="row-actions">
                          <button
                            className="btn btn-sm"
                            type="button"
                            onClick={() => handleResetPassword(u)}
                          >
                            Reset password
                          </button>
                          <button
                            className="btn btn-sm"
                            type="button"
                            onClick={() => handleToggleDisabled(u)}
                            disabled={isSelf}
                            title={isSelf ? "You cannot disable yourself" : ""}
                          >
                            {u.disabled ? "Enable" : "Disable"}
                          </button>
                          <button
                            className="btn btn-sm btn-danger"
                            type="button"
                            onClick={() => handleDelete(u)}
                            disabled={isSelf}
                            title={isSelf ? "You cannot delete yourself" : ""}
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
