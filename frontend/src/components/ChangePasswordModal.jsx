import { useState } from "react";
import { api } from "../lib/api.js";

function validate({ username, currentPassword, newPassword, confirm }) {
  if (newPassword.length < 12) return "New password must be at least 12 characters.";
  if (username && newPassword.toLowerCase() === username.toLowerCase()) {
    return "New password must not equal your username.";
  }
  if (currentPassword && newPassword === currentPassword) {
    return "New password must differ from the current password.";
  }
  if (newPassword !== confirm) return "New password and confirmation do not match.";
  return null;
}

export default function ChangePasswordModal({ user, forced = false, onComplete, onCancel }) {
  const [currentPassword, setCurrent] = useState("");
  const [newPassword, setNew] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  async function handleSubmit(e) {
    e.preventDefault();
    if (busy) return;
    const reason = validate({
      username: user?.username,
      currentPassword,
      newPassword,
      confirm,
    });
    if (reason) { setError(reason); return; }

    setError(null);
    setBusy(true);
    try {
      await api.changePassword(currentPassword, newPassword);
      onComplete?.();
    } catch (err) {
      setError(err?.body?.error || err.message || "Password change failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-overlay" role="dialog" aria-modal="true">
      <div className="modal" style={{ maxWidth: 480 }}>
        <div className="modal-head">
          <h2 className="modal-title">
            {forced ? "Set a new password" : "Change password"}
          </h2>
          {!forced && (
            <button className="modal-close" type="button" onClick={onCancel} aria-label="Close">×</button>
          )}
        </div>
        <form className="modal-body" onSubmit={handleSubmit} autoComplete="off">
          {forced && (
            <div className="callout">
              <span className="callout-icon">FIRST LOGIN</span>
              <span>
                Your initial password must be changed before you can use Aegis Studio.
                The on-disk password file will be deleted automatically once you confirm.
              </span>
            </div>
          )}
          {error && <div className="auth-error">{error}</div>}

          <div className="field">
            <label className="field-label" htmlFor="cp-cur">Current password</label>
            <input
              id="cp-cur"
              className="field-input"
              type="password"
              autoComplete="current-password"
              required
              autoFocus
              value={currentPassword}
              onChange={(e) => setCurrent(e.target.value)}
              disabled={busy}
            />
          </div>
          <div className="field">
            <label className="field-label" htmlFor="cp-new">New password</label>
            <input
              id="cp-new"
              className="field-input"
              type="password"
              autoComplete="new-password"
              required
              minLength={12}
              value={newPassword}
              onChange={(e) => setNew(e.target.value)}
              disabled={busy}
            />
            <div className="auth-help">Minimum 12 characters · must differ from username.</div>
          </div>
          <div className="field">
            <label className="field-label" htmlFor="cp-confirm">Confirm new password</label>
            <input
              id="cp-confirm"
              className="field-input"
              type="password"
              autoComplete="new-password"
              required
              minLength={12}
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              disabled={busy}
            />
          </div>

          <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 18 }}>
            {!forced && (
              <button className="btn btn-ghost" type="button" onClick={onCancel} disabled={busy}>
                Cancel
              </button>
            )}
            <button className="btn btn-primary" type="submit" disabled={busy}>
              {busy ? "Saving…" : "Save password"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
