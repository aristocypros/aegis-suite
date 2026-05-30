import { useEffect, useState, useCallback } from "react";
import { api } from "../lib/api.js";

const PURPOSES = [
  {
    id: "opa-auth-signing",
    label: "OPA Auth (Aegis Core → OPA)",
    help: "Aegis Core signs every OPA request with this key. system_authz.rego rejects requests whose JWT doesn't verify under one of these pubkeys.",
  },
  {
    id: "session-signing",
    label: "Session JWTs (user logins)",
    help: "User-session tokens minted at /api/auth/login are signed with this key. Verified locally by the authenticate middleware (EdDSA whitelist).",
  },
  {
    id: "pep-opa-auth-signing",
    label: "Sentry Auth (Aegis Sentry → OPA)",
    help: "Aegis Sentry signs its OPA requests with this key. JWT aud=opa-studio-pep, which system_authz.rego restricts to read paths only.",
  },
];

function formatDate(s) {
  if (!s) return "—";
  try { return new Date(s).toLocaleString(); }
  catch { return s; }
}

function shortFp(hex) {
  if (!hex) return "";
  return `${hex.slice(0, 12)}…${hex.slice(-6)}`;
}

function statusBadge(status) {
  const map = {
    pending: { label: "Pending", cls: "" },
    active: { label: "Active", cls: "" },
    retired: { label: "Retired", cls: "disabled" },
    revoked: { label: "Revoked", cls: "disabled" },
  };
  const m = map[status] || { label: status, cls: "" };
  return <span className={`status-pill ${m.cls}`}>{m.label}</span>;
}

export default function PlatformKeys({ onClose }) {
  const [keys, setKeys] = useState([]);
  const [trust, setTrust] = useState(null);
  const [opaState, setOpaState] = useState(null);
  const [loading, setLoading] = useState(true);
  const [busyPurpose, setBusyPurpose] = useState(null);
  const [error, setError] = useState(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const list = await api.listPlatformKeys();
      setKeys(list.keys || []);
      setTrust(list.trust || null);
    } catch (e) {
      setError(e?.body?.error || e.message || "Failed to load platform keys");
    } finally {
      setLoading(false);
    }
    try {
      const state = await api.getPlatformKeysOpaState();
      setOpaState(state);
    } catch (e) {
      // Soft failure — OPA may be unreachable; surface the issue but keep
      // the table populated from the DB.
      setOpaState({ inSync: false, issues: [`OPA probe failed: ${e?.body?.error || e.message}`] });
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  async function handleRotate(purpose) {
    const label = PURPOSES.find((p) => p.id === purpose)?.label || purpose;
    if (!confirm(`Rotate ${label}? A new Aegis TrustVault key will be minted and pushed to OPA. The previous key stays accepted as 'retired' until you revoke it.`)) return;
    setBusyPurpose(purpose);
    setError(null);
    try {
      await api.rotatePlatformKey(purpose);
      await refresh();
    } catch (e) {
      setError(e?.body?.error || e.message || "Rotate failed");
    } finally {
      setBusyPurpose(null);
    }
  }

  async function handleRevoke(row) {
    if (row.status === "active") {
      setError("Active keys must be rotated first; the previous key (now retired) is what you revoke.");
      return;
    }
    if (!confirm(`Revoke key ${shortFp(row.fpHex)} (${row.purpose})? Tokens signed under it will stop verifying on the next OPA publish.`)) return;
    setBusyPurpose(row.purpose);
    setError(null);
    try {
      await api.revokePlatformKey(row.fpHex);
      await refresh();
    } catch (e) {
      setError(e?.body?.error || e.message || "Revoke failed");
    } finally {
      setBusyPurpose(null);
    }
  }

  const byPurpose = Object.fromEntries(PURPOSES.map((p) => [p.id, []]));
  for (const k of keys) {
    if (byPurpose[k.purpose]) byPurpose[k.purpose].push(k);
  }
  for (const arr of Object.values(byPurpose)) {
    arr.sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
  }

  const trustBroken = trust && trust.ok === false;
  const opaIssues = opaState?.issues || [];

  return (
    <div className="modal-overlay" role="dialog" aria-modal="true">
      <div className="modal" style={{ maxWidth: 1080 }}>
        <div className="modal-head">
          <h2 className="modal-title">
            Platform <em>signing keys</em>
          </h2>
          <button className="modal-close" type="button" onClick={onClose} aria-label="Close">×</button>
        </div>
        <div className="modal-body">
          {error && <div className="auth-error">{error}</div>}

          {trustBroken && (
            <div className="auth-error">
              Platform trust integrity broken — mutations are frozen until resolved.
              {trust.byPurpose && (
                <ul style={{ margin: "4px 0 0 16px" }}>
                  {Object.entries(trust.byPurpose).map(([p, v]) =>
                    v.ok ? null : <li key={p}>{p}: {v.reason}</li>
                  )}
                </ul>
              )}
            </div>
          )}

          {opaIssues.length > 0 && (
            <div className="auth-error">
              OPA trust drift detected:
              <ul style={{ margin: "4px 0 0 16px" }}>
                {opaIssues.map((m, i) => <li key={i}>{m}</li>)}
              </ul>
            </div>
          )}

          <div className="auth-help" style={{ marginBottom: 12 }}>
            These keys live inside the KMS provider — only their public material
            is stored here. The audit chain records every rotation and revoke.
            Deletion is not permitted (revoke-only invariant).
          </div>

          {loading ? (
            <div className="diff-empty">Loading platform keys…</div>
          ) : (
            PURPOSES.map((p) => {
              const rows = byPurpose[p.id];
              const activeRow = rows.find((r) => r.status === "active");
              const busy = busyPurpose === p.id;
              return (
                <section key={p.id} style={{ marginBottom: 24 }}>
                  <div className="row" style={{ alignItems: "center", marginBottom: 6 }}>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontWeight: 600 }}>{p.label}</div>
                      <div className="auth-help">{p.help}</div>
                    </div>
                    <button
                      className="btn btn-primary"
                      type="button"
                      disabled={busy || !activeRow}
                      onClick={() => handleRotate(p.id)}
                    >
                      {busy ? "Rotating…" : "Rotate"}
                    </button>
                  </div>
                  {rows.length === 0 ? (
                    <div className="diff-empty">No keys yet — bootstrap pending.</div>
                  ) : (
                    <table className="users-table">
                      <thead>
                        <tr>
                          <th>Fingerprint</th>
                          <th>Key ID</th>
                          <th>Status</th>
                          <th>Created</th>
                          <th>Retired</th>
                          <th>Revoked</th>
                          <th style={{ textAlign: "right" }}>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {rows.map((r) => (
                          <tr key={r.fpHex}>
                            <td>
                              <code title={r.fpHex}>{shortFp(r.fpHex)}</code>
                            </td>
                            <td><span className="auth-help">{r.keyId}</span></td>
                            <td>{statusBadge(r.status)}</td>
                            <td><span className="auth-help">{formatDate(r.createdAt)}</span></td>
                            <td><span className="auth-help">{formatDate(r.retiredAt)}</span></td>
                            <td><span className="auth-help">{formatDate(r.revokedAt)}</span></td>
                            <td>
                              <div className="row-actions">
                                {r.status === "retired" && (
                                  <button
                                    className="btn btn-sm"
                                    type="button"
                                    disabled={busy}
                                    onClick={() => handleRevoke(r)}
                                  >
                                    Revoke
                                  </button>
                                )}
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </section>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}
