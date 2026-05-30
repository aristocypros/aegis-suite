import { useEffect, useState, useCallback } from "react";
import { api } from "../lib/api.js";
import { useOrgs } from "../lib/useOrgs.js";

const ASYMMETRIC_ALGS = [
  "EdDSA",
  "ES256", "ES384", "ES512",
  "RS256", "RS384", "RS512",
  "PS256", "PS384", "PS512",
];
const HMAC_ALGS = ["HS256", "HS384", "HS512"];
const ALL_ALGS = [...ASYMMETRIC_ALGS, ...HMAC_ALGS];

function formatDate(s) {
  if (!s) return "—";
  try { return new Date(s).toLocaleString(); }
  catch { return s; }
}

function isHmac(alg) {
  return HMAC_ALGS.includes(alg);
}

export default function TrustKeys({ currentUser, onClose }) {
  const [keys, setKeys] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const isRoot = !!currentUser?.isRoot;
  const { orgs, lookup: orgName } = useOrgs();

  const [mode, setMode] = useState("inline"); // 'inline' | 'jwks_url'
  const [newKid, setNewKid] = useState("");
  const [newAlg, setNewAlg] = useState("EdDSA");
  const [newPem, setNewPem] = useState("");
  const [newJwk, setNewJwk] = useState("");
  const [newSecret, setNewSecret] = useState("");
  const [newJwksUrl, setNewJwksUrl] = useState("");
  const [newJwksTtl, setNewJwksTtl] = useState("");
  const [newTenant, setNewTenant] = useState("");
  const [newOrgId, setNewOrgId] = useState("");
  const [creating, setCreating] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const list = await api.listTrustKeys();
      setKeys(list);
    } catch (e) {
      setError(e?.body?.error || e.message || "Failed to load trust keys");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  function resetForm() {
    setNewKid("");
    setNewPem("");
    setNewJwk("");
    setNewSecret("");
    setNewJwksUrl("");
    setNewJwksTtl("");
    setNewTenant("");
  }

  async function handleCreate(e) {
    e.preventDefault();
    if (creating) return;
    if (!newKid.trim()) { setError("kid is required"); return; }
    setCreating(true);
    setError(null);
    try {
      const payload = {
        kid: newKid.trim(),
        alg: newAlg,
        sourceKind: mode,
      };
      if (newTenant.trim()) payload.tenant = newTenant.trim();
      // Only root can target another org; sub-admins are pinned to their
      // own by the backend regardless of body content.
      if (isRoot && newOrgId) payload.orgId = newOrgId;

      if (mode === "inline") {
        if (isHmac(newAlg)) {
          if (!newSecret) { setError("secret is required for HMAC algorithms"); setCreating(false); return; }
          payload.secret = newSecret;
        } else if (newPem.trim()) {
          payload.pem = newPem;
        } else if (newJwk.trim()) {
          try {
            payload.jwk = JSON.parse(newJwk);
          } catch {
            setError("JWK is not valid JSON"); setCreating(false); return;
          }
        } else {
          setError("Either PEM or JWK is required for asymmetric algorithms");
          setCreating(false);
          return;
        }
      } else {
        if (!newJwksUrl.trim()) {
          setError("JWKS URL is required"); setCreating(false); return;
        }
        payload.jwksUrl = newJwksUrl.trim();
        if (newJwksTtl) {
          const ttl = parseInt(newJwksTtl, 10);
          if (Number.isFinite(ttl) && ttl > 0) payload.jwksTtlSeconds = ttl;
        }
      }

      await api.createTrustKey(payload);
      resetForm();
      await refresh();
    } catch (e) {
      setError(e?.body?.error || e.message || "Create failed");
    } finally {
      setCreating(false);
    }
  }

  async function handleRevoke(k) {
    if (!confirm(`Revoke key "${k.kid}"? Policies that reference this kid will fail verification within ~30s.`)) return;
    try {
      await api.revokeTrustKey(k.kid);
      await refresh();
    } catch (e) {
      setError(e?.body?.error || e.message || "Revoke failed");
    }
  }

  async function handleRefresh(k) {
    try {
      const res = await api.refreshTrustKey(k.kid);
      if (res?.error) setError(`Refresh: ${res.error}`);
      await refresh();
    } catch (e) {
      setError(e?.body?.error || e.message || "Refresh failed");
    }
  }

  async function handleDelete(k) {
    if (!confirm(`Permanently delete revoked key "${k.kid}"? This cannot be undone.`)) return;
    try {
      await api.deleteTrustKey(k.kid);
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
            Manage <em>trust keys</em>
          </h2>
          <button className="modal-close" type="button" onClick={onClose} aria-label="Close">×</button>
        </div>
        <div className="modal-body">
          {error && <div className="auth-error">{error}</div>}

          <form className="user-create-form" onSubmit={handleCreate} autoComplete="off">
            <div className="row" style={{ marginBottom: 8 }}>
              <div className="field" style={{ marginBottom: 0 }}>
                <label className="field-label">Source</label>
                <select
                  className="field-input"
                  value={mode}
                  onChange={(e) => setMode(e.target.value)}
                  disabled={creating}
                >
                  <option value="inline">Inline (paste PEM / JWK / secret)</option>
                  <option value="jwks_url">JWKS URL (BYO, refreshes on a timer)</option>
                </select>
              </div>
              <div className="field" style={{ marginBottom: 0 }}>
                <label className="field-label" htmlFor="tk-kid">KID</label>
                <input
                  id="tk-kid"
                  className="field-input"
                  type="text"
                  value={newKid}
                  onChange={(e) => setNewKid(e.target.value)}
                  required
                  disabled={creating}
                  placeholder="e.g. tenant-1"
                />
              </div>
              <div className="field" style={{ marginBottom: 0 }}>
                <label className="field-label" htmlFor="tk-alg">Algorithm</label>
                <select
                  id="tk-alg"
                  className="field-input"
                  value={newAlg}
                  onChange={(e) => setNewAlg(e.target.value)}
                  disabled={creating || mode === "jwks_url" && isHmac(newAlg)}
                >
                  {ALL_ALGS.map((a) => (
                    <option key={a} value={a}
                      disabled={mode === "jwks_url" && HMAC_ALGS.includes(a)}>
                      {a}{HMAC_ALGS.includes(a) ? " (HMAC)" : ""}
                    </option>
                  ))}
                </select>
              </div>
              <div className="field" style={{ marginBottom: 0 }}>
                <label className="field-label" htmlFor="tk-tenant">Tenant (optional)</label>
                <input
                  id="tk-tenant"
                  className="field-input"
                  type="text"
                  value={newTenant}
                  onChange={(e) => setNewTenant(e.target.value)}
                  disabled={creating}
                />
              </div>
              {isRoot && (
                <div className="field" style={{ marginBottom: 0 }}>
                  <label className="field-label" htmlFor="tk-org">Org</label>
                  <select
                    id="tk-org"
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

            {mode === "inline" && !isHmac(newAlg) && (
              <>
                <div className="field">
                  <label className="field-label" htmlFor="tk-pem">PEM public key</label>
                  <textarea
                    id="tk-pem"
                    className="field-input"
                    rows={5}
                    value={newPem}
                    onChange={(e) => setNewPem(e.target.value)}
                    disabled={creating}
                    placeholder="-----BEGIN PUBLIC KEY-----&#10;...&#10;-----END PUBLIC KEY-----"
                  />
                </div>
                <div className="field">
                  <label className="field-label" htmlFor="tk-jwk">…or JWK JSON</label>
                  <textarea
                    id="tk-jwk"
                    className="field-input"
                    rows={4}
                    value={newJwk}
                    onChange={(e) => setNewJwk(e.target.value)}
                    disabled={creating}
                    placeholder={`{"kty":"OKP","crv":"Ed25519","x":"..."}`}
                  />
                  <div className="auth-help">Provide either a PEM or a JWK — the other form is derived.</div>
                </div>
              </>
            )}

            {mode === "inline" && isHmac(newAlg) && (
              <div className="field">
                <label className="field-label" htmlFor="tk-secret">HMAC secret</label>
                <input
                  id="tk-secret"
                  className="field-input"
                  type="password"
                  value={newSecret}
                  onChange={(e) => setNewSecret(e.target.value)}
                  disabled={creating}
                  autoComplete="new-password"
                />
                <div className="auth-help">The secret is never echoed back from the server.</div>
              </div>
            )}

            {mode === "jwks_url" && (
              <div className="row">
                <div className="field" style={{ marginBottom: 0, flex: 2 }}>
                  <label className="field-label" htmlFor="tk-url">JWKS URL</label>
                  <input
                    id="tk-url"
                    className="field-input"
                    type="url"
                    value={newJwksUrl}
                    onChange={(e) => setNewJwksUrl(e.target.value)}
                    disabled={creating}
                    placeholder="https://idp.example.com/.well-known/jwks.json"
                  />
                </div>
                <div className="field" style={{ marginBottom: 0 }}>
                  <label className="field-label" htmlFor="tk-ttl">TTL (seconds, optional)</label>
                  <input
                    id="tk-ttl"
                    className="field-input"
                    type="number"
                    min={30}
                    value={newJwksTtl}
                    onChange={(e) => setNewJwksTtl(e.target.value)}
                    disabled={creating}
                    placeholder="300"
                  />
                </div>
              </div>
            )}

            <div className="row" style={{ marginTop: 8 }}>
              <button className="btn btn-primary" type="submit" disabled={creating || !newKid.trim()}>
                {creating ? "Adding…" : "Add trust key"}
              </button>
            </div>
            <div className="auth-help">
              Keys are published to OPA at <code>data.studio.keys[kid]</code>. Reference them from a policy via a <code>verify</code> condition with <code>keyRef.source: "data.studio.keys"</code>.
            </div>
          </form>

          {loading ? (
            <div className="diff-empty">Loading trust keys…</div>
          ) : keys.length === 0 ? (
            <div className="diff-empty">No trust keys yet. Add one above.</div>
          ) : (
            <table className="users-table">
              <thead>
                <tr>
                  <th>KID</th>
                  <th>Alg</th>
                  {isRoot && <th>Org</th>}
                  <th>Source</th>
                  <th>Status</th>
                  <th>Created</th>
                  <th>Last fetched</th>
                  <th style={{ textAlign: "right" }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {keys.map((k) => {
                  const revoked = k.status === "revoked";
                  const isJwks = k.sourceKind === "jwks_url";
                  return (
                    <tr key={k.kid}>
                      <td>
                        <strong>{k.kid}</strong>
                        {k.tenant && (
                          <div className="auth-help" style={{ marginTop: 2 }}>tenant: {k.tenant}</div>
                        )}
                      </td>
                      <td><span className="role-badge">{k.alg}</span></td>
                      {isRoot && (
                        <td>
                          <span className="auth-help">{orgName(k.orgId)}</span>
                        </td>
                      )}
                      <td>
                        {isJwks ? (
                          <span className="auth-help" title={k.jwksUrl}>
                            JWKS URL
                            {k.jwksTtlSeconds ? ` · ${k.jwksTtlSeconds}s TTL` : ""}
                          </span>
                        ) : (
                          <span className="auth-help">Inline</span>
                        )}
                      </td>
                      <td>
                        <span className={`status-pill ${revoked ? "disabled" : ""}`}>
                          {revoked ? "Revoked" : "Active"}
                        </span>
                        {k.jwksLastError && !revoked && (
                          <div className="auth-help" style={{ color: "var(--danger, #b00)", marginTop: 2 }}>
                            {k.jwksLastError}
                          </div>
                        )}
                      </td>
                      <td><span className="auth-help">{formatDate(k.createdAt)}</span></td>
                      <td><span className="auth-help">{formatDate(k.jwksLastFetchedAt)}</span></td>
                      <td>
                        <div className="row-actions">
                          {isJwks && !revoked && (
                            <button className="btn btn-sm" type="button" onClick={() => handleRefresh(k)}>
                              Refresh
                            </button>
                          )}
                          {!revoked && (
                            <button className="btn btn-sm" type="button" onClick={() => handleRevoke(k)}>
                              Revoke
                            </button>
                          )}
                          {revoked && (
                            <button
                              className="btn btn-sm btn-danger"
                              type="button"
                              onClick={() => handleDelete(k)}
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
    </div>
  );
}
