import { useEffect, useState, useCallback } from "react";
import { api } from "../lib/api.js";

// Helper to format timestamps relative to current time
function timeAgo(dateVal) {
  if (!dateVal) return "never";
  const seconds = Math.floor((Date.now() - new Date(dateVal).getTime()) / 1000);
  if (seconds < 5) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ago`;
}

function shortHash(hex) {
  if (!hex) return "—";
  return hex.length > 12 ? `${hex.slice(0, 8)}…${hex.slice(-4)}` : hex;
}

export default function OpaFleet({ onClose }) {
  const [data, setData] = useState({ replicas: [], currentRevision: "", currentPolicies: [], orgs: [] });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedReplicaIp, setSelectedReplicaIp] = useState(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [refreshTick, setRefreshTick] = useState(0);
  const [searchQuery, setSearchQuery] = useState("");

  const refresh = useCallback(async () => {
    try {
      const res = await api.getOpaFleet();
      setData(res);
      setError(null);
    } catch (e) {
      setError(e?.body?.error || e.message || "Failed to load fleet status");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh, refreshTick]);

  useEffect(() => {
    if (!autoRefresh) return undefined;
    const t = setInterval(() => {
      refresh();
    }, 5000);
    return () => clearInterval(t);
  }, [autoRefresh, refresh]);

  // Auto-select first replica if none is selected
  useEffect(() => {
    if (data.replicas.length > 0 && !selectedReplicaIp) {
      setSelectedReplicaIp(data.replicas[0].ip);
    }
  }, [data.replicas, selectedReplicaIp]);

  const selectedReplica = data.replicas.find((r) => r.ip === selectedReplicaIp) || null;

  // Calculate sync status statistics
  const totalCount = data.replicas.length;
  const inSyncCount = data.replicas.filter((r) => r.inSync).length;
  const syncPercentage = totalCount > 0 ? Math.round((inSyncCount / totalCount) * 100) : 0;

  // Filter replicas by search query (IP or User-Agent)
  const filteredReplicas = data.replicas.filter(
    (r) =>
      r.ip.toLowerCase().includes(searchQuery.toLowerCase()) ||
      r.userAgent.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="modal-overlay" role="dialog" aria-modal="true">
      <style>{`
        .fleet-modal {
          max-width: 1200px !important;
          width: 95% !important;
          height: 85vh !important;
          display: flex;
          flex-direction: column;
        }
        .fleet-grid {
          display: grid;
          grid-template-columns: repeat(3, 1fr);
          gap: 16px;
          margin-bottom: 20px;
        }
        .fleet-card {
          padding: 16px;
          background: var(--surface);
          border: 1px solid var(--border);
          border-radius: var(--radius-lg);
          display: flex;
          flex-direction: column;
          position: relative;
          overflow: hidden;
        }
        .fleet-card::before {
          content: '';
          position: absolute;
          top: 0;
          left: 0;
          width: 100%;
          height: 2px;
          background: var(--border-strong);
        }
        .fleet-card.accented::before {
          background: var(--accent-gradient);
        }
        .fleet-kpi {
          font-size: 26px;
          font-family: var(--font-display);
          font-weight: 600;
          color: var(--text);
          margin-top: 6px;
          display: flex;
          align-items: baseline;
          gap: 8px;
        }
        .fleet-kpi-sub {
          font-size: 11px;
          color: var(--text-muted);
          margin-top: 4px;
        }
        .fleet-layout {
          display: grid;
          grid-template-columns: 1.3fr 1fr;
          gap: 20px;
          flex: 1;
          min-height: 0; /* Ensures proper scroll behaviour in child grids */
        }
        .fleet-panel {
          display: flex;
          flex-direction: column;
          background: var(--bg-tint);
          border: 1px solid var(--border);
          border-radius: var(--radius-lg);
          padding: 18px;
          overflow: hidden;
          min-height: 0;
        }
        .fleet-panel-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 12px;
        }
        .fleet-panel-title {
          font-size: 13px;
          font-weight: 600;
          color: var(--text-soft);
          text-transform: uppercase;
          letter-spacing: 0.05em;
        }
        .pulse-dot {
          border-radius: 50%;
          width: 8px;
          height: 8px;
          display: inline-block;
          flex-shrink: 0;
        }
        .pulse-dot.success {
          background: var(--success);
          box-shadow: 0 0 8px var(--success);
        }
        .pulse-dot.warning {
          background: var(--danger);
          box-shadow: 0 0 8px var(--danger);
          animation: fleet-pulse 1.8s infinite;
        }
        .pulse-dot.neutral {
          background: var(--text-dim);
        }
        @keyframes fleet-pulse {
          0% { opacity: 0.4; }
          50% { opacity: 1; }
          100% { opacity: 0.4; }
        }
        .replica-row {
          cursor: pointer;
          transition: background 0.15s, border-left-color 0.15s;
          border-left: 3px solid transparent;
        }
        .replica-row:hover td {
          background: var(--surface) !important;
        }
        .replica-row.selected {
          background: var(--accent-soft);
          border-left-color: var(--accent);
        }
        .replica-row.selected td {
          background: var(--accent-soft) !important;
        }
        .badge-status {
          font-size: 11px;
          font-weight: 600;
          padding: 2px 8px;
          border-radius: 12px;
          display: inline-flex;
          align-items: center;
          gap: 6px;
        }
        .badge-status.success {
          background: var(--success-soft);
          color: var(--success);
          border: 1px solid rgba(16, 185, 129, 0.2);
        }
        .badge-status.warning {
          background: var(--danger-soft);
          color: var(--danger);
          border: 1px solid rgba(239, 68, 68, 0.2);
        }
        .controls-row {
          display: flex;
          align-items: center;
          gap: 16px;
          margin-bottom: 12px;
        }
        .search-input {
          background: var(--surface);
          border: 1px solid var(--border);
          color: var(--text);
          padding: 6px 12px;
          border-radius: var(--radius);
          font-size: 13px;
          width: 240px;
          outline: none;
        }
        .search-input:focus {
          border-color: var(--border-strong);
        }
        .live-refresh-badge {
          display: flex;
          align-items: center;
          gap: 6px;
          font-size: 12px;
          color: var(--text-muted);
          margin-left: auto;
        }
        .active-policies-badge {
          background: var(--surface-3);
          padding: 2px 6px;
          border-radius: 4px;
          font-size: 11px;
          color: var(--text-soft);
          font-family: var(--font-mono);
        }
        .detail-card-grid {
          display: grid;
          grid-template-columns: 1fr;
          gap: 12px;
          margin-bottom: 16px;
        }
        .detail-meta-item {
          display: flex;
          flex-direction: column;
          gap: 4px;
          padding: 10px;
          background: var(--surface-2);
          border: 1px solid var(--border);
          border-radius: var(--radius);
        }
        .detail-meta-label {
          font-size: 11px;
          color: var(--text-muted);
          text-transform: uppercase;
        }
        .detail-meta-val {
          font-size: 13px;
          font-family: var(--font-mono);
          word-break: break-all;
        }
        .policy-tag-list {
          display: flex;
          flex-direction: column;
          gap: 6px;
          overflow-y: auto;
          flex: 1;
        }
        .policy-tag-item {
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 8px 12px;
          background: var(--surface);
          border: 1px solid var(--border);
          border-radius: var(--radius);
          font-size: 12px;
        }
        .policy-tag-name {
          font-weight: 500;
          color: var(--text);
        }
        .policy-tag-pkg {
          font-size: 11px;
          color: var(--text-muted);
          font-family: var(--font-mono);
          margin-top: 2px;
        }
        .policy-tag-ver {
          background: var(--surface-3);
          color: var(--accent);
          padding: 1px 6px;
          border-radius: 4px;
          font-size: 10px;
          font-family: var(--font-mono);
          border: 1px solid var(--border-strong);
        }
        .no-replicas-placeholder {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          color: var(--text-dim);
          text-align: center;
          padding: 40px 20px;
          flex: 1;
        }
        .no-replicas-placeholder svg {
          margin-bottom: 12px;
          opacity: 0.4;
        }
      `}</style>

      <div className="modal fleet-modal">
        <div className="modal-head">
          <h2 className="modal-title">
            OPA <em>Fleet Status</em>
          </h2>
          <button className="modal-close" type="button" onClick={onClose} aria-label="Close">
            ×
          </button>
        </div>

        <div className="modal-body" style={{ display: "flex", flexDirection: "column", minHeight: 0 }}>
          {error && <div className="auth-error">{error}</div>}

          {/* KPI Dashboard Cards */}
          <div className="fleet-grid">
            <div className="fleet-card accented">
              <span className="auth-help uppercase text-xxs tracking-wider font-semibold">Active Replicas</span>
              <div className="fleet-kpi">
                {totalCount}
                <span className={`pulse-dot ${totalCount > 0 ? "success" : "neutral"}`} style={{ alignSelf: "center" }} />
              </div>
              <div className="fleet-kpi-sub">Containers currently polling bundle</div>
            </div>

            <div className="fleet-card accented">
              <span className="auth-help uppercase text-xxs tracking-wider font-semibold">Sync Health</span>
              <div className="fleet-kpi">
                {syncPercentage}%
                <span className="text-xs text-muted font-normal">({inSyncCount} / {totalCount} sync)</span>
              </div>
              <div className="fleet-kpi-sub">
                <div style={{ width: "100%", height: 4, background: "var(--border)", borderRadius: 2, marginTop: 4 }}>
                  <div
                    style={{
                      width: `${syncPercentage}%`,
                      height: "100%",
                      background: syncPercentage === 100 ? "var(--success)" : "var(--accent)",
                      borderRadius: 2,
                      transition: "width 0.3s ease",
                    }}
                  />
                </div>
              </div>
            </div>

            <div className="fleet-card">
              <span className="auth-help uppercase text-xxs tracking-wider font-semibold">Latest Revision</span>
              <div className="fleet-kpi text-lg mono" style={{ fontSize: 16, marginTop: 14 }}>
                {shortHash(data.currentRevision)}
              </div>
              <div className="fleet-kpi-sub">Active policies in bundle: {data.currentPolicies.length}</div>
            </div>
          </div>

          <div className="controls-row">
            <input
              type="text"
              placeholder="Filter replicas by IP or agent..."
              className="search-input"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
            <button
              className="btn btn-sm btn-secondary"
              type="button"
              onClick={() => setRefreshTick((t) => t + 1)}
              disabled={loading}
            >
              {loading ? "Refreshing..." : "Refresh Now"}
            </button>

            <label className="live-refresh-badge">
              <input
                type="checkbox"
                checked={autoRefresh}
                onChange={(e) => setAutoRefresh(e.target.checked)}
                style={{ cursor: "pointer" }}
              />
              <span>Live polling updates (5s)</span>
            </label>
          </div>

          {totalCount === 0 && !loading ? (
            <div className="no-replicas-placeholder">
              <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path strokeLinecap="round" strokeLinejoin="round" d="M5.121 17.804A13.937 13.937 0 0 1 12 16c2.5 0 4.847.655 6.879 1.804M15 10a3 3 0 1 1-6 0 3 3 0 0 1 6 0Zm6 2a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z" />
              </svg>
              <h4>No OPA instances registered</h4>
              <p className="auth-help" style={{ maxWidth: 450, marginTop: 4 }}>
                Aegis Core has not received any bundle poll requests yet. Ensure your OPA replicas are running and verified against the BUNDLE_TOKEN.
              </p>
            </div>
          ) : (
            <div className="fleet-layout">
              {/* Left Panel: List of Replicas */}
              <div className="fleet-panel">
                <div className="fleet-panel-header">
                  <h3 className="fleet-panel-title">OPA Replicas ({filteredReplicas.length})</h3>
                </div>
                <div style={{ flex: 1, overflowY: "auto" }}>
                  <table className="users-table" style={{ width: "100%", borderCollapse: "collapse" }}>
                    <thead>
                      <tr>
                        <th>Replica IP</th>
                        <th>Tenant</th>
                        <th>Poll Interval</th>
                        <th>Last Poll</th>
                        <th>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredReplicas.map((rep) => {
                        const isSelected = selectedReplicaIp === rep.ip;
                        const org = data.orgs?.find((o) => o.id === rep.orgId);
                        const orgLabel = org ? org.name : (rep.orgId === null ? "Global" : "Default");
                        return (
                          <tr
                            key={rep.ip}
                            className={`replica-row ${isSelected ? "selected" : ""}`}
                            onClick={() => setSelectedReplicaIp(rep.ip)}
                          >
                            <td className="mono" style={{ fontWeight: 600 }}>{rep.ip}</td>
                            <td><span className="auth-help text-xs" style={{ fontSize: 12 }}>{orgLabel}</span></td>
                            <td>{rep.pollingInterval ? `${rep.pollingInterval}s` : "—"}</td>
                            <td>{timeAgo(rep.lastPollAt)}</td>
                            <td>
                              <span className={`badge-status ${rep.inSync ? "success" : "warning"}`}>
                                <span className={`pulse-dot ${rep.inSync ? "success" : "warning"}`} />
                                {rep.inSync ? "In Sync" : "Syncing"}
                              </span>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Right Panel: Selected Replica Details */}
              <div className="fleet-panel">
                {selectedReplica ? (
                  <>
                    <div className="fleet-panel-header">
                      <h3 className="fleet-panel-title">Replica Details ({selectedReplica.ip})</h3>
                    </div>
                    <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0 }}>
                      <div className="detail-card-grid">
                        <div className="detail-meta-item">
                          <span className="detail-meta-label">Tenant / Org</span>
                          <span className="detail-meta-val" style={{ fontSize: 12, fontFamily: "var(--font-sans)", color: "var(--text-soft)", fontWeight: 600 }}>
                            {(() => {
                              const org = data.orgs?.find((o) => o.id === selectedReplica.orgId);
                              return org ? `${org.name} (slug: ${org.slug})` : (selectedReplica.orgId === null ? "Global Platform OPA" : `Org UUID: ${selectedReplica.orgId}`);
                            })()}
                          </span>
                        </div>
                        <div className="detail-meta-item">
                          <span className="detail-meta-label">Bundle Subscription URL</span>
                          <span className="detail-meta-val" style={{ fontSize: 12, color: "var(--accent)" }}>
                            {selectedReplica.orgId
                              ? `/bundle/orgs/${selectedReplica.orgId}/aegis.tar.gz`
                              : "/bundle/aegis.tar.gz"}
                          </span>
                        </div>
                        <div className="detail-meta-item">
                          <span className="detail-meta-label">User-Agent</span>
                          <span className="detail-meta-val" style={{ fontSize: 11, fontFamily: "var(--font-sans)", color: "var(--text-soft)" }}>
                            {selectedReplica.userAgent}
                          </span>
                        </div>
                        <div className="detail-meta-item">
                          <span className="detail-meta-label">Active Revision</span>
                          <span className="detail-meta-val">
                            {selectedReplica.reportedRevision ? selectedReplica.reportedRevision : "None / Pulling initial"}
                          </span>
                        </div>
                      </div>

                      <div className="fleet-panel-header" style={{ borderTop: "1px solid var(--border)", paddingTop: 12, marginTop: 4 }}>
                        <h4 className="fleet-panel-title">
                          Policies Running ({selectedReplica.policies ? selectedReplica.policies.length : 0})
                        </h4>
                        {!selectedReplica.inSync && (
                          <span className="badge-status warning" style={{ fontSize: 10, padding: "1px 6px" }}>
                            Stale revision
                          </span>
                        )}
                      </div>

                      <div className="policy-tag-list">
                        {selectedReplica.policies && selectedReplica.policies.length > 0 ? (
                          selectedReplica.policies.map((pol) => (
                            <div key={pol.id} className="policy-tag-item">
                              <div>
                                <div className="policy-tag-name">{pol.name}</div>
                                <div className="policy-tag-pkg">{pol.package}</div>
                              </div>
                              <span className="policy-tag-ver">v{pol.version}</span>
                            </div>
                          ))
                        ) : selectedReplica.reportedRevision === data.currentRevision ? (
                          <div style={{ padding: "20px 0", textAlign: "center", color: "var(--text-dim)" }}>
                            No active user policies deployed (bundle only carries system/studio authz)
                          </div>
                        ) : (
                          <div style={{ padding: "20px 0", textAlign: "center", color: "var(--text-dim)" }} className="auth-help">
                            Stale revision policies manifest not cached or empty. Waiting for replica to synchronize.
                          </div>
                        )}
                      </div>
                    </div>
                  </>
                ) : (
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", color: "var(--text-dim)" }}>
                    Select a replica from the left list to view active policies and metadata.
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
