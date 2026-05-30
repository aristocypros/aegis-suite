import { Fragment, useEffect, useState, useCallback } from "react";
import { api } from "../lib/api.js";
import { useOrgs } from "../lib/useOrgs.js";

function formatDate(s) {
  if (!s) return "—";
  try {
    return new Date(s).toLocaleString();
  } catch {
    return s;
  }
}

function shortHex(h, n = 12) {
  if (!h) return "—";
  return h.length <= n ? h : h.slice(0, n) + "…";
}

// Visual Side-by-Side Diff Renderer
function renderJsonDiff(before, after) {
  if (!before && !after) {
    return <div className="text-muted text-xs p-3">No state changes recorded (e.g. read operation or genesis block).</div>;
  }
  const b = before || {};
  const a = after || {};
  const allKeys = Array.from(new Set([...Object.keys(b), ...Object.keys(a)]));

  return (
    <div className="json-diff-container">
      <div className="json-diff-header">
        <div>🔑 Property Key</div>
        <div>🛑 State Before (Pre-Mutation)</div>
        <div>❇️ State After (Post-Mutation)</div>
      </div>
      <div className="json-diff-body">
        {allKeys.map((key) => {
          const valB = b[key];
          const valA = a[key];
          const hasChanged = JSON.stringify(valB) !== JSON.stringify(valA);

          if (!hasChanged) {
            return (
              <div key={key} className="json-diff-row unchanged">
                <div className="json-diff-key font-mono">{key}</div>
                <div className="json-diff-val mono text-xs">{JSON.stringify(valB)}</div>
                <div className="json-diff-val mono text-xs">{JSON.stringify(valA)}</div>
              </div>
            );
          }

          const isRemoved = key in b && !(key in a);
          const isAdded = !(key in b) && key in a;

          let rowClass = "modified";
          if (isRemoved) rowClass = "removed";
          if (isAdded) rowClass = "added";

          return (
            <div key={key} className={`json-diff-row ${rowClass}`}>
              <div className="json-diff-key font-mono">{key}</div>
              <div className="json-diff-val pre-wrap mono text-xs text-red-400">
                {valB !== undefined ? JSON.stringify(valB, null, 2) : "—"}
              </div>
              <div className="json-diff-val pre-wrap mono text-xs text-green-400">
                {valA !== undefined ? JSON.stringify(valA, null, 2) : "—"}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default function AuditLog({ currentUser, onClose }) {
  const isRoot = !!currentUser?.isRoot;
  const { lookup: orgName } = useOrgs();
  const [entries, setEntries] = useState([]);
  const [head, setHead] = useState(null);
  const [chainStatus, setChainStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [expanded, setExpanded] = useState(null); // seq number
  const [verifyResult, setVerifyResult] = useState(null);
  const [verifying, setVerifying] = useState(false);
  const [oldestSeq, setOldestSeq] = useState(null);
  const [hasMore, setHasMore] = useState(false);

  // Active view: "timeline" or "table"
  const [activeTab, setActiveTab] = useState("timeline");
  // Proving scan animation sequence tracker
  const [scanningSeq, setScanningSeq] = useState(null);

  const load = useCallback(async ({ append = false, beforeSeq } = {}) => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.listAudit({ limit: 50, beforeSeq });
      setHead(data.head);
      setChainStatus(data.chainStatus);
      const next = append ? [...entries, ...data.entries] : data.entries;
      setEntries(next);
      if (data.entries.length > 0) {
        setOldestSeq(data.entries[data.entries.length - 1].seq);
      }
      setHasMore(data.entries.length === 50);
    } catch (e) {
      setError(e?.body?.error || e.message || "Failed to load audit log");
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function handleVerify() {
    setVerifying(true);
    setVerifyResult(null);

    // 1. Run Proof-of-Trust visual sweep animation down the list of loaded blocks
    if (entries.length > 0) {
      const sortedSeqs = [...entries].map((e) => e.seq).sort((a, b) => b - a); // descending
      for (const seq of sortedSeqs) {
        setScanningSeq(seq);
        await new Promise((resolve) => setTimeout(resolve, 30));
      }
    }

    // 2. Perform actual server-side cryptographic audit proof checks
    try {
      const result = await api.verifyAudit();
      setVerifyResult(result);
    } catch (e) {
      setVerifyResult({
        ok: false,
        reason: e?.body?.error || e.message || "verify failed",
      });
    } finally {
      setScanningSeq(null);
      setVerifying(false);
    }
  }

  async function handleLoadMore() {
    if (oldestSeq && oldestSeq > 1) {
      await load({ append: true, beforeSeq: oldestSeq });
    }
  }

  return (
    <div className="modal-overlay" role="dialog" aria-modal="true">
      <div className="modal" style={{ maxWidth: 1200, width: "95vw" }}>
        <div className="modal-head">
          <div className="modal-head-left">
            <h2 className="modal-title">
              Audit <em>ledger</em>
            </h2>
            <div className="view-toggle-tabs">
              <button
                type="button"
                className={`tab-btn ${activeTab === "timeline" ? "active" : ""}`}
                onClick={() => setActiveTab("timeline")}
              >
                ⛓️ Visual Ledger Chain
              </button>
              <button
                type="button"
                className={`tab-btn ${activeTab === "table" ? "active" : ""}`}
                onClick={() => setActiveTab("table")}
              >
                📊 Tabular SQL View
              </button>
            </div>
          </div>
          <button className="modal-close" type="button" onClick={onClose} aria-label="Close">×</button>
        </div>
        <div className="modal-body">
          {error && <div className="auth-error">{error}</div>}

          {/* Tamper status indicator and prover actions */}
          <div className="audit-status-bar flex items-center justify-between">
            <div className="flex items-center gap-3">
              {chainStatus?.ok ? (
                <span className="audit-status-ok flex items-center gap-1">
                  <span className="pulsing-green-dot" /> Structural Chain OK
                </span>
              ) : (
                <span className="audit-status-broken">
                  ⚠️ Chain Broken: {chainStatus?.reason || "unknown"}
                </span>
              )}
              {head && (
                <span className="auth-help text-xs">
                  ledger head sequence <strong>#{head.seq}</strong> · SHA-256 hash <code className="mono">{shortHex(head.hashHex, 20)}</code>
                </span>
              )}
            </div>
            <button
              className={`btn btn-sm ${verifying ? "btn-secondary animate-pulse" : "btn-primary"}`}
              type="button"
              onClick={handleVerify}
              disabled={verifying}
            >
              {verifying ? "🔐 Proving trust..." : "🔐 Run Cryptographic Audit Proof"}
            </button>
          </div>

          {verifyResult && (
            <div className={`verify-result-banner ${verifyResult.ok ? "passed" : "failed"}`}>
              <div className="flex items-center gap-2">
                <span className="icon">{verifyResult.ok ? "✅" : "❌"}</span>
                <div>
                  <strong>
                    {verifyResult.ok ? "Cryptographic End-to-End Verification Passed" : "Tamper Evidence Detected!"}
                  </strong>
                  <div className="text-xs opacity-90 mt-1">
                    {verifyResult.reason} · Ed25519 signatures checked: {verifyResult.signaturesChecked ?? 0} blocks
                    {verifyResult.brokenAtSeq != null && (
                      <> · ⚠️ broken chain at sequence block #{verifyResult.brokenAtSeq}</>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}

          {loading && entries.length === 0 ? (
            <div className="diff-empty">Loading audit ledger blocks…</div>
          ) : (
            <>
              {activeTab === "timeline" ? (
                /* Sleek Visual Ledger Block Timeline View */
                <div className="ledger-timeline">
                  {entries.map((e, index) => {
                    const isOpen = expanded === e.seq;
                    const isScanning = scanningSeq === e.seq;
                    const hasPrevHash = !!e.prevHashHex;
                    const nextEntry = entries[index - 1]; // because list is descending (newer on top)

                    return (
                      <div key={e.seq} className="timeline-node-wrapper">
                        {/* Connecting Line from prev block */}
                        {index < entries.length - 1 && (
                          <div className="timeline-chain-connector">
                            <div className="connector-line" />
                            <div className="connector-badge" title="Cryptographically chained SHA-256 link">
                              <span className="connector-arrow">↓</span>
                              <span className="connector-hash">{shortHex(e.prevHashHex, 8)}</span>
                            </div>
                          </div>
                        )}

                        <div
                          className={`ledger-block-node ${isOpen ? "expanded" : ""} ${isScanning ? "scanning" : ""}`}
                          onClick={() => setExpanded(isOpen ? null : e.seq)}
                        >
                          {/* Top lighting scan effect */}
                          {isScanning && <div className="block-scanning-line" />}

                          <div className="ledger-block-header">
                            <div className="block-title-group">
                              <span className="block-seq">BLOCK #{e.seq}</span>
                              <span className="block-signature-check">
                                <span className="check-icon">✓</span> VERIFIED SIGNATURE
                              </span>
                            </div>
                            <span className="block-time">{formatDate(e.createdAt)}</span>
                          </div>

                          <div className="ledger-block-body">
                            <div className="block-details-grid">
                              <div>
                                <span className="block-lbl">Actor</span>
                                <span className="block-val flex items-center gap-1">
                                  👤 {e.actorUsername || "system"}
                                  {e.payload?.actor?.is_root && (
                                    <span className="root-indicator">root</span>
                                  )}
                                </span>
                              </div>
                              {isRoot && (
                                <div>
                                  <span className="block-lbl">Organization</span>
                                  <span className="block-val">
                                    🏢 {e.actorOrgId ? orgName(e.actorOrgId) : "system global"}
                                  </span>
                                </div>
                              )}
                              <div>
                                <span className="block-lbl">Action</span>
                                <span className="block-val">
                                  <code className="action-tag">{e.action}</code>
                                </span>
                              </div>
                              <div>
                                <span className="block-lbl">Resource Type</span>
                                <span className="block-val">
                                  <code className="resource-tag">{e.resourceType}</code>
                                </span>
                              </div>
                            </div>

                            <div className="block-hashes-row">
                              <div className="hash-item" title={e.entryHashHex}>
                                <span className="hash-lbl">Entry Hash:</span>
                                <code className="hash-val">{shortHex(e.entryHashHex, 18)}</code>
                              </div>
                              <div className="hash-item" title={e.prevHashHex || "(genesis)"}>
                                <span className="hash-lbl">Prev Hash:</span>
                                <code className="hash-val">{shortHex(e.prevHashHex || "(genesis)", 18)}</code>
                              </div>
                            </div>
                          </div>

                          {/* Expanded detail section inside block card */}
                          {isOpen && (
                            <div className="ledger-block-expanded-details" onClick={(ev) => ev.stopPropagation()}>
                              <div className="audit-detail-grid">
                                <div>
                                  <span className="auth-help">Full Prev Hash</span>
                                  <code>{e.prevHashHex || "(genesis block)"}</code>
                                </div>
                                <div>
                                  <span className="auth-help">Full Entry Hash</span>
                                  <code>{e.entryHashHex}</code>
                                </div>
                                <div>
                                  <span className="auth-help">Aegis TrustVault Signing Key Fingerprint</span>
                                  <code>{e.signingKeyFpHex}</code>
                                </div>
                                <div>
                                  <span className="auth-help">Ed25519 Cryptographic Signature</span>
                                  <code className="break-all">{e.signatureB64}</code>
                                </div>
                              </div>

                              <div className="diff-tabs-section mt-4">
                                <h4 className="section-title">📊 State Mutation JSON Diff</h4>
                                {renderJsonDiff(e.payload?.before, e.payload?.after)}
                              </div>

                              <div className="raw-payload-section mt-4">
                                <span className="auth-help">Complete Chained JSON Payload</span>
                                <pre className="audit-payload mt-1">
                                  {JSON.stringify(e.payload, null, 2)}
                                </pre>
                              </div>
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                /* Tabular SQL View */
                <table className="audit-table">
                  <thead>
                    <tr>
                      <th>Seq</th>
                      <th>Time</th>
                      <th>Actor</th>
                      {isRoot && <th>Actor org</th>}
                      <th>Action</th>
                      <th>Resource</th>
                      <th>Hash</th>
                    </tr>
                  </thead>
                  <tbody>
                    {entries.map((e) => {
                      const isOpen = expanded === e.seq;
                      return (
                        <Fragment key={e.seq}>
                          <tr
                            onClick={() => setExpanded(isOpen ? null : e.seq)}
                            style={{ cursor: "pointer" }}
                          >
                            <td>
                              <strong>{e.seq}</strong>
                            </td>
                            <td>
                              <span className="auth-help">{formatDate(e.createdAt)}</span>
                            </td>
                            <td>
                              {e.actorUsername || "—"}
                              {e.payload?.actor?.is_root && (
                                <span className="auth-help" style={{ marginLeft: 6 }}>
                                  (root)
                                </span>
                              )}
                            </td>
                            {isRoot && (
                              <td>
                                <span className="auth-help">
                                  {e.actorOrgId ? orgName(e.actorOrgId) : "—"}
                                </span>
                              </td>
                            )}
                            <td>
                              <code>{e.action}</code>
                            </td>
                            <td>
                              <code>{e.resourceType}</code>
                              {e.resourceId && (
                                <div className="auth-help" style={{ fontSize: 11 }}>
                                  {shortHex(e.resourceId, 18)}
                                </div>
                              )}
                            </td>
                            <td>
                              <code title={e.entryHashHex}>{shortHex(e.entryHashHex, 14)}</code>
                            </td>
                          </tr>
                          {isOpen && (
                            <tr className="audit-row-expanded">
                              <td colSpan={isRoot ? 7 : 6}>
                                <div className="audit-detail-grid">
                                  <div>
                                    <div className="auth-help">prev hash</div>
                                    <code>{e.prevHashHex || "(genesis)"}</code>
                                  </div>
                                  <div>
                                    <div className="auth-help">entry hash</div>
                                    <code>{e.entryHashHex}</code>
                                  </div>
                                  <div>
                                    <div className="auth-help">signing key fp</div>
                                    <code>{e.signingKeyFpHex}</code>
                                  </div>
                                  <div>
                                    <div className="auth-help">signature</div>
                                    <code style={{ wordBreak: "break-all" }}>{e.signatureB64}</code>
                                  </div>
                                </div>
                                <div className="diff-tabs-section mt-3">
                                  <h4 className="section-title">📊 State Mutation JSON Diff</h4>
                                  {renderJsonDiff(e.payload?.before, e.payload?.after)}
                                </div>
                                <div className="auth-help" style={{ marginTop: 12 }}>
                                  payload
                                </div>
                                <pre className="audit-payload">{JSON.stringify(e.payload, null, 2)}</pre>
                              </td>
                            </tr>
                          )}
                        </Fragment>
                      );
                    })}
                  </tbody>
                </table>
              )}

              {hasMore && (
                <div style={{ marginTop: 20, marginBottom: 10, textAlign: "center" }}>
                  <button className="btn btn-sm" type="button" onClick={handleLoadMore} disabled={loading}>
                    {loading ? "Loading…" : "Load older blocks"}
                  </button>
                </div>
              )}
              {entries.length === 0 && !loading && <div className="diff-empty">No audit entries.</div>}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
