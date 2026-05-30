import { useEffect, useState, useCallback } from "react";
import { api } from "../lib/api.js";

// LCS-based line diff: old → new produces add/del/eq entries
function lineDiff(oldLines, newLines) {
  const m = oldLines.length, n = newLines.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 1; i <= m; i++)
    for (let j = 1; j <= n; j++)
      dp[i][j] = oldLines[i - 1] === newLines[j - 1]
        ? dp[i - 1][j - 1] + 1
        : Math.max(dp[i - 1][j], dp[i][j - 1]);
  const result = [];
  let i = m, j = n;
  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && oldLines[i - 1] === newLines[j - 1]) {
      result.unshift({ type: "eq", line: oldLines[i - 1] }); i--; j--;
    } else if (j > 0 && (i === 0 || dp[i][j - 1] >= dp[i - 1][j])) {
      result.unshift({ type: "add", line: newLines[j - 1] }); j--;
    } else {
      result.unshift({ type: "del", line: oldLines[i - 1] }); i--;
    }
  }
  return result;
}

export default function PolicyHistory({ policyId, currentVersion, currentRego, currentLocked, onRestore, isNew }) {
  const [versions, setVersions] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [restoring, setRestoring] = useState(null);
  const [expandedDiffs, setExpandedDiffs] = useState(new Set());
  const [diffData, setDiffData] = useState({});
  const [loadingDiff, setLoadingDiff] = useState(new Set());

  useEffect(() => {
    if (isNew || !policyId) { setVersions([]); return; }
    setLoading(true);
    setError(null);
    api.listVersions(policyId)
      .then(setVersions)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [policyId, currentVersion, isNew]);

  // Clear cached diffs after each save so they re-compute against the new current
  useEffect(() => {
    setDiffData({});
    setExpandedDiffs(new Set());
  }, [currentVersion]);

  const handleRestore = useCallback(async (versionNum) => {
    setRestoring(versionNum);
    try {
      const entry = await api.getVersion(policyId, versionNum);
      onRestore(entry.spec);
    } catch (e) {
      alert(`Failed to load version: ${e.message}`);
    } finally {
      setRestoring(null);
    }
  }, [policyId, onRestore]);

  const handleToggleDiff = useCallback(async (versionNum) => {
    setExpandedDiffs((prev) => {
      const next = new Set(prev);
      if (next.has(versionNum)) { next.delete(versionNum); return next; }
      next.add(versionNum);
      return next;
    });
    if (diffData[versionNum]) return;
    setLoadingDiff((prev) => new Set(prev).add(versionNum));
    try {
      const entry = await api.getVersion(policyId, versionNum);
      const diff = lineDiff(
        (entry.spec.rego || "").split("\n"),
        (currentRego || "").split("\n"),
      );
      const wasLocked = !!entry.spec.locked;
      const lockChanged = wasLocked !== !!currentLocked;
      setDiffData((prev) => ({
        ...prev,
        [versionNum]: { lines: diff, wasLocked, lockChanged },
      }));
    } catch (e) {
      setDiffData((prev) => ({
        ...prev,
        [versionNum]: { lines: [{ type: "err", line: `Error: ${e.message}` }], wasLocked: false, lockChanged: false },
      }));
    } finally {
      setLoadingDiff((prev) => { const s = new Set(prev); s.delete(versionNum); return s; });
    }
  }, [policyId, currentRego, currentLocked, diffData]);

  if (isNew) {
    return <div className="history-empty"><p>Save this policy to start tracking versions.</p></div>;
  }
  if (loading) {
    return <div className="history-empty"><p>Loading version history…</p></div>;
  }
  if (error) {
    return <div className="history-empty"><p style={{ color: "var(--danger)" }}>Failed to load history: {error}</p></div>;
  }
  if (!versions.length) {
    return <div className="history-empty"><p>No version history yet.</p></div>;
  }

  return (
    <div className="history">
      <div className="history-header">
        <span className="history-title">Version History</span>
        <span className="history-count">{versions.length} saved version{versions.length !== 1 ? "s" : ""}</span>
      </div>
      <div className="history-list">
        {versions.map((v) => {
          const isCurrent = v.version === currentVersion;
          const d = new Date(v.savedAt);
          const isExpanded = expandedDiffs.has(v.version);
          const isDiffLoading = loadingDiff.has(v.version);
          const diffEntry = diffData[v.version];
          const lines = diffEntry?.lines;
          const hasRegoChanges = lines && lines.some((l) => l.type !== "eq" && l.type !== "err");
          return (
            <div key={v.version} className={`history-item-wrap${isCurrent ? " current" : ""}`}>
              <div className="history-item">
                <div className="history-item-left">
                  <span className="history-version">v{v.version}</span>
                  {isCurrent && <span className="history-current-badge">current</span>}
                  {v.locked && (
                    <span className="locked-badge sm" title="This version was saved while the policy was locked">
                      Locked
                    </span>
                  )}
                </div>
                <div className="history-item-meta">
                  <span className="history-date">
                    {d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" })}
                  </span>
                  <span className="history-time">
                    {d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })}
                  </span>
                </div>
                <div className="history-item-actions">
                  {!isCurrent && (
                    <>
                      <button
                        className={`btn btn-sm btn-ghost${isExpanded ? " active" : ""}`}
                        onClick={() => handleToggleDiff(v.version)}
                        disabled={isDiffLoading}
                        title="Show Rego diff vs current"
                      >
                        {isDiffLoading ? "…" : isExpanded ? "▾ Diff" : "▸ Diff"}
                      </button>
                      <button
                        className="btn btn-sm"
                        onClick={() => handleRestore(v.version)}
                        disabled={restoring !== null}
                      >
                        {restoring === v.version ? "Loading…" : "Restore"}
                      </button>
                    </>
                  )}
                </div>
              </div>
              {isExpanded && (
                <div className="history-diff">
                  {!diffEntry ? (
                    <div className="diff-empty">Loading diff…</div>
                  ) : (
                    <>
                      {diffEntry.lockChanged && (
                        <div className="diff-lock-change">
                          Lock state: <strong>{diffEntry.wasLocked ? "locked" : "unlocked"}</strong>
                          {" → "}
                          <strong>{currentLocked ? "locked" : "unlocked"}</strong>
                        </div>
                      )}
                      {!hasRegoChanges ? (
                        <div className="diff-empty">
                          {diffEntry.lockChanged
                            ? `No Rego changes — the only difference between v${v.version} and current is the lock state.`
                            : `No Rego changes from v${v.version} to current.`}
                        </div>
                      ) : (
                        <>
                          <div className="diff-legend">v{v.version} → current (Rego)</div>
                          {lines.map((line, idx) => (
                            <div key={idx} className={`diff-line diff-${line.type}`}>
                              <span className="diff-gutter">
                                {line.type === "add" ? "+" : line.type === "del" ? "−" : " "}
                              </span>
                              <span className="diff-content">{line.line}</span>
                            </div>
                          ))}
                        </>
                      )}
                    </>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
      <div className="history-footer">
        Restoring loads a previous version into the editor as unsaved changes. Save to create a new version.
      </div>
    </div>
  );
}
