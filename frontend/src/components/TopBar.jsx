import { useEffect, useRef, useState } from "react";
import { THEMES } from "../lib/themes.js";
import { can } from "../lib/auth.js";
import { api } from "../lib/api.js";

function avatarLetter(s) {
  return (s || "?").trim().charAt(0).toUpperCase();
}

export default function TopBar({
  opaStatus,
  user,
  onLogout,
  onShowUsers,
  onShowAudit,
  onShowTrustKeys,
  onShowPepCallers,
  onShowPlatformKeys,
  onShowOrgs,
  onShowRoles,
  onChangePassword,
  currentTheme,
  onThemeChange,
}) {
  const ok = opaStatus?.ok && opaStatus?.opa?.ok;
  const [menuOpen, setMenuOpen] = useState(false);
  const [hudOpen, setHudOpen] = useState(false);
  const menuRef = useRef(null);
  const hudRef = useRef(null);

  // Background integrity state for header-level badge alerts
  const [integrityState, setIntegrityState] = useState({
    ok: true,
    reason: "",
    checking: false,
  });

  // HUD specific detailed status data
  const [hudData, setHudData] = useState({
    loading: false,
    audit: null,
    keys: null,
    drift: null,
    trust: null,
    error: null,
  });

  // 1. Click-outside handlers
  useEffect(() => {
    if (!menuOpen) return undefined;
    function onDoc(e) {
      if (menuRef.current && !menuRef.current.contains(e.target)) {
        setMenuOpen(false);
      }
    }
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [menuOpen]);

  useEffect(() => {
    if (!hudOpen) return undefined;
    function onDoc(e) {
      if (hudRef.current && !hudRef.current.contains(e.target)) {
        setHudOpen(false);
      }
    }
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [hudOpen]);

  // 2. Background integrity check loop (every 20s)
  useEffect(() => {
    if (!user) return;
    const hasAudit = can(user, "read", "audit");
    if (!hasAudit) {
      // Non-admins default to engine health only
      setIntegrityState({ ok: true, reason: "", checking: false });
      return;
    }

    let active = true;
    async function checkIntegrity() {
      try {
        const res = await api.verifyAudit();
        if (active) {
          setIntegrityState({
            ok: res.ok,
            reason: res.reason || "",
            checking: false,
          });
        }
      } catch (e) {
        if (active) {
          setIntegrityState({
            ok: false,
            reason: e.message || "Cryptographic check failed",
            checking: false,
          });
        }
      }
    }

    checkIntegrity();
    const interval = setInterval(checkIntegrity, 20000);
    return () => {
      active = false;
      clearInterval(interval);
    };
  }, [user]);

  // 3. HUD data loader (runs when HUD is expanded)
  useEffect(() => {
    if (!hudOpen || !user) return;

    let active = true;
    async function loadHudData() {
      setHudData((d) => ({ ...d, loading: true, error: null }));
      try {
        const promises = [];
        const hasAudit = can(user, "read", "audit");
        const hasKeys = can(user, "read", "platform_key");

        if (hasAudit) {
          promises.push(api.verifyAudit().then((res) => ({ type: "audit", data: res })));
        }
        if (hasKeys) {
          promises.push(api.listPlatformKeys().then((res) => ({ type: "keys", data: res })));
          promises.push(api.getPlatformKeysOpaState().then((res) => ({ type: "drift", data: res })));
        } else {
          promises.push(api.getPlatformKeysTrustStatus().then((res) => ({ type: "trust", data: res })));
        }

        const results = await Promise.all(promises);
        if (!active) return;

        const nextData = { loading: false, error: null };
        results.forEach(({ type, data }) => {
          nextData[type] = data;
        });
        setHudData((d) => ({ ...d, ...nextData }));
      } catch (e) {
        if (!active) return;
        setHudData((d) => ({ ...d, loading: false, error: e.message }));
      }
    }

    loadHudData();
    const interval = setInterval(loadHudData, 10000);
    return () => {
      active = false;
      clearInterval(interval);
    };
  }, [hudOpen, user]);

  const trustOk = hudData.keys ? hudData.keys.trust : hudData.trust?.trust;
  const trustBroken = !integrityState.ok || trustOk === false;
  const isDrifting = hudData.drift && !hudData.drift.inSync;

  return (
    <header className="topbar">
      <div className="brand">
        <div className="brand-mark">/0</div>
        <div>
          <div className="brand-title">
            Aegis Policy <em>Fabric</em>
          </div>
          <span className="brand-subtitle">OPA · REGO · DIGITAL ASSETS</span>
        </div>
      </div>
      <div className="topbar-actions">
        {/* Unified Shield Integrity HUD Badge */}
        <div className="integrity-hud-container" ref={hudRef}>
          <button
            type="button"
            className={`integrity-badge ${!ok ? "offline" : trustBroken ? "compromised" : isDrifting ? "drift" : "secure"}`}
            onClick={() => setHudOpen((o) => !o)}
            aria-label="Toggle cryptographic integrity and engine trust dashboard"
            aria-expanded={hudOpen}
          >
            <span className="integrity-icon">
              {!ok ? "🚨" : trustBroken ? "❌" : isDrifting ? "⚠️" : "🛡️"}
            </span>
            <span className="integrity-text">
              {!ok
                ? "OPA: OFFLINE"
                : trustBroken
                  ? "MUTATIONS FROZEN"
                  : isDrifting
                    ? "DRIFT DETECTED"
                    : "INTEGRITY: SECURE"}
            </span>
            <span className="integrity-pulse" />
          </button>

          {hudOpen && (
            <div className="integrity-hud-dropdown">
              <div className="hud-header">
                <h4>🛡️ Cryptographic Trust & Integrity HUD</h4>
                {hudData.loading && <span className="hud-spinner" />}
              </div>

              {hudData.error && (
                <div className="hud-alert-banner danger">
                  <strong>Error:</strong> {hudData.error}
                </div>
              )}

              {/* CARD 1: OPA Engine Health */}
              <div className="hud-card">
                <h5>Engine Health</h5>
                <div className="hud-row">
                  <span>Connection:</span>
                  <span className={ok ? "status-success" : "status-danger"}>
                    {ok ? "● Connected" : "● Disconnected"}
                  </span>
                </div>
                {opaStatus?.opa?.version && (
                  <div className="hud-row">
                    <span>OPA Version:</span>
                    <span className="mono">{opaStatus.opa.version}</span>
                  </div>
                )}
                <div className="hud-row">
                  <span>Trust Store status:</span>
                  <span className={trustOk ? "status-success" : "status-warning"}>
                    {trustOk ? "✓ Valid Platform Signatures" : "● Unverified / Drifting"}
                  </span>
                </div>
              </div>

              {/* CARD 2: Cryptographic Audit Ledger Proof */}
              {can(user, "read", "audit") && (
                <div className="hud-card">
                  <h5>Audit Ledger Proof</h5>
                  <div className="hud-row">
                    <span>Ledger chain:</span>
                    <span className={integrityState.ok ? "status-success" : "status-danger"}>
                      {integrityState.ok ? "✓ Structural Chain Intact" : "❌ Hash Chain Broken!"}
                    </span>
                  </div>
                  {hudData.audit && (
                    <>
                      <div className="hud-row">
                        <span>Signatures verified:</span>
                        <span className="status-success font-semibold">
                          ✓ {hudData.audit.signaturesChecked} blocks cryptographically checked
                        </span>
                      </div>
                      <div className="hud-row">
                        <span>Verification model:</span>
                        <span className="mono text-xs">Ed25519 / PostgreSQL Ledger</span>
                      </div>
                      {hudData.audit.brokenAtSeq && (
                        <div className="hud-alert-banner danger text-xs mt-2">
                          <strong>Tampering detected:</strong> broken at sequence block #{hudData.audit.brokenAtSeq}!
                        </div>
                      )}
                    </>
                  )}
                  {integrityState.reason && !hudData.audit && (
                    <div className="hud-alert-banner danger text-xs mt-2">
                      <strong>Audit failure:</strong> {integrityState.reason}
                    </div>
                  )}
                </div>
              )}

              {/* CARD 3: KMS Platform Trust Status */}
              {can(user, "read", "platform_key") && hudData.keys && (
                <div className="hud-card">
                  <h5>Aegis TrustVault Platform Key Status</h5>
                  <div className="hud-keys-list">
                    {hudData.keys.keys && hudData.keys.keys.length > 0 ? (
                      hudData.keys.keys.map((k) => (
                        <div key={k.fpHex} className="hud-key-item">
                          <div className="hud-key-meta">
                            <span className="hud-key-purpose mono text-xs">{k.purpose}</span>
                            <span className="hud-key-fp text-muted text-xxs mono">{k.fpHex.substring(0, 16)}...</span>
                          </div>
                          <span className={`status-badge ${k.status}`}>
                            {k.status}
                          </span>
                        </div>
                      ))
                    ) : (
                      <span className="text-muted text-xs">No active Aegis TrustVault keys loaded.</span>
                    )}
                  </div>
                </div>
              )}

              {/* Drift alerts section */}
              {can(user, "read", "platform_key") && isDrifting && (
                <div className="hud-alert-banner warning text-xs mt-1">
                  <strong>⚠️ OPA drift detected!</strong> DB key map differs from active OPA configs.
                  <ul className="text-xxs list-disc pl-4 mt-1 font-mono">
                    {hudData.drift.issues?.map((issue, idx) => (
                      <li key={idx}>{issue}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </div>

        <div className="theme-selector">
          <select
            value={currentTheme}
            onChange={(e) => onThemeChange(e.target.value)}
            className="theme-select"
            aria-label="Select theme"
          >
            {THEMES.map((t) => (
              <option key={t.id} value={t.id}>
                {t.name}
              </option>
            ))}
          </select>
          <div className="theme-select-icon">🎨</div>
        </div>

        {user && (
          <div ref={menuRef} style={{ position: "relative" }}>
            <button
              type="button"
              className="user-chip"
              onClick={() => setMenuOpen((o) => !o)}
              aria-haspopup="menu"
              aria-expanded={menuOpen}
            >
              <span className="user-chip-avatar">{avatarLetter(user.username)}</span>
              <span className="user-chip-name">{user.username}</span>
              <span className="user-chip-role">{user.role}</span>
              <span className="user-chip-caret">▼</span>
            </button>
            {menuOpen && (
              <div className="user-menu" role="menu">
                <div className="user-menu-header">Signed in as {user.username}</div>
                <button
                  type="button"
                  className="user-menu-item"
                  onClick={() => { setMenuOpen(false); onChangePassword?.(); }}
                >
                  Change password
                </button>
                {can(user, "read", "audit") && (
                  <button
                    type="button"
                    className="user-menu-item"
                    onClick={() => { setMenuOpen(false); onShowAudit?.(); }}
                  >
                    Audit log
                  </button>
                )}
                {can(user, "read", "user") && (
                  <button
                    type="button"
                    className="user-menu-item"
                    onClick={() => { setMenuOpen(false); onShowUsers?.(); }}
                  >
                    Manage users
                  </button>
                )}
                {can(user, "read", "trust_key") && (
                  <button
                    type="button"
                    className="user-menu-item"
                    onClick={() => { setMenuOpen(false); onShowTrustKeys?.(); }}
                  >
                    Trust keys
                  </button>
                )}
                {can(user, "read", "pep_caller") && (
                  <button
                    type="button"
                    className="user-menu-item"
                    onClick={() => { setMenuOpen(false); onShowPepCallers?.(); }}
                  >
                    Aegis Sentry callers
                  </button>
                )}
                {can(user, "read", "role") && (
                  <button
                    type="button"
                    className="user-menu-item"
                    onClick={() => { setMenuOpen(false); onShowRoles?.(); }}
                  >
                    Roles
                  </button>
                )}
                {can(user, "read", "org") && (
                  <button
                    type="button"
                    className="user-menu-item"
                    onClick={() => { setMenuOpen(false); onShowOrgs?.(); }}
                  >
                    Organizations
                  </button>
                )}
                {can(user, "read", "platform_key") && (
                  <button
                    type="button"
                    className="user-menu-item"
                    onClick={() => { setMenuOpen(false); onShowPlatformKeys?.(); }}
                  >
                    Platform keys
                  </button>
                )}
                <div className="user-menu-divider" />
                <button
                  type="button"
                  className="user-menu-item danger"
                  onClick={() => { setMenuOpen(false); onLogout?.(); }}
                >
                  Sign out
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    </header>
  );
}

