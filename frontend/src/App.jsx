import { useState, useEffect, useCallback } from "react";
import { api } from "./lib/api.js";
import { getToken, clearToken, onAuthChange } from "./lib/auth.js";

import TopBar from "./components/TopBar.jsx";
import Sidebar from "./components/Sidebar.jsx";
import PolicyEditor from "./components/PolicyEditor.jsx";
import EmptyState from "./components/EmptyState.jsx";
import TemplatesModal from "./components/TemplatesModal.jsx";
import Toast from "./components/Toast.jsx";
import LoginPage from "./components/LoginPage.jsx";
import ChangePasswordModal from "./components/ChangePasswordModal.jsx";
import UserManagement from "./components/UserManagement.jsx";
import TrustKeys from "./components/TrustKeys.jsx";
import PepCallers from "./components/PepCallers.jsx";
import PlatformKeys from "./components/PlatformKeys.jsx";
import AuditLog from "./components/AuditLog.jsx";
import Orgs from "./components/Orgs.jsx";
import Roles from "./components/Roles.jsx";
import OpaFleet from "./components/OpaFleet.jsx";
import { THEMES } from "./lib/themes.js";


function newBlankPolicy() {
  return {
    id: crypto.randomUUID(),
    name: "Untitled Policy",
    package: "studio.untitled_policy",
    description: "",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "",
            conditions: [],
          },
        ],
      },
    ],
  };
}

// Branches saved before the groups format was introduced may have both a
// legacy `conditions` array AND a `groups` array on the same branch object.
// VB reads/writes only `groups`, so strip the stale `conditions` on load.
function normalizePolicy(policy) {
  if (!policy?.rules) return policy;
  return {
    ...policy,
    rules: policy.rules.map((rule) => ({
      ...rule,
      branches: (rule.branches || []).map((branch) => {
        if (Array.isArray(branch.groups) && branch.groups.length && Array.isArray(branch.conditions)) {
          const { conditions: _dropped, ...rest } = branch;
          return rest;
        }
        return branch;
      }),
    })),
  };
}

export default function App() {
  // ── Auth state ─────────────────────────────────────────────────────────
  const [user, setUser] = useState(null);
  const [authChecked, setAuthChecked] = useState(false);
  const [showChangePassword, setShowChangePassword] = useState(false);
  const [showUserManagement, setShowUserManagement] = useState(false);
  const [showTrustKeys, setShowTrustKeys] = useState(false);
  const [showPepCallers, setShowPepCallers] = useState(false);
  const [showPlatformKeys, setShowPlatformKeys] = useState(false);
  const [showAuditLog, setShowAuditLog] = useState(false);
  const [showOrgs, setShowOrgs] = useState(false);
  const [showRoles, setShowRoles] = useState(false);
  const [showOpaFleet, setShowOpaFleet] = useState(false);

  // ── Studio state ───────────────────────────────────────────────────────
  const [policies, setPolicies] = useState([]);
  const [activeId, setActiveId] = useState(null);
  const [active, setActive] = useState(null);
  const [dirty, setDirty] = useState(false);

  const [showTemplates, setShowTemplates] = useState(false);
  const [opaStatus, setOpaStatus] = useState({ ok: false });
  const [toast, setToast] = useState(null);
  const [templates, setTemplates] = useState([]);
  const [policyHealth, setPolicyHealth] = useState({});

  const showToast = useCallback((message, type = "success") => {
    setToast({ message, type, key: Date.now() });
    setTimeout(() => setToast(null), 3000);
  }, []);

  // ── Theme state ────────────────────────────────────────────────────────
  const [themeId, setThemeId] = useState(() => localStorage.getItem("opa-theme") || "indigo");

  // ── Sidebar collapsed state ────────────────────────────────────────────
  const [sidebarCollapsed, setSidebarCollapsed] = useState(
    () => localStorage.getItem("opa-sidebar-collapsed") === "1"
  );
  useEffect(() => {
    localStorage.setItem("opa-sidebar-collapsed", sidebarCollapsed ? "1" : "0");
  }, [sidebarCollapsed]);

  useEffect(() => {
    const theme = THEMES.find(t => t.id === themeId) || THEMES[0];
    const root = document.documentElement;
    Object.entries(theme.colors).forEach(([key, value]) => {
      root.style.setProperty(key, value);
    });
    localStorage.setItem("opa-theme", themeId);
  }, [themeId]);


  // ── Bootstrap auth on mount ────────────────────────────────────────────
  useEffect(() => {
    const token = getToken();
    if (!token) { setAuthChecked(true); return; }
    api.me()
      .then(({ user }) => setUser(user))
      .catch(() => clearToken())
      .finally(() => setAuthChecked(true));
  }, []);

  // ── React to 401-driven logouts (api.js calls clearToken → emitAuthChange).
  useEffect(() => {
    const off = onAuthChange(() => {
      if (!getToken()) {
        setUser(null);
        setShowChangePassword(false);
        setShowUserManagement(false);
        setShowTrustKeys(false);
        setShowPepCallers(false);
        setShowPlatformKeys(false);
        setShowAuditLog(false);
        setShowOrgs(false);
        setShowRoles(false);
        setShowOpaFleet(false);
        setActive(null);
        setActiveId(null);
        setPolicies([]);
      }
    });
    return off;
  }, []);

  // ── Load policies + health, but only after auth ────────────────────────
  useEffect(() => {
    if (!user) return undefined;
    api.listPolicies().then(setPolicies).catch(() => setPolicies([]));
    api.listTemplates().then(setTemplates).catch(() => setTemplates([]));
    api.health().then(setOpaStatus).catch(() => setOpaStatus({ ok: false }));
    const t = setInterval(() => {
      api.health().then(setOpaStatus).catch(() => setOpaStatus({ ok: false }));
    }, 8000);
    return () => clearInterval(t);
  }, [user]);

  // Background validation scanner running on policy list changes
  useEffect(() => {
    if (policies.length === 0) return;
    let activeScanner = true;
    
    const scanAll = async () => {
      await Promise.all(
        policies.map(async (policy) => {
          let needsValidation = false;
          setPolicyHealth(prev => {
            if (prev[policy.id]?.version !== policy.version) {
              needsValidation = true;
            }
            return prev;
          });

          if (!needsValidation) return;

          try {
            const res = await api.validate(policy);
            if (!activeScanner) return;
            setPolicyHealth(prev => ({
              ...prev,
              [policy.id]: {
                version: policy.version,
                valid: (res.errors || []).length === 0,
                errors: res.errors || [],
                warnings: res.warnings || [],
              }
            }));
          } catch (err) {
            console.error(`Health scan failed for policy ${policy.id}:`, err);
          }
        })
      );
    };
    
    scanAll();
    
    return () => {
      activeScanner = false;
    };
  }, [policies]);

  // ── When activeId changes, fetch the policy
  useEffect(() => {
    if (!user) return;
    if (!activeId) { setActive(null); setDirty(false); return; }
    // Only fetch if the policy is already persisted in the database
    const exists = policies.some((p) => p.id === activeId);
    if (!exists) return;
    api.getPolicy(activeId).then((p) => { setActive(normalizePolicy(p)); setDirty(false); });
  }, [activeId, user, policies]);

  const refreshPolicies = useCallback(async () => {
    const list = await api.listPolicies();
    setPolicies(list);
    return list;
  }, []);

  const handleNew = useCallback(() => {
    const blank = newBlankPolicy();
    setActive(blank);
    setActiveId(blank.id);
    setDirty(true);
  }, []);

  const handleFromTemplate = useCallback(async (templateId) => {
    const { template, sampleInput } = await api.getTemplate(templateId);
    const tempId = crypto.randomUUID();
    const cloned = {
      ...template,
      id: tempId,
      _sampleInput: sampleInput,
    };
    setActive(normalizePolicy(cloned));
    setActiveId(tempId);
    setDirty(true);
    setShowTemplates(false);
    showToast(`Loaded template: ${template.name}`);
  }, [showToast]);

  const handleSelect = useCallback((id) => {
    if (dirty) {
      if (!confirm("You have unsaved changes. Discard?")) return;
    }
    setActiveId(id);
  }, [dirty]);

  const handleChange = useCallback((updated) => {
    setActive(updated);
    setDirty(true);
  }, []);

  const handleSave = useCallback(async () => {
    if (!active) return;
    try {
      const existing = policies.find((p) => p.id === active.id);
      const saved = existing
        ? await api.updatePolicy(active.id, active)
        : await api.savePolicy(active);
      setActive(normalizePolicy(saved));
      setActiveId(saved.id);
      setDirty(false);
      await refreshPolicies();
      showToast(`Saved & deployed to OPA: ${saved.name}`);
    } catch (e) {
      showToast(`Save failed: ${e.message}`, "error");
    }
  }, [active, policies, refreshPolicies, showToast]);

  const handleToggleLock = useCallback(async () => {
    if (!active) return;
    const willLock = !active.locked;
    const verb = willLock ? "Lock" : "Unlock";
    const consequence = willLock
      ? "It will be removed from OPA and stop enforcing until unlocked."
      : "It will be re-deployed to OPA and resume enforcing.";
    if (!confirm(`${verb} policy "${active.name}"?\n\n${consequence}`)) return;
    try {
      const updated = willLock
        ? await api.lockPolicy(active.id)
        : await api.unlockPolicy(active.id);
      setActive(normalizePolicy(updated));
      setDirty(false);
      await refreshPolicies();
      showToast(willLock ? "Policy locked" : "Policy unlocked");
    } catch (e) {
      showToast(`${verb} failed: ${e.message}`, "error");
    }
  }, [active, refreshPolicies, showToast]);

  const handleRestore = useCallback((spec) => {
    setActive(normalizePolicy({ ...active, ...spec }));
    setDirty(true);
  }, [active]);

  const handleDiscard = useCallback(async () => {
    if (!active || !dirty) return;
    const isNew = !policies.find((p) => p.id === active.id);
    if (!confirm(isNew ? "Discard this new policy?" : "Discard unsaved changes?")) return;
    if (isNew) {
      setActive(null);
      setActiveId(null);
      setDirty(false);
      return;
    }
    try {
      const fresh = await api.getPolicy(active.id);
      setActive(normalizePolicy(fresh));
      setDirty(false);
    } catch (e) {
      showToast(`Discard failed: ${e.message}`, "error");
    }
  }, [active, dirty, policies, showToast]);

  const handleClonePolicy = useCallback(async (policyToClone) => {
    if (dirty) {
      if (!confirm("You have unsaved changes. Discard them to clone?")) return;
    }
    try {
      let sourcePolicy = policyToClone;
      if (typeof policyToClone === "string") {
        sourcePolicy = policies.find((p) => p.id === policyToClone);
        if (!sourcePolicy) {
          sourcePolicy = await api.getPolicy(policyToClone);
        } else {
          sourcePolicy = await api.getPolicy(sourcePolicy.id);
        }
      }
      if (!sourcePolicy) {
        showToast("Source policy not found for cloning", "error");
        return;
      }
      const clonedSpec = JSON.parse(JSON.stringify(sourcePolicy));
      clonedSpec.id = crypto.randomUUID();
      clonedSpec.name = `${clonedSpec.name || "Untitled Policy"}_copy`;
      clonedSpec.package = `${clonedSpec.package || "studio.untitled_policy"}_copy`;
      clonedSpec.locked = false;
      delete clonedSpec.version;
      delete clonedSpec.createdAt;
      delete clonedSpec.updatedAt;

      const normalized = normalizePolicy(clonedSpec);
      setActive(normalized);
      setActiveId(clonedSpec.id);
      setDirty(true);
      showToast(`Loaded copy of ${sourcePolicy.name || "policy"}. Click Save & Deploy to persist.`);
    } catch (e) {
      showToast(`Cloning failed: ${e.message}`, "error");
    }
  }, [policies, showToast, dirty]);

  const handleLogout = useCallback(async () => {
    await api.logout();
    clearToken();
  }, []);

  const handlePasswordChanged = useCallback(async () => {
    setShowChangePassword(false);
    try {
      const { user: fresh } = await api.me();
      setUser(fresh);
      showToast("Password updated");
    } catch {
      // If /me fails (e.g. server invalidated token) the 401 handler will log out.
    }
  }, [showToast]);

  // ── Render gates ───────────────────────────────────────────────────────
  if (!authChecked) return null;
  if (!user) return <LoginPage onLogin={setUser} />;

  const forcedChange = !!user.mustChangePassword;

  return (
    <div className="app">
      <TopBar
        opaStatus={opaStatus}
        user={user}
        onLogout={handleLogout}
        onShowUsers={() => setShowUserManagement(true)}
        onShowTrustKeys={() => setShowTrustKeys(true)}
        onShowPepCallers={() => setShowPepCallers(true)}
        onShowPlatformKeys={() => setShowPlatformKeys(true)}
        onShowAudit={() => setShowAuditLog(true)}
        onShowOrgs={() => setShowOrgs(true)}
        onShowRoles={() => setShowRoles(true)}
        onShowOpaFleet={() => setShowOpaFleet(true)}
        onChangePassword={() => setShowChangePassword(true)}
        currentTheme={themeId}
        onThemeChange={setThemeId}
      />

      <div className={`main ${sidebarCollapsed ? "sidebar-collapsed" : ""}`}>
        <Sidebar
          policies={policies}
          activeId={activeId}
          onSelect={handleSelect}
          onNew={handleNew}
          onShowTemplates={() => setShowTemplates(true)}
          collapsed={sidebarCollapsed}
          onToggleCollapsed={() => setSidebarCollapsed((v) => !v)}
          currentUser={user}
          templates={templates}
          onSelectTemplate={handleFromTemplate}
          policyHealth={policyHealth}
          onClone={handleClonePolicy}
        />
        {active ? (
          <PolicyEditor
            policy={active}
            onChange={handleChange}
            onSave={handleSave}
            onToggleLock={handleToggleLock}
            onRestore={handleRestore}
            onDiscard={handleDiscard}
            dirty={dirty}
            isNew={!policies.find((p) => p.id === active.id)}
            currentTheme={themeId}
            onClone={handleClonePolicy}
          />


        ) : (
          <EmptyState
            onNew={handleNew}
            onShowTemplates={() => setShowTemplates(true)}
          />
        )}
      </div>

      {showTemplates && !forcedChange && (
        <TemplatesModal
          onSelect={handleFromTemplate}
          onClose={() => setShowTemplates(false)}
        />
      )}

      {showUserManagement && !forcedChange && (
        <UserManagement
          currentUser={user}
          onClose={() => setShowUserManagement(false)}
        />
      )}

      {showTrustKeys && !forcedChange && (
        <TrustKeys currentUser={user} onClose={() => setShowTrustKeys(false)} />
      )}

      {showPepCallers && !forcedChange && (
        <PepCallers currentUser={user} onClose={() => setShowPepCallers(false)} />
      )}

      {showPlatformKeys && !forcedChange && (
        <PlatformKeys onClose={() => setShowPlatformKeys(false)} />
      )}

      {showAuditLog && !forcedChange && (
        <AuditLog currentUser={user} onClose={() => setShowAuditLog(false)} />
      )}

      {showOrgs && !forcedChange && (
        <Orgs currentUser={user} onClose={() => setShowOrgs(false)} />
      )}

      {showRoles && !forcedChange && (
        <Roles currentUser={user} onClose={() => setShowRoles(false)} />
      )}

      {showOpaFleet && !forcedChange && (
        <OpaFleet onClose={() => setShowOpaFleet(false)} />
      )}

      {(forcedChange || showChangePassword) && (
        <ChangePasswordModal
          user={user}
          forced={forcedChange}
          onComplete={handlePasswordChanged}
          onCancel={() => setShowChangePassword(false)}
        />
      )}

      {toast && <Toast message={toast.message} type={toast.type} />}
    </div>
  );
}
