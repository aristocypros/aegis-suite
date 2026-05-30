import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../lib/api.js";
import { highlightJson } from "../lib/highlight.js";
import { buildSampleInput } from "../lib/buildSampleInput.js";

// Sandbox: send an input document to OPA, see what the policy decides.
// - If the policy is saved AND not currently dirty, we hit /evaluate/:id
//   which evaluates the already-deployed policy in OPA.
// - Otherwise we hit /preview-evaluate which compiles + uploads a temp
//   policy, evaluates it, and removes it — so users can test unsaved edits
//   without polluting the OPA store.
export default function Sandbox({ policy, dirty, evaluationResult, evaluationInput, onEvaluateComplete }) {
  const ruleOptions = useMemo(() => {
    const rules = (policy.rules || []).map((r) => ({
      value: r.name,
      label: `${r.name} (${r.type})`,
    }));
    return [{ value: "", label: "— whole package —" }, ...rules];
  }, [policy.rules]);

  // Default rule target = the first rule in the policy (so the auto-built
  // payload has something to target without requiring user interaction).
  const firstRuleName = (policy.rules || [])[0]?.name || "";
  const [ruleName, setRuleName] = useState(firstRuleName);

  // Compose the initial payload from the rule itself, falling back to the
  // template's curated `_sampleInput` if the rule has no branches yet.
  const composeSeed = (pol, rname) => {
    const fromRule = buildSampleInput(pol, rname);
    if (fromRule && Object.keys(fromRule).length) return fromRule;
    return pol._sampleInput || {};
  };

  const [inputText, setInputText] = useState(() => {
    if (evaluationInput) return JSON.stringify(evaluationInput, null, 2);
    return JSON.stringify(composeSeed(policy, firstRuleName), null, 2);
  });
  const [parseError, setParseError] = useState(null);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState(evaluationResult);
  const [error, setError] = useState(null);

  // Track the last auto-generated text so we know when the user has hand-edited
  // the input. While the input still matches the auto-generated payload, we
  // refresh it freely on rule changes; once it diverges, we leave it alone.
  const lastAutoTextRef = useRef(inputText);
  const userEditedRef = useRef(false);

  // Active Left Tab: "json", "scenarios", "jwt"
  const [activeLeftTab, setActiveLeftTab] = useState("json");

  // Scenarios State
  const [scenarios, setScenarios] = useState([]);
  const [activeScenarioId, setActiveScenarioId] = useState("default");

  // JWT State
  const [jwtAlg, setJwtAlg] = useState("HS256");
  const [jwtSecret, setJwtSecret] = useState("secret");
  const [jwtClaims, setJwtClaims] = useState(() => 
    JSON.stringify({ sub: "1234567890", name: "Alice Admin", role: "admin", iat: Math.floor(Date.now() / 1000) }, null, 2)
  );
  const [jwtClaimsError, setJwtClaimsError] = useState(null);
  const [jwtToken, setJwtToken] = useState("");
  const [copySuccess, setCopySuccess] = useState(false);
  const [injectSuccess, setInjectSuccess] = useState(false);

  // PEP Callers State
  const [pepCallers, setPepCallers] = useState([]);
  const [selectedPepCallerId, setSelectedPepCallerId] = useState("");

  // Load PEP Callers from DB
  useEffect(() => {
    let active = true;
    api.listPepCallers()
      .then((data) => {
        if (active) {
          setPepCallers(Array.isArray(data) ? data : []);
        }
      })
      .catch((err) => {
        console.error("Failed to load PEP callers for sandbox", err);
      });
    return () => {
      active = false;
    };
  }, [policy.id]);

  // Reset PEP Caller selection when policy changes
  useEffect(() => {
    setSelectedPepCallerId("");
  }, [policy.id]);

  const handlePepCallerChange = (callerId) => {
    setSelectedPepCallerId(callerId);
    let obj = {};
    try {
      obj = inputText.trim() ? JSON.parse(inputText) : {};
    } catch {
      obj = {};
    }

    if (!callerId) {
      delete obj.caller;
    } else {
      const caller = pepCallers.find((c) => c.callerId === callerId);
      if (caller) {
        obj.caller = {
          id: caller.callerId,
          mode: caller.authMode,
          tenant: caller.tenant || "tenant-1",
          orgId: caller.orgId || "default-org",
          scopeTags: caller.scopeTags || []
        };

        // If caller mode is "jwt", automatically prep the Mock JWT Signer claims payload
        if (caller.authMode === "jwt") {
          let claims = {};
          try {
            claims = JSON.parse(jwtClaims);
          } catch {
            claims = { sub: "1234567890", name: "Alice Admin", role: "admin", iat: Math.floor(Date.now() / 1000) };
          }
          claims.sub = caller.jwtSubject || caller.callerId;
          claims.orgId = caller.orgId || "default-org";
          claims.iat = Math.floor(Date.now() / 1000);
          setJwtClaims(JSON.stringify(claims, null, 2));
        }
      }
    }

    const nextText = JSON.stringify(obj, null, 2);
    setInputText(nextText);
    lastAutoTextRef.current = nextText;
    setParseError(null);
  };

  // Synchronize result from props when they change (e.g. from outer evaluations)
  useEffect(() => {
    setResult(evaluationResult);
  }, [evaluationResult]);

  // Load scenarios from localStorage scoped by policy.id
  useEffect(() => {
    const key = `sandbox_scenarios_${policy.id}`;
    let stored = [];
    try {
      const parsed = JSON.parse(localStorage.getItem(key));
      if (Array.isArray(parsed) && parsed.length > 0) {
        stored = parsed;
      }
    } catch (e) {
      console.error("Failed to load scenarios from localStorage", e);
    }

    if (stored.length === 0) {
      const seed = composeSeed(policy, ruleName);
      stored = [{
        id: "default",
        name: "Default Scenario",
        text: JSON.stringify(seed, null, 2)
      }];
    }

    setScenarios(stored);

    // Auto-select the first scenario and populate inputText if user hasn't edited
    if (!userEditedRef.current) {
      const active = stored[0];
      setActiveScenarioId(active.id);
      setInputText(active.text);
      lastAutoTextRef.current = active.text;
    }
  }, [policy.id]);

  // Regenerate the payload when the policy, selected rule, or PEP caller changes — but
  // only if the user hasn't hand-edited it.
  useEffect(() => {
    if (userEditedRef.current) return;
    let seed = composeSeed(policy, ruleName);
    if (selectedPepCallerId) {
      const caller = pepCallers.find((c) => c.callerId === selectedPepCallerId);
      if (caller) {
        seed = {
          ...seed,
          caller: {
            id: caller.callerId,
            mode: caller.authMode,
            tenant: caller.tenant || "tenant-1",
            orgId: caller.orgId || "default-org",
            scopeTags: caller.scopeTags || []
          }
        };
      }
    }
    const seedStr = JSON.stringify(seed, null, 2);
    setInputText(seedStr);
    lastAutoTextRef.current = seedStr;
    setResult(null);
    setError(null);
    setParseError(null);
  }, [policy.id, ruleName, selectedPepCallerId, pepCallers]);

  // When switching to a different policy, snap back to the new policy's first
  // rule and clear the user-edited flag so auto-fill resumes.
  useEffect(() => {
    userEditedRef.current = false;
    setRuleName((policy.rules || [])[0]?.name || "");
  }, [policy.id]);

  const regenerateFromRule = () => {
    let seed = composeSeed(policy, ruleName);
    if (selectedPepCallerId) {
      const caller = pepCallers.find((c) => c.callerId === selectedPepCallerId);
      if (caller) {
        seed = {
          ...seed,
          caller: {
            id: caller.callerId,
            mode: caller.authMode,
            tenant: caller.tenant || "tenant-1",
            orgId: caller.orgId || "default-org",
            scopeTags: caller.scopeTags || []
          }
        };
      }
    }
    const seedStr = JSON.stringify(seed, null, 2);
    setInputText(seedStr);
    lastAutoTextRef.current = seedStr;
    userEditedRef.current = false;
    setParseError(null);
  };

  const handleInputChange = (val) => {
    setInputText(val);
    if (val !== lastAutoTextRef.current) userEditedRef.current = true;
    if (!val.trim()) {
      setParseError(null);
      return;
    }
    try {
      JSON.parse(val);
      setParseError(null);
    } catch (e) {
      setParseError(e.message);
    }
  };

  const handleEvaluate = async () => {
    let input;
    try {
      input = inputText.trim() ? JSON.parse(inputText) : {};
    } catch (e) {
      setParseError(e.message);
      return;
    }
    setRunning(true);
    setError(null);
    setResult(null);
    const t0 = performance.now();
    try {
      // A locked policy is not in OPA — fall back to preview-evaluate so the
      // user can still see what the policy WOULD decide if unlocked. Same
      // path for unsaved/new policies.
      const usePreview = dirty || policy._isNew || policy.locked;
      
      // Always evaluate the whole package under the hood to fetch all rule outcomes
      // for the visual debugger, but display the specific rule verdict in the verdict pane.
      const res = usePreview
        ? await api.previewEvaluate(policy, input, undefined)
        : await api.evaluate(policy.id, input, undefined);
      
      const elapsed = Math.round(performance.now() - t0);
      const mode = policy.locked ? "locked-preview" : usePreview ? "preview" : "deployed";
      const finalRes = { ...res, _elapsed: elapsed, _mode: mode };
      
      setResult(finalRes);
      if (onEvaluateComplete) {
        onEvaluateComplete(finalRes, input);
      }
    } catch (e) {
      const detail = e.body?.details
        ? typeof e.body.details === "string"
          ? e.body.details
          : JSON.stringify(e.body.details, null, 2)
        : null;
      setError(detail ? `${e.message}\n\n${detail}` : e.message);
    } finally {
      setRunning(false);
    }
  };

  // Scenario Manager Handlers
  const handleSelectScenario = (s) => {
    setActiveScenarioId(s.id);
    setInputText(s.text);
    lastAutoTextRef.current = s.text;
    setParseError(null);
  };

  const handleCreateScenario = () => {
    const name = prompt("Enter scenario profile name:", `Scenario ${scenarios.length + 1}`);
    if (name === null) return;
    const trimmed = name.trim();
    if (!trimmed) return;

    const newScenario = {
      id: `scenario_${Date.now()}`,
      name: trimmed,
      text: inputText
    };

    const nextScenarios = [...scenarios, newScenario];
    setScenarios(nextScenarios);
    setActiveScenarioId(newScenario.id);
    localStorage.setItem(`sandbox_scenarios_${policy.id}`, JSON.stringify(nextScenarios));
  };

  const handleRenameScenario = (id) => {
    const s = scenarios.find(item => item.id === id);
    if (!s) return;
    const name = prompt("Rename scenario profile to:", s.name);
    if (name === null) return;
    const trimmed = name.trim();
    if (!trimmed) return;

    const nextScenarios = scenarios.map(item => item.id === id ? { ...item, name: trimmed } : item);
    setScenarios(nextScenarios);
    localStorage.setItem(`sandbox_scenarios_${policy.id}`, JSON.stringify(nextScenarios));
  };

  const handleDeleteScenario = (id) => {
    if (scenarios.length <= 1) return;
    const confirmDelete = window.confirm("Are you sure you want to delete this scenario profile?");
    if (!confirmDelete) return;

    const nextScenarios = scenarios.filter(item => item.id !== id);
    setScenarios(nextScenarios);
    localStorage.setItem(`sandbox_scenarios_${policy.id}`, JSON.stringify(nextScenarios));

    if (activeScenarioId === id) {
      const fallback = nextScenarios[0];
      setActiveScenarioId(fallback.id);
      setInputText(fallback.text);
      lastAutoTextRef.current = fallback.text;
    }
  };

  const handleSaveActiveScenario = () => {
    const nextScenarios = scenarios.map(item => item.id === activeScenarioId ? { ...item, text: inputText } : item);
    setScenarios(nextScenarios);
    localStorage.setItem(`sandbox_scenarios_${policy.id}`, JSON.stringify(nextScenarios));

    const btn = document.getElementById("scenario-save-indicator");
    if (btn) {
      btn.innerText = "✓ Saved!";
      setTimeout(() => {
        if (btn) btn.innerText = "Save current input";
      }, 1500);
    }
  };

  // JWT Helper Handlers
  const handleJwtClaimsChange = (val) => {
    setJwtClaims(val);
    if (!val.trim()) {
      setJwtClaimsError(null);
      return;
    }
    try {
      JSON.parse(val);
      setJwtClaimsError(null);
    } catch (e) {
      setJwtClaimsError(e.message);
    }
  };

  const handleMintJwt = async () => {
    let parsedClaims;
    try {
      parsedClaims = JSON.parse(jwtClaims);
    } catch (e) {
      setJwtClaimsError(e.message);
      return;
    }

    try {
      const header = { alg: jwtAlg, typ: "JWT" };
      const token = await signHS256(header, parsedClaims, jwtSecret || "secret");
      setJwtToken(token);
      setInjectSuccess(false);
      setCopySuccess(false);
    } catch (e) {
      console.error("Failed to sign JWT client side", e);
      const headerB64 = base64url(header);
      const payloadB64 = base64url(parsedClaims);
      setJwtToken(`${headerB64}.${payloadB64}.fallbackSignatureString`);
      setInjectSuccess(false);
      setCopySuccess(false);
    }
  };

  const handleCopyJwt = () => {
    navigator.clipboard.writeText(jwtToken);
    setCopySuccess(true);
    setTimeout(() => setCopySuccess(false), 2000);
  };

  const handleInjectJwt = () => {
    let obj = {};
    try {
      obj = inputText.trim() ? JSON.parse(inputText) : {};
    } catch {
      obj = {};
    }
    obj.token = jwtToken;
    const nextText = JSON.stringify(obj, null, 2);
    setInputText(nextText);
    lastAutoTextRef.current = nextText;
    setParseError(null);
    setInjectSuccess(true);
    setTimeout(() => setInjectSuccess(false), 2500);
  };

  const verdict = computeVerdict(result, ruleName, policy);

  // Compute test coverage
  const coverage = useMemo(() => {
    if (!result || !policy.rules || policy.rules.length === 0) return null;

    let val = result.result;
    if (val && typeof val === "object" && !Array.isArray(val) && "decision_id" in val && "result" in val) {
      val = val.result;
    }

    if (!val || typeof val !== "object" || Array.isArray(val)) {
      if (ruleName) {
        return {
          percent: 100,
          total: 1,
          covered: 1,
          coveredNames: [ruleName],
          uncoveredNames: []
        };
      }
      return null;
    }

    const policyRules = policy.rules.map(r => r.name);
    const covered = [];
    const uncovered = [];

    policyRules.forEach(name => {
      if (name in val && val[name] !== undefined) {
        covered.push(name);
      } else {
        uncovered.push(name);
      }
    });

    const percent = Math.round((covered.length / policyRules.length) * 100);
    return {
      percent,
      total: policyRules.length,
      covered: covered.length,
      coveredNames: covered,
      uncoveredNames: uncovered
    };
  }, [result, policy.rules, ruleName]);

  return (
    <div className="sandbox">
      {/* LEFT: input + controls */}
      <div className="sandbox-col">
        <div className="sandbox-controls">
          <div style={{ display: "flex", flexDirection: "column", gap: 10, width: "100%" }}>
            <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr", gap: 12 }}>
              <label style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                <span
                  style={{
                    fontFamily: "var(--font-mono)",
                    fontSize: 10.5,
                    letterSpacing: "0.18em",
                    textTransform: "uppercase",
                    color: "var(--text-dim)",
                  }}
                >
                  target rule
                </span>
                <select
                  value={ruleName}
                  onChange={(e) => setRuleName(e.target.value)}
                  style={{
                    background: "var(--surface)",
                    color: "var(--text)",
                    border: "1px solid var(--border)",
                    borderRadius: "var(--radius-sm)",
                    padding: "8px 10px",
                    fontFamily: "var(--font-mono)",
                    fontSize: 12.5,
                    width: "100%",
                  }}
                >
                  {ruleOptions.map((o) => (
                    <option key={o.value} value={o.value}>{o.label}</option>
                  ))}
                </select>
              </label>

              <label style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                <span
                  style={{
                    fontFamily: "var(--font-mono)",
                    fontSize: 10.5,
                    letterSpacing: "0.18em",
                    textTransform: "uppercase",
                    color: "var(--text-dim)",
                  }}
                >
                  mock Aegis Sentry caller
                </span>
                <select
                  value={selectedPepCallerId}
                  onChange={(e) => handlePepCallerChange(e.target.value)}
                  style={{
                    background: "var(--surface)",
                    color: "var(--text)",
                    border: "1px solid var(--border)",
                    borderRadius: "var(--radius-sm)",
                    padding: "8px 10px",
                    fontFamily: "var(--font-mono)",
                    fontSize: 12.5,
                    width: "100%",
                  }}
                >
                  <option value="">— none —</option>
                  {pepCallers.map((c) => (
                    <option key={c.callerId} value={c.callerId}>
                      {c.callerId} ({c.authMode})
                    </option>
                  ))}
                </select>
              </label>
            </div>

            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10 }}>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-dim)" }}>
                {policy.locked ? (
                  <>mode: <strong style={{ color: "#b45309" }}>locked</strong> · not enforcing (sandbox uses preview)</>
                ) : dirty || policy._isNew ? (
                  <>mode: <strong style={{ color: "var(--accent)" }}>preview</strong> · ephemeral compile</>
                ) : (
                  <>mode: <strong style={{ color: "var(--success)" }}>deployed</strong> · live in OPA</>
                )}
              </div>
              <button
                className="btn btn-primary btn-sm"
                onClick={handleEvaluate}
                disabled={running || parseError}
                title={parseError ? "Fix input JSON first" : "Send input to OPA"}
              >
                {running ? "Evaluating…" : "Evaluate ▸"}
              </button>
            </div>
          </div>
        </div>

        <div className="code-pane" style={{ flex: 1, marginTop: 12, display: "flex", flexDirection: "column", minHeight: 0 }}>
          {/* Typographic minimal tab selector */}
          <div className="sandbox-tab-bar" style={{
            display: "flex",
            gap: 16,
            padding: "8px 16px",
            borderBottom: "1px solid var(--border)",
            background: "var(--bg-tint)"
          }}>
            <button
              onClick={() => setActiveLeftTab("json")}
              style={{
                background: "transparent",
                border: "none",
                color: activeLeftTab === "json" ? "var(--accent)" : "var(--text-dim)",
                fontFamily: "var(--font-mono)",
                fontSize: 11,
                fontWeight: activeLeftTab === "json" ? "600" : "500",
                padding: "6px 0",
                borderBottom: activeLeftTab === "json" ? "2px solid var(--accent)" : "2px solid transparent",
                cursor: "pointer",
                textTransform: "uppercase",
                letterSpacing: "0.06em",
                transition: "all 0.15s ease"
              }}
            >
              Payload JSON
            </button>
            <button
              onClick={() => setActiveLeftTab("scenarios")}
              style={{
                background: "transparent",
                border: "none",
                color: activeLeftTab === "scenarios" ? "var(--accent)" : "var(--text-dim)",
                fontFamily: "var(--font-mono)",
                fontSize: 11,
                fontWeight: activeLeftTab === "scenarios" ? "600" : "500",
                padding: "6px 0",
                borderBottom: activeLeftTab === "scenarios" ? "2px solid var(--accent)" : "2px solid transparent",
                cursor: "pointer",
                textTransform: "uppercase",
                letterSpacing: "0.06em",
                transition: "all 0.15s ease"
              }}
            >
              Saved Scenarios
            </button>
            <button
              onClick={() => setActiveLeftTab("jwt")}
              style={{
                background: "transparent",
                border: "none",
                color: activeLeftTab === "jwt" ? "var(--accent)" : "var(--text-dim)",
                fontFamily: "var(--font-mono)",
                fontSize: 11,
                fontWeight: activeLeftTab === "jwt" ? "600" : "500",
                padding: "6px 0",
                borderBottom: activeLeftTab === "jwt" ? "2px solid var(--accent)" : "2px solid transparent",
                cursor: "pointer",
                textTransform: "uppercase",
                letterSpacing: "0.06em",
                transition: "all 0.15s ease"
              }}
            >
              Mock JWT Signer
            </button>
          </div>

          {activeLeftTab === "json" && (
            <>
              <div className="code-head">
                <div className="code-label">
                  <strong>input</strong> &nbsp;·&nbsp; the document sent to OPA
                </div>
                <div className="code-tools">
                  <button
                    className="btn btn-ghost btn-sm"
                    onClick={() => {
                      try {
                        const obj = JSON.parse(inputText || "{}");
                        setInputText(JSON.stringify(obj, null, 2));
                        setParseError(null);
                      } catch (e) {
                        setParseError(e.message);
                      }
                    }}
                  >
                    Format
                  </button>
                  <button
                    className="btn btn-ghost btn-sm"
                    onClick={regenerateFromRule}
                    title="Rebuild a satisfying input from the selected rule"
                  >
                    Auto-fill
                  </button>
                </div>
              </div>
              <div className="code-body" style={{ padding: 0, flex: 1, minHeight: 0 }}>
                <textarea
                  className="code-textarea"
                  value={inputText}
                  onChange={(e) => handleInputChange(e.target.value)}
                  spellCheck="false"
                  autoCorrect="off"
                  autoCapitalize="off"
                  placeholder='{ "user": { "role": "admin" }, "amount": 1000 }'
                />
              </div>
              {parseError && (
                <div className="code-error">
                  <strong>Invalid JSON</strong>
                  <pre style={{ margin: "6px 0 0", whiteSpace: "pre-wrap", fontSize: 11.5 }}>
                    {parseError}
                  </pre>
                </div>
              )}
            </>
          )}

          {activeLeftTab === "scenarios" && (
            <div className="code-body" style={{ padding: "16px", flex: 1, minHeight: 0, display: "flex", flexDirection: "column", gap: 14, overflowY: "auto" }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <span style={{ fontSize: 10.5, fontFamily: "var(--font-mono)", color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: "0.08em" }}>
                  Scenario profiles
                </span>
                <button className="btn btn-ghost btn-sm" onClick={handleCreateScenario} style={{ textDecoration: "none", fontSize: 12 }}>
                  + Create Profile
                </button>
              </div>

              <div className="scenarios-list" style={{ display: "flex", flexDirection: "column", gap: 6, maxHeight: 220, overflowY: "auto", border: "1px solid var(--border)", borderRadius: "var(--radius)", padding: 6, background: "rgba(0, 0, 0, 0.25)" }}>
                {scenarios.map(s => (
                  <div key={s.id} onClick={() => handleSelectScenario(s)} style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    padding: "8px 12px",
                    borderRadius: "var(--radius-sm)",
                    cursor: "pointer",
                    background: activeScenarioId === s.id ? "var(--accent-soft)" : "transparent",
                    border: activeScenarioId === s.id ? "1px solid var(--accent-line)" : "1px solid transparent",
                    transition: "all 0.15s ease"
                  }}>
                    <span style={{ fontWeight: activeScenarioId === s.id ? "600" : "normal", color: activeScenarioId === s.id ? "var(--text)" : "var(--text-soft)", fontSize: 12.5 }}>
                      {s.name}
                    </span>
                    <div style={{ display: "flex", gap: 10 }} onClick={e => e.stopPropagation()}>
                      <button className="btn btn-ghost btn-xs text-link" onClick={() => handleRenameScenario(s.id)} style={{ fontSize: 11, padding: 0 }}>
                        Rename
                      </button>
                      {scenarios.length > 1 && (
                        <button className="btn btn-ghost btn-xs text-link" onClick={() => handleDeleteScenario(s.id)} style={{ fontSize: 11, padding: 0, color: "var(--danger)" }}>
                          Delete
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>

              {activeScenarioId && (
                <div style={{ display: "flex", alignItems: "center", gap: 12, marginTop: "auto", padding: "12px", background: "var(--surface-2)", borderRadius: "var(--radius)", border: "1px solid var(--border)" }}>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 12, color: "var(--text)", fontWeight: 500 }}>
                      Active: {scenarios.find(s => s.id === activeScenarioId)?.name || "—"}
                    </div>
                    <div style={{ fontSize: 10.5, color: "var(--text-dim)", marginTop: 2 }}>
                      Save the active JSON edits back to this profile.
                    </div>
                  </div>
                  <button id="scenario-save-indicator" className="btn btn-primary btn-sm" onClick={handleSaveActiveScenario}>
                    Save current input
                  </button>
                </div>
              )}
            </div>
          )}

          {activeLeftTab === "jwt" && (
            <div className="code-body" style={{ padding: "16px", flex: 1, minHeight: 0, display: "flex", flexDirection: "column", gap: 14, overflowY: "auto" }}>
              <div style={{ fontSize: 10.5, fontFamily: "var(--font-mono)", color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: "0.08em" }}>
                cryptographic jwt signer helper
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                <label style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  <span style={{ fontSize: 11, color: "var(--text-dim)" }}>Algorithm</span>
                  <select value={jwtAlg} onChange={e => setJwtAlg(e.target.value)} style={{
                    background: "var(--surface-2)",
                    color: "var(--text)",
                    border: "1px solid var(--border)",
                    borderRadius: "var(--radius-sm)",
                    padding: "6px 8px",
                    fontSize: 12,
                    outline: "none"
                  }}>
                    <option value="HS256">HS256 (HMAC-SHA256)</option>
                  </select>
                </label>

                <label style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  <span style={{ fontSize: 11, color: "var(--text-dim)" }}>HMAC Secret</span>
                  <input type="text" value={jwtSecret} onChange={e => setJwtSecret(e.target.value)} style={{
                    background: "var(--surface-2)",
                    color: "var(--text)",
                    border: "1px solid var(--border)",
                    borderRadius: "var(--radius-sm)",
                    padding: "6px 8px",
                    fontSize: 12,
                    outline: "none"
                  }} placeholder="secret" />
                </label>
              </div>

              <label style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                <span style={{ fontSize: 11, color: "var(--text-dim)" }}>Claims Payload (JSON)</span>
                <textarea value={jwtClaims} onChange={e => handleJwtClaimsChange(e.target.value)} spellCheck="false" style={{
                  background: "var(--surface-2)",
                  color: "var(--text)",
                  border: "1px solid var(--border)",
                  borderRadius: "var(--radius-sm)",
                  padding: "8px",
                  fontFamily: "var(--font-mono)",
                  fontSize: 12,
                  height: 90,
                  resize: "none",
                  outline: "none"
                }} />
                {jwtClaimsError && (
                  <span style={{ fontSize: 11, color: "var(--danger)", marginTop: 2 }}>{jwtClaimsError}</span>
                )}
              </label>

              <button className="btn btn-primary btn-sm" onClick={handleMintJwt} disabled={!!jwtClaimsError} style={{ alignSelf: "flex-start" }}>
                Mint JWT Token ▸
              </button>

              {jwtToken && (
                <div style={{ display: "flex", flexDirection: "column", gap: 8, marginTop: 8, padding: "10px 12px", background: "rgba(16, 185, 129, 0.04)", border: "1px solid var(--success-soft)", borderRadius: "var(--radius)" }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                    <span style={{ fontSize: 11, color: "var(--success)", fontWeight: 500 }}>Generated Token</span>
                    <div style={{ display: "flex", gap: 10 }}>
                      <button className="btn btn-ghost btn-xs text-link" onClick={handleCopyJwt} style={{ fontSize: 11, padding: 0 }}>
                        {copySuccess ? "Copied!" : "Copy"}
                      </button>
                      <button className="btn btn-ghost btn-xs text-link" onClick={handleInjectJwt} style={{ fontSize: 11, padding: 0, color: "var(--accent)" }}>
                        Inject into input.token
                      </button>
                    </div>
                  </div>
                  <textarea readOnly value={jwtToken} style={{
                    background: "transparent",
                    color: "var(--text-soft)",
                    border: "none",
                    fontFamily: "var(--font-mono)",
                    fontSize: 11,
                    lineHeight: 1.4,
                    resize: "none",
                    height: 50,
                    outline: "none",
                    wordBreak: "break-all"
                  }} />
                  {injectSuccess && (
                    <span style={{ fontSize: 11, color: "var(--success)", marginTop: 4 }}>✓ Token injected into input JSON payload!</span>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* RIGHT: result */}
      <div className="sandbox-col">
        <div className="eval-result-box">
          {!result && !error && !running && (
            <div style={{ padding: "40px 24px", textAlign: "center", color: "var(--text-dim)" }}>
              <div
                style={{
                  fontFamily: "var(--font-display)",
                  fontSize: 22,
                  color: "var(--text-muted)",
                  fontStyle: "italic",
                  marginBottom: 8,
                }}
              >
                Awaiting evaluation
              </div>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: 11.5 }}>
                Press Evaluate to send your input to OPA and see the decision.
              </div>
            </div>
          )}

          {running && (
            <div style={{ padding: "40px 24px", textAlign: "center", color: "var(--text-dim)" }}>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>
                evaluating against OPA…
              </div>
            </div>
          )}

          {error && !running && (
            <div className="code-error" style={{ borderTop: "none", borderRadius: "var(--radius-lg)" }}>
              <strong>Evaluation failed</strong>
              <pre style={{ margin: "6px 0 0", whiteSpace: "pre-wrap", fontSize: 11.5 }}>
                {error}
              </pre>
            </div>
          )}

          {result && !running && !error && (
            <>
              <div className={`eval-banner ${verdict.kind}`}>
                <div className="eval-banner-icon">
                  {verdict.kind === "allow" ? "✓" : verdict.kind === "deny" ? "✕" : "?"}
                </div>
                <div className="eval-banner-text">
                  <div className="eval-banner-verdict">{verdict.label}</div>
                  <div className="eval-banner-meta">
                    {verdict.path} · {result._elapsed}ms · mode={result._mode}
                  </div>
                </div>
              </div>

              {/* Typographic Test Coverage Gauge */}
              {coverage && (
                <div className="eval-coverage" style={{
                  padding: "14px 20px",
                  borderBottom: "1px solid var(--border)",
                  background: "rgba(255, 255, 255, 0.02)",
                  display: "flex",
                  flexDirection: "column",
                  gap: 8
                }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span style={{ fontSize: 10.5, fontFamily: "var(--font-mono)", color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: "0.08em" }}>
                      Rule Evaluation Coverage
                    </span>
                    <span style={{ fontSize: 12, fontWeight: "600", color: "var(--accent)" }}>
                      {coverage.percent}% ({coverage.covered} of {coverage.total})
                    </span>
                  </div>
                  
                  <div style={{
                    width: "100%",
                    height: 5,
                    background: "var(--surface-3)",
                    borderRadius: 99,
                    overflow: "hidden",
                    position: "relative"
                  }}>
                    <div style={{
                      width: `${coverage.percent}%`,
                      height: "100%",
                      background: "var(--accent-gradient)",
                      borderRadius: 99,
                      transition: "width 0.4s ease"
                    }} />
                  </div>
                  
                  <div style={{ display: "flex", flexWrap: "wrap", gap: "6px 12px", marginTop: 4 }}>
                    {coverage.coveredNames.map(name => (
                      <span key={name} style={{ fontSize: 11, color: "var(--success)", fontFamily: "var(--font-mono)" }}>
                        ✓ {name}
                      </span>
                    ))}
                    {coverage.uncoveredNames.map(name => (
                      <span key={name} style={{ fontSize: 11, color: "var(--text-dim)", fontFamily: "var(--font-mono)" }}>
                        ○ {name}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              <div className="eval-detail">
                <div
                  style={{
                    fontFamily: "var(--font-mono)",
                    fontSize: 10.5,
                    letterSpacing: "0.18em",
                    textTransform: "uppercase",
                    color: "var(--text-dim)",
                    marginBottom: 8,
                  }}
                >
                  raw response
                </div>
                <pre
                  style={{
                    margin: 0,
                    fontFamily: "var(--font-mono)",
                    fontSize: 12,
                    lineHeight: 1.55,
                    whiteSpace: "pre-wrap",
                    wordBreak: "break-word",
                  }}
                  dangerouslySetInnerHTML={{
                    __html: highlightJson(JSON.stringify(stripMeta(result), null, 2)),
                  }}
                />
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function stripMeta(r) {
  const { _elapsed, _mode, ...rest } = r;
  return rest;
}

// Compute a human verdict from the OPA evaluation response.
// Backend wraps OPA's response as { result, elapsedMs, evaluatedPath } where
// `result` is OPA's full data-API envelope { decision_id, result: <value> }.
// We unwrap to surface the actual decision value.
function computeVerdict(res, ruleName, policy) {
  if (!res) return { kind: "unknown", label: "—", path: "" };
  const path =
    res.evaluatedPath || res.path ||
    (ruleName ? `${policy.package}.${ruleName}` : policy.package);
  let value = res.result;
  if (
    value && typeof value === "object" && !Array.isArray(value) &&
    "decision_id" in value && "result" in value
  ) {
    value = value.result;
  }

  // If we evaluated the whole package (so value is a dictionary of all rules),
  // but a specific ruleName was targeted, extract it!
  if (value && typeof value === "object" && !Array.isArray(value) && ruleName) {
    if (ruleName in value) {
      value = value[ruleName];
    }
  }

  if (value === undefined) {
    return { kind: "unknown", label: "UNDEFINED", path };
  }
  if (typeof value === "boolean") {
    return {
      kind: value ? "allow" : "deny",
      label: value ? "ALLOWED" : "DENIED",
      path,
    };
  }
  // Whole-package response: object of rule -> value. If there's an `allow`
  // boolean inside, surface it.
  if (value && typeof value === "object" && !Array.isArray(value) && "allow" in value) {
    const a = value.allow;
    if (typeof a === "boolean") {
      return {
        kind: a ? "allow" : "deny",
        label: a ? "ALLOWED" : "DENIED",
        path: `${path}.allow`,
      };
    }
  }
  // Fallback: show the computed value.
  const summary =
    typeof value === "string"
      ? `"${value}"`
      : typeof value === "number"
      ? String(value)
      : Array.isArray(value)
      ? `array(${value.length})`
      : typeof value === "object"
      ? `object(${Object.keys(value).length} keys)`
      : String(value);
  return { kind: "unknown", label: summary, path };
}

// HMAC HS256 Client-Side Signer helpers
async function signHS256(header, payload, secret) {
  const encoder = new TextEncoder();
  const secretData = encoder.encode(secret);
  const headerB64 = base64url(header);
  const payloadB64 = base64url(payload);
  const dataToSign = encoder.encode(`${headerB64}.${payloadB64}`);
  
  const key = await window.crypto.subtle.importKey(
    "raw",
    secretData,
    { name: "HMAC", hash: { name: "SHA-256" } },
    false,
    ["sign"]
  );
  
  const signature = await window.crypto.subtle.sign(
    "HMAC",
    key,
    dataToSign
  );
  
  const signatureBytes = new Uint8Array(signature);
  let binary = "";
  for (let i = 0; i < signatureBytes.byteLength; i++) {
    binary += String.fromCharCode(signatureBytes[i]);
  }
  const sigB64 = btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  
  return `${headerB64}.${payloadB64}.${sigB64}`;
}

function base64url(source) {
  const jsonStr = JSON.stringify(source);
  const bytes = new TextEncoder().encode(jsonStr);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const encoded = btoa(binary);
  return encoded.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

