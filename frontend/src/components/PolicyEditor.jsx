import { useState } from "react";
import VisualBuilder from "./VisualBuilder.jsx";
import RegoViewer from "./RegoViewer.jsx";
import Sandbox from "./Sandbox.jsx";
import FlowDiagram from "./FlowDiagram.jsx";
import PolicyHistory from "./PolicyHistory.jsx";
import PolicyCallersPane from "./PolicyCallersPane.jsx";
import TagChipInput from "./TagChipInput.jsx";
import { api } from "../lib/api.js";

const TABS = [
  { key: "visual", label: "Visual Builder" },
  { key: "diagram", label: "Diagram" },
  { key: "rego", label: "Rego" },
  { key: "sandbox", label: "Sandbox" },
  { key: "history", label: "History" },
  { key: "callers", label: "Callers" },
];

export default function PolicyEditor({ policy, onChange, onSave, onToggleLock, onRestore, onDiscard, dirty, isNew, currentTheme, onClone }) {

  const [tab, setTab] = useState("visual");

  const [evaluationResult, setEvaluationResult] = useState(null);
  const [evaluationInput, setEvaluationInput] = useState(null);

  const updateField = (field, value) => onChange({ ...policy, [field]: value });
  const locked = !!policy.locked;

  return (
    <main className="editor">
      <div className="editor-head">
        <div className="editor-meta">
          <div className="editor-meta-main">
            <div className="editor-name-row">
              <input
                type="text"
                className="editor-name-input"
                value={policy.name}
                onChange={(e) => updateField("name", e.target.value)}
                placeholder="Policy name"
                disabled={locked}
              />
              {policy.version && <span className="version-badge">v{policy.version}</span>}
              {locked && (
                <span className="locked-badge" title="Locked: removed from OPA, not enforcing">
                  Locked
                </span>
              )}
            </div>
            <div className="editor-pkg-row">
              <span className="editor-pkg-label">Package</span>
              <input
                type="text"
                className="editor-pkg-input"
                value={policy.package}
                onChange={(e) => updateField("package", e.target.value)}
                placeholder="namespace.policy_name"
                spellCheck="false"
                disabled={locked}
              />
            </div>
          </div>
          <div className="editor-actions">
            <button
              className="btn"
              onClick={onDiscard}
              disabled={!dirty}
              title={
                dirty
                  ? (isNew ? "Discard new policy" : "Discard unsaved changes and revert to saved version")
                  : "No changes to discard"
              }
            >
              Discard
            </button>
            {!isNew && (
              <button
                className="btn"
                onClick={() => onClone(policy)}
                title="Clone this policy as a new duplicate"
              >
                Clone Policy
              </button>
            )}
            {!isNew && (
              <button
                className={locked ? "btn btn-primary" : "btn btn-warn"}
                onClick={onToggleLock}
                title={
                  locked
                    ? "Unlock — re-deploy to OPA, resume enforcement"
                    : "Lock — remove from OPA, stop enforcing (audit-tracked)"
                }
              >
                {locked ? "Unlock" : "Lock"}
              </button>
            )}
            <button
              className="btn btn-primary"
              onClick={onSave}
              disabled={!dirty || locked}
              title={
                locked
                  ? "Locked policies cannot be modified — unlock first"
                  : dirty
                    ? "Save & deploy to OPA"
                    : "No changes"
              }
            >
              {dirty ? "Save & Deploy" : "Saved"}
            </button>
          </div>
        </div>

        <textarea
          className="editor-desc"
          value={policy.description || ""}
          onChange={(e) => updateField("description", e.target.value)}
          placeholder="Describe what this policy decides…"
          rows={1}
          disabled={locked}
          onInput={(e) => {
            e.target.style.height = "auto";
            e.target.style.height = e.target.scrollHeight + "px";
          }}
        />

        {!isNew && policy.id && (
          <div className="editor-pkg-row" style={{ marginTop: 6 }}>
            <span className="editor-pkg-label">Tags</span>
            <div style={{ flex: 1 }}>
              <TagChipInput
                value={policy.tags || []}
                disabled={locked}
                placeholder="label this policy for caller scope_tags…"
                onCommit={async (next) => {
                  const cur = new Set(policy.tags || []);
                  const nxt = new Set(next);
                  const add = [...nxt].filter((t) => !cur.has(t));
                  const remove = [...cur].filter((t) => !nxt.has(t));
                  if (add.length === 0 && remove.length === 0) return;
                  const res = await api.updatePolicyTags(policy.id, { add, remove });
                  updateField("tags", res.tags ?? next);
                }}
              />
            </div>
          </div>
        )}

        <nav className="tabs">
          {TABS.map((t, i) => (
            <button
              key={t.key}
              className={`tab ${tab === t.key ? "active" : ""}`}
              onClick={() => setTab(t.key)}
            >
              <span className="tab-num">{String(i + 1).padStart(2, "0")}</span>
              {t.label}
            </button>
          ))}
        </nav>
      </div>

      <div className="editor-body">
        <div className="editor-pane">
          {tab === "visual"  && <VisualBuilder policy={policy} onChange={onChange} />}
          {tab === "diagram" && (
            <FlowDiagram
              policy={policy}
              currentTheme={currentTheme}
              evaluationResult={evaluationResult}
              evaluationInput={evaluationInput}
            />
          )}
          {tab === "rego"    && <RegoViewer policy={policy} />}

          {tab === "sandbox" && (
            <Sandbox
              policy={policy}
              dirty={dirty}
              evaluationResult={evaluationResult}
              evaluationInput={evaluationInput}
              onEvaluateComplete={(res, input) => {
                setEvaluationResult(res);
                setEvaluationInput(input);
              }}
            />
          )}
          {tab === "history" && (
            <PolicyHistory
              policyId={policy.id}
              currentVersion={policy.version}
              currentRego={policy.rego}
              currentLocked={!!policy.locked}
              onRestore={onRestore}
              isNew={isNew}
            />
          )}
          {tab === "callers" && <PolicyCallersPane policy={policy} isNew={isNew} />}
        </div>
      </div>
    </main>
  );
}
