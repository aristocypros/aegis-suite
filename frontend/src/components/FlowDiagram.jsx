import { Fragment, useCallback, useEffect, useMemo, useState } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  ReactFlowProvider,
  Position,
  Handle,
  useReactFlow,
  MarkerType,
  useNodesState,
  useEdgesState,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import dagre from "dagre";
import { buildRuleGraph, isStrictRuleRef } from "../lib/ruleGraph.js";

// ─── Evaluation Debugger Helpers ───────────────────────────────────────

function resolvePath(obj, path) {
  if (!path) return undefined;
  if (path === "input") return obj;
  if (path.startsWith("input.")) {
    const parts = path.substring(6).split(".");
    let current = obj;
    for (const p of parts) {
      if (current === null || current === undefined) return undefined;
      const match = p.match(/^([^\[]+)(?:\[['"]?([^\]'"]+)['"]?\])?$/);
      if (match) {
        const key = match[1];
        const idx = match[2];
        current = current[key];
        if (idx !== undefined && current) {
          current = current[idx];
        }
      } else {
        current = current[p];
      }
    }
    return current;
  }
  return undefined;
}

function resolveOperand(val, input, ruleValues, type) {
  if (type === "ref") {
    if (val === "input") return input;
    if (val.startsWith("input.")) {
      return resolvePath(input, val);
    }
    if (ruleValues && val in ruleValues) {
      return ruleValues[val];
    }
    if (input && val in input) return input[val];
    return undefined;
  }
  return val;
}

function checkCmp(leftVal, op, rightVal) {
  if (leftVal === undefined) return false;
  switch (op) {
    case "==": return leftVal === rightVal;
    case "!=": return leftVal !== rightVal;
    case "<": return Number(leftVal) < Number(rightVal);
    case "<=": return Number(leftVal) <= Number(rightVal);
    case ">": return Number(leftVal) > Number(rightVal);
    case ">=": return Number(leftVal) >= Number(rightVal);
    case "exists": return leftVal !== undefined && leftVal !== null;
    case "startswith": return typeof leftVal === "string" && leftVal.startsWith(String(rightVal));
    case "endswith": return typeof leftVal === "string" && leftVal.endsWith(String(rightVal));
    case "contains":
      if (Array.isArray(leftVal)) return leftVal.includes(rightVal);
      if (typeof leftVal === "string") return leftVal.includes(String(rightVal));
      return false;
    case "in":
      if (Array.isArray(rightVal)) return rightVal.includes(leftVal);
      return false;
    case "cidr_contains":
      return true; // Simple frontend mock for preview
    default:
      return false;
  }
}

function getConditionEvalDetails(cond, input, ruleValues) {
  try {
    let leftVal;
    let rightVal = cond.rightType === "ref" ? resolveOperand(cond.right, input, ruleValues, "ref") : cond.right;
    const negated = !!cond.negate;
    let ok = false;

    if (cond.condType === "arith") {
      leftVal = resolvePath(input, cond.leftExpr) || 0;
      ok = checkCmp(leftVal, cond.op, rightVal);
      if (negated) ok = !ok;
    } else if (cond.condType === "aggregate") {
      const colVal = resolveOperand(cond.collection, input, ruleValues, "ref");
      leftVal = 0;
      if (Array.isArray(colVal)) leftVal = colVal.length;
      else if (colVal && typeof colVal === "object") leftVal = Object.keys(colVal).length;
      ok = checkCmp(leftVal, cond.op, rightVal);
      if (negated) ok = !ok;
    } else if (cond.condType === "object_get") {
      const obj = resolveOperand(cond.obj || cond.object, input, ruleValues, "ref");
      leftVal = (obj && typeof obj === "object") ? obj[cond.key] : cond.default;
      ok = checkCmp(leftVal, cond.op, rightVal);
      if (negated) ok = !ok;
    } else if (cond.condType === "every") {
      ok = !negated;
    } else if (cond.condType === "builtin_left") {
      ok = !negated;
    } else if (cond.condType === "verify" || cond.condType === "verification") {
      ok = !negated;
    } else {
      leftVal = resolveOperand(cond.left, input, ruleValues, "ref");
      ok = checkCmp(leftVal, cond.op, rightVal);
      if (negated) ok = !ok;
    }

    return { ok, leftVal, rightVal };
  } catch (e) {
    return { ok: false, leftVal: undefined, rightVal: undefined };
  }
}

function evaluateBranch(branch, input, ruleValues) {
  const groups = getGroups(branch);
  if (groups.length === 0) return true;
  
  for (const group of groups) {
    const conds = group.conditions || [];
    if (conds.length === 0) continue;
    
    let groupSatisfied = group.mode === "and";
    for (const cond of conds) {
      const details = getConditionEvalDetails(cond, input, ruleValues);
      if (group.mode === "and") {
        if (!details.ok) {
          groupSatisfied = false;
          break;
        }
      } else {
        if (details.ok) {
          groupSatisfied = true;
          break;
        }
      }
    }
    
    if (!groupSatisfied) {
      return false;
    }
  }
  return true;
}

function formatDebugValue(v) {
  if (v === undefined) return "undefined";
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "string") return `"${v}"`;
  if (Array.isArray(v)) return `[len:${v.length}]`;
  if (typeof v === "object") return `{keys:${Object.keys(v).length}}`;
  return String(v);
}

// Decision-flow diagram. For each rule we render three layers:
//
//   ruleHead  → branch[n]  → outcome
//
// — so non-technical users can see what a rule actually decides without
// clicking. Cross-rule references are drawn as edges from the consumer rule's
// head to the producer rule's head (read as: "evaluating A requires B").

const ROLE_LABELS = {
  decision:    "FINAL DECISION",
  accumulator: "COLLECT DATA",
  gate:        "CONDITION CHECK",
  helper:      "SUB-RULE",
  orphan:      "UNUSED",
};

const ROLE_ICONS = {
  decision:    "🎯",
  accumulator: "📊",
  gate:        "⚖️",
  helper:      "🧩",
  orphan:      "🗑️",
};

// Layout sizes fed to dagre.
const ENTRY_W = 260, ENTRY_H = 64;
const BRANCH_BASE_H = 46, BRANCH_COND_H = 20, BRANCH_MAX_CONDS = 3;

function branchHeight(branch) {
  const groups = getGroups(branch);
  const n = groups.reduce((acc, g) => acc + (g.conditions?.length || 0), 0);
  const shown = Math.min(n, BRANCH_MAX_CONDS);
  return BRANCH_BASE_H + (shown === 0 ? 12 : shown * BRANCH_COND_H) + (n > BRANCH_MAX_CONDS ? 14 : 0);
}

function calculatedRuleHeight(rule) {
  if (rule.kind === "result_object") {
    const fieldsCount = Array.isArray(rule.fields) ? rule.fields.length : 0;
    return 100 + (fieldsCount === 0 ? 30 : fieldsCount * 28);
  }
  
  const branches = rule.branches || [];
  if (branches.length === 0) {
    return 110;
  }
  
  let totalBranchesHeight = 0;
  for (const b of branches) {
    totalBranchesHeight += branchHeight(b) + 8;
  }
  
  return 85 + totalBranchesHeight + 52;
}

// Compute a human-readable "matched outcome" for a rule.
function matchedOutcomeText(rule) {
  if (rule.kind === "partial_set") {
    return `${rule.name} ∋ values`;
  }
  if (rule.type === "boolean" || !rule.type) {
    return `${rule.name} = true`;
  }
  const v = rule.returnValue;
  if (v === undefined || v === null) return `${rule.name} = (value)`;
  if (typeof v === "string") return `${rule.name} = "${v}"`;
  if (typeof v === "object") return `${rule.name} = { … }`;
  return `${rule.name} = ${String(v)}`;
}

function defaultOutcomeText(rule) {
  if (rule.kind === "partial_set") return "(empty set)";
  if (rule.default === undefined) {
    return rule.type === "boolean" || !rule.type ? "false" : "(undefined)";
  }
  if (typeof rule.default === "string") return `"${rule.default}"`;
  if (typeof rule.default === "object") return "{ … }";
  return String(rule.default);
}

function branchValueText(branch, rule) {
  if (rule.kind === "partial_set") {
    const v = branch.value;
    if (v === undefined) return null;
    return typeof v === "string" ? `"${v}"` : String(v);
  }
  return null;
}

function groupModeLabel(group) {
  return group.mode === "or" ? "ANY of these is true" : "ALL of these are true";
}

// ─── Layout ─────────────────────────────────────────────────────────────

function layoutGraph(rules, crossEdges, entryRuleName, dir = "TB") {
  const g = new dagre.graphlib.Graph();
  g.setGraph({
    rankdir: dir,
    ranksep: dir === "TB" ? 90 : 110,
    nodesep: dir === "TB" ? 50 : 60,
    edgesep: 30,
    marginx: 40,
    marginy: 40,
  });
  g.setDefaultEdgeLabel(() => ({}));

  if (entryRuleName) g.setNode("__entry__", { width: ENTRY_W, height: ENTRY_H });

  for (const r of rules) {
    const rawRule = r.rule || r;
    const height = calculatedRuleHeight(rawRule);
    g.setNode(rawRule.name, { width: 340, height: height });
  }

  if (entryRuleName) {
    g.setEdge("__entry__", entryRuleName);
  }
  for (const e of crossEdges) {
    g.setEdge(e.from, e.to);
  }

  dagre.layout(g);

  const pos = new Map();
  const node = (id, w, h) => {
    const n = g.node(id);
    if (!n) return;
    pos.set(id, { x: n.x - w / 2, y: n.y - h / 2 });
  };

  if (entryRuleName) node("__entry__", ENTRY_W, ENTRY_H);
  for (const r of rules) {
    const rawRule = r.rule || r;
    node(rawRule.name, 340, calculatedRuleHeight(rawRule));
  }
  return pos;
}

// ─── Custom nodes ───────────────────────────────────────────────────────

function EntryNode({ data }) {
  const isLR = data?.layoutDir === "LR";
  const sourcePos = isLR ? Position.Right : Position.Bottom;
  return (
    <div className="flow-graph-entry-node">
      <div className="flow-graph-entry-row">
        <span className="flow-graph-entry-icon" aria-hidden="true">🚀</span>
        <span className="flow-graph-entry-label">Start Request</span>
      </div>
      <Handle type="source" position={sourcePos} isConnectable={false} />
    </div>
  );
}

function RuleContainerNode({ data, selected }) {
  if (!data?.rule) return null;
  const { rule, role, ruleNames, onOpenDetail, onRefClick, evaluationInput, ruleValues, layoutDir } = data;
  const safeRole = role || "helper";
  const isLR = layoutDir === "LR";
  const targetPos = isLR ? Position.Left : Position.Top;
  const sourcePos = isLR ? Position.Right : Position.Bottom;

  const hasEvaluated = ruleValues !== null;
  
  let isRuleActive = false;
  if (hasEvaluated && ruleValues) {
    const ruleVal = ruleValues[rule.name];
    if (rule.type === "boolean" || !rule.type) {
      isRuleActive = ruleVal === true;
    } else if (rule.kind === "result_object") {
      isRuleActive = ruleVal !== undefined && ruleVal !== null;
    } else if (rule.kind === "partial_set") {
      isRuleActive = Array.isArray(ruleVal) && ruleVal.length > 0;
    } else {
      isRuleActive = ruleVal !== undefined && ruleVal !== null && ruleVal !== rule.default;
    }
  }

  const evalClass = hasEvaluated
    ? (isRuleActive ? "flow-node-eval-active flow-head-node" : "flow-node-eval-inactive")
    : "";

  const kindLabel = rule.kind === "partial_set" ? "accumulator" 
    : rule.kind === "result_object" ? "dashboard" 
    : rule.type || "boolean";

  return (
    <div
      className={`flow-rule-container rule-kind-${rule.kind} ${evalClass} ${selected ? "is-selected" : ""}`}
      onClick={(e) => { e.stopPropagation(); onOpenDetail(rule.name); }}
      style={{
        width: "340px",
        height: "100%",
        display: "flex",
        flexDirection: "column",
        cursor: "pointer",
        position: "relative"
      }}
    >
      <Handle type="target" position={targetPos} id="rule-target" style={{ background: "var(--accent)" }} />

      <div className="flow-container-header" style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <span className="flow-rule-icon" aria-hidden="true" style={{ fontSize: "16px" }}>{ROLE_ICONS[safeRole]}</span>
          <div style={{ display: "flex", flexDirection: "column" }}>
            <span className={`flow-rule-role flow-rule-role-${safeRole}`} style={{ fontSize: "8px", textTransform: "uppercase", letterSpacing: "0.05em", fontWeight: 700 }}>
              {ROLE_LABELS[safeRole]}
            </span>
            <span className="flow-graph-node-name" title={rule.name} style={{ fontFamily: "var(--font-mono)", fontSize: "13px", fontWeight: 600 }}>
              {rule.name}
            </span>
          </div>
        </div>
        <span className="badge" style={{
          fontSize: "9px",
          background: "rgba(255, 255, 255, 0.06)",
          color: "var(--text-soft)",
          border: "1px solid rgba(255, 255, 255, 0.1)",
          padding: "1px 5px",
          borderRadius: "4px",
          textTransform: "uppercase"
        }}>
          {kindLabel}
        </span>
      </div>

      <div style={{ flex: 1, display: "flex", flexDirection: "column" }}>
        {rule.kind === "result_object" ? (
          <ResultObjectDashboard rule={rule} ruleNames={ruleNames} onRefClick={onRefClick} sourcePos={sourcePos} />
        ) : rule.kind === "partial_set" ? (
          <PartialSetDashboard rule={rule} ruleNames={ruleNames} onRefClick={onRefClick} evaluationInput={evaluationInput} ruleValues={ruleValues} />
        ) : (
          <NormalRuleDashboard rule={rule} ruleNames={ruleNames} onRefClick={onRefClick} evaluationInput={evaluationInput} ruleValues={ruleValues} />
        )}
      </div>

      {rule.kind !== "result_object" && rule.kind !== "partial_set" && (
        <VerdictFooter rule={rule} evaluationInput={evaluationInput} ruleValues={ruleValues} />
      )}

      {rule.kind !== "result_object" && (
        <Handle type="source" position={sourcePos} id="rule-source" style={{ background: "var(--accent)" }} />
      )}
    </div>
  );
}

function ResultObjectDashboard({ rule, ruleNames, onRefClick, sourcePos }) {
  const fields = Array.isArray(rule.fields) ? rule.fields : [];
  return (
    <div className="flow-object-dashboard" style={{ display: "flex", flexDirection: "column", gap: "6px", padding: "8px 4px" }}>
      {fields.length === 0 ? (
        <div style={{ color: "var(--text-dim)", fontStyle: "italic", fontSize: "11px", textAlign: "center", padding: "8px 0" }}>
          No data fields defined
        </div>
      ) : (
        fields.map((f, i) => {
          const isRef = f.valueType === "ref" && ruleNames.has(f.value);
          return (
            <div key={i} className="flow-object-row" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "4px 0", borderBottom: "1px dashed rgba(255, 255, 255, 0.04)" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "6px", overflow: "hidden" }}>
                <span className="flow-result-key" style={{ fontFamily: "var(--font-mono)", fontSize: "12px", color: "var(--accent)", fontWeight: 600 }}>
                  {f.key}
                </span>
                <span style={{ color: "var(--text-dim)", fontSize: "11px" }}>:=</span>
                <ResultFieldValue field={f} ruleNames={ruleNames} onRefClick={onRefClick} />
              </div>
              
              {isRef && (
                <div style={{ display: "flex", alignItems: "center", position: "relative", width: "12px", height: "12px" }}>
                  <div className="flow-object-socket" title={`Wired to ${f.value}`} style={{ width: "8px", height: "8px", borderRadius: "50%", background: "var(--accent)", border: "1.5px solid var(--bg)" }} />
                  <Handle
                    type="source"
                    position={sourcePos}
                    id={`field:${f.key}`}
                    style={{
                      background: "transparent",
                      border: "none",
                      width: "12px",
                      height: "12px",
                      top: 0,
                      left: 0,
                      opacity: 0
                    }}
                  />
                </div>
              )}
            </div>
          );
        })
      )}
    </div>
  );
}

function PartialSetDashboard({ rule, ruleNames, onRefClick, evaluationInput, ruleValues }) {
  const branches = rule.branches || [];
  const hasEvaluated = ruleValues !== null;
  const activeBranches = [];
  if (hasEvaluated) {
    branches.forEach((b, i) => {
      if (evaluateBranch(b, evaluationInput, ruleValues)) {
        activeBranches.push(i);
      }
    });
  }

  const accumulatedVal = hasEvaluated ? ruleValues[rule.name] : null;
  const elements = Array.isArray(accumulatedVal) ? accumulatedVal : [];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "8px", padding: "4px 0" }}>
      {branches.length === 0 ? (
        <div style={{ color: "var(--text-dim)", fontStyle: "italic", fontSize: "11px", textAlign: "center", padding: "8px 0" }}>
          No logic branches defined
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
          {branches.map((b, i) => {
            const isActive = activeBranches.includes(i);
            const val = branchValueText(b, rule) || "?";
            return (
              <div
                key={i}
                className={`accumulator-track ${isActive ? "cond-glow-true" : ""}`}
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  gap: "8px",
                  borderLeft: isActive ? "3px solid #10b981" : "3px dashed var(--violet)",
                  background: isActive ? "rgba(16, 185, 129, 0.04)" : "rgba(255, 255, 255, 0.01)",
                  padding: "6px 10px",
                  borderRadius: "6px",
                  transition: "all 0.2s"
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: "6px", overflow: "hidden" }}>
                  <span style={{ fontSize: "10px", color: "var(--text-dim)", fontFamily: "var(--font-mono)" }}>#{i + 1}</span>
                  <span style={{ fontSize: "11px", fontWeight: 500, color: isActive ? "#34d399" : "var(--text-soft)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", maxWidth: "160px" }}>
                    {b.description || `Alternative ${i + 1}`}
                  </span>
                </div>
                <span className="badge" style={{
                  fontFamily: "var(--font-mono)",
                  fontSize: "10px",
                  background: isActive ? "rgba(16, 185, 129, 0.15)" : "rgba(139, 92, 246, 0.12)",
                  color: isActive ? "#34d399" : "#c084fc",
                  border: isActive ? "1px solid rgba(16, 185, 129, 0.25)" : "1px solid rgba(139, 92, 246, 0.25)",
                  padding: "1px 5px",
                  borderRadius: "4px",
                  whiteSpace: "nowrap"
                }}>
                  + {val}
                </span>
              </div>
            );
          })}
        </div>
      )}

      <div className="flow-container-verdict" style={{ display: "flex", flexDirection: "column", gap: "4px", marginTop: "4px" }}>
        <span style={{ fontSize: "9px", textTransform: "uppercase", letterSpacing: "0.05em", color: "var(--text-dim)" }}>Accumulated Set</span>
        <div style={{ display: "flex", flexWrap: "wrap", gap: "4px", fontFamily: "var(--font-mono)", fontSize: "11px", color: "var(--text-soft)" }}>
          <span>[</span>
          {elements.length === 0 ? (
            <span style={{ color: "var(--text-dim)", fontStyle: "italic" }}>empty set</span>
          ) : (
            elements.map((el, i) => (
              <span key={i} style={{ color: "#c084fc" }}>
                {formatLit(el)}{i < elements.length - 1 ? "," : ""}
              </span>
            ))
          )}
          <span>]</span>
        </div>
      </div>
    </div>
  );
}

function NormalRuleDashboard({ rule, ruleNames, onRefClick, evaluationInput, ruleValues }) {
  const branches = rule.branches || [];
  const hasEvaluated = ruleValues !== null;
  
  let activeBranchIndex = -1;
  if (hasEvaluated) {
    for (let i = 0; i < branches.length; i++) {
      if (evaluateBranch(branches[i], evaluationInput, ruleValues)) {
        activeBranchIndex = i;
        break;
      }
    }
  }

  const isBypassActive = hasEvaluated && activeBranchIndex === -1;

  return (
    <div style={{ display: "flex", gap: "10px", padding: "4px 0", position: "relative" }}>
      <div style={{
        width: "20px",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        position: "relative"
      }}>
        <div style={{
          width: "2px",
          height: "100%",
          borderLeft: isBypassActive ? "2px solid var(--info, #3b82f6)" : "2px dashed rgba(255, 255, 255, 0.08)",
          boxShadow: isBypassActive ? "0 0 8px var(--info, #3b82f6)" : "none",
          transition: "all 0.2s"
        }} />
        <div
          title="Fallback Bypass Channel"
          style={{
            position: "absolute",
            width: "12px",
            height: "12px",
            borderRadius: "50%",
            background: isBypassActive ? "var(--info, #3b82f6)" : "rgba(255, 255, 255, 0.08)",
            border: "2.5px solid var(--bg)",
            top: "50%",
            transform: "translateY(-50%)",
            boxShadow: isBypassActive ? "0 0 6px var(--info, #3b82f6)" : "none",
            transition: "all 0.2s"
          }}
        />
      </div>

      <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: "8px" }}>
        {branches.length === 0 ? (
          <div style={{ color: "var(--text-dim)", fontStyle: "italic", fontSize: "11px", textAlign: "center", padding: "12px 0" }}>
            No branches (always returns default)
          </div>
        ) : (
          branches.map((b, i) => {
            const isActive = hasEvaluated && i === activeBranchIndex;
            const isInactive = hasEvaluated && i !== activeBranchIndex;
            
            const groups = getGroups(b);
            const totalConds = groups.reduce((a, g) => a + (g.conditions?.length || 0), 0);
            
            const rows = [];
            groups.forEach((group, gi) => {
              if (gi > 0) rows.push({ kind: "sep", label: "AND" });
              if (group.conditions && group.conditions.length > 1 && group.mode === "or") {
                rows.push({ kind: "subsep", label: "ANY of:" });
              }
              for (const c of group.conditions || []) rows.push({ kind: "cond", cond: c });
            });
            const shown = rows.slice(0, BRANCH_MAX_CONDS);
            const hiddenConds = Math.max(0, totalConds - shown.filter(r => r.kind === "cond").length);

            return (
              <div
                key={i}
                className={`flow-graph-node flow-branch-node ${isActive ? "flow-node-eval-active" : isInactive ? "flow-node-eval-inactive" : ""}`}
                style={{
                  margin: 0,
                  width: "auto",
                  border: isActive ? "1.5px solid #34d399" : "1px solid rgba(255, 255, 255, 0.05)",
                  boxShadow: isActive ? "0 0 12px rgba(52, 211, 153, 0.25)" : "none",
                  padding: "8px 10px",
                  background: isActive ? "rgba(16, 185, 129, 0.02)" : "rgba(255, 255, 255, 0.02)",
                  borderRadius: "10px",
                  transition: "all 0.2s"
                }}
              >
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "4px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "6px", overflow: "hidden" }}>
                    <span style={{
                      width: "16px",
                      height: "16px",
                      borderRadius: "50%",
                      background: isActive ? "#10b981" : "rgba(255, 255, 255, 0.08)",
                      color: isActive ? "#fff" : "var(--text-dim)",
                      fontSize: "9px",
                      fontWeight: 700,
                      display: "grid",
                      placeItems: "center"
                    }}>
                      {i + 1}
                    </span>
                    <span style={{ fontSize: "11px", fontWeight: 600, color: isActive ? "#34d399" : "var(--text-soft)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", maxWidth: "160px" }}>
                      {b.description || `Alternative ${i + 1}`}
                    </span>
                  </div>
                  <span style={{ fontSize: "9px", color: "var(--text-dim)", fontFamily: "var(--font-mono)" }}>{totalConds}c</span>
                </div>

                <div style={{ display: "flex", flexDirection: "column", gap: "3px" }}>
                  {totalConds === 0 ? (
                    <div style={{ fontStyle: "italic", fontSize: "10px", color: "var(--text-dim)", padding: "2px 0" }}>always matches</div>
                  ) : (
                    <>
                      {shown.map((row, ri) => {
                        if (row.kind === "sep") {
                          return (
                            <div key={ri} className="flow-branch-node-rail" style={{ margin: "2px 0", fontSize: "9px", padding: 0 }}>
                              <span style={{ fontSize: "9px", padding: "1px 4px" }}>{row.label}</span>
                            </div>
                          );
                        }
                        if (row.kind === "subsep") {
                          return (
                            <div key={ri} className="flow-branch-node-subrail" style={{ margin: "1px 0", fontSize: "9px" }}>
                              {row.label}
                            </div>
                          );
                        }
                        return (
                          <CondPreview
                            key={ri}
                            cond={row.cond}
                            ruleNames={ruleNames}
                            onRefClick={onRefClick}
                            evaluationInput={evaluationInput}
                            ruleValues={ruleValues}
                          />
                        );
                      })}
                      {hiddenConds > 0 && (
                        <div className="flow-branch-node-more" style={{ fontSize: "9px", padding: "2px 0" }}>
                          +{hiddenConds} more — click to view
                        </div>
                      )}
                    </>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

function VerdictFooter({ rule, evaluationInput, ruleValues }) {
  const hasEvaluated = ruleValues !== null;
  const outcomeVal = hasEvaluated ? ruleValues[rule.name] : null;

  let verdictText = "";
  if (hasEvaluated) {
    if (outcomeVal === undefined || outcomeVal === null) {
      verdictText = "undefined";
    } else {
      verdictText = formatLit(outcomeVal);
    }
  } else {
    verdictText = "Pending evaluation";
  }

  const isMatched = hasEvaluated && outcomeVal !== undefined && outcomeVal !== null && outcomeVal !== rule.default;

  return (
    <div className="flow-container-verdict" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "6px 8px", background: "rgba(0, 0, 0, 0.2)", borderRadius: "8px", marginTop: "10px" }}>
      <span style={{ fontSize: "9px", textTransform: "uppercase", letterSpacing: "0.05em", color: "var(--text-dim)" }}>Verdict</span>
      <span style={{ fontFamily: "var(--font-mono)", fontSize: "11px", color: hasEvaluated ? (isMatched ? "#34d399" : "#60a5fa") : "var(--text-dim)", fontWeight: 600 }}>
        {rule.name} = {verdictText}
      </span>
    </div>
  );
}

const NODE_TYPES = {
  entry: EntryNode,
  ruleContainer: RuleContainerNode,
};


// ─── Compact condition preview (one-liner) ──────────────────────────────

function CondPreview({ cond, ruleNames, onRefClick, evaluationInput, ruleValues }) {
  // Advanced types get a short tag + tight summary; standard conditions get the
  // op-with-words rendering. Either way: single line, ellipsis on overflow.
  if (cond.condType) return <AdvancedCondPreview cond={cond} ruleNames={ruleNames} onRefClick={onRefClick} evaluationInput={evaluationInput} ruleValues={ruleValues} />;

  const opLabel = OP_LABELS[cond.op] || cond.op;
  const negated = !!cond.negate;
  const leftIsRef = isStrictRuleRef(cond.left, ruleNames);

  const hasEvaluated = ruleValues !== null;
  const details = hasEvaluated ? getConditionEvalDetails(cond, evaluationInput, ruleValues) : null;
  const condClass = details ? (details.ok ? "cond-eval-true" : "cond-eval-false") : "";

  return (
    <div className={`flow-branch-cond ${negated ? "negated" : ""} ${condClass}`}>
      <span className="flow-branch-cond-bullet">•</span>
      {negated && <span className="flow-branch-cond-not">NOT</span>}
      {leftIsRef
        ? <RefChip name={cond.left} onClick={onRefClick} variant="left" small />
        : <span className="flow-branch-cond-path" title={cond.left || ""}>{cond.left || "?"}</span>}
      {hasEvaluated && details && (
        <span className={`flow-cond-debug-val ${details.ok ? "" : "false-val"}`} title={`Runtime value: ${JSON.stringify(details.leftVal)}`}>
          {formatDebugValue(details.leftVal)}
        </span>
      )}
      <span className="flow-branch-cond-op">{opLabel}</span>
      <CondRightSidePreview cond={cond} ruleNames={ruleNames} onRefClick={onRefClick} />
    </div>
  );
}

function CondRightSidePreview({ cond, ruleNames, onRefClick }) {
  if (cond.op === "exists") return null;
  const t = cond.rightType;
  if (t === "ref") {
    const v = String(cond.right ?? "");
    if (isStrictRuleRef(v, ruleNames)) {
      return <RefChip name={v} onClick={onRefClick} variant="ref" small />;
    }
    return <span className="flow-branch-cond-path" title={v}>{v}</span>;
  }
  if (t === "string")  return <span className="flow-branch-cond-lit str">"{String(cond.right ?? "")}"</span>;
  if (t === "boolean") return <span className="flow-branch-cond-lit bool">{cond.right ? "true" : "false"}</span>;
  if (t === "null")    return <span className="flow-branch-cond-lit null">null</span>;
  if (t === "array") {
    const arr = Array.isArray(cond.right) ? cond.right : [];
    const preview = arr.length > 2
      ? `[${arr.slice(0, 2).map(formatLit).join(", ")}, +${arr.length - 2}]`
      : `[${arr.map(formatLit).join(", ")}]`;
    return <span className="flow-branch-cond-lit arr">{preview}</span>;
  }
  return <span className="flow-branch-cond-lit num">{String(cond.right ?? "")}</span>;
}

function AdvancedCondPreview({ cond, ruleNames, onRefClick, evaluationInput, ruleValues }) {
  const tag = cond.condType === "arith" ? "math"
    : cond.condType === "aggregate" ? "count"
    : cond.condType === "every" ? "for each"
    : cond.condType === "builtin_left" ? "builtin"
    : cond.condType === "verification" ? "verify"
    : cond.condType === "verify" ? "verify"
    : cond.condType === "object_get" ? "object.get"
    : cond.condType === "raw" ? "raw"
    : cond.condType;
  let summary = "";
  if (cond.condType === "arith") summary = `${cond.leftExpr || "…"} ${cond.op || ""} ${cond.right ?? ""}`;
  else if (cond.condType === "aggregate") summary = `${cond.fn || "count"}(${cond.collection || "…"}) ${cond.op || ""} ${cond.right ?? ""}`;
  else if (cond.condType === "every") summary = `${cond.variable || "x"} in ${cond.collection || "…"}`;
  else if (cond.condType === "builtin_left") summary = `${cond.builtin || "?"} ${cond.op || ""} ${cond.right ?? ""}`;
  else if (cond.condType === "verify") summary = `${cond.kind || "?"} (${cond.alg || "?"})`;
  else if (cond.condType === "verification") summary = `${cond.function || "?"}(…)`;
  else if (cond.condType === "object_get") summary = `${cond.obj || cond.object || "…"}[${JSON.stringify(cond.key)}]`;
  else if (cond.condType === "raw") summary = `${(cond.rego || "").split("\n").length} line(s) of Rego`;

  const hasEvaluated = ruleValues !== null;
  const details = hasEvaluated ? getConditionEvalDetails(cond, evaluationInput, ruleValues) : null;
  const condClass = details ? (details.ok ? "cond-eval-true" : "cond-eval-false") : "";

  return (
    <div className={`flow-branch-cond flow-branch-cond-advanced ${condClass}`}>
      <span className="flow-branch-cond-bullet">•</span>
      <span className="flow-branch-cond-tag">{tag}</span>
      <span className="flow-branch-cond-summary" title={summary}>{summary}</span>
      {hasEvaluated && details && (
        <span className={`flow-cond-debug-val ${details.ok ? "" : "false-val"}`} title={`Runtime: left=${JSON.stringify(details.leftVal)}, right=${JSON.stringify(details.rightVal)}`}>
          {formatDebugValue(details.leftVal)}
        </span>
      )}
    </div>
  );
}

function miniMapColor(node) {
  const rootStyle = getComputedStyle(document.documentElement);
  const accent = rootStyle.getPropertyValue("--accent").trim();
  const violet = rootStyle.getPropertyValue("--violet").trim();
  const danger = rootStyle.getPropertyValue("--danger").trim();
  const textDim = rootStyle.getPropertyValue("--text-dim").trim();

  if (node.type === "entry") return accent;
  if (node.type === "branch") return textDim;
  if (node.type === "outcome") return violet || accent;
  const role = node.data?.role;
  if (role === "decision")    return accent;
  if (role === "accumulator") return violet;
  if (role === "gate")        return accent;
  if (role === "orphan")      return danger;
  return textDim;
}

// ─── Main component ─────────────────────────────────────────────────────

// ─── Main component ─────────────────────────────────────────────────────

function topologicalSort(rules, edges) {
  const ruleNames = rules.map(r => r.name);
  const adj = new Map();
  const inDegree = new Map();
  
  for (const name of ruleNames) {
    adj.set(name, []);
    inDegree.set(name, 0);
  }
  
  for (const e of edges) {
    if (inDegree.has(e.from) && inDegree.has(e.to)) {
      adj.get(e.to).push(e.from);
      inDegree.set(e.from, inDegree.get(e.from) + 1);
    }
  }
  
  const queue = [];
  for (const name of ruleNames) {
    if (inDegree.get(name) === 0) {
      queue.push(name);
    }
  }
  
  const order = [];
  while (queue.length > 0) {
    const u = queue.shift();
    order.push(u);
    for (const v of adj.get(u)) {
      inDegree.set(v, inDegree.get(v) - 1);
      if (inDegree.get(v) === 0) {
        queue.push(v);
      }
    }
  }
  
  for (const name of ruleNames) {
    if (!order.includes(name)) {
      order.push(name);
    }
  }
  
  return order;
}

function FlowDiagramInner({ policy, currentTheme, evaluationResult, evaluationInput }) {
  const rules = useMemo(() => policy?.rules || [], [policy]);
  const graph = useMemo(() => buildRuleGraph(rules), [rules]);

  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [selected, setSelected] = useState(null);
  const { fitView, setCenter } = useReactFlow();

  const onOpenDetail = useCallback((name) => setSelected(name), []);
  const onCloseDetail = useCallback(() => setSelected(null), []);
  const onRefClick = useCallback((name) => { if (name) setSelected(name); }, []);

  // Trace player and Layout direction states
  const [currentStepIndex, setCurrentStepIndex] = useState(-1);
  const [isPlaying, setIsPlaying] = useState(false);
  const [layoutDir, setLayoutDir] = useState("TB");

  // Rule node Finder states
  const [findQuery, setFindQuery] = useState("");
  const [showFindPopover, setShowFindPopover] = useState(false);

  const ruleValues = useMemo(() => {
    if (!evaluationResult) return null;
    let val = evaluationResult.result;
    if (val && typeof val === "object" && !Array.isArray(val) && "decision_id" in val && "result" in val) {
      val = val.result;
    }
    return val && typeof val === "object" && !Array.isArray(val) ? val : null;
  }, [evaluationResult]);

  const sortedRuleNames = useMemo(() => {
    return topologicalSort(rules, graph.edges);
  }, [rules, graph.edges]);

  // Autoplay step-by-step trace intervals
  useEffect(() => {
    if (!isPlaying) return undefined;
    const interval = setInterval(() => {
      setCurrentStepIndex((prev) => {
        const next = prev + 1;
        if (next >= sortedRuleNames.length) {
          setIsPlaying(false);
          return -1;
        }
        return next;
      });
    }, 1800);
    return () => clearInterval(interval);
  }, [isPlaying, sortedRuleNames]);

  // Find matching rules for the search finder popover
  const matchingRules = useMemo(() => {
    const q = findQuery.toLowerCase().trim();
    if (!q) return [];
    return rules.filter(r => r.name.toLowerCase().includes(q));
  }, [rules, findQuery]);

  const handleCenterOnRule = useCallback((ruleName) => {
    const targetNode = nodes.find(n => n.id === ruleName);
    if (targetNode) {
      const x = targetNode.position.x + 170;
      const y = targetNode.position.y + 50;
      setCenter(x, y, { zoom: 1.1, duration: 800 });
      setSelected(ruleName);
    }
    setShowFindPopover(false);
    setFindQuery("");
  }, [nodes, setCenter]);

  // Handle centering when active trace player step changes
  useEffect(() => {
    if (currentStepIndex >= 0 && currentStepIndex < sortedRuleNames.length) {
      const activeRuleName = sortedRuleNames[currentStepIndex];
      const targetNode = nodes.find(n => n.id === activeRuleName);
      if (targetNode) {
        setCenter(targetNode.position.x + 170, targetNode.position.y + 50, { zoom: 1.1, duration: 800 });
        setSelected(activeRuleName);
      }
    }
  }, [currentStepIndex, sortedRuleNames, nodes, setCenter]);

  useEffect(() => {
    if (rules.length === 0) {
      setNodes([]);
      setEdges([]);
      return;
    }

    const rootStyle = getComputedStyle(document.documentElement);
    const accent = rootStyle.getPropertyValue("--accent").trim() || "#818cf8";
    const violet = rootStyle.getPropertyValue("--violet").trim() || "#a78bfa";
    const textDim = rootStyle.getPropertyValue("--text-dim").trim() || "#6b7280";

    const hasEvaluated = ruleValues !== null;

    const subgraphs = rules.map((r) => {
      const isResultObject = r.kind === "result_object";
      const branchesArr = isResultObject ? [] : (r.branches || []);
      const branches = branchesArr.map((b, i) => ({
        id: `${r.name}:b${i}`,
        index: i,
        branch: b,
        h: branchHeight(b),
      }));
      return {
        rule: r,
        role: graph.roleOf.get(r.name),
        isResultObject,
        branches,
      };
    });

    const positions = layoutGraph(subgraphs, graph.edges, graph.entryPoint?.name, layoutDir);

    const outNodes = [];
    if (graph.entryPoint) {
      outNodes.push({
        id: "__entry__",
        type: "entry",
        position: positions.get("__entry__") || { x: 0, y: 0 },
        draggable: true,
        selectable: false,
        data: {
          layoutDir,
        },
      });
    }

    for (const sg of subgraphs) {
      const isFocused = currentStepIndex >= 0 && sortedRuleNames[currentStepIndex] === sg.rule.name;
      outNodes.push({
        id: sg.rule.name,
        type: "ruleContainer",
        position: positions.get(sg.rule.name) || { x: 0, y: 0 },
        draggable: true,
        className: isFocused ? "flow-node-step-focused" : "",
        data: {
          rule: sg.rule,
          role: sg.role,
          ruleNames: graph.byName,
          onOpenDetail,
          onRefClick,
          evaluationInput,
          ruleValues,
          layoutDir,
        },
      });
    }

    const outEdges = [];

    if (graph.entryPoint) {
      outEdges.push({
        id: `__entry__->${graph.entryPoint.name}`,
        source: "__entry__",
        target: graph.entryPoint.name,
        targetHandle: "rule-target",
        type: "smoothstep",
        animated: true,
        className: "laser-edge-accent",
        label: "evaluate",
        labelStyle: { fontSize: 10, fill: accent, fontWeight: 600, letterSpacing: "0.06em" },
        labelBgStyle: { fill: "rgba(20,20,28,0.85)" },
        labelBgPadding: [4, 6],
        labelBgBorderRadius: 4,
        style: { stroke: accent, strokeWidth: 2.5 },
        markerEnd: { type: MarkerType.ArrowClosed, color: accent },
      });
    }

    for (const e of graph.edges) {
      const isWeak = e.kind === "weak";
      const isCrossActive = hasEvaluated && (e.from in ruleValues) && (e.to in ruleValues);
      const color = hasEvaluated
        ? (isCrossActive ? "#818cf8" : "rgba(100,116,139,0.15)")
        : (isWeak ? "rgba(150, 150, 170, 0.5)" : accent);

      // Determine correct source handle for Result Object wiring dashboard
      let sourceHandle = "rule-source";
      const fromRule = graph.byName.get(e.from);
      if (fromRule && fromRule.kind === "result_object" && Array.isArray(fromRule.fields)) {
        const matchingField = fromRule.fields.find(f => f.value === e.to && f.valueType === "ref");
        if (matchingField) {
          sourceHandle = `field:${matchingField.key}`;
        }
      }

      outEdges.push({
        id: `xref:${e.from}->${e.to}${isWeak ? ":w" : ""}`,
        source: e.from,
        sourceHandle: sourceHandle,
        target: e.to,
        targetHandle: "rule-target",
        type: "bezier",
        animated: hasEvaluated ? isCrossActive && !isWeak : !isWeak,
        className: isCrossActive && !isWeak ? "laser-edge-accent" : "",
        label: isWeak ? "uses (maybe)" : "uses",
        labelStyle: { fontSize: 9.5, fill: hasEvaluated ? (isCrossActive ? "#818cf8" : "rgba(100,116,139,0.3)") : (isWeak ? textDim : accent), fontWeight: 600 },
        labelBgStyle: { fill: "rgba(20,20,28,0.85)" },
        labelBgPadding: [3, 6],
        labelBgBorderRadius: 4,
        style: {
          stroke: color,
          strokeWidth: hasEvaluated ? (isCrossActive ? 2.25 : 0.75) : (isWeak ? 1.25 : 1.75),
          strokeDasharray: isWeak || (hasEvaluated && !isCrossActive) ? "4 4" : "2 4",
          opacity: hasEvaluated ? (isCrossActive ? 1 : 0.25) : 0.85,
        },
        markerEnd: { type: MarkerType.ArrowClosed, color, width: 14, height: 14 },
      });
    }

    setNodes(outNodes);
    setEdges(outEdges);

    requestAnimationFrame(() => fitView({ padding: 0.18, duration: 240 }));
  }, [rules, graph, onOpenDetail, onRefClick, fitView, setNodes, setEdges, currentTheme, evaluationInput, ruleValues, currentStepIndex, sortedRuleNames, layoutDir]);

  useEffect(() => { setSelected(null); }, [policy?.id]);

  if (rules.length === 0) {
    return (
      <div className="flow-graph-wrap">
        <div className="flow-graph-empty">
          <div className="flow-graph-empty-title">No rules yet</div>
          <div className="flow-graph-empty-sub">Add a rule in the Visual Builder to see the flowchart.</div>
        </div>
      </div>
    );
  }

  const selectedRule = selected ? graph.byName.get(selected) : null;
  const selectedRole = selected ? graph.roleOf.get(selected) : null;

  return (
    <div className="flow-graph-wrap">
      <div className="flow-graph-toolbar" style={{ display: "flex", flexWrap: "wrap", gap: "12px", padding: "8px 12px", alignItems: "center" }}>
        
        {/* Media Player Controls */}
        <div className="flow-player-controls" style={{
          display: "flex",
          alignItems: "center",
          gap: "8px",
          background: "var(--surface-2, rgba(20,20,28,0.75))",
          padding: "4px 8px",
          borderRadius: "8px",
          border: "1px solid rgba(255,255,255,0.06)",
        }}>
          <button
            type="button"
            className="btn btn-ghost btn-xs"
            onClick={() => {
              setCurrentStepIndex(-1);
              setIsPlaying(false);
              setSelected(null);
            }}
            title="Reset playback"
            style={{ fontSize: "10px", fontFamily: "var(--font-mono)", color: "var(--text-dim)", padding: "2px 6px" }}
          >
            reset
          </button>
          
          <button
            type="button"
            className="btn btn-ghost btn-xs"
            onClick={() => {
              setIsPlaying(false);
              setCurrentStepIndex((prev) => Math.max(-1, prev - 1));
            }}
            disabled={currentStepIndex <= -1}
            title="Previous step"
            style={{ fontSize: "10px", padding: "2px 6px" }}
          >
            prev
          </button>

          <button
            type="button"
            className="btn btn-primary btn-xs"
            onClick={() => setIsPlaying(!isPlaying)}
            title={isPlaying ? "Pause trace player" : "Play step-by-step trace"}
            style={{ fontSize: "10px", padding: "2px 8px" }}
          >
            {isPlaying ? "pause" : "play trace"}
          </button>

          <button
            type="button"
            className="btn btn-ghost btn-xs"
            onClick={() => {
              setIsPlaying(false);
              setCurrentStepIndex((prev) => {
                const next = prev + 1;
                if (next >= sortedRuleNames.length) return prev;
                return next;
              });
            }}
            disabled={currentStepIndex >= sortedRuleNames.length - 1}
            title="Next step"
            style={{ fontSize: "10px", padding: "2px 6px" }}
          >
            next
          </button>

          {currentStepIndex >= 0 && (
            <span style={{ fontSize: "10px", fontFamily: "var(--font-mono)", color: "var(--accent)", marginLeft: "4px" }}>
              {currentStepIndex + 1}/{sortedRuleNames.length}: {sortedRuleNames[currentStepIndex]}
            </span>
          )}
        </div>

        {/* Layout direction selector */}
        <div className="flow-layout-toggle" style={{
          display: "flex",
          alignItems: "center",
          gap: "4px",
          background: "var(--surface-2, rgba(20,20,28,0.75))",
          padding: "4px 8px",
          borderRadius: "8px",
          border: "1px solid rgba(255,255,255,0.06)",
        }}>
          <span style={{ fontSize: "9px", textTransform: "uppercase", letterSpacing: "0.05em", color: "var(--text-dim)", fontWeight: 700, marginRight: "4px" }}>dir</span>
          <button
            type="button"
            className={`btn btn-xs ${layoutDir === "TB" ? "btn-primary" : "btn-ghost"}`}
            onClick={() => setLayoutDir("TB")}
            style={{ fontSize: "10px", padding: "2px 6px" }}
          >
            vertical
          </button>
          <button
            type="button"
            className={`btn btn-xs ${layoutDir === "LR" ? "btn-primary" : "btn-ghost"}`}
            onClick={() => setLayoutDir("LR")}
            style={{ fontSize: "10px", padding: "2px 6px" }}
          >
            horizontal
          </button>
        </div>

        {/* Finder search bar */}
        <div className="flow-find-node" style={{ position: "relative", display: "flex", alignItems: "center" }}>
          <input
            type="text"
            className="sidebar-search"
            value={findQuery}
            onChange={(e) => {
              setFindQuery(e.target.value);
              setShowFindPopover(true);
            }}
            onFocus={() => setShowFindPopover(true)}
            placeholder="Find node..."
            style={{ height: "24px", fontSize: "11px", width: "120px", padding: "4px 8px", borderRadius: "6px" }}
          />
          {showFindPopover && matchingRules.length > 0 && (
            <div className="search-results-popover" style={{ top: "100%", left: 0, width: "120px" }}>
              {matchingRules.map((r) => (
                <div key={r.name} onClick={() => handleCenterOnRule(r.name)}>
                  {r.name}
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="flow-graph-toolbar-legend" style={{ marginLeft: "auto", display: "flex", gap: "10px" }}>
          <LegendDot color="var(--accent)" label="when matched" />
          <LegendDot color="var(--text-dim)" label="default path" dashed />
          <LegendDot color="var(--accent)" label="cross-rule use" dotted />
        </div>
        
        <div className="flow-graph-toolbar-actions" style={{ marginLeft: "8px" }}>
          <button type="button" className="flow-density-btn" onClick={() => fitView({ padding: 0.18, duration: 240 })} style={{ fontSize: "10px", padding: "4px 8px" }}>Fit Canvas</button>
        </div>
      </div>

      <div className={`flow-graph-shell ${selectedRule ? "has-panel" : ""}`}>
        <div className="flow-graph-canvas">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            nodeTypes={NODE_TYPES}
            fitView
            fitViewOptions={{ padding: 0.18 }}
            minZoom={0.2}
            maxZoom={1.5}
            proOptions={{ hideAttribution: true }}
            nodesDraggable
            nodesConnectable={false}
            elementsSelectable
            onNodeClick={(_, n) => {
              if (n.type === "ruleContainer") {
                setSelected(n.id || null);
              }
            }}
            onPaneClick={() => setSelected(null)}
          >
            <Background gap={20} size={1} color="rgba(255,255,255,0.04)" />
            <MiniMap pannable zoomable nodeColor={miniMapColor} nodeStrokeWidth={2} maskColor="rgba(8,10,14,0.6)" />
            <Controls showInteractive={false} />
          </ReactFlow>
        </div>

        {selectedRule && (
          <RuleDetailPanel
            rule={selectedRule}
            role={selectedRole}
            ruleNames={graph.byName}
            onRefClick={onRefClick}
            onClose={onCloseDetail}
            evaluationInput={evaluationInput}
            ruleValues={ruleValues}
          />
        )}
      </div>
    </div>
  );
}

export default function FlowDiagram(props) {
  return (
    <ReactFlowProvider>
      <FlowDiagramInner {...props} />
    </ReactFlowProvider>
  );
}

// ─── Legend ─────────────────────────────────────────────────────────────

function LegendDot({ color, label, dashed, dotted }) {
  const borderStyle = dashed ? "dashed" : dotted ? "dotted" : "solid";
  return (
    <span className="flow-graph-legend-item">
      <span
        className="flow-graph-legend-bar"
        style={{
          background: dashed || dotted ? "transparent" : color,
          borderTop: dashed || dotted ? `2px ${borderStyle} ${color}` : undefined,
        }}
      />
      <span className="flow-graph-legend-label">{label}</span>
    </span>
  );
}

// ─── Side panel ─────────────────────────────────────────────────────────

function RuleDetailPanel({ rule, role, ruleNames, onRefClick, onClose, evaluationInput, ruleValues }) {
  const safeRole = role || "helper";
  const isResultObject = rule.kind === "result_object";
  return (
    <aside className="flow-graph-side-panel">
      <header className="flow-graph-side-head">
        <span className="flow-rule-icon" style={{ width: 40, height: 40, fontSize: 24 }}>
          {ROLE_ICONS[safeRole]}
        </span>
        <div className="flow-graph-node-title-group">
          <span className={`flow-rule-role flow-rule-role-${safeRole}`} style={{ fontSize: 10 }}>
            {ROLE_LABELS[safeRole]}
          </span>
          <span className="flow-graph-side-name">{rule.name}</span>
        </div>
        <button type="button" className="flow-graph-side-close" onClick={onClose} aria-label="Close">×</button>
      </header>

      {rule.description && (
        <div className="flow-rule-description" style={{ padding: "16px 20px", borderBottom: "1px solid rgba(255,255,255,0.05)", color: "var(--text-soft)", fontSize: 14, lineHeight: 1.5 }}>
          {rule.description}
        </div>
      )}

      <div className="flow-graph-side-body">
        {isResultObject
          ? <ResultObjectBody rule={rule} ruleNames={ruleNames} onRefClick={onRefClick} evaluationInput={evaluationInput} ruleValues={ruleValues} />
          : <RuleBranches rule={rule} ruleNames={ruleNames} onRefClick={onRefClick} evaluationInput={evaluationInput} ruleValues={ruleValues} />}
      </div>
    </aside>
  );
}

// ─── Branch / group / condition renderers (used inside the side panel) ──

function RuleBranches({ rule, ruleNames, onRefClick, evaluationInput, ruleValues }) {
  const branches = rule.branches || [];
  const [expandedIndex, setExpandedIndex] = useState(0);

  if (branches.length === 0) {
    return (
      <div className="flow-empty" style={{ background: "rgba(255,255,255,0.03)", padding: 24, borderRadius: 12, textAlign: "center", color: "var(--text-dim)" }}>
        No logic branches defined. This rule returns its default value.
      </div>
    );
  }

  return (
    <div className="flow-branches">
      <div className="flow-logic-intro" style={{ marginBottom: 16, fontSize: 13, color: "var(--text-dim)", fontWeight: 500, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span>Rule logic summary:</span>
        <span style={{ fontSize: 11, background: "rgba(255,255,255,0.05)", padding: "2px 8px", borderRadius: 4 }}>{branches.length} requirement{branches.length === 1 ? "" : "s"}</span>
      </div>
      {branches.map((b, i) => (
        <Fragment key={i}>
          {i > 0 && (
            <div className="flow-or-rail" style={{ margin: "12px 0", display: "flex", alignItems: "center", gap: 12 }}>
              <div style={{ flex: 1, height: 1, background: "rgba(255,255,255,0.05)" }} />
              <span className="flow-or-pill" style={{ fontSize: 10, fontWeight: 800, color: "var(--text-dim)", background: "rgba(255,255,255,0.05)", padding: "2px 8px", borderRadius: 4 }}>OR</span>
              <div style={{ flex: 1, height: 1, background: "rgba(255,255,255,0.05)" }} />
            </div>
          )}
          <BranchCard
            branch={b}
            index={i}
            ruleKind={rule.kind}
            ruleNames={ruleNames}
            onRefClick={onRefClick}
            isExpanded={expandedIndex === i}
            onToggle={() => setExpandedIndex(expandedIndex === i ? -1 : i)}
            evaluationInput={evaluationInput}
            ruleValues={ruleValues}
          />
        </Fragment>
      ))}
    </div>
  );
}

function ResultObjectBody({ rule, ruleNames, onRefClick, evaluationInput, ruleValues }) {
  const fields = Array.isArray(rule.fields) ? rule.fields : [];
  return (
    <div className="flow-result-card" style={{ background: "rgba(255,255,255,0.03)", borderRadius: 12, padding: 16, border: "1px solid rgba(255,255,255,0.05)" }}>
      <div className="flow-logic-intro" style={{ marginBottom: 16, fontSize: 13, color: "var(--text-dim)", fontWeight: 500 }}>
        This rule constructs a result with the following data:
      </div>
      {fields.length === 0 ? (
        <div className="flow-empty" style={{ fontStyle: "italic", color: "var(--text-dim)", textAlign: "center", padding: "12px 0" }}>
          No data fields defined.
        </div>
      ) : (
        <div className="flow-result-fields" style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {fields.map((f, i) => (
            <div key={i} className="flow-result-field" style={{ display: "flex", alignItems: "center", gap: 12, padding: "8px 12px", background: "rgba(0,0,0,0.2)", borderRadius: 8 }}>
              <span className="flow-result-key" style={{ fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--accent)", fontWeight: 600 }}>{f.key || "?"}</span>
              <span style={{ color: "var(--text-dim)", fontSize: 12 }}>is set to</span>
              <ResultFieldValue field={f} ruleNames={ruleNames} onRefClick={onRefClick} />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function ResultFieldValue({ field, ruleNames, onRefClick }) {
  const t = field.valueType || "ref";
  if (t === "ref") {
    const v = String(field.value ?? "");
    if (isStrictRuleRef(v, ruleNames)) {
      return <RefChip name={v} onClick={onRefClick} variant="ref" />;
    }
    return <span className="flow-result-value flow-result-value-ref"><RulePath text={v} /></span>;
  }
  if (t === "string")  return <span className="flow-result-value flow-result-value-string">{JSON.stringify(field.value ?? "")}</span>;
  if (t === "null")    return <span className="flow-result-value flow-result-value-null">null</span>;
  if (t === "boolean") return <span className="flow-result-value flow-result-value-boolean">{String(!!field.value)}</span>;
  return <span className="flow-result-value flow-result-value-number">{String(field.value ?? "")}</span>;
}

function BranchCard({ branch, index, ruleKind, ruleNames, onRefClick, isExpanded, onToggle, evaluationInput, ruleValues }) {
  const groups = getGroups(branch);
  const conditionCount = countConditions(branch);

  const hasEvaluated = ruleValues !== null;
  const isActive = hasEvaluated && evaluateBranch(branch, evaluationInput, ruleValues);

  return (
    <div className={`flow-branch ${isExpanded ? "is-expanded" : ""}`} style={{
      borderRadius: 12,
      border: hasEvaluated
        ? (isActive ? "1px solid rgba(16, 185, 129, 0.45)" : "1px solid rgba(255,255,255,0.03)")
        : "1px solid rgba(255,255,255,0.05)",
      background: hasEvaluated && isActive ? "rgba(16, 185, 129, 0.02)" : "rgba(255,255,255,0.03)",
      overflow: "hidden",
      transition: "all 0.2s"
    }}>
      <button
        type="button"
        onClick={onToggle}
        className="flow-branch-header-btn"
        style={{ width: "100%", textAlign: "left", background: "none", border: "none", padding: 16, cursor: "pointer", display: "flex", alignItems: "center", gap: 12 }}
      >
        <span className="flow-branch-num" style={{
          background: isExpanded ? "var(--accent)" : (hasEvaluated && isActive ? "#10b981" : "rgba(255,255,255,0.1)"),
          color: isExpanded || (hasEvaluated && isActive) ? "#fff" : "var(--text-dim)",
          width: 24, height: 24, display: "grid", placeItems: "center", borderRadius: "50%", fontSize: 12, fontWeight: 700,
          transition: "all 0.2s"
        }}>
          {index + 1}
        </span>
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 14, fontWeight: 600, color: isExpanded ? "var(--text)" : (hasEvaluated && isActive ? "#34d399" : "var(--text-soft)") }}>
            {branch.description || `Requirement Set #${index + 1}`}
          </div>
          {!isExpanded && (
            <div style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 2 }}>
              {conditionCount} condition{conditionCount === 1 ? "" : "s"}{hasEvaluated && (isActive ? " • Match satisfied ✓" : " • Conditions not met ✕")}
            </div>
          )}
          {isExpanded && ruleKind === "partial_set" && branch.value !== undefined && (
            <div style={{ fontSize: 11, color: "var(--accent)", fontWeight: 500, marginTop: 2 }}>
              Result: {typeof branch.value === "string" ? `"${branch.value}"` : JSON.stringify(branch.value)}
            </div>
          )}
        </div>
        <span style={{ fontSize: 12, color: "var(--text-dim)", transform: isExpanded ? "rotate(180deg)" : "rotate(0deg)", transition: "transform 0.2s" }}>
          ▼
        </span>
      </button>

      {isExpanded && (
        <div className="flow-branch-body" style={{ padding: "0 16px 16px", borderTop: "1px solid rgba(255,255,255,0.05)" }}>
          <div className="flow-branch-groups" style={{ marginTop: 16 }}>
            {groups.map((group, gi) => (
              <Fragment key={gi}>
                {gi > 0 && (
                  <div className="flow-group-rail" style={{ padding: "8px 0", textAlign: "center", position: "relative" }}>
                    <span className="flow-group-rail-pill" style={{ fontSize: 9, color: "var(--text-dim)", background: "var(--bg)", position: "relative", zIndex: 1, padding: "0 8px" }}>AND</span>
                    <div style={{ position: "absolute", top: "50%", left: 0, right: 0, height: 1, background: "rgba(255,255,255,0.05)" }} />
                  </div>
                )}
                <GroupCard
                  group={group}
                  ruleNames={ruleNames}
                  onRefClick={onRefClick}
                  evaluationInput={evaluationInput}
                  ruleValues={ruleValues}
                />
              </Fragment>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function GroupCard({ group, ruleNames, onRefClick, evaluationInput, ruleValues }) {
  const conds = group.conditions || [];
  const isOr = group.mode === "or";
  return (
    <div className={`flow-group flow-group-${group.mode}`} style={{ background: "rgba(0,0,0,0.2)", borderRadius: 8, padding: 12 }}>
      <div className="flow-logic-label" style={{ fontSize: 10, fontWeight: 700, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 8, display: "flex", alignItems: "center", gap: 6 }}>
        <span style={{ width: 6, height: 6, borderRadius: "50%", background: isOr ? "#f59e0b" : "#10b981" }} />
        {groupModeLabel(group)}
      </div>
      <div className="flow-conditions" style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        {conds.length === 0 ? (
          <div className="flow-cond empty" style={{ fontStyle: "italic", color: "var(--text-dim)", fontSize: 12 }}>
            Always true
          </div>
        ) : (
          conds.map((c, i) => (
            <ConditionRow
              key={i}
              cond={c}
              ruleNames={ruleNames}
              onRefClick={onRefClick}
              evaluationInput={evaluationInput}
              ruleValues={ruleValues}
            />
          ))
        )}
      </div>
    </div>
  );
}

function getGroups(branch) {
  if (Array.isArray(branch.groups) && branch.groups.length) return branch.groups;
  return [{ mode: "and", conditions: branch.conditions || [] }];
}

function countConditions(branch) {
  const groups = getGroups(branch);
  return groups.reduce((acc, g) => acc + (g.conditions?.length || 0), 0);
}

function ConditionRow({ cond, ruleNames, onRefClick, evaluationInput, ruleValues }) {
  if (cond.condType) {
    return <AdvancedCondRow cond={cond} ruleNames={ruleNames} onRefClick={onRefClick} evaluationInput={evaluationInput} ruleValues={ruleValues} />;
  }
  const opLabel = OP_LABELS[cond.op] || cond.op;
  const opClass = OP_CLASSES[cond.op] || "neutral";
  const negated = !!cond.negate;
  const leftIsRuleRef = isStrictRuleRef(cond.left, ruleNames);

  const hasEvaluated = ruleValues !== null;
  const details = hasEvaluated ? getConditionEvalDetails(cond, evaluationInput, ruleValues) : null;
  const condClass = details ? (details.ok ? "cond-eval-true" : "cond-eval-false") : "";

  return (
    <div className={`flow-cond ${negated ? "negated" : ""} ${condClass}`} style={{
      display: "flex",
      alignItems: "center",
      gap: 8,
      padding: "6px 10px",
      background: hasEvaluated
        ? (details.ok ? "rgba(16, 185, 129, 0.02)" : "rgba(239, 68, 68, 0.02)")
        : "rgba(255,255,255,0.02)",
      border: hasEvaluated
        ? (details.ok ? "1px solid rgba(16, 185, 129, 0.25)" : "1px solid rgba(239, 68, 68, 0.25)")
        : "1px solid transparent",
      borderRadius: 6,
      fontSize: 13
    }}>
      <span style={{ color: "var(--text-dim)", fontSize: 14 }}>•</span>
      {negated && <span className="flow-not" style={{ color: "var(--danger)", fontWeight: 700, fontSize: 11 }}>NOT</span>}
      {leftIsRuleRef
        ? <RefChip name={cond.left} onClick={onRefClick} variant="left" />
        : <RulePath text={cond.left || ""} className="flow-path" style={{ color: "var(--text-soft)" }} />}
      {hasEvaluated && details && (
        <span className={`flow-cond-debug-val ${details.ok ? "" : "false-val"}`} title={`Runtime value: ${JSON.stringify(details.leftVal)}`}>
          {formatDebugValue(details.leftVal)}
        </span>
      )}
      <span className={`flow-op flow-op-${opClass}`} style={{ color: "var(--accent)", fontWeight: 500, fontSize: 12, textTransform: "lowercase" }}>{opLabel}</span>
      <ConditionRightSide cond={cond} ruleNames={ruleNames} onRefClick={onRefClick} />
    </div>
  );
}

function ConditionRightSide({ cond, ruleNames, onRefClick }) {
  if (cond.op === "exists") return null;
  const t = cond.rightType;
  if (t === "ref") {
    const v = String(cond.right ?? "");
    if (isStrictRuleRef(v, ruleNames)) {
      return <RefChip name={v} onClick={onRefClick} variant="ref" />;
    }
    return <RulePath text={v} className="flow-value ref" title={v} />;
  }
  if (t === "string")  return <span className="flow-value str" title="string">{`"${String(cond.right ?? "")}"`}</span>;
  if (t === "boolean") return <span className="flow-value bool" title="boolean">{cond.right ? "true" : "false"}</span>;
  if (t === "null")    return <span className="flow-value null" title="null">null</span>;
  if (t === "array") {
    const arr = Array.isArray(cond.right) ? cond.right : [];
    const preview = arr.length > 3
      ? `[${arr.slice(0, 3).map(formatLit).join(", ")}, …+${arr.length - 3}]`
      : `[${arr.map(formatLit).join(", ")}]`;
    return <span className="flow-value arr" title={arr.map(formatLit).join(", ")}>{preview}</span>;
  }
  return <span className="flow-value num" title="number">{String(cond.right ?? "")}</span>;
}

function AdvancedCondRow({ cond, ruleNames, onRefClick, evaluationInput, ruleValues }) {
  const negated = !!cond.negate;
  const hasEvaluated = ruleValues !== null;
  const details = hasEvaluated ? getConditionEvalDetails(cond, evaluationInput, ruleValues) : null;

  const borderLeftColor = {
    arith: "#6366f1",
    aggregate: "#a855f7",
    every: "#3b82f6",
    builtin_left: "#10b981",
    verification: "#f59e0b",
    verify: "#ec4899",
    object_get: "#06b6d4",
    raw: "#6b7280"
  }[cond.condType] || "#6b7280";

  const condBg = hasEvaluated
    ? (details?.ok ? "rgba(16, 185, 129, 0.02)" : "rgba(239, 68, 68, 0.02)")
    : "rgba(255,255,255,0.03)";

  const condBorder = hasEvaluated
    ? (details?.ok ? "1px solid rgba(16, 185, 129, 0.25)" : "1px solid rgba(239, 68, 68, 0.25)")
    : "1px solid rgba(255,255,255,0.05)";

  const baseClass = `flow-cond flow-cond-advanced ${negated ? "negated" : ""} ${hasEvaluated ? (details?.ok ? "cond-eval-true" : "cond-eval-false") : ""}`;

  const renderDebugValue = () => {
    if (!hasEvaluated || !details) return null;
    return (
      <span className={`flow-cond-debug-val ${details.ok ? "" : "false-val"}`} title={`Runtime: left=${JSON.stringify(details.leftVal)}, right=${JSON.stringify(details.rightVal)}`}>
        {formatDebugValue(details.leftVal)}
      </span>
    );
  };

  const refOrLiteralRight = (rightType, rightValue) => {
    if (rightType === "ref") {
      const v = String(rightValue ?? "");
      if (isStrictRuleRef(v, ruleNames)) {
        return <RefChip name={v} onClick={onRefClick} variant="ref" />;
      }
      return <RulePath text={v} className="flow-value ref" />;
    }
    return (
      <span className={`flow-value ${rightType === "number" ? "num" : rightType === "boolean" ? "bool" : "str"}`}>
        {rightType === "string" ? `"${String(rightValue ?? "")}"` : String(rightValue ?? "")}
      </span>
    );
  };

  if (cond.condType === "arith") {
    return (
      <div className={baseClass} style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 10px", background: condBg, border: condBorder, borderRadius: 6, fontSize: 13, borderLeft: `3px solid ${borderLeftColor}` }}>
        <span className="flow-cond-type-tag" style={{ fontSize: 9, background: "rgba(99, 102, 241, 0.2)", color: "#818cf8", padding: "1px 4px", borderRadius: 3, textTransform: "uppercase" }}>math</span>
        {negated && <span className="flow-not" style={{ color: "var(--danger)", fontWeight: 700, fontSize: 11 }}>NOT</span>}
        <ArithExpr text={cond.leftExpr || "…"} ruleNames={ruleNames} onRefClick={onRefClick} />
        {renderDebugValue()}
        <span className="flow-op flow-op-cmp" style={{ color: "var(--accent)" }}>{cond.op}</span>
        {refOrLiteralRight(cond.rightType, cond.right)}
      </div>
    );
  }

  if (cond.condType === "aggregate") {
    const hasFilter = Array.isArray(cond.filter) && cond.filter.length > 0;
    return (
      <div className={baseClass} style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 10px", background: condBg, border: condBorder, borderRadius: 6, fontSize: 13, borderLeft: `3px solid ${borderLeftColor}` }}>
        <span className="flow-cond-type-tag" style={{ fontSize: 9, background: "rgba(168, 85, 247, 0.2)", color: "#c084fc", padding: "1px 4px", borderRadius: 3, textTransform: "uppercase" }}>count</span>
        {negated && <span className="flow-not" style={{ color: "var(--danger)", fontWeight: 700, fontSize: 11 }}>NOT</span>}
        <span className="flow-op flow-op-set" style={{ fontWeight: 600 }}>{cond.fn || "count"}</span>
        <span className="flow-cond-collection" style={{ color: "var(--text-soft)" }}><RulePath text={cond.collection || "…"} /></span>
        {renderDebugValue()}
        <span className="flow-op flow-op-cmp" style={{ color: "var(--accent)" }}>{cond.op}</span>
        {refOrLiteralRight(cond.rightType, cond.right)}
        {hasFilter && (
          <span style={{ color: "var(--text-dim)", fontSize: 10, fontStyle: "italic" }}>
            (filtered)
          </span>
        )}
      </div>
    );
  }

  if (cond.condType === "every") {
    const innerConds = cond.conditions || [];
    return (
      <div className={baseClass} style={{ background: condBg, border: condBorder, borderLeft: `3px solid ${borderLeftColor}`, padding: "6px 10px", borderRadius: 6 }}>
        <span className="flow-cond-type-tag">every</span>
        {negated && <span className="flow-not">NOT</span>}
        <span className="flow-cond-keyword">for every</span>
        <span className="flow-value ref">{cond.variable || "item"}</span>
        <span className="flow-cond-keyword">in</span>
        <span className="flow-cond-collection"><RulePath text={cond.collection || "…"} /></span>
        {renderDebugValue()}
        {innerConds.length > 0 && (
          <div className="flow-every-inner">
            {innerConds.slice(0, 4).map((c, i) => (
              <span key={i} className="flow-every-inner-cond">
                {c.left} {OP_LABELS[c.op] || c.op}
                {c.rightType !== undefined && c.op !== "exists" ? ` ${String(c.right ?? "")}` : ""}
              </span>
            ))}
            {innerConds.length > 4 && (
              <span className="flow-every-inner-cond" style={{ color: "var(--text-dim)" }}>
                …+{innerConds.length - 4} more
              </span>
            )}
          </div>
        )}
      </div>
    );
  }

  if (cond.condType === "builtin_left") {
    const builtinLabel = {
      "time.now_ns":  "time.now_ns()",
      "time.weekday": `time.weekday(${cond.arg || "…"})`,
      "time.date":    `time.date(${cond.arg || "…"})[${cond.component ?? 0}]`,
    }[cond.builtin] || cond.builtin;
    return (
      <div className={baseClass} style={{ background: condBg, border: condBorder, borderLeft: `3px solid ${borderLeftColor}`, padding: "6px 10px", borderRadius: 6, display: "flex", alignItems: "center", gap: 8 }}>
        <span className="flow-cond-type-tag">builtin</span>
        {negated && <span className="flow-not">NOT</span>}
        <span className="flow-cond-keyword">{builtinLabel}</span>
        {renderDebugValue()}
        <span className="flow-op flow-op-cmp">{cond.op}</span>
        {refOrLiteralRight(cond.rightType, cond.right)}
      </div>
    );
  }

  if (cond.condType === "verification") {
    const fn = cond.function || "";
    const args = Array.isArray(cond.args) ? cond.args : [];
    const renderedArgs = args.map((a) => {
      if (!a) return "?";
      if (a.type === "ref") return a.value || "…";
      if (a.type === "object") {
        try { return JSON.stringify(typeof a.value === "string" ? JSON.parse(a.value) : (a.value || {})); }
        catch { return typeof a.value === "string" ? a.value : "{…}"; }
      }
      return JSON.stringify(a.value ?? "");
    }).join(", ");
    const isTuple = Array.isArray(cond.bind);
    const useBind = cond.bindAs && cond.bindAs.length > 0;
    return (
      <div className={baseClass} style={{ background: condBg, border: condBorder, borderLeft: `3px solid ${borderLeftColor}`, padding: "6px 10px", borderRadius: 6, display: "flex", alignItems: "center", gap: 8 }}>
        <span className="flow-cond-type-tag">verify</span>
        {negated && <span className="flow-not">NOT</span>}
        {isTuple && <span className="flow-cond-expr">[{cond.bind.join(", ")}] := </span>}
        {useBind && <span className="flow-cond-expr">{cond.bindAs} := </span>}
        <span className="flow-cond-keyword">{fn}(</span>
        <span className="flow-cond-expr">{renderedArgs}</span>
        <span className="flow-cond-keyword">)</span>
        {renderDebugValue()}
        {!isTuple && !useBind && cond.compareOp && (
          <>
            <span className="flow-op flow-op-cmp">{cond.compareOp}</span>
            {refOrLiteralRight(cond.compareTo?.type, cond.compareTo?.value)}
          </>
        )}
      </div>
    );
  }

  if (cond.condType === "verify") {
    const kind = cond.kind || "?";
    const keyRef = cond.keyRef || {};
    const keySourceLabel = keyRef.source === "inline_pem" ? "inline PEM"
      : keyRef.source === "inline_secret" ? "inline secret"
      : keyRef.source === "data.studio.keys" ? `data.studio.keys${keyRef.selector ? `[${keyRef.selector}]` : ""}`
      : keyRef.source || "?";
    const constraints = cond.constraints || {};
    const constraintBits = [];
    if (constraints.iss) constraintBits.push(`iss=${constraints.iss}`);
    if (constraints.aud) {
      const aud = Array.isArray(constraints.aud) ? constraints.aud.join(",") : constraints.aud;
      constraintBits.push(`aud=${aud}`);
    }
    if (constraints.exp_required) constraintBits.push("exp");
    if (constraints.nbf_required) constraintBits.push("nbf");
    return (
      <div className={baseClass} style={{ background: condBg, border: condBorder, borderLeft: `3px solid ${borderLeftColor}`, padding: "6px 10px", borderRadius: 6, display: "flex", alignItems: "center", gap: 8 }}>
        <span className="flow-cond-type-tag">verify</span>
        <span className="flow-cond-keyword">{kind}</span>
        {kind === "jwt" && (
          <>
            <span className="flow-cond-expr">token=</span>
            <RulePath text={cond.tokenRef || ""} />
            <span className="flow-cond-expr">alg={cond.alg}</span>
          </>
        )}
        {kind === "x509" && (
          <>
            <span className="flow-cond-expr">chain=</span>
            <RulePath text={cond.chainRef || ""} />
          </>
        )}
        {kind === "raw" && (
          <>
            <span className="flow-cond-expr">alg={cond.alg}</span>
            <span className="flow-cond-expr">payload=</span>
            <RulePath text={cond.payloadRef || ""} />
            <span className="flow-cond-expr">sig=</span>
            <RulePath text={cond.signatureRef || ""} />
          </>
        )}
        {kind !== "x509" && <span className="flow-cond-expr">key={keySourceLabel}</span>}
        {constraintBits.length > 0 && <span className="flow-cond-expr">[{constraintBits.join(", ")}]</span>}
        {renderDebugValue()}
      </div>
    );
  }

  if (cond.condType === "object_get") {
    const opLabel = OP_LABELS[cond.op] || cond.op;
    const opClass = OP_CLASSES[cond.op] || "neutral";
    const objPath = cond.obj ?? cond.object ?? "";
    return (
      <div className={baseClass} style={{ background: condBg, border: condBorder, borderLeft: `3px solid ${borderLeftColor}`, padding: "6px 10px", borderRadius: 6, display: "flex", alignItems: "center", gap: 8 }}>
        <span className="flow-cond-type-tag">object.get</span>
        {negated && <span className="flow-not">NOT</span>}
        <span className="flow-cond-expr">
          object.get(<RulePath text={objPath} />, {JSON.stringify(cond.key)}, {JSON.stringify(cond.default)})
        </span>
        {renderDebugValue()}
        <span className={`flow-op flow-op-${opClass}`}>{opLabel}</span>
        {refOrLiteralRight(cond.rightType, cond.right)}
      </div>
    );
  }

  if (cond.condType === "raw") {
    const rego = cond.rego || "";
    const lines = rego.split("\n");
    return (
      <div className={`${baseClass} flow-cond-raw`} style={{ background: condBg, border: condBorder, borderLeft: `3px solid ${borderLeftColor}`, padding: "6px 10px", borderRadius: 6 }}>
        <div className="flow-cond-raw-head">
          <span className="flow-cond-type-tag">raw</span>
          {negated && <span className="flow-not">NOT</span>}
          <span className="flow-cond-raw-meta">{lines.length} line{lines.length === 1 ? "" : "s"}</span>
          {renderDebugValue()}
        </div>
        <pre className="flow-cond-raw-block">{rego}</pre>
      </div>
    );
  }

  return (
    <div className={baseClass} style={{ background: condBg, border: condBorder, borderLeft: `3px solid ${borderLeftColor}`, padding: "6px 10px", borderRadius: 6 }}>
      <span className="flow-cond-type-tag">{cond.condType}</span>
      <span style={{ color: "var(--text-dim)", fontSize: 11 }}>{JSON.stringify(cond).slice(0, 60)}…</span>
    </div>
  );
}

// ─── Inline atoms ───────────────────────────────────────────────────────

function RefChip({ name, onClick, variant, small }) {
  return (
    <button
      type="button"
      className={`flow-ref-chip flow-ref-chip-${variant || "ref"}`}
      onClick={(e) => { e.stopPropagation(); onClick && onClick(name); }}
      style={{
        background: "rgba(99, 102, 241, 0.1)",
        border: "1px solid rgba(99, 102, 241, 0.2)",
        color: "#a5b4fc",
        padding: small ? "1px 6px" : "2px 8px",
        borderRadius: 4,
        fontSize: small ? 11 : 12,
        fontWeight: 500,
        cursor: "pointer",
        display: "inline-flex",
        alignItems: "center",
        gap: 4,
        transition: "all 0.2s"
      }}
    >
      <span style={{ fontSize: small ? 9 : 10, opacity: 0.7 }}>↗</span>
      {name}
    </button>
  );
}

function RulePath({ text, className = "flow-path", title }) {
  const s = String(text || "");
  if (!s) return <span className={className}>{""}</span>;
  const parts = [];
  let buf = "";
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    buf += ch;
    if (ch === "." || ch === "[") { parts.push(buf); buf = ""; }
  }
  if (buf) parts.push(buf);
  return (
    <span className={className} title={title || s}>
      {parts.map((p, i) => (
        <Fragment key={i}>
          <span className="flow-path-segment">{p}</span>
          {i < parts.length - 1 && <wbr />}
        </Fragment>
      ))}
    </span>
  );
}

function ArithExpr({ text, ruleNames, onRefClick }) {
  const s = String(text || "");
  const tokens = [];
  let i = 0;
  const isIdStart = (c) => /[a-zA-Z_]/.test(c);
  const isIdCont = (c) => /[a-zA-Z0-9_]/.test(c);
  while (i < s.length) {
    const ch = s[i];
    if (isIdStart(ch)) {
      let j = i + 1;
      while (j < s.length && isIdCont(s[j])) j++;
      const ident = s.slice(i, j);
      if (ruleNames.has(ident) && (j >= s.length || s[j] !== ".")) {
        tokens.push({ kind: "ref", text: ident });
      } else {
        tokens.push({ kind: "text", text: ident });
      }
      i = j;
    } else {
      let j = i;
      while (j < s.length && !isIdStart(s[j])) j++;
      tokens.push({ kind: "text", text: s.slice(i, j) });
      i = j;
    }
  }
  return (
    <span className="flow-cond-expr">
      {tokens.map((t, k) => t.kind === "ref"
        ? <RefChip key={k} name={t.text} onClick={onRefClick} variant="arith" />
        : <Fragment key={k}>{t.text}</Fragment>)}
    </span>
  );
}

// ─── Operator label / colour tables ─────────────────────────────────────

const OP_LABELS = {
  "==": "is", "!=": "is not", "<": "<", "<=": "≤", ">": ">", ">=": "≥",
  in: "in", contains: "contains", startswith: "starts with",
  endswith: "ends with", regex: "matches", exists: "is set",
  lower_eq: "lower( ) ==", upper_eq: "upper( ) ==",
  count_gte: "count ≥", count_lte: "count ≤",
  sum_gte: "sum ≥", sum_lte: "sum ≤",
  cidr_contains: "in CIDR",
  is_number: "is number", is_string: "is string",
  is_array: "is array", is_object: "is object",
  time_now_gte: "now ≥", time_now_lte: "now ≤",
};

const OP_CLASSES = {
  "==": "eq", "!=": "neq",
  "<": "cmp", "<=": "cmp", ">": "cmp", ">=": "cmp",
  in: "set", contains: "str", startswith: "str", endswith: "str",
  regex: "str", exists: "exists",
  lower_eq: "str", upper_eq: "str",
  count_gte: "set", count_lte: "set", sum_gte: "set", sum_lte: "set",
  cidr_contains: "set",
  is_number: "exists", is_string: "exists", is_array: "exists", is_object: "exists",
  time_now_gte: "cmp", time_now_lte: "cmp",
};

function formatLit(v) {
  if (typeof v === "string") return `"${v}"`;
  return String(v);
}
