// VisualBuilder.jsx — the no-code rule composer.
import { useEffect, useState, useRef, useMemo } from "react";
import { api } from "../lib/api.js";

const DYNAMIC_SELECTOR_SENTINEL = "__verify_dynamic_selector__";
const isDynamicTrustSelector = (s) =>
  typeof s === "string" && /^(input|data)\b/.test(s.trim());

const OPS = [
  { value: "==", label: "==" },
  { value: "!=", label: "≠" },
  { value: "<",  label: "<"  },
  { value: "<=", label: "≤"  },
  { value: ">",  label: ">"  },
  { value: ">=", label: "≥"  },
  { value: "in", label: "in array" },
  { value: "contains",   label: "contains" },
  { value: "startswith", label: "starts with" },
  { value: "endswith",   label: "ends with" },
  { value: "regex",      label: "matches regex" },
  { value: "exists",     label: "is defined" },
  // String normalization
  { value: "lower_eq", label: "lower( ) ==" },
  { value: "upper_eq", label: "upper( ) ==" },
  // Aggregate
  { value: "count_gte", label: "count ≥" },
  { value: "count_lte", label: "count ≤" },
  { value: "sum_gte",   label: "sum ≥"   },
  { value: "sum_lte",   label: "sum ≤"   },
  // Network
  { value: "cidr_contains", label: "in CIDR" },
  // Type guards
  { value: "is_number", label: "is number" },
  { value: "is_string", label: "is string" },
  { value: "is_array",  label: "is array"  },
  { value: "is_object", label: "is object" },
  // Time
  { value: "time_now_gte", label: "now ≥ field (ns)" },
  { value: "time_now_lte", label: "now ≤ field (ns)" },
];

const TYPES = [
  { value: "string",  label: "string"  },
  { value: "number",  label: "number"  },
  { value: "boolean", label: "boolean" },
  { value: "ref",     label: "ref"     },
  { value: "array",   label: "array"   },
  { value: "null",    label: "null"    },
];

const RULE_TYPES = [
  { value: "boolean", label: "boolean" },
  { value: "string",  label: "string"  },
  { value: "number",  label: "number"  },
  { value: "object",  label: "object"  },
];

const RULE_KINDS = [
  { value: "",              label: "Normal rule" },
  { value: "partial_set",   label: "Partial set" },
  { value: "result_object", label: "Result object" },
];

const FIELD_VALUE_TYPES = [
  { value: "ref",     label: "ref" },
  { value: "string",  label: "string" },
  { value: "number",  label: "number" },
  { value: "boolean", label: "boolean" },
  { value: "null",    label: "null" },
];

function newField() {
  return { key: "", value: "input.field", valueType: "ref" };
}

// Ops that have no right-hand value
const UNARY_OPS = new Set([
  "exists", "is_number", "is_string", "is_array", "is_object",
  "time_now_gte", "time_now_lte",
]);

// Ops whose right-hand type is fixed (no type selector shown)
const FORCED_RIGHT_TYPE = {
  lower_eq: "string", upper_eq: "string",
  count_gte: "number", count_lte: "number",
  sum_gte: "number", sum_lte: "number",
  cidr_contains: "string",
};

const AGGREGATE_FNS = ["count", "sum", "min", "max"];
const BUILTIN_OPTIONS = [
  { value: "time.now_ns", label: "Current time (ns)" },
  { value: "time.weekday", label: "Day of week" },
  { value: "time.date", label: "Date component" },
];
const DATE_COMPONENTS = [
  { value: 0, label: "Year" },
  { value: 1, label: "Month" },
  { value: 2, label: "Day" },
];

// Verification (crypto / JWT) function table — mirrors VERIFICATION_FUNCS in
// backend/src/services/regoCompiler.js. Categories drive UI shape:
//   bool   → no bind, no compareTo (just args)
//   tuple  → editable bind names; truthy guard handled by compiler
//   value  → toggle between compare-to-literal vs. bind-as-variable
const VERIFICATION_FUNCS = {
  "io.jwt.verify_es256": { category: "bool",  arity: 2, group: "JWT verify" },
  "io.jwt.verify_es384": { category: "bool",  arity: 2, group: "JWT verify" },
  "io.jwt.verify_es512": { category: "bool",  arity: 2, group: "JWT verify" },
  "io.jwt.verify_rs256": { category: "bool",  arity: 2, group: "JWT verify" },
  "io.jwt.verify_rs384": { category: "bool",  arity: 2, group: "JWT verify" },
  "io.jwt.verify_rs512": { category: "bool",  arity: 2, group: "JWT verify" },
  "io.jwt.verify_ps256": { category: "bool",  arity: 2, group: "JWT verify" },
  "io.jwt.verify_ps384": { category: "bool",  arity: 2, group: "JWT verify" },
  "io.jwt.verify_ps512": { category: "bool",  arity: 2, group: "JWT verify" },
  "io.jwt.verify_hs256": { category: "bool",  arity: 2, group: "JWT verify" },
  "io.jwt.verify_hs384": { category: "bool",  arity: 2, group: "JWT verify" },
  "io.jwt.verify_hs512": { category: "bool",  arity: 2, group: "JWT verify" },
  "io.jwt.decode_verify": { category: "tuple", arity: 2, returns: ["valid", "header", "payload"], group: "JWT decode" },
  "io.jwt.decode":        { category: "tuple", arity: 1, returns: ["header", "payload", "sig"],   group: "JWT decode" },
  "crypto.x509.parse_and_verify_certificates": { category: "tuple", arity: 1, returns: ["valid", "certs"], group: "X.509" },
  "crypto.x509.parse_certificates":            { category: "value", arity: 1, group: "X.509" },
  "crypto.hmac.sha256": { category: "value", arity: 2, group: "HMAC" },
  "crypto.hmac.sha384": { category: "value", arity: 2, group: "HMAC" },
  "crypto.hmac.sha512": { category: "value", arity: 2, group: "HMAC" },
  "crypto.hmac.equal":  { category: "bool",  arity: 2, group: "HMAC" },
  "crypto.sha256": { category: "value", arity: 1, group: "Hash" },
  "crypto.sha1":   { category: "value", arity: 1, group: "Hash", deprecated: true },
  "crypto.md5":    { category: "value", arity: 1, group: "Hash", deprecated: true },
};

const VERIFICATION_ARG_TYPES = ["ref", "string", "object"];
const VERIFICATION_COMPARE_OPS = ["==", "!=", "<", "<=", ">", ">="];
const VERIFICATION_GROUPS = ["JWT verify", "JWT decode", "X.509", "HMAC", "Hash"];

function newCondition() {
  return { left: "input.", op: "==", right: "", rightType: "string", negate: false };
}

function newGroup(mode = "and") {
  return { mode, conditions: [newCondition()] };
}

function newBranch() {
  return { description: "", groups: [newGroup("and")] };
}

function newRule() {
  return {
    name: "rule",
    type: "boolean",
    default: false,
    branches: [newBranch()],
  };
}

function newArithCondition() {
  return { condType: "arith", leftExpr: "input.amount", op: "<=", right: 0, rightType: "number", negate: false };
}

function newAggregateCondition() {
  return { condType: "aggregate", fn: "count", collection: "input.items", op: ">=", right: 1, rightType: "number", negate: false };
}

function newEveryCondition() {
  return { condType: "every", variable: "item", collection: "input.items", conditions: [newCondition()], negate: false };
}

function newBuiltinLeftCondition() {
  return { condType: "builtin_left", builtin: "time.now_ns", op: ">=", right: "input.unlock_ts_ns", rightType: "ref", negate: false };
}

function newRawCondition() {
  return { condType: "raw", rego: "" };
}

function newVerificationCondition() {
  return {
    condType: "verification",
    function: "io.jwt.verify_es256",
    args: [
      { value: "input.token", type: "ref" },
      { value: "data.keys.es256_pub", type: "ref" },
    ],
    negate: false,
  };
}

// High-level `verify` condType (CRY-02). Discriminated union over kind:
// jwt (default), x509, raw (HMAC-only). The compiler emits multiple body
// lines and the truthy-guard variable, so this is strictly boolean.
const VERIFY_KINDS = ["jwt", "x509", "raw"];
const VERIFY_JWT_ALGS = [
  "EdDSA",
  "ES256", "ES384", "ES512",
  "RS256", "RS384", "RS512",
  "PS256", "PS384", "PS512",
  "HS256", "HS384", "HS512",
];
const VERIFY_HMAC_ALGS = ["HS256", "HS384", "HS512"];

function newVerifyCondition() {
  return {
    condType: "verify",
    kind: "jwt",
    tokenRef: "input.token",
    alg: "ES256",
    keyRef: { source: "inline_pem", pem: "" },
    constraints: { iss: "", aud: "", exp_required: false, nbf_required: false },
  };
}

function newObjectGetCondition() {
  return {
    condType: "object_get",
    obj: "input.meta",
    key: "tier",
    keyType: "string",
    default: "free",
    defaultType: "string",
    op: "==",
    right: "premium",
    rightType: "string",
    negate: false,
  };
}

function getGroups(branch) {
  if (Array.isArray(branch.groups) && branch.groups.length) return branch.groups;
  return [{ mode: "and", conditions: branch.conditions || [] }];
}

function writeGroups(branch, groups) {
  const next = { ...branch, groups };
  delete next.conditions;
  return next;
}

const scrollToElement = (id) => {
  const element = document.getElementById(id);
  if (element) {
    element.scrollIntoView({ behavior: "smooth", block: "start" });
  }
};

function getSampleInputPaths(sampleInput) {
  const paths = [];
  function traverse(val, prefix) {
    if (val === null || val === undefined) return;
    if (typeof val === "object") {
      if (Array.isArray(val)) {
        paths.push(prefix);
        if (val.length > 0) {
          traverse(val[0], prefix + "[]");
        }
      } else {
        Object.keys(val).forEach((k) => {
          traverse(val[k], prefix + (prefix ? "." : "") + k);
        });
      }
    } else {
      paths.push(prefix);
    }
  }
  traverse(sampleInput, "input");
  return paths;
}

function PathAutocompleteInput({ value, onChange, placeholder, className, style, sampleInput }) {
  const [showDropdown, setShowDropdown] = useState(false);
  const [activeIndex, setActiveIndex] = useState(0);
  const containerRef = useRef(null);
  
  const paths = useMemo(() => {
    let parsed = null;
    if (sampleInput) {
      try {
        parsed = typeof sampleInput === "string" ? JSON.parse(sampleInput) : sampleInput;
      } catch (e) {
        console.error("Failed to parse sample input in autocomplete", e);
      }
    }
    const basePaths = parsed ? getSampleInputPaths(parsed) : [];
    const fallbacks = ["input.user.role", "input.user.groups", "input.action", "input.resource", "input.ip_address"];
    const unique = Array.from(new Set([...basePaths, ...fallbacks]));
    return unique;
  }, [sampleInput]);
  
  const filteredPaths = useMemo(() => {
    const v = (value || "").toLowerCase();
    if (!v) return [];
    return paths.filter(p => p.toLowerCase().startsWith(v) && p.toLowerCase() !== v);
  }, [paths, value]);
  
  useEffect(() => {
    const handler = (e) => {
      if (containerRef.current && !containerRef.current.contains(e.target)) {
        setShowDropdown(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);
  
  const handleKeyDown = (e) => {
    if (!filteredPaths.length || !showDropdown) return;
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActiveIndex(prev => (prev + 1) % filteredPaths.length);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActiveIndex(prev => (prev - 1 + filteredPaths.length) % filteredPaths.length);
    } else if (e.key === "Enter" || e.key === "Tab") {
      e.preventDefault();
      onChange(filteredPaths[activeIndex]);
      setShowDropdown(false);
    } else if (e.key === "Escape") {
      setShowDropdown(false);
    }
  };
  
  return (
    <div ref={containerRef} style={{ position: "relative", display: "inline-block", ...style }}>
      <input
        type="text"
        className={className}
        value={value}
        onChange={(e) => {
          onChange(e.target.value);
          setShowDropdown(true);
          setActiveIndex(0);
        }}
        onFocus={() => setShowDropdown(true)}
        onKeyDown={handleKeyDown}
        placeholder={placeholder}
        spellCheck="false"
      />
      {showDropdown && filteredPaths.length > 0 && (
        <ul className="autocomplete-dropdown" style={{
          position: "absolute",
          top: "100%",
          left: 0,
          right: 0,
          zIndex: 1000,
          background: "var(--surface-3, #1e1e24)",
          border: "1px solid var(--border-strong, rgba(255, 255, 255, 0.15))",
          boxShadow: "0 4px 12px rgba(0,0,0,0.5)",
          borderRadius: "4px",
          listStyle: "none",
          margin: "4px 0 0 0",
          padding: "4px 0",
          maxHeight: "150px",
          overflowY: "auto"
        }}>
          {filteredPaths.map((p, idx) => (
            <li
              key={p}
              onClick={() => {
                onChange(p);
                setShowDropdown(false);
              }}
              style={{
                padding: "6px 10px",
                fontSize: "11px",
                fontFamily: "var(--font-mono, monospace)",
                color: idx === activeIndex ? "var(--accent, #34d399)" : "var(--text, #f8fafc)",
                background: idx === activeIndex ? "rgba(52, 211, 153, 0.1)" : "transparent",
                cursor: "pointer"
              }}
              onMouseEnter={() => setActiveIndex(idx)}
            >
              {p}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

const parseValidationMessages = (errors, warnings) => {
  const result = {
    rules: {},      // { [ruleIndex]: { errors: [], warnings: [] } }
    fields: {},     // { `${ruleIndex}-${fieldIndex}`: { errors: [], warnings: [] } }
    conditions: {}, // { `${ruleIndex}-${branchIndex}-${groupIndex}-${condIndex}`: { errors: [], warnings: [] } }
  };

  const processMessage = (msg, isError) => {
    const condMatch = msg.match(/^Rule (\d+) branch (\d+) group (\d+) cond (\d+):\s*(.*)$/);
    if (condMatch) {
      const [_, ri, bi, gi, ci, text] = condMatch;
      const key = `${ri}-${bi}-${gi}-${ci}`;
      if (!result.conditions[key]) result.conditions[key] = { errors: [], warnings: [] };
      if (isError) result.conditions[key].errors.push(text);
      else result.conditions[key].warnings.push(text);
      return;
    }

    const branchMatch = msg.match(/^Rule (\d+) branch (\d+):\s*(.*)$/);
    if (branchMatch) {
      const [_, ri, bi, text] = branchMatch;
      if (!result.rules[ri]) result.rules[ri] = { errors: [], warnings: [] };
      if (isError) result.rules[ri].errors.push(`Branch ${Number(bi)+1}: ${text}`);
      else result.rules[ri].warnings.push(`Branch ${Number(bi)+1}: ${text}`);
      return;
    }

    const fieldMatch = msg.match(/^Rule (\d+) field (\d+):\s*(.*)$/);
    if (fieldMatch) {
      const [_, ri, fi, text] = fieldMatch;
      const key = `${ri}-${fi}`;
      if (!result.fields[key]) result.fields[key] = { errors: [], warnings: [] };
      if (isError) result.fields[key].errors.push(text);
      else result.fields[key].warnings.push(text);
      return;
    }

    const ruleMatch = msg.match(/^Rule (\d+):\s*(.*)$/);
    if (ruleMatch) {
      const [_, ri, text] = ruleMatch;
      if (!result.rules[ri]) result.rules[ri] = { errors: [], warnings: [] };
      if (isError) result.rules[ri].errors.push(text);
      else result.rules[ri].warnings.push(text);
      return;
    }

    if (!result.global) result.global = { errors: [], warnings: [] };
    if (isError) result.global.errors.push(msg);
    else result.global.warnings.push(msg);
  };

  if (Array.isArray(errors)) errors.forEach(e => processMessage(e, true));
  if (Array.isArray(warnings)) warnings.forEach(w => processMessage(w, false));

  return result;
};

export default function VisualBuilder({ policy, onChange }) {
  const [expandedRuleIndices, setExpandedRuleIndices] = useState({});
  const [validationMap, setValidationMap] = useState({ rules: {}, fields: {}, conditions: {} });
  const [outlineOpen, setOutlineOpen] = useState(true);

  useEffect(() => {
    const timer = setTimeout(async () => {
      try {
        const res = await api.validate(policy);
        const parsed = parseValidationMessages(res.errors, res.warnings);
        setValidationMap(parsed);
      } catch (err) {
        console.error("Validation loop failed:", err);
      }
    }, 400);

    return () => clearTimeout(timer);
  }, [policy]);

  const updateRules = (rules) => onChange({ ...policy, rules });

  const updateRule = (i, patch) => {
    const rules = policy.rules.map((r, idx) => (idx === i ? { ...r, ...patch } : r));
    updateRules(rules);
  };

  const addRule = () => {
    const nextRules = [...policy.rules, newRule()];
    const newIndex = nextRules.length - 1;
    setExpandedRuleIndices(prev => ({ ...prev, [newIndex]: true }));
    updateRules(nextRules);
  };

  const removeRule = (i) => {
    const nextRules = policy.rules.filter((_, idx) => idx !== i);
    setExpandedRuleIndices(prev => {
      const nextExpanded = {};
      Object.keys(prev).forEach(k => {
        const idx = parseInt(k, 10);
        if (idx < i) {
          nextExpanded[idx] = prev[idx];
        } else if (idx > i) {
          nextExpanded[idx - 1] = prev[idx];
        }
      });
      return nextExpanded;
    });
    updateRules(nextRules);
  };

  const cloneRule = (i) => {
    const targetRule = policy.rules[i];
    if (!targetRule) return;
    const clonedRule = JSON.parse(JSON.stringify(targetRule));
    clonedRule.name = `${clonedRule.name}_copy`;
    const nextRules = [...policy.rules];
    nextRules.splice(i + 1, 0, clonedRule);
    
    setExpandedRuleIndices(prev => {
      const nextExpanded = {};
      Object.keys(prev).forEach(k => {
        const idx = parseInt(k, 10);
        if (idx <= i) {
          nextExpanded[idx] = prev[idx];
        } else {
          nextExpanded[idx + 1] = prev[idx];
        }
      });
      nextExpanded[i + 1] = true;
      return nextExpanded;
    });
    updateRules(nextRules);
  };

  const moveRule = (index, direction) => {
    const nextIndex = index + direction;
    if (nextIndex < 0 || nextIndex >= policy.rules.length) return;
    const newRules = [...policy.rules];
    const temp = newRules[index];
    newRules[index] = newRules[nextIndex];
    newRules[nextIndex] = temp;
    
    setExpandedRuleIndices(prev => {
      const nextExpanded = { ...prev };
      const currentVal = prev[index];
      const targetVal = prev[nextIndex];
      if (currentVal !== undefined) {
        nextExpanded[nextIndex] = currentVal;
      } else {
        delete nextExpanded[nextIndex];
      }
      if (targetVal !== undefined) {
        nextExpanded[index] = targetVal;
      } else {
        delete nextExpanded[index];
      }
      return nextExpanded;
    });

    updateRules(newRules);
  };

  const expandAll = () => {
    const next = {};
    policy.rules.forEach((_, idx) => {
      next[idx] = true;
    });
    setExpandedRuleIndices(next);
  };

  const collapseAll = () => {
    setExpandedRuleIndices({});
  };

  return (
    <div className="builder" style={{ position: "relative" }}>
      <div className="builder-toolbar" style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        marginBottom: "2px",
        gap: "12px",
        flexWrap: "wrap",
        rowGap: "8px",
      }}>
        <div className="builder-help" style={{ margin: 0, flex: 1 }}>
          Branches are <code>OR'd</code> at the rule level. Inside a branch, groups are <code>AND'd</code>; each group is either <code>ALL OF</code> (AND) or <code>ANY OF</code> (OR) of its conditions. Use <strong>Advanced</strong> to add arithmetic, aggregate, time, or universal-quantifier conditions.
        </div>
        <div className="builder-controls" style={{
          display: "flex",
          gap: "8px",
          padding: "6px 12px",
          background: "var(--surface-2, rgba(20, 20, 25, 0.7))",
          backdropFilter: "blur(12px)",
          border: "1px solid var(--border-strong, rgba(255, 255, 255, 0.08))",
          borderRadius: "var(--radius-lg, 8px)",
          boxShadow: "0 0 15px rgba(52, 211, 153, 0.1), inset 0 1px 1px rgba(255, 255, 255, 0.05)",
          flexShrink: 0,
        }}>
          <button 
            type="button" 
            className="btn btn-ghost btn-sm" 
            onClick={expandAll}
            style={{
              fontSize: "11px",
              fontFamily: "var(--font-mono, monospace)",
              display: "flex",
              alignItems: "center",
              gap: "6px",
              color: "var(--accent, #34d399)",
              textShadow: "0 0 8px rgba(52, 211, 153, 0.3)",
              fontWeight: 600,
            }}
          >
            Expand All
          </button>
          <div style={{ width: "1px", background: "var(--border, rgba(255, 255, 255, 0.1))", alignSelf: "stretch" }} />
          <button 
            type="button" 
            className="btn btn-ghost btn-sm" 
            onClick={collapseAll}
            style={{
              fontSize: "11px",
              fontFamily: "var(--font-mono, monospace)",
              display: "flex",
              alignItems: "center",
              gap: "6px",
              color: "var(--text, #f8fafc)",
              fontWeight: 600,
            }}
          >
            Collapse All
          </button>
        </div>
      </div>

      <div className="builder-layout" style={{ display: "flex", gap: "16px", marginTop: "12px", alignItems: "flex-start" }}>
        {outlineOpen && (
          <aside className="builder-outline" style={{
            width: "220px",
            flexShrink: 0,
            background: "var(--surface-2, rgba(20, 20, 25, 0.7))",
            backdropFilter: "blur(12px)",
            border: "1px solid var(--border-strong, rgba(255, 255, 255, 0.08))",
            padding: "16px",
            borderRadius: "var(--radius-lg, 8px)",
            display: "flex",
            flexDirection: "column",
            gap: "12px",
            position: "sticky",
            top: "16px",
            maxHeight: "calc(100vh - 180px)",
            overflowY: "auto",
            boxShadow: "0 4px 20px rgba(0, 0, 0, 0.15)",
          }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderBottom: "1px solid var(--border, rgba(255, 255, 255, 0.05))", paddingBottom: "8px" }}>
              <span style={{ fontSize: "10px", textTransform: "uppercase", letterSpacing: "0.05em", color: "var(--text-dim)", fontWeight: 700 }}>Outline</span>
              <button
                type="button"
                className="btn btn-ghost btn-xs"
                onClick={() => setOutlineOpen(false)}
                style={{ fontSize: "10px", padding: "2px 6px", textTransform: "lowercase" }}
              >
                hide
              </button>
            </div>
            <nav style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
              {policy.rules.map((r, rIdx) => (
                <div key={rIdx} style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
                  <button
                    type="button"
                    onClick={() => {
                      setExpandedRuleIndices(prev => ({ ...prev, [rIdx]: true }));
                      setTimeout(() => scrollToElement(`rule-card-${rIdx}`), 50);
                    }}
                    style={{
                      background: "none",
                      border: "none",
                      textAlign: "left",
                      padding: "4px 6px",
                      fontSize: "12px",
                      color: "var(--accent, #34d399)",
                      cursor: "pointer",
                      borderRadius: "4px",
                      fontWeight: 600,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap"
                    }}
                    className="outline-rule-link"
                  >
                    {r.name || `rule_${rIdx + 1}`}
                  </button>
                  {r.branches && r.branches.map((b, bIdx) => (
                    <button
                      key={bIdx}
                      type="button"
                      onClick={() => {
                        setExpandedRuleIndices(prev => ({ ...prev, [rIdx]: true }));
                        setTimeout(() => scrollToElement(`rule-${rIdx}-branch-${bIdx}`), 50);
                      }}
                      style={{
                        background: "none",
                        border: "none",
                        textAlign: "left",
                        padding: "2px 6px 2px 16px",
                        fontSize: "11px",
                        color: "var(--text-dim)",
                        cursor: "pointer",
                        borderRadius: "4px",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                        opacity: 0.8
                      }}
                      className="outline-branch-link"
                    >
                      {b.description ? `branch: ${b.description}` : `branch ${bIdx + 1}`}
                    </button>
                  ))}
                </div>
              ))}
            </nav>
          </aside>
        )}

        <div className="builder-canvas" style={{ flex: 1, display: "flex", flexDirection: "column", gap: "16px", width: "100%", overflowX: "hidden" }}>
          {!outlineOpen && (
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              onClick={() => setOutlineOpen(true)}
              style={{
                alignSelf: "flex-start",
                fontSize: "11px",
                fontFamily: "var(--font-mono, monospace)",
                textTransform: "lowercase",
                border: "1px solid var(--border, rgba(255, 255, 255, 0.08))",
                padding: "4px 10px",
                borderRadius: "4px"
              }}
            >
              show outline
            </button>
          )}

          {policy.rules.map((rule, i) => (
            <div key={i} id={`rule-card-${i}`}>
              <RuleCard
                index={i}
                rule={rule}
                isExpanded={!!expandedRuleIndices[i]}
                onToggleExpand={() => setExpandedRuleIndices(prev => ({ ...prev, [i]: !prev[i] }))}
                onChange={(patch) => updateRule(i, patch)}
                onRemove={policy.rules.length > 1 ? () => removeRule(i) : null}
                onMoveUp={i > 0 ? () => moveRule(i, -1) : null}
                onMoveDown={i < policy.rules.length - 1 ? () => moveRule(i, 1) : null}
                onClone={() => cloneRule(i)}
                validation={validationMap.rules[i]}
                validationMap={validationMap}
                policy={policy}
              />
            </div>
          ))}

          <button className="add-rule" onClick={addRule}>
            + Add another rule
          </button>
        </div>
      </div>
    </div>
  );
}

function RuleCard({ rule, index, isExpanded, onToggleExpand, onChange, onRemove, onMoveUp, onMoveDown, onClone, validation, validationMap, policy }) {
  const kind = rule.kind || "";
  const isResultObject = kind === "result_object";
  const isPartialSet = kind === "partial_set";

  const updateBranches = (branches) => onChange({ branches });
  const updateBranch = (i, patch) => {
    updateBranches((rule.branches || []).map((b, idx) => (idx === i ? { ...b, ...patch } : b)));
  };
  const addBranch = () => updateBranches([...(rule.branches || []), newBranch()]);
  const removeBranch = (i) =>
    updateBranches((rule.branches || []).filter((_, idx) => idx !== i));

  const cloneBranch = (i) => {
    const targetBranch = rule.branches[i];
    if (!targetBranch) return;
    const clonedBranch = JSON.parse(JSON.stringify(targetBranch));
    if (clonedBranch.description) {
      clonedBranch.description = `${clonedBranch.description} (Copy)`;
    }
    const nextBranches = [...rule.branches];
    nextBranches.splice(i + 1, 0, clonedBranch);
    updateBranches(nextBranches);
  };

  const setDefault = (val) => {
    let parsed = val;
    if (rule.type === "boolean") parsed = val === "true";
    else if (rule.type === "number") parsed = Number(val);
    onChange({ default: parsed });
  };

  const setKind = (newKind) => {
    const patch = { kind: newKind || undefined };
    if (newKind === "result_object") {
      if (!Array.isArray(rule.fields)) patch.fields = [];
    } else if (newKind === "partial_set") {
      if (!Array.isArray(rule.branches) || rule.branches.length === 0) {
        patch.branches = [newBranch()];
      }
    }
    onChange(patch);
  };

  const moveBranch = (idx, direction) => {
    const nextIdx = idx + direction;
    if (nextIdx < 0 || nextIdx >= rule.branches.length) return;
    const newBranches = [...rule.branches];
    const temp = newBranches[idx];
    newBranches[idx] = newBranches[nextIdx];
    newBranches[nextIdx] = temp;
    updateBranches(newBranches);
  };

  const renderValidationChips = () => {
    if (!validation) return null;
    const { errors, warnings } = validation;
    return (
      <div className="rule-validation-chips" style={{ display: "flex", gap: "6px", marginLeft: "12px", alignItems: "center" }}>
        {errors && errors.length > 0 && (
          <span className="validation-chip chip-error" title={errors.join("\n")} style={{
            background: "rgba(239, 68, 68, 0.15)",
            color: "#ef4444",
            border: "1px solid rgba(239, 68, 68, 0.3)",
            boxShadow: "0 0 10px rgba(239, 68, 68, 0.2)",
            padding: "2px 6px",
            borderRadius: "4px",
            fontSize: "11px",
            fontFamily: "var(--font-mono)",
            fontWeight: 600,
            cursor: "help",
            display: "flex",
            alignItems: "center",
            gap: "4px"
          }}>
            ❌ {errors.length} {errors.length === 1 ? "Error" : "Errors"}
          </span>
        )}
        {warnings && warnings.length > 0 && (
          <span className="validation-chip chip-warning" title={warnings.join("\n")} style={{
            background: "rgba(245, 158, 11, 0.15)",
            color: "#f59e0b",
            border: "1px solid rgba(245, 158, 11, 0.3)",
            boxShadow: "0 0 10px rgba(245, 158, 11, 0.2)",
            padding: "2px 6px",
            borderRadius: "4px",
            fontSize: "11px",
            fontFamily: "var(--font-mono)",
            fontWeight: 600,
            cursor: "help",
            display: "flex",
            alignItems: "center",
            gap: "4px"
          }}>
            ⚠️ {warnings.length} {warnings.length === 1 ? "Warning" : "Warnings"}
          </span>
        )}
      </div>
    );
  };

  return (
    <div className={`rule-card ${!isExpanded ? "is-collapsed" : ""}`}>
      <div className="rule-head">
        <button
          className="btn btn-ghost btn-sm rule-collapse-toggle"
          onClick={onToggleExpand}
          title={isExpanded ? "Collapse rule" : "Expand rule"}
          style={{ padding: "4px", fontSize: "10px", minWidth: "24px" }}
        >
          {isExpanded ? "▼" : "▶"}
        </button>

        <div className="rule-order-controls" style={{ display: "flex", gap: "6px", marginRight: "8px" }}>
          <button
            type="button"
            className="btn btn-ghost btn-xs"
            onClick={onMoveUp}
            disabled={!onMoveUp}
            title="Move Rule Up"
            style={{ 
              padding: "2px 6px", 
              fontSize: "10px", 
              opacity: onMoveUp ? 1 : 0.25, 
              cursor: onMoveUp ? "pointer" : "not-allowed",
              color: "var(--accent)",
              fontFamily: "var(--font-mono)",
            }}
          >
            Up
          </button>
          <button
            type="button"
            className="btn btn-ghost btn-xs"
            onClick={onMoveDown}
            disabled={!onMoveDown}
            title="Move Rule Down"
            style={{ 
              padding: "2px 6px", 
              fontSize: "10px", 
              opacity: onMoveDown ? 1 : 0.25, 
              cursor: onMoveDown ? "pointer" : "not-allowed",
              color: "var(--accent)",
              fontFamily: "var(--font-mono)",
            }}
          >
            Down
          </button>
        </div>

        <input
          type="text"
          className="rule-name-input"
          value={rule.name}
          onChange={(e) => onChange({ name: e.target.value.replace(/[^a-zA-Z0-9_]/g, "") })}
          placeholder="rule_name"
        />
        <select
          className="rule-kind-select"
          value={kind}
          onChange={(e) => setKind(e.target.value)}
          title="Rule kind"
        >
          {RULE_KINDS.map((k) => (
            <option key={k.value || "normal"} value={k.value}>{k.label}</option>
          ))}
        </select>
        {!isResultObject && !isPartialSet && (
          <select
            className="rule-type-select"
            value={rule.type || "boolean"}
            onChange={(e) => onChange({ type: e.target.value })}
          >
            {RULE_TYPES.map((t) => (
              <option key={t.value} value={t.value}>
                {t.label}
              </option>
            ))}
          </select>
        )}
        {!isResultObject && !isPartialSet && (
          <div className="rule-default">
            <span>default</span>
            {rule.type === "boolean" || !rule.type ? (
              <select
                className="rule-default-input"
                value={String(rule.default ?? false)}
                onChange={(e) => setDefault(e.target.value)}
              >
                <option value="false">false</option>
                <option value="true">true</option>
              </select>
            ) : (
              <input
                type="text"
                className="rule-default-input"
                value={String(rule.default ?? "")}
                onChange={(e) => setDefault(e.target.value)}
              />
            )}
          </div>
        )}
        
        {renderValidationChips()}

        <div className="rule-actions" style={{ marginLeft: "auto", display: "flex", gap: "8px" }}>
          <button className="btn btn-ghost btn-sm" onClick={onClone}>
            Clone
          </button>
          {onRemove && (
            <button className="btn btn-ghost btn-sm btn-danger" onClick={onRemove}>
              Remove
            </button>
          )}
        </div>
      </div>

      {isExpanded && (
        isResultObject ? (
          <ResultObjectFields rule={rule} onChange={onChange} ruleIndex={index} validationMap={validationMap} />
        ) : (
          <div className="rule-body">
            <div className="branches">
              {(rule.branches || []).map((branch, i) => (
                <div key={i} id={`rule-${index}-branch-${i}`}>
                  <Branch
                    branch={branch}
                    onChange={(patch) => updateBranch(i, patch)}
                    onRemove={rule.branches.length > 1 ? () => removeBranch(i) : null}
                    index={i}
                    ruleIndex={index}
                    validationMap={validationMap}
                    onMoveUp={i > 0 ? () => moveBranch(i, -1) : null}
                    onMoveDown={i < rule.branches.length - 1 ? () => moveBranch(i, 1) : null}
                    onClone={() => cloneBranch(i)}
                    policy={policy}
                  />
                  {i < rule.branches.length - 1 && (
                    <div className="or-divider">
                      <div className="or-divider-line" />
                      <div className="or-divider-text">— <strong>OR</strong> —</div>
                      <div className="or-divider-line" />
                    </div>
                  )}
                </div>
              ))}
            </div>

            <button className="add-branch" onClick={addBranch} style={{ marginTop: 14 }}>
              + Add OR branch
            </button>
          </div>
        )
      )}
    </div>
  );
}

function ResultObjectFields({ rule, onChange, ruleIndex, validationMap }) {
  const fields = Array.isArray(rule.fields) ? rule.fields : [];
  const updateFields = (next) => onChange({ fields: next });
  const updateField = (i, patch) =>
    updateFields(fields.map((f, idx) => (idx === i ? { ...f, ...patch } : f)));
  const addField = () => updateFields([...fields, newField()]);
  const removeField = (i) => updateFields(fields.filter((_, idx) => idx !== i));

  const setValueType = (i, newType) => {
    const patch = { valueType: newType };
    if (newType === "boolean") patch.value = false;
    else if (newType === "number") patch.value = 0;
    else if (newType === "null") patch.value = null;
    else if (newType === "ref") patch.value = "input.field";
    else patch.value = "";
    updateField(i, patch);
  };

  return (
    <div className="rule-body">
      <div className="result-fields-help">
        Decision document — emits <code>{rule.name || "rule"} := {"{ ... }"}</code> as an unconditional
        Rego object. Use <strong>ref</strong> values to embed other rules (<code>allow</code>,
        <code> violations</code>) or input paths (<code>input.request.id</code>).
      </div>
      <div className="result-fields">
        {fields.length === 0 && (
          <div className="result-fields-empty">No fields yet — add one below.</div>
        )}
        {fields.map((f, i) => {
          const key = `${ruleIndex}-${i}`;
          const val = validationMap && validationMap.fields && validationMap.fields[key];
          return (
            <div key={i} className="result-field-row-container" style={{ display: "flex", flexDirection: "column", gap: "4px", marginBottom: "8px" }}>
              <div className="result-field-row" style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                <input
                  type="text"
                  className="result-field-key"
                  value={f.key || ""}
                  onChange={(e) =>
                    updateField(i, { key: e.target.value.replace(/[^a-zA-Z0-9_]/g, "") })
                  }
                  placeholder="key"
                  spellCheck="false"
                  title='JSON key (Rego-safe identifier)'
                />
                <span className="result-field-colon">:</span>
                <select
                  className="result-field-type"
                  value={f.valueType || "ref"}
                  onChange={(e) => setValueType(i, e.target.value)}
                  title="Value type"
                >
                  {FIELD_VALUE_TYPES.map((t) => (
                    <option key={t.value} value={t.value}>{t.label}</option>
                  ))}
                </select>
                <ResultFieldValueInput field={f} onChange={(patch) => updateField(i, patch)} />
                <button
                  className="cond-remove"
                  onClick={() => removeField(i)}
                  title="Remove field"
                >
                  ×
                </button>
              </div>
              {val && val.errors && val.errors.map((e, idx) => (
                <div key={`err-${idx}`} className="field-validation-err" style={{
                  color: "#ef4444",
                  fontSize: "11px",
                  fontFamily: "var(--font-mono)",
                  background: "rgba(239, 68, 68, 0.08)",
                  border: "1px solid rgba(239, 68, 68, 0.2)",
                  padding: "4px 8px",
                  borderRadius: "4px",
                  display: "flex",
                  alignItems: "center",
                  gap: "6px",
                  alignSelf: "flex-start",
                  boxShadow: "0 0 10px rgba(239, 68, 68, 0.1)"
                }}>
                  ❌ {e}
                </div>
              ))}
              {val && val.warnings && val.warnings.map((w, idx) => (
                <div key={`warn-${idx}`} className="field-validation-warn" style={{
                  color: "#f59e0b",
                  fontSize: "11px",
                  fontFamily: "var(--font-mono)",
                  background: "rgba(245, 158, 11, 0.08)",
                  border: "1px solid rgba(245, 158, 11, 0.2)",
                  padding: "4px 8px",
                  borderRadius: "4px",
                  display: "flex",
                  alignItems: "center",
                  gap: "6px",
                  alignSelf: "flex-start",
                  boxShadow: "0 0 10px rgba(245, 158, 11, 0.1)"
                }}>
                  ⚠️ {w}
                </div>
              ))}
            </div>
          );
        })}
      </div>
      <button className="add-cond" onClick={addField} style={{ marginTop: 8 }}>
        + Add field
      </button>
    </div>
  );
}

function ResultFieldValueInput({ field, onChange }) {
  const type = field.valueType || "ref";
  if (type === "boolean") {
    return (
      <select
        className="result-field-value"
        value={String(field.value ?? false)}
        onChange={(e) => onChange({ value: e.target.value === "true" })}
      >
        <option value="true">true</option>
        <option value="false">false</option>
      </select>
    );
  }
  if (type === "null") {
    return <input type="text" className="result-field-value" value="null" disabled />;
  }
  if (type === "number") {
    return (
      <input
        type="number"
        className="result-field-value value-num"
        value={field.value ?? 0}
        onChange={(e) =>
          onChange({ value: e.target.value === "" ? 0 : Number(e.target.value) })
        }
      />
    );
  }
  if (type === "ref") {
    return (
      <input
        type="text"
        className="result-field-value path"
        value={field.value || ""}
        onChange={(e) => onChange({ value: e.target.value })}
        placeholder="allow  or  input.request.id"
        spellCheck="false"
        title="Rego reference: another rule name in this policy (allow, violations, …) or an input/data path"
      />
    );
  }
  return (
    <input
      type="text"
      className="result-field-value value"
      value={field.value ?? ""}
      onChange={(e) => onChange({ value: e.target.value })}
      placeholder="value"
    />
  );
}

function Branch({ branch, onChange, onRemove, index, ruleIndex, validationMap, onMoveUp, onMoveDown, onClone, policy }) {
  const [isCollapsed, setIsCollapsed] = useState(true);
  const groups = getGroups(branch);

  const replaceGroups = (next) => onChange(writeGroups(branch, next));
  const updateGroup = (i, patch) =>
    replaceGroups(groups.map((g, idx) => (idx === i ? { ...g, ...patch } : g)));
  const addGroup = (mode) => replaceGroups([...groups, newGroup(mode)]);
  const removeGroup = (i) => replaceGroups(groups.filter((_, idx) => idx !== i));

  const cloneGroup = (groupIndex) => {
    const targetGroup = groups[groupIndex];
    if (!targetGroup) return;
    const clonedGroup = JSON.parse(JSON.stringify(targetGroup));
    const nextGroups = [...groups];
    nextGroups.splice(groupIndex + 1, 0, clonedGroup);
    replaceGroups(nextGroups);
  };

  return (
    <div className={`branch ${isCollapsed ? "is-collapsed" : ""}`}>
      <div className="branch-head">
        <button
          className="btn btn-ghost btn-sm branch-collapse-toggle"
          onClick={() => setIsCollapsed(!isCollapsed)}
          title={isCollapsed ? "Expand branch" : "Collapse branch"}
          style={{ padding: "2px", fontSize: "10px", minWidth: "20px", color: "var(--text-dim)" }}
        >
          {isCollapsed ? "▶" : "▼"}
        </button>

        <div className="branch-order-controls" style={{ display: "flex", gap: "6px", marginRight: "8px" }}>
          <button
            type="button"
            className="btn btn-ghost btn-xs"
            onClick={onMoveUp}
            disabled={!onMoveUp}
            title="Move Branch Up"
            style={{ 
              padding: "2px 6px", 
              fontSize: "10px", 
              opacity: onMoveUp ? 1 : 0.25, 
              cursor: onMoveUp ? "pointer" : "not-allowed",
              color: "var(--accent)",
              fontFamily: "var(--font-mono)",
            }}
          >
            Up
          </button>
          <button
            type="button"
            className="btn btn-ghost btn-xs"
            onClick={onMoveDown}
            disabled={!onMoveDown}
            title="Move Branch Down"
            style={{ 
              padding: "2px 6px", 
              fontSize: "10px", 
              opacity: onMoveDown ? 1 : 0.25, 
              cursor: onMoveDown ? "pointer" : "not-allowed",
              color: "var(--accent)",
              fontFamily: "var(--font-mono)",
            }}
          >
            Down
          </button>
        </div>

        <div className="branch-num">
          BRANCH <span>{String(index + 1).padStart(2, "0")}</span>
        </div>
        <input
          type="text"
          className="branch-desc-input"
          value={branch.description || ""}
          onChange={(e) => onChange({ description: e.target.value })}
          placeholder="Describe this branch (becomes a code comment)"
        />
        <div style={{ marginLeft: "auto", display: "flex", gap: "8px" }}>
          <button className="btn btn-ghost btn-sm" onClick={onClone}>
            Clone
          </button>
          {onRemove && (
            <button className="btn btn-ghost btn-sm btn-danger" onClick={onRemove}>
              Remove
            </button>
          )}
        </div>
      </div>
      {!isCollapsed && (
        <div className="branch-body">
          <div className="groups">
            {groups.map((group, i) => (
              <div key={i}>
                <Group
                  group={group}
                  onChange={(patch) => updateGroup(i, patch)}
                  onRemove={groups.length > 1 ? () => removeGroup(i) : null}
                  isOnly={groups.length === 1}
                  ruleIndex={ruleIndex}
                  branchIndex={index}
                  groupIndex={i}
                  validationMap={validationMap}
                  onClone={() => cloneGroup(i)}
                  policy={policy}
                />
                {i < groups.length - 1 && (
                  <div className="and-divider">
                    <div className="and-divider-line" />
                    <div className="and-divider-text">— <strong>AND</strong> —</div>
                    <div className="and-divider-line" />
                  </div>
                )}
              </div>
            ))}
          </div>
          <button
            className="add-group"
            onClick={() => addGroup("or")}
            title="Add another condition group ANDed with the existing ones"
          >
            + Add AND group
          </button>
        </div>
      )}
    </div>
  );
}

function Group({ group, onChange, onRemove, isOnly, ruleIndex, branchIndex, groupIndex, validationMap, onClone, policy }) {
  const conditions = group.conditions || [];
  const updateConditions = (next) => onChange({ conditions: next });
  const updateCondition = (i, patch) =>
    updateConditions(conditions.map((c, idx) => (idx === i ? { ...c, ...patch } : c)));
  const addCondition = () => updateConditions([...conditions, newCondition()]);
  const removeCondition = (i) =>
    updateConditions(conditions.filter((_, idx) => idx !== i));

  const addAdvanced = (type) => {
    const factories = {
      arith: newArithCondition,
      aggregate: newAggregateCondition,
      every: newEveryCondition,
      builtin_left: newBuiltinLeftCondition,
      object_get: newObjectGetCondition,
      raw: newRawCondition,
      verification: newVerificationCondition,
      verify: newVerifyCondition,
    };
    const factory = factories[type];
    if (factory) updateConditions([...conditions, factory()]);
  };

  const setMode = (mode) => onChange({ mode });

  return (
    <div className={`group group-${group.mode}`}>
      <div className="group-head">
        <div className="group-mode-toggle" role="group">
          <button
            type="button"
            className={`group-mode-btn ${group.mode === "and" ? "active" : ""}`}
            onClick={() => setMode("and")}
            title="All conditions must hold"
          >
            ALL OF (AND)
          </button>
          <button
            type="button"
            className={`group-mode-btn ${group.mode === "or" ? "active" : ""}`}
            onClick={() => setMode("or")}
            title="At least one condition must hold"
          >
            ANY OF (OR)
          </button>
        </div>
        <div style={{ marginLeft: "auto", display: "flex", gap: "8px" }}>
          <button
            type="button"
            className="btn btn-ghost btn-sm group-clone"
            onClick={onClone}
          >
            Clone
          </button>
          {!isOnly && onRemove && (
            <button
              className="btn btn-ghost btn-sm btn-danger group-remove"
              onClick={onRemove}
              title="Remove this group"
            >
              Remove
            </button>
          )}
        </div>
      </div>
      <div className="conditions">
        {conditions.length === 0 && (
          <div style={{
            padding: "10px 0",
            color: "var(--text-dim)",
            fontFamily: "var(--font-mono)",
            fontSize: 11,
          }}>
            No conditions — group always matches.
          </div>
        )}
        {conditions.map((cond, i) => (
          <Condition
            key={i}
            cond={cond}
            onChange={(patch) => updateCondition(i, patch)}
            onRemove={() => removeCondition(i)}
            ruleIndex={ruleIndex}
            branchIndex={branchIndex}
            groupIndex={groupIndex}
            condIndex={i}
            validationMap={validationMap}
            policy={policy}
          />
        ))}
      </div>
      <div className="cond-add-row">
        <button className="add-cond" onClick={addCondition}>
          + {group.mode === "and" ? "AND" : "OR"} condition
        </button>
        <select
          className="add-cond-advanced"
          value=""
          onChange={(e) => { if (e.target.value) addAdvanced(e.target.value); }}
          title="Add an advanced condition type"
        >
          <option value="">⊕ Advanced…</option>
          <option value="arith">Arithmetic expression</option>
          <option value="aggregate">Aggregate (count / sum / min / max)</option>
          <option value="every">For every… (universal quantifier)</option>
          <option value="builtin_left">Builtin function (time…)</option>
          <option value="object_get">object.get(safe key access)</option>
          <option value="verify">Verify signature (JWT / X.509 / HMAC)…</option>
          <option value="verification">Crypto / JWT verify (low-level)…</option>
          <option value="raw">Raw Rego (escape hatch)</option>
        </select>
      </div>
    </div>
  );
}

// ─── Condition dispatcher ──────────────────────────────────────────────────

function Condition({ cond, onChange, onRemove, ruleIndex, branchIndex, groupIndex, condIndex, validationMap, policy }) {
  let inner = null;
  const props = { cond, onChange, onRemove, policy };
  switch (cond.condType) {
    case "arith":        inner = <CondArith {...props} />; break;
    case "aggregate":    inner = <CondAggregate {...props} />; break;
    case "every":        inner = <CondEvery {...props} />; break;
    case "builtin_left": inner = <CondBuiltinLeft {...props} />; break;
    case "object_get":   inner = <CondObjectGet {...props} />; break;
    case "raw":          inner = <CondRaw {...props} />; break;
    case "verification": inner = <CondVerification {...props} />; break;
    case "verify":       inner = <CondVerify {...props} />; break;
    default:             inner = <CondStandard {...props} />; break;
  }

  const key = `${ruleIndex}-${branchIndex}-${groupIndex}-${condIndex}`;
  const val = validationMap && validationMap.conditions && validationMap.conditions[key];

  if (!val) return inner;

  const { errors, warnings } = val;
  return (
    <div className="condition-wrapper-with-validation" style={{ display: "flex", flexDirection: "column", gap: "4px", width: "100%" }}>
      {inner}
      {errors && errors.map((err, idx) => (
        <div key={`err-${idx}`} className="cond-validation-err" style={{
          color: "#ef4444",
          fontSize: "11px",
          fontFamily: "var(--font-mono)",
          background: "rgba(239, 68, 68, 0.08)",
          border: "1px solid rgba(239, 68, 68, 0.2)",
          padding: "4px 8px",
          borderRadius: "4px",
          marginLeft: "24px",
          display: "flex",
          alignItems: "center",
          gap: "6px",
          alignSelf: "flex-start",
          boxShadow: "0 0 10px rgba(239, 68, 68, 0.1)"
        }}>
          ❌ {err}
        </div>
      ))}
      {warnings && warnings.map((warn, idx) => (
        <div key={`warn-${idx}`} className="cond-validation-warn" style={{
          color: "#f59e0b",
          fontSize: "11px",
          fontFamily: "var(--font-mono)",
          background: "rgba(245, 158, 11, 0.08)",
          border: "1px solid rgba(245, 158, 11, 0.2)",
          padding: "4px 8px",
          borderRadius: "4px",
          marginLeft: "24px",
          display: "flex",
          alignItems: "center",
          gap: "6px",
          alignSelf: "flex-start",
          boxShadow: "0 0 10px rgba(245, 158, 11, 0.1)"
        }}>
          ⚠️ {warn}
        </div>
      ))}
    </div>
  );
}

// ─── Standard condition ────────────────────────────────────────────────────

function CondStandard({ cond, onChange, onRemove, policy }) {
  const isUnary = UNARY_OPS.has(cond.op);
  const forcedType = FORCED_RIGHT_TYPE[cond.op];

  const setType = (newType) => {
    const patch = { rightType: newType };
    if (newType === "boolean") patch.right = false;
    else if (newType === "number") patch.right = 0;
    else if (newType === "null") patch.right = null;
    else if (newType === "array") patch.right = [];
    else if (newType === "ref") patch.right = "input.field";
    else patch.right = "";
    onChange(patch);
  };

  const effectiveType = forcedType || cond.rightType || "string";

  const renderRight = () => {
    if (isUnary) {
      // time_now_* still needs a left-side path (the timestamp field)
      if (cond.op === "time_now_gte" || cond.op === "time_now_lte") {
        return (
          <input
            type="text"
            className="cond-input path"
            value={cond.left || ""}
            onChange={(e) => onChange({ left: e.target.value })}
            placeholder="input.unlock_ts_ns"
            spellCheck="false"
          />
        );
      }
      return (
        <span style={{
          color: "var(--text-dim)",
          fontFamily: "var(--font-mono)",
          fontSize: 11,
          fontStyle: "italic",
          padding: "6px 10px",
        }}>
          (no value)
        </span>
      );
    }

    if (effectiveType === "boolean") {
      return (
        <select
          className="cond-input"
          value={String(cond.right ?? false)}
          onChange={(e) => onChange({ right: e.target.value === "true" })}
        >
          <option value="true">true</option>
          <option value="false">false</option>
        </select>
      );
    }
    if (effectiveType === "null") {
      return <input type="text" className="cond-input" value="null" disabled />;
    }
    if (effectiveType === "array") {
      const v = Array.isArray(cond.right) ? JSON.stringify(cond.right) : String(cond.right || "[]");
      return (
        <input
          type="text"
          className="cond-input value"
          value={v}
          onChange={(e) => {
            try {
              const arr = JSON.parse(e.target.value);
              onChange({ right: Array.isArray(arr) ? arr : [] });
            } catch {
              onChange({ right: e.target.value });
            }
          }}
          placeholder='["a", "b", "c"]'
          spellCheck="false"
        />
      );
    }
    if (effectiveType === "number") {
      return (
        <input
          type="number"
          className="cond-input value-num"
          value={cond.right ?? ""}
          onChange={(e) => onChange({ right: e.target.value === "" ? "" : Number(e.target.value) })}
          placeholder={cond.op === "cidr_contains" ? undefined : "0"}
        />
      );
    }
    if (effectiveType === "ref") {
      return (
        <PathAutocompleteInput
          className="cond-input path"
          value={cond.right || ""}
          onChange={(v) => onChange({ right: v })}
          placeholder="input.something"
          sampleInput={policy?._sampleInput}
        />
      );
    }
    // string (default) — also used for lower_eq, upper_eq, cidr_contains
    const placeholder = cond.op === "cidr_contains" ? "10.0.0.0/8"
      : cond.op === "lower_eq" || cond.op === "upper_eq" ? "eth"
      : "value";
    return (
      <input
        type="text"
        className="cond-input value"
        value={cond.right ?? ""}
        onChange={(e) => onChange({ right: e.target.value })}
        placeholder={placeholder}
      />
    );
  };

  // For time_now ops the left input is repurposed as the timestamp path — hide
  // the standard left input in that case (rendered inline in renderRight).
  const hideLeft = cond.op === "time_now_gte" || cond.op === "time_now_lte";

  return (
    <div className="condition">
      <button
        type="button"
        className={`condition-not ${cond.negate ? "active" : ""}`}
        onClick={() => onChange({ negate: !cond.negate })}
        title="Negate this condition"
      >
        NOT
      </button>
      {!hideLeft && (
        <PathAutocompleteInput
          className="cond-input path"
          value={cond.left || ""}
          onChange={(v) => onChange({ left: v })}
          placeholder="input.user.role"
          sampleInput={policy?._sampleInput}
        />
      )}
      <select
        className="cond-op"
        value={cond.op}
        onChange={(e) => {
          const op = e.target.value;
          const patch = { op };
          if (op === "in" && cond.rightType !== "ref" && cond.rightType !== "array") {
            patch.rightType = "array";
            patch.right = [];
          }
          if (FORCED_RIGHT_TYPE[op]) {
            patch.rightType = FORCED_RIGHT_TYPE[op];
          }
          onChange(patch);
        }}
      >
        {OPS.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
      {renderRight()}
      {!isUnary && !forcedType ? (
        <select
          className="cond-type-select"
          value={cond.rightType || "string"}
          onChange={(e) => setType(e.target.value)}
        >
          {TYPES.map((t) => (
            <option key={t.value} value={t.value}>
              {t.label}
            </option>
          ))}
        </select>
      ) : (
        <span />
      )}
      <button className="cond-remove" onClick={onRemove} title="Remove condition">
        ×
      </button>
    </div>
  );
}

// ─── Arithmetic expression condition ──────────────────────────────────────

function CondArith({ cond, onChange, onRemove }) {
  const CMP_OPS = ["==", "!=", "<", "<=", ">", ">="];
  const effectiveType = cond.rightType || "number";

  const setType = (newType) => {
    const patch = { rightType: newType };
    if (newType === "number") patch.right = 0;
    else if (newType === "ref") patch.right = "input.field";
    else patch.right = "";
    onChange(patch);
  };

  return (
    <div className="condition cond-advanced cond-arith">
      <span className="cond-advanced-tag">arith</span>
      <button
        type="button"
        className={`condition-not ${cond.negate ? "active" : ""}`}
        onClick={() => onChange({ negate: !cond.negate })}
        title="Negate"
      >
        NOT
      </button>
      <input
        type="text"
        className="cond-input cond-arith-expr"
        value={cond.leftExpr || ""}
        onChange={(e) => onChange({ leftExpr: e.target.value })}
        placeholder="input.amount * input.rate_bps / 10000"
        spellCheck="false"
        title="Arithmetic expression (identifiers, +, -, *, /, %, parentheses)"
      />
      <select
        className="cond-op"
        value={cond.op || "<="}
        onChange={(e) => onChange({ op: e.target.value })}
      >
        {CMP_OPS.map((op) => (
          <option key={op} value={op}>{op}</option>
        ))}
      </select>
      {effectiveType === "number" ? (
        <input
          type="number"
          className="cond-input value-num"
          value={cond.right ?? 0}
          onChange={(e) => onChange({ right: e.target.value === "" ? 0 : Number(e.target.value) })}
        />
      ) : (
        <input
          type="text"
          className="cond-input path"
          value={cond.right || ""}
          onChange={(e) => onChange({ right: e.target.value })}
          placeholder="input.max_fee"
          spellCheck="false"
        />
      )}
      <select
        className="cond-type-select"
        value={effectiveType}
        onChange={(e) => setType(e.target.value)}
      >
        <option value="number">number</option>
        <option value="ref">ref</option>
      </select>
      <button className="cond-remove" onClick={onRemove} title="Remove">×</button>
    </div>
  );
}

// ─── object.get(obj, key, default) condition ──────────────────────────────

function CondObjectGet({ cond, onChange, onRemove }) {
  const OBJ_OPS = ["==", "!=", "<", "<=", ">", ">=", "in"];
  const KEY_TYPES = ["string", "number"];
  const DEFAULT_TYPES = ["string", "number", "boolean", "null"];

  // Backward-compat: older specs may have stored the object path under `object`.
  const objPath = cond.obj ?? cond.object ?? "";

  const keyType = cond.keyType || "string";
  const defType = cond.defaultType || "string";
  const rightType = cond.rightType || (cond.op === "in" ? "array" : "string");

  const setRightType = (newType) => {
    const patch = { rightType: newType };
    if (newType === "boolean") patch.right = false;
    else if (newType === "number") patch.right = 0;
    else if (newType === "null") patch.right = null;
    else if (newType === "array") patch.right = [];
    else if (newType === "ref") patch.right = "input.field";
    else patch.right = "";
    onChange(patch);
  };

  const setDefaultType = (newType) => {
    const patch = { defaultType: newType };
    if (newType === "boolean") patch.default = false;
    else if (newType === "number") patch.default = 0;
    else if (newType === "null") patch.default = null;
    else patch.default = "";
    onChange(patch);
  };

  const setKeyType = (newType) => {
    const patch = { keyType: newType };
    if (newType === "number") patch.key = 0;
    else patch.key = "";
    onChange(patch);
  };

  const renderTyped = (value, type, onValueChange, placeholder) => {
    if (type === "boolean") {
      return (
        <select
          className="cond-input"
          value={String(value ?? false)}
          onChange={(e) => onValueChange(e.target.value === "true")}
        >
          <option value="true">true</option>
          <option value="false">false</option>
        </select>
      );
    }
    if (type === "null") {
      return <input type="text" className="cond-input" value="null" disabled />;
    }
    if (type === "number") {
      return (
        <input
          type="number"
          className="cond-input value-num"
          value={value ?? 0}
          onChange={(e) => onValueChange(e.target.value === "" ? 0 : Number(e.target.value))}
        />
      );
    }
    if (type === "array") {
      const v = Array.isArray(value) ? JSON.stringify(value) : String(value || "[]");
      return (
        <input
          type="text"
          className="cond-input value"
          value={v}
          onChange={(e) => {
            try {
              const arr = JSON.parse(e.target.value);
              onValueChange(Array.isArray(arr) ? arr : []);
            } catch {
              onValueChange(e.target.value);
            }
          }}
          placeholder='["a", "b"]'
          spellCheck="false"
        />
      );
    }
    if (type === "ref") {
      return (
        <input
          type="text"
          className="cond-input path"
          value={value || ""}
          onChange={(e) => onValueChange(e.target.value)}
          placeholder="input.something"
          spellCheck="false"
        />
      );
    }
    return (
      <input
        type="text"
        className="cond-input value"
        value={value ?? ""}
        onChange={(e) => onValueChange(e.target.value)}
        placeholder={placeholder}
      />
    );
  };

  return (
    <div className="condition cond-advanced cond-object-get">
      <span className="cond-advanced-tag">object.get</span>
      <button
        type="button"
        className={`condition-not ${cond.negate ? "active" : ""}`}
        onClick={() => onChange({ negate: !cond.negate })}
        title="Negate"
      >
        NOT
      </button>
      <span className="cond-object-get-keyword">object.get(</span>
      <input
        type="text"
        className="cond-input path"
        value={objPath}
        onChange={(e) => {
          const patch = { obj: e.target.value };
          if (cond.object !== undefined) patch.object = undefined;
          onChange(patch);
        }}
        placeholder="input.meta"
        spellCheck="false"
        title="Object reference"
      />
      <span className="cond-object-get-keyword">,</span>
      {renderTyped(cond.key, keyType, (v) => onChange({ key: v }), "tier")}
      <select
        className="cond-type-select"
        value={keyType}
        onChange={(e) => setKeyType(e.target.value)}
        title="Key type"
      >
        {KEY_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
      </select>
      <span className="cond-object-get-keyword">,</span>
      {renderTyped(cond.default, defType, (v) => onChange({ default: v }), "free")}
      <select
        className="cond-type-select"
        value={defType}
        onChange={(e) => setDefaultType(e.target.value)}
        title="Default type"
      >
        {DEFAULT_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
      </select>
      <span className="cond-object-get-keyword">)</span>
      <select
        className="cond-op"
        value={cond.op || "=="}
        onChange={(e) => {
          const op = e.target.value;
          const patch = { op };
          if (op === "in" && rightType !== "array" && rightType !== "ref") {
            patch.rightType = "array";
            patch.right = [];
          }
          onChange(patch);
        }}
      >
        {OBJ_OPS.map((op) => <option key={op} value={op}>{op}</option>)}
      </select>
      {renderTyped(cond.right, rightType, (v) => onChange({ right: v }), "value")}
      <select
        className="cond-type-select"
        value={rightType}
        onChange={(e) => setRightType(e.target.value)}
        title="Right-hand type"
      >
        {TYPES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
      </select>
      <button className="cond-remove" onClick={onRemove} title="Remove">×</button>
    </div>
  );
}

// ─── Raw Rego escape hatch ─────────────────────────────────────────────────
// The raw renderer in regoCompiler emits cond.rego verbatim. No left/op/right.
// Used for multi-statement Rego that doesn't fit the structured condition shape
// (e.g. regex.match with backticks, comprehensions, helper-rule bodies).

function CondRaw({ cond, onChange, onRemove }) {
  const lineCount = (cond.rego || "").split("\n").length;
  return (
    <div className="condition cond-advanced cond-raw">
      <div className="cond-raw-head">
        <span className="cond-advanced-tag">raw</span>
        <span className="cond-raw-hint">
          Rego is emitted verbatim. Printable ASCII only.
          {lineCount > 1 ? ` · ${lineCount} lines` : ""}
        </span>
        <button className="cond-remove" onClick={onRemove} title="Remove" style={{ marginLeft: "auto" }}>×</button>
      </div>
      <textarea
        className="cond-raw-textarea"
        value={cond.rego || ""}
        onChange={(e) => onChange({ rego: e.target.value })}
        placeholder={`input.wallet.chain == "ethereum"\nregex.match(\`^0x[a-fA-F0-9]{40}$\`, input.wallet.address)`}
        spellCheck="false"
        rows={Math.max(3, Math.min(12, lineCount + 1))}
      />
    </div>
  );
}

// ─── Aggregate condition ───────────────────────────────────────────────────

function CondAggregate({ cond, onChange, onRemove }) {
  const CMP_OPS = ["==", "!=", "<", "<=", ">", ">="];
  const filters = cond.filter || [];

  const updateFilter = (i, patch) =>
    onChange({ filter: filters.map((f, idx) => (idx === i ? { ...f, ...patch } : f)) });
  const addFilter = () => onChange({ filter: [...filters, newCondition()] });
  const removeFilter = (i) => onChange({ filter: filters.filter((_, idx) => idx !== i) });

  return (
    <div className="condition cond-advanced cond-aggregate">
      <span className="cond-advanced-tag">aggregate</span>
      <button
        type="button"
        className={`condition-not ${cond.negate ? "active" : ""}`}
        onClick={() => onChange({ negate: !cond.negate })}
      >
        NOT
      </button>
      <select
        className="cond-op"
        value={cond.fn || "count"}
        onChange={(e) => onChange({ fn: e.target.value })}
      >
        {AGGREGATE_FNS.map((fn) => (
          <option key={fn} value={fn}>{fn}</option>
        ))}
      </select>
      <span className="cond-aggregate-paren">(</span>
      <input
        type="text"
        className="cond-input path"
        value={cond.collection || ""}
        onChange={(e) => onChange({ collection: e.target.value })}
        placeholder="input.approvals"
        spellCheck="false"
      />
      <span className="cond-aggregate-paren">)</span>
      <select
        className="cond-op"
        value={cond.op || ">="}
        onChange={(e) => onChange({ op: e.target.value })}
      >
        {CMP_OPS.map((op) => (
          <option key={op} value={op}>{op}</option>
        ))}
      </select>
      <input
        type="number"
        className="cond-input value-num"
        value={cond.right ?? 1}
        onChange={(e) => onChange({ right: e.target.value === "" ? 0 : Number(e.target.value) })}
      />
      <button className="cond-remove" onClick={onRemove} title="Remove">×</button>

      {/* Filter sub-panel */}
      <div className="cond-aggregate-filter">
        <div className="cond-aggregate-filter-label">
          Filter <span className="cond-filter-hint">(item.field op value)</span>
        </div>
        {filters.map((f, i) => (
          <CondStandard
            key={i}
            cond={f}
            onChange={(patch) => updateFilter(i, patch)}
            onRemove={() => removeFilter(i)}
          />
        ))}
        <button className="add-cond" onClick={addFilter} style={{ marginTop: 4 }}>
          + Add filter
        </button>
      </div>
    </div>
  );
}

// ─── Every (universal quantifier) condition ────────────────────────────────

function CondEvery({ cond, onChange, onRemove }) {
  const conditions = cond.conditions || [];

  const updateInner = (i, patch) =>
    onChange({ conditions: conditions.map((c, idx) => (idx === i ? { ...c, ...patch } : c)) });
  const addInner = () => onChange({ conditions: [...conditions, newCondition()] });
  const removeInner = (i) => onChange({ conditions: conditions.filter((_, idx) => idx !== i) });

  return (
    <div className="condition cond-advanced cond-every">
      <div className="cond-every-head">
        <span className="cond-advanced-tag">every</span>
        <button
          type="button"
          className={`condition-not ${cond.negate ? "active" : ""}`}
          onClick={() => onChange({ negate: !cond.negate })}
        >
          NOT
        </button>
        <span className="cond-every-keyword">for every</span>
        <input
          type="text"
          className="cond-input cond-every-var"
          value={cond.variable || "item"}
          onChange={(e) => onChange({ variable: e.target.value.replace(/[^a-zA-Z0-9_]/g, "") })}
          placeholder="item"
          spellCheck="false"
        />
        <span className="cond-every-keyword">in</span>
        <input
          type="text"
          className="cond-input path"
          value={cond.collection || ""}
          onChange={(e) => onChange({ collection: e.target.value })}
          placeholder="input.transactions"
          spellCheck="false"
        />
        <button className="cond-remove" onClick={onRemove} title="Remove">×</button>
      </div>
      <div className="cond-every-body">
        {conditions.map((c, i) => (
          <CondStandard
            key={i}
            cond={c}
            onChange={(patch) => updateInner(i, patch)}
            onRemove={() => removeInner(i)}
          />
        ))}
        <button className="add-cond" onClick={addInner} style={{ marginTop: 4 }}>
          + Add inner condition
        </button>
      </div>
    </div>
  );
}

// ─── Builtin-left condition (time…) ───────────────────────────────────────

function CondBuiltinLeft({ cond, onChange, onRemove }) {
  const CMP_OPS = ["==", "!=", "<", "<=", ">", ">="];
  const builtin = cond.builtin || "time.now_ns";
  const needsArg = builtin === "time.weekday" || builtin === "time.date";

  const setType = (newType) => {
    const patch = { rightType: newType };
    if (newType === "number") patch.right = 0;
    else if (newType === "ref") patch.right = "input.unlock_ts_ns";
    else if (newType === "string") patch.right = "";
    onChange(patch);
  };

  const effectiveType = cond.rightType || "ref";

  return (
    <div className="condition cond-advanced cond-builtin">
      <span className="cond-advanced-tag">builtin</span>
      <button
        type="button"
        className={`condition-not ${cond.negate ? "active" : ""}`}
        onClick={() => onChange({ negate: !cond.negate })}
      >
        NOT
      </button>
      <select
        className="cond-op"
        value={builtin}
        onChange={(e) => onChange({ builtin: e.target.value, arg: undefined, component: undefined })}
      >
        {BUILTIN_OPTIONS.map((b) => (
          <option key={b.value} value={b.value}>{b.label}</option>
        ))}
      </select>
      {needsArg && (
        <input
          type="text"
          className="cond-input path"
          value={cond.arg || ""}
          onChange={(e) => onChange({ arg: e.target.value })}
          placeholder="input.timestamp_ns"
          spellCheck="false"
          title="Timestamp path (nanoseconds)"
        />
      )}
      {builtin === "time.date" && (
        <select
          className="cond-op"
          value={cond.component ?? 0}
          onChange={(e) => onChange({ component: Number(e.target.value) })}
        >
          {DATE_COMPONENTS.map((d) => (
            <option key={d.value} value={d.value}>{d.label}</option>
          ))}
        </select>
      )}
      <select
        className="cond-op"
        value={cond.op || ">="}
        onChange={(e) => onChange({ op: e.target.value })}
      >
        {CMP_OPS.map((op) => (
          <option key={op} value={op}>{op}</option>
        ))}
      </select>
      {effectiveType === "number" ? (
        <input
          type="number"
          className="cond-input value-num"
          value={cond.right ?? 0}
          onChange={(e) => onChange({ right: e.target.value === "" ? 0 : Number(e.target.value) })}
        />
      ) : effectiveType === "string" ? (
        <input
          type="text"
          className="cond-input value"
          value={cond.right ?? ""}
          onChange={(e) => onChange({ right: e.target.value })}
          placeholder={builtin === "time.weekday" ? "Monday" : "value"}
        />
      ) : (
        <input
          type="text"
          className="cond-input path"
          value={cond.right || ""}
          onChange={(e) => onChange({ right: e.target.value })}
          placeholder="input.unlock_ts_ns"
          spellCheck="false"
        />
      )}
      <select
        className="cond-type-select"
        value={effectiveType}
        onChange={(e) => setType(e.target.value)}
      >
        <option value="ref">ref</option>
        <option value="number">number</option>
        <option value="string">string</option>
      </select>
      <button className="cond-remove" onClick={onRemove} title="Remove">×</button>
    </div>
  );
}

// ─── Verification (crypto / JWT) condition ────────────────────────────────

function defaultArgValueForType(t) {
  if (t === "ref") return "input.field";
  if (t === "string") return "";
  if (t === "object") return {};
  return "";
}

function defaultVerificationArgs(fn) {
  const spec = VERIFICATION_FUNCS[fn];
  if (!spec) return [];
  if (fn.startsWith("io.jwt.verify_")) {
    return [
      { value: "input.token", type: "ref" },
      { value: fn.startsWith("io.jwt.verify_hs") ? "data.keys.hmac_secret" : "data.keys.public_pem", type: "ref" },
    ];
  }
  if (fn === "io.jwt.decode_verify") {
    return [
      { value: "input.token", type: "ref" },
      { value: { cert: "", aud: "", iss: "" }, type: "object" },
    ];
  }
  if (fn === "io.jwt.decode") {
    return [{ value: "input.token", type: "ref" }];
  }
  if (fn === "crypto.x509.parse_and_verify_certificates" || fn === "crypto.x509.parse_certificates") {
    return [{ value: "input.cert_chain_pem", type: "ref" }];
  }
  if (fn === "crypto.hmac.equal") {
    return [
      { value: "input.signature_hex", type: "ref" },
      { value: "input.expected_hex", type: "ref" },
    ];
  }
  if (fn.startsWith("crypto.hmac.")) {
    return [
      { value: "input.payload", type: "ref" },
      { value: "data.keys.hmac_secret", type: "ref" },
    ];
  }
  return [{ value: "input.payload", type: "ref" }];
}

function CondVerification({ cond, onChange, onRemove }) {
  const fn = cond.function || "io.jwt.verify_es256";
  const spec = VERIFICATION_FUNCS[fn] || { category: "bool", arity: 0 };
  const args = Array.isArray(cond.args) ? cond.args : [];

  const setFunction = (newFn) => {
    const newSpec = VERIFICATION_FUNCS[newFn];
    const patch = {
      function: newFn,
      args: defaultVerificationArgs(newFn),
      bind: undefined,
      compareOp: undefined,
      compareTo: undefined,
      bindAs: undefined,
      negate: false,
    };
    if (newSpec && newSpec.category === "tuple") {
      patch.bind = [...newSpec.returns];
    }
    if (newSpec && newSpec.category === "value") {
      patch.compareOp = "==";
      patch.compareTo = { value: "", type: "string" };
    }
    onChange(patch);
  };

  const updateArg = (i, patch) => {
    onChange({ args: args.map((a, idx) => (idx === i ? { ...a, ...patch } : a)) });
  };

  const setArgType = (i, newType) => {
    updateArg(i, { type: newType, value: defaultArgValueForType(newType) });
  };

  const renderArgInput = (arg, i) => {
    const t = arg.type || "ref";
    if (t === "object") {
      const text = typeof arg.value === "string"
        ? arg.value
        : JSON.stringify(arg.value || {}, null, 0);
      return (
        <input
          type="text"
          className="cond-input value"
          value={text}
          onChange={(e) => {
            const raw = e.target.value;
            try {
              const parsed = JSON.parse(raw);
              if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
                updateArg(i, { value: parsed });
                return;
              }
            } catch {}
            updateArg(i, { value: raw });
          }}
          placeholder='{"iss": "https://issuer"}'
          spellCheck="false"
          title="JSON object literal"
        />
      );
    }
    if (t === "string") {
      return (
        <input
          type="text"
          className="cond-input value"
          value={arg.value ?? ""}
          onChange={(e) => updateArg(i, { value: e.target.value })}
          placeholder="literal"
        />
      );
    }
    return (
      <input
        type="text"
        className="cond-input path"
        value={arg.value ?? ""}
        onChange={(e) => updateArg(i, { value: e.target.value })}
        placeholder="input.something"
        spellCheck="false"
      />
    );
  };

  const renderBinds = () => {
    if (spec.category !== "tuple") return null;
    const binds = Array.isArray(cond.bind) && cond.bind.length === spec.returns.length
      ? cond.bind
      : [...spec.returns];
    return (
      <>
        <span className="cond-object-get-keyword">→ [</span>
        {binds.map((b, i) => (
          <input
            key={i}
            type="text"
            className="cond-input path"
            value={b}
            onChange={(e) => {
              const next = binds.slice();
              next[i] = e.target.value;
              onChange({ bind: next });
            }}
            placeholder={spec.returns[i]}
            spellCheck="false"
            style={{ minWidth: 70 }}
            title={`Bind name for ${spec.returns[i]}`}
          />
        ))}
        <span className="cond-object-get-keyword">]</span>
      </>
    );
  };

  const renderValueTail = () => {
    if (spec.category !== "value") return null;
    const useBind = cond.bindAs !== undefined && cond.bindAs !== null && cond.bindAs !== "";
    return (
      <>
        <select
          className="cond-op"
          value={useBind ? "bind" : "compare"}
          onChange={(e) => {
            if (e.target.value === "bind") {
              onChange({ bindAs: "result", compareOp: undefined, compareTo: undefined });
            } else {
              onChange({ bindAs: undefined, compareOp: "==", compareTo: { value: "", type: "string" } });
            }
          }}
          title="Compare result vs. bind to variable"
        >
          <option value="compare">compare</option>
          <option value="bind">bind as</option>
        </select>
        {useBind ? (
          <input
            type="text"
            className="cond-input path"
            value={cond.bindAs || ""}
            onChange={(e) => onChange({ bindAs: e.target.value })}
            placeholder="result"
            spellCheck="false"
          />
        ) : (
          <>
            <select
              className="cond-op"
              value={cond.compareOp || "=="}
              onChange={(e) => onChange({ compareOp: e.target.value })}
            >
              {VERIFICATION_COMPARE_OPS.map((op) => (
                <option key={op} value={op}>{op}</option>
              ))}
            </select>
            <input
              type="text"
              className="cond-input value"
              value={(cond.compareTo && cond.compareTo.value) ?? ""}
              onChange={(e) => onChange({ compareTo: { ...(cond.compareTo || {}), value: e.target.value, type: (cond.compareTo && cond.compareTo.type) || "string" } })}
              placeholder="expected (hex)"
            />
            <select
              className="cond-type-select"
              value={(cond.compareTo && cond.compareTo.type) || "string"}
              onChange={(e) => {
                const t = e.target.value;
                const v = t === "ref" ? "input.expected" : t === "number" ? 0 : "";
                onChange({ compareTo: { value: v, type: t } });
              }}
            >
              <option value="string">string</option>
              <option value="ref">ref</option>
            </select>
          </>
        )}
      </>
    );
  };

  const canNegate =
    spec.category === "bool" ||
    (spec.category === "value" && !(cond.bindAs !== undefined && cond.bindAs !== null && cond.bindAs !== "")) ||
    (spec.category === "tuple" && (VERIFICATION_FUNCS[fn] || {}).returns && fn !== "io.jwt.decode");

  return (
    <div className="condition cond-advanced cond-verification">
      <span className="cond-advanced-tag">verify</span>
      {canNegate && (
        <button
          type="button"
          className={`condition-not ${cond.negate ? "active" : ""}`}
          onClick={() => onChange({ negate: !cond.negate })}
          title="Negate"
        >
          NOT
        </button>
      )}
      <select
        className="cond-op"
        value={fn}
        onChange={(e) => setFunction(e.target.value)}
        style={{ minWidth: 220 }}
      >
        {VERIFICATION_GROUPS.map((group) => (
          <optgroup key={group} label={group}>
            {Object.entries(VERIFICATION_FUNCS)
              .filter(([, v]) => v.group === group)
              .map(([name, v]) => (
                <option key={name} value={name}>
                  {name}{v.deprecated ? " (deprecated)" : ""}
                </option>
              ))}
          </optgroup>
        ))}
      </select>
      {spec.deprecated && (
        <span
          className="cond-advanced-tag"
          style={{ background: "var(--warn-bg, #4a2a00)", color: "var(--warn-fg, #ffb84d)" }}
          title="Deprecated cryptographic primitive — prefer crypto.sha256 or stronger"
        >
          deprecated
        </span>
      )}
      <span className="cond-object-get-keyword">(</span>
      {args.map((arg, i) => (
        <span key={i} style={{ display: "inline-flex", gap: 4, alignItems: "center" }}>
          {i > 0 && <span className="cond-object-get-keyword">,</span>}
          {renderArgInput(arg, i)}
          <select
            className="cond-type-select"
            value={arg.type || "ref"}
            onChange={(e) => setArgType(i, e.target.value)}
            title={`Arg ${i + 1} type`}
          >
            {VERIFICATION_ARG_TYPES.map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
        </span>
      ))}
      <span className="cond-object-get-keyword">)</span>
      {renderBinds()}
      {renderValueTail()}
      <button className="cond-remove" onClick={onRemove} title="Remove">×</button>
    </div>
  );
}

// ─── verify (CRY-02) ───────────────────────────────────────────────────────
// High-level signature-verification condition. Strictly boolean — emits a
// truthy-guard expression so it slots into rule bodies like any other cond.

function CondVerify({ cond, onChange, onRemove }) {
  const kind = cond.kind || "jwt";
  const keyRef = cond.keyRef || {};
  const isHmac = VERIFY_HMAC_ALGS.includes(cond.alg);
  const constraints = cond.constraints || {};

  const needsTrustKeys = keyRef.source === "data.studio.keys";
  const [trustKeys, setTrustKeys] = useState([]);
  const [trustKeysLoading, setTrustKeysLoading] = useState(false);
  const [trustKeysError, setTrustKeysError] = useState(null);
  const [dynamicSelectorEdit, setDynamicSelectorEdit] = useState(() =>
    isDynamicTrustSelector(keyRef.selector || "")
  );

  useEffect(() => {
    if (!needsTrustKeys) return undefined;
    let cancelled = false;
    setTrustKeysLoading(true);
    setTrustKeysError(null);
    api
      .listTrustKeys()
      .then((list) => {
        if (cancelled) return;
        setTrustKeys(Array.isArray(list) ? list : []);
      })
      .catch((e) => {
        if (cancelled) return;
        setTrustKeysError(e?.body?.error || e.message || "Failed to load trust keys");
      })
      .finally(() => { if (!cancelled) setTrustKeysLoading(false); });
    return () => { cancelled = true; };
  }, [needsTrustKeys]);

  const setKind = (newKind) => {
    if (newKind === "jwt") {
      onChange({
        kind: "jwt",
        tokenRef: cond.tokenRef || "input.token",
        alg: "ES256",
        keyRef: { source: "inline_pem", pem: "" },
        constraints: constraints || { iss: "", aud: "", exp_required: false, nbf_required: false },
        chainRef: undefined,
        payloadRef: undefined,
        signatureRef: undefined,
      });
    } else if (newKind === "x509") {
      onChange({
        kind: "x509",
        chainRef: cond.chainRef || "input.client_cert_chain_pem",
        tokenRef: undefined,
        alg: undefined,
        keyRef: undefined,
        constraints: undefined,
        payloadRef: undefined,
        signatureRef: undefined,
      });
    } else if (newKind === "raw") {
      onChange({
        kind: "raw",
        alg: "HS256",
        payloadRef: cond.payloadRef || "input.signed_payload",
        signatureRef: cond.signatureRef || "input.signature_hex",
        keyRef: { source: "inline_secret", secret: "" },
        tokenRef: undefined,
        chainRef: undefined,
        constraints: undefined,
      });
    }
  };

  const setAlg = (newAlg) => {
    const patch = { alg: newAlg };
    if (kind === "jwt") {
      const nowHmac = VERIFY_HMAC_ALGS.includes(newAlg);
      const wasHmac = isHmac;
      if (nowHmac && !wasHmac) patch.keyRef = { source: "inline_secret", secret: "" };
      else if (!nowHmac && wasHmac) patch.keyRef = { source: "inline_pem", pem: "" };
    }
    onChange(patch);
  };

  const setKeySource = (newSource) => {
    let next;
    if (newSource === "inline_pem") next = { source: "inline_pem", pem: "" };
    else if (newSource === "inline_secret") next = { source: "inline_secret", secret: "" };
    else if (newSource === "data.studio.keys") next = { source: "data.studio.keys", selector: "" };
    else next = { source: newSource };
    onChange({ keyRef: next });
  };

  const setKeyRefField = (field, value) => onChange({ keyRef: { ...keyRef, [field]: value } });
  const setConstraint = (field, value) =>
    onChange({ constraints: { ...constraints, [field]: value } });

  const keySourceOptions = kind === "raw"
    ? [
        { value: "inline_secret", label: "inline secret" },
        { value: "data.studio.keys", label: "trust store (managed keys)" },
      ]
    : isHmac
      ? [
          { value: "inline_secret", label: "inline secret" },
          { value: "data.studio.keys", label: "trust store (managed keys)" },
        ]
      : [
          { value: "inline_pem", label: "inline PEM" },
          { value: "data.studio.keys", label: "trust store (managed keys)" },
        ];

  const renderKeySourceInput = () => {
    if (keyRef.source === "inline_pem") {
      return (
        <textarea
          className="cond-input value"
          value={keyRef.pem || ""}
          onChange={(e) => setKeyRefField("pem", e.target.value)}
          placeholder="-----BEGIN PUBLIC KEY-----&#10;...&#10;-----END PUBLIC KEY-----"
          spellCheck="false"
          rows={4}
          style={{ width: "100%", minWidth: 360, fontFamily: "var(--font-mono)", fontSize: 11 }}
        />
      );
    }
    if (keyRef.source === "inline_secret") {
      return (
        <input
          type="text"
          className="cond-input value"
          value={keyRef.secret || ""}
          onChange={(e) => setKeyRefField("secret", e.target.value)}
          placeholder="HMAC secret (hex or utf8)"
          spellCheck="false"
        />
      );
    }
    if (keyRef.source === "data.studio.keys") {
      const selector = keyRef.selector || "";
      const activeKeys = trustKeys.filter((k) => k.status === "active");
      const matchesKnownKid = activeKeys.some((k) => k.kid === selector);
      const dynamic = dynamicSelectorEdit || isDynamicTrustSelector(selector);
      const unknownKid = !!selector && !matchesKnownKid && !dynamic;
      const selectValue = dynamic
        ? DYNAMIC_SELECTOR_SENTINEL
        : matchesKnownKid
          ? selector
          : unknownKid
            ? `__unknown__:${selector}`
            : "";
      const placeholderLabel = trustKeysLoading
        ? "loading trust keys…"
        : activeKeys.length === 0
          ? "no managed keys available — add one in Trust keys"
          : "— select managed key —";
      return (
        <div style={{ display: "flex", flexDirection: "column", gap: 4, flex: 1, minWidth: 240 }}>
          <select
            className="cond-op"
            value={selectValue}
            onChange={(e) => {
              const v = e.target.value;
              if (v === DYNAMIC_SELECTOR_SENTINEL) {
                setDynamicSelectorEdit(true);
                if (!isDynamicTrustSelector(selector)) setKeyRefField("selector", "");
              } else if (v.startsWith("__unknown__:")) {
                // No-op — preserves the existing unknown selector value.
              } else {
                setDynamicSelectorEdit(false);
                setKeyRefField("selector", v);
              }
            }}
            title="Pick a kid from the trust store, or switch to a dynamic input./data. reference"
          >
            <option value="" disabled>{placeholderLabel}</option>
            {activeKeys.map((k) => (
              <option key={k.kid} value={k.kid}>
                {k.kid}{k.alg ? ` (${k.alg})` : ""}{k.tenant ? ` · tenant: ${k.tenant}` : ""}
              </option>
            ))}
            {unknownKid && (
              <option value={`__unknown__:${selector}`}>
                {selector} (not in trust store)
              </option>
            )}
            <option value={DYNAMIC_SELECTOR_SENTINEL}>
              — dynamic reference (input.* / data.*) —
            </option>
          </select>
          {dynamic && (
            <input
              type="text"
              className="cond-input path"
              value={selector}
              onChange={(e) => setKeyRefField("selector", e.target.value)}
              placeholder="input.tenant_id"
              spellCheck="false"
              title={"A dynamic ref like input.tenant_id is emitted as data.studio.keys[input.tenant_id]"}
            />
          )}
          {trustKeysError && (
            <span style={{ color: "var(--err, #f66)", fontSize: 11 }}>
              {trustKeysError}
            </span>
          )}
        </div>
      );
    }
    return null;
  };

  const algOptions = kind === "raw" ? VERIFY_HMAC_ALGS : VERIFY_JWT_ALGS;

  return (
    <div className="condition cond-advanced cond-verification" style={{ flexWrap: "wrap" }}>
      <span className="cond-advanced-tag">verify</span>
      <select
        className="cond-op"
        value={kind}
        onChange={(e) => setKind(e.target.value)}
        title="Verification kind"
      >
        {VERIFY_KINDS.map((k) => (
          <option key={k} value={k}>{k}</option>
        ))}
      </select>

      {kind === "jwt" && (
        <>
          <span className="cond-object-get-keyword">token</span>
          <input
            type="text"
            className="cond-input path"
            value={cond.tokenRef || ""}
            onChange={(e) => onChange({ tokenRef: e.target.value })}
            placeholder="input.request.headers.authorization"
            spellCheck="false"
            style={{ minWidth: 220 }}
          />
          <span className="cond-object-get-keyword">alg</span>
          <select className="cond-op" value={cond.alg || "ES256"} onChange={(e) => setAlg(e.target.value)}>
            {algOptions.map((a) => (
              <option key={a} value={a}>{a}</option>
            ))}
          </select>
        </>
      )}

      {kind === "x509" && (
        <>
          <span className="cond-object-get-keyword">cert chain</span>
          <input
            type="text"
            className="cond-input path"
            value={cond.chainRef || ""}
            onChange={(e) => onChange({ chainRef: e.target.value })}
            placeholder="input.client_cert_chain_pem"
            spellCheck="false"
            style={{ minWidth: 260 }}
          />
        </>
      )}

      {kind === "raw" && (
        <>
          <span className="cond-object-get-keyword">alg</span>
          <select className="cond-op" value={cond.alg || "HS256"} onChange={(e) => setAlg(e.target.value)}>
            {algOptions.map((a) => (
              <option key={a} value={a}>{a}</option>
            ))}
          </select>
          <span className="cond-object-get-keyword">payload</span>
          <input
            type="text"
            className="cond-input path"
            value={cond.payloadRef || ""}
            onChange={(e) => onChange({ payloadRef: e.target.value })}
            placeholder="input.signed_payload"
            spellCheck="false"
            style={{ minWidth: 180 }}
          />
          <span className="cond-object-get-keyword">sig</span>
          <input
            type="text"
            className="cond-input path"
            value={cond.signatureRef || ""}
            onChange={(e) => onChange({ signatureRef: e.target.value })}
            placeholder="input.signature_hex"
            spellCheck="false"
            style={{ minWidth: 180 }}
          />
        </>
      )}

      {kind !== "x509" && (
        <div style={{ flexBasis: "100%", display: "flex", flexWrap: "wrap", gap: 6, alignItems: "flex-start", marginTop: 6 }}>
          <span className="cond-object-get-keyword">key</span>
          <select
            className="cond-op"
            value={keyRef.source || ""}
            onChange={(e) => setKeySource(e.target.value)}
          >
            {keySourceOptions.map((o) => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>
          {renderKeySourceInput()}
        </div>
      )}

      {kind === "jwt" && (
        <div style={{ flexBasis: "100%", display: "flex", flexWrap: "wrap", gap: 6, alignItems: "center", marginTop: 6 }}>
          <span className="cond-object-get-keyword">iss</span>
          <input
            type="text"
            className="cond-input value"
            value={constraints.iss || ""}
            onChange={(e) => setConstraint("iss", e.target.value)}
            placeholder="https://idp.example.com (optional)"
            spellCheck="false"
            style={{ minWidth: 220 }}
          />
          <span className="cond-object-get-keyword">aud</span>
          <input
            type="text"
            className="cond-input value"
            value={typeof constraints.aud === "string" ? constraints.aud : (Array.isArray(constraints.aud) ? constraints.aud.join(",") : "")}
            onChange={(e) => {
              const raw = e.target.value;
              if (raw.includes(",")) {
                const parts = raw.split(",").map((s) => s.trim()).filter(Boolean);
                setConstraint("aud", parts);
              } else {
                setConstraint("aud", raw);
              }
            }}
            placeholder="my-app (optional, comma for multi)"
            spellCheck="false"
            style={{ minWidth: 200 }}
          />
          <label style={{ display: "inline-flex", gap: 4, alignItems: "center", fontSize: 11 }}>
            <input
              type="checkbox"
              checked={constraints.exp_required === true}
              onChange={(e) => setConstraint("exp_required", e.target.checked)}
            />
            require exp
          </label>
          <label style={{ display: "inline-flex", gap: 4, alignItems: "center", fontSize: 11 }}>
            <input
              type="checkbox"
              checked={constraints.nbf_required === true}
              onChange={(e) => setConstraint("nbf_required", e.target.checked)}
            />
            require nbf
          </label>
        </div>
      )}

      <button className="cond-remove" onClick={onRemove} title="Remove">×</button>
    </div>
  );
}
