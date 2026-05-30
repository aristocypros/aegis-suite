// ruleGraph.js
// Pure helpers that derive a navigable graph view of the policy spec:
//   - which rule the PEP queries (entry point)
//   - which rules reference which other rules (cross-rule edges)
//   - an inferred semantic role for each rule (decision / accumulator / gate /
//     helper / orphan) used to colour-code the diagram.
//
// Walker shape mirrors backend/src/services/policyIndex.js intentionally, but
// the filter is inverted: policyIndex.js KEEPS input.*/data.* paths to publish
// to the PEP; this module DROPS them and keeps only bare identifiers that
// match another rule name in the same policy. Modules stay independent.

const IDENT_RE = /[a-zA-Z_][a-zA-Z0-9_]*/g;
const BARE_IDENT_RE = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
const GATE_NAMES = new Set(["allow", "deny", "permit", "authorized"]);
const ENTRY_FALLBACK_NAMES = ["main", "decision", "result", "allow", "deny"];

function isBareIdent(v) {
  return typeof v === "string" && BARE_IDENT_RE.test(v);
}

function addStrictRef(set, value, byName) {
  if (!isBareIdent(value)) return;
  if (!byName.has(value)) return;
  set.add(value);
}

function scanIdentifiers(expr, byName, set) {
  if (typeof expr !== "string") return;
  const matches = expr.matchAll(IDENT_RE);
  for (const m of matches) {
    const name = m[0];
    if (byName.has(name)) set.add(name);
  }
}

function collectFromCondition(cond, byName, strict, weak) {
  if (!cond || typeof cond !== "object") return;

  const ct = cond.condType;

  // Standard condition: left and right may be bare rule refs.
  if (!ct) {
    addStrictRef(strict, cond.left, byName);
    if (cond.rightType === "ref") addStrictRef(strict, cond.right, byName);
    return;
  }

  if (ct === "arith") {
    // leftExpr is an arithmetic expression — scan identifiers as WEAK refs
    // (may include local bindings, constants, or false matches).
    scanIdentifiers(cond.leftExpr, byName, weak);
    if (cond.rightType === "ref") addStrictRef(strict, cond.right, byName);
    return;
  }

  if (ct === "aggregate") {
    addStrictRef(strict, cond.collection, byName);
    if (cond.rightType === "ref") addStrictRef(strict, cond.right, byName);
    for (const f of cond.filter || []) collectFromCondition(f, byName, strict, weak);
    return;
  }

  if (ct === "every") {
    addStrictRef(strict, cond.collection, byName);
    for (const c of cond.conditions || []) collectFromCondition(c, byName, strict, weak);
    return;
  }

  if (ct === "builtin_left") {
    addStrictRef(strict, cond.arg, byName);
    if (cond.rightType === "ref") addStrictRef(strict, cond.right, byName);
    return;
  }

  if (ct === "object_get") {
    addStrictRef(strict, cond.obj ?? cond.object, byName);
    if (cond.rightType === "ref") addStrictRef(strict, cond.right, byName);
    return;
  }

  if (ct === "raw") {
    // Raw Rego — regex-scan identifiers as WEAK refs.
    scanIdentifiers(cond.rego, byName, weak);
    return;
  }

  if (ct === "verification") {
    for (const a of cond.args || []) {
      if (a && a.type === "ref") addStrictRef(strict, a.value, byName);
    }
    if (cond.compareTo && cond.compareTo.type === "ref") {
      addStrictRef(strict, cond.compareTo.value, byName);
    }
    return;
  }
}

function collectFromBranch(branch, byName, strict, weak) {
  if (!branch || typeof branch !== "object") return;
  const groups = Array.isArray(branch.groups) && branch.groups.length
    ? branch.groups
    : [{ conditions: branch.conditions || [] }];
  for (const g of groups) {
    for (const c of g.conditions || []) collectFromCondition(c, byName, strict, weak);
  }
}

function collectFromRule(rule, byName) {
  const strict = new Set();
  const weak = new Set();

  if (rule.kind === "result_object") {
    for (const f of rule.fields || []) {
      if (f && f.valueType === "ref") addStrictRef(strict, f.value, byName);
    }
  } else {
    for (const b of rule.branches || []) collectFromBranch(b, byName, strict, weak);
  }

  // Strict wins: any name in both sets stays strict only.
  for (const name of strict) weak.delete(name);
  // Self-references don't count as cross-rule edges.
  strict.delete(rule.name);
  weak.delete(rule.name);
  return { strict, weak };
}

function pickEntryPoint(rules, inbound) {
  if (!rules || rules.length === 0) return null;

  // 1. First result_object rule.
  const ro = rules.find((r) => r.kind === "result_object");
  if (ro) return ro;

  // 2. First rule named main / decision / result / allow / deny (in order).
  for (const wanted of ENTRY_FALLBACK_NAMES) {
    const hit = rules.find((r) => r.name === wanted);
    if (hit) return hit;
  }

  // 3. First rule with zero inbound edges and at least one branch.
  const root = rules.find(
    (r) => (inbound.get(r.name)?.size ?? 0) === 0 && Array.isArray(r.branches) && r.branches.length > 0
  );
  if (root) return root;

  // 4. Last rule in array.
  return rules[rules.length - 1];
}

function inferRole(rule, entryPoint, inboundCount) {
  if (rule.kind === "partial_set") return "accumulator";
  if (entryPoint && rule.name === entryPoint.name) return "decision";
  if (inboundCount > 0 && GATE_NAMES.has(rule.name)) return "gate";
  if (inboundCount > 0) return "helper";
  return "orphan";
}

export function buildRuleGraph(rules) {
  const safeRules = Array.isArray(rules) ? rules.filter((r) => r && r.name) : [];
  const byName = new Map();
  for (const r of safeRules) byName.set(r.name, r);

  const inbound = new Map();
  const outbound = new Map();
  const outboundWeak = new Map();
  const edges = [];

  for (const r of safeRules) {
    inbound.set(r.name, new Set());
    outbound.set(r.name, new Set());
    outboundWeak.set(r.name, new Set());
  }

  for (const r of safeRules) {
    const { strict, weak } = collectFromRule(r, byName);
    for (const target of strict) {
      outbound.get(r.name).add(target);
      inbound.get(target).add(r.name);
      edges.push({ from: r.name, to: target, kind: "strict" });
    }
    for (const target of weak) {
      outboundWeak.get(r.name).add(target);
      // Weak refs do count as inbound — a regex-scanned identifier match is
      // a strong-enough signal that the target rule is consumed somewhere.
      inbound.get(target).add(r.name);
      edges.push({ from: r.name, to: target, kind: "weak" });
    }
  }

  const entryPoint = pickEntryPoint(safeRules, inbound);

  const roleOf = new Map();
  for (const r of safeRules) {
    roleOf.set(r.name, inferRole(r, entryPoint, inbound.get(r.name)?.size ?? 0));
  }

  return { byName, inbound, outbound, outboundWeak, edges, entryPoint, roleOf };
}

// Returns whether a string is a strict cross-rule ref (bare identifier
// matching a rule name in the policy). Used by the diagram to decide between
// a clickable RefChip and a plain RulePath.
export function isStrictRuleRef(value, ruleNames) {
  return isBareIdent(value) && ruleNames.has(value);
}

// Initial collapse map: entry point + accumulators expanded; everything else
// collapsed. Returns Map<name, boolean> where true = collapsed.
export function initialCollapse(graph) {
  const collapsed = new Map();
  if (!graph || !graph.byName) return collapsed;
  for (const [name, rule] of graph.byName.entries()) {
    const role = graph.roleOf.get(name);
    const isEntry = graph.entryPoint?.name === name;
    const expanded = isEntry || role === "accumulator";
    collapsed.set(name, !expanded);
  }
  return collapsed;
}
