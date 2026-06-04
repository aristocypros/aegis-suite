// policyIndex.js
// Pure functions that derive a discovery index from policy specs.
//
// The index lets the PEP answer "given this input, which policies could be
// evaluated?" without having to parse Rego or call the studio backend. The
// backend publishes the index to OPA at data.studio.policy_index after every
// save / lock / unlock and on startup; the PEP fetches it via the same OPA
// channel it already uses for evaluation.
//
// "Required input paths" are extracted by walking the spec — left/right refs,
// arithmetic expressions, aggregate collections + filters, every-quantifier
// collections + bodies, builtin_left args, object_get objects, and a regex
// pass over `raw` Rego. Paths are stripped of their leading `input.` prefix
// and stored as dotted strings like "user.tier", "amount", "approval.signed".

const INPUT_REF_RE = /\binput(?:\.[a-zA-Z_][a-zA-Z0-9_]*)+/g;

function addPath(set, ref) {
  if (typeof ref !== "string") return;
  const trimmed = ref.trim();
  if (!trimmed.startsWith("input.")) return;
  const path = trimmed.slice("input.".length);
  if (!path) return;
  set.add(path);
}

function collectFromExpression(expr, set) {
  if (typeof expr !== "string") return;
  const matches = expr.match(INPUT_REF_RE);
  if (!matches) return;
  for (const m of matches) addPath(set, m);
}

function collectFromCondition(cond, set) {
  if (!cond || typeof cond !== "object") return;

  // Standard left/right refs
  if (cond.left) addPath(set, cond.left);
  if (cond.rightType === "ref" && typeof cond.right === "string") {
    addPath(set, cond.right);
  }

  // Advanced condTypes
  switch (cond.condType) {
    case "arith":
      collectFromExpression(cond.leftExpr, set);
      break;
    case "aggregate":
      if (cond.collection) addPath(set, cond.collection);
      if (Array.isArray(cond.filter)) {
        for (const f of cond.filter) collectFromCondition(f, set);
      }
      break;
    case "every":
      if (cond.collection) addPath(set, cond.collection);
      if (Array.isArray(cond.conditions)) {
        for (const inner of cond.conditions) collectFromCondition(inner, set);
      }
      break;
    case "builtin_left":
      if (cond.arg) addPath(set, cond.arg);
      break;
    case "object_get":
      if (cond.object) addPath(set, cond.object);
      else if (cond.obj) addPath(set, cond.obj);
      break;
    case "raw":
      collectFromExpression(cond.rego, set);
      break;
    case "verify":
      if (cond.tokenRef) addPath(set, cond.tokenRef);
      if (cond.chainRef) addPath(set, cond.chainRef);
      if (cond.payloadRef) addPath(set, cond.payloadRef);
      if (cond.signatureRef) addPath(set, cond.signatureRef);
      if (cond.keyRef && typeof cond.keyRef === "object" && typeof cond.keyRef.selector === "string") {
        addPath(set, cond.keyRef.selector);
      }
      break;
  }
}

function collectFromBranch(branch, set) {
  if (!branch || typeof branch !== "object") return;
  if (Array.isArray(branch.groups)) {
    for (const g of branch.groups) {
      if (Array.isArray(g?.conditions)) {
        for (const c of g.conditions) collectFromCondition(c, set);
      }
    }
  }
  // Legacy flat conditions (treated as single AND group by the compiler)
  if (Array.isArray(branch.conditions)) {
    for (const c of branch.conditions) collectFromCondition(c, set);
  }
}

export function extractInputPaths(rules) {
  const set = new Set();
  if (!Array.isArray(rules)) return [];
  for (const rule of rules) {
    if (!Array.isArray(rule?.branches)) continue;
    for (const b of rule.branches) collectFromBranch(b, set);
  }
  return [...set].sort();
}

// Build the discovery index for the PEP. Only ACTIVE (non-locked) policies are
// included — a locked policy is intentionally absent from OPA, so it can never
// be evaluated and should not be a discovery candidate.
//
// Each entry carries org_id so the PEP can filter discovery results to
// only the policies in the caller's org (a PEP caller in org A must not
// see policies in org B, even if input paths match). org_id is null for
// global / root-owned policies; the PEP treats those as visible to all
// callers in v1 (they're seeded by root and are platform-wide).
// `generatedAt` is intentionally NOT a wall-clock by default: the policy
// index is embedded in the OPA bundle, whose revision/ETag is a content hash.
// A per-build `new Date()` would change the hash on every rebuild even when
// the policy set is unchanged, defeating the 304-not-modified path. Callers
// that genuinely want a timestamp (none currently) can pass one explicitly.
export function buildPolicyIndex(policies, { generatedAt = null } = {}) {
  const list = (Array.isArray(policies) ? policies : [])
    .filter((p) => p && !p.locked)
    .map((p) => ({
      id: p.id,
      name: p.name ?? null,
      package: p.package ?? null,
      description: p.description ?? null,
      org_id: p.orgId ?? null,
      requiredPaths: extractInputPaths(p.rules),
    }))
    .sort((a, b) => String(a.id).localeCompare(String(b.id)));

  return {
    version: 1,
    generatedAt,
    policies: list,
  };
}
