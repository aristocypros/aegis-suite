// Walk a policy rule's first branch and synthesize an input document that
// would satisfy every condition. Users can then tweak it in the Sandbox.
//
// We aim for the simplest "happy path": one branch's worth of satisfying
// values, picking literal `right` values when present and inferring sensible
// placeholders otherwise. Path-vs-path (`rightType: "ref"`) comparisons set
// both sides consistently with the operator.

function setPath(obj, path, value) {
  const parts = stripInputPrefix(path);
  if (!parts.length) return;
  let cur = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    const k = parts[i];
    if (cur[k] == null || typeof cur[k] !== "object" || Array.isArray(cur[k])) {
      cur[k] = {};
    }
    cur = cur[k];
  }
  cur[parts[parts.length - 1]] = value;
}

function getPath(obj, path) {
  const parts = stripInputPrefix(path);
  let cur = obj;
  for (const k of parts) {
    if (cur == null || typeof cur !== "object") return undefined;
    cur = cur[k];
  }
  return cur;
}

function stripInputPrefix(path) {
  const parts = path.split(".");
  if (parts[0] === "input") parts.shift();
  return parts;
}

function placeholderFor(path, rightType) {
  const parts = stripInputPrefix(path);
  const last = (parts[parts.length - 1] || "").toLowerCase();

  // Special handling for PEP caller paths to provide high-quality sandbox mocks
  if (parts.length > 0 && parts[0] === "caller") {
    if (parts.length === 1) {
      return {
        id: "checkout-service",
        mode: "hmac",
        orgId: "default-org",
        tenant: "tenant-1",
        status: "active",
        scopeTags: ["payment", "checkout"]
      };
    }
    if (last === "id" || last === "callerid" || last === "caller_id") return "checkout-service";
    if (last === "orgid" || last === "org_id") return "default-org";
    if (last === "mode" || last === "authmode" || last === "auth_mode") return "hmac";
    if (last === "tenant") return "tenant-1";
    if (last === "status") return "active";
    if (last === "scopetags" || last === "scope_tags") return ["payment", "checkout"];
    if (last === "allowedcn" || last === "allowed_cn") return "checkout-service.local";
    if (last === "jwtsubject" || last === "jwt_subject") return "sub-12345";
  }

  if (rightType === "boolean") return false;
  if (rightType === "number") {
    if (last.endsWith("_count") || last === "count") return 1;
    if (last.endsWith("_bps")) return 0;
    if (last.endsWith("_pct") || last.endsWith("_percent")) return 0;
    if (last.endsWith("_ts") || last.endsWith("_at") || last === "now_ts") {
      return Math.floor(Date.now() / 1000);
    }
    return 0;
  }
  if (last === "id" || last.endsWith("_id") || last.endsWith("id")) return last;
  if (last === "active" || last === "signed" || last === "verified") return true;
  if (last === "status") return "verified";
  if (last === "role") return "user";
  return "";
}

function valueForCondition(cond) {
  const { op, right, rightType } = cond;
  switch (op) {
    case "==":
      return rightType === "ref" ? { kind: "mirror" } : { kind: "value", value: right };
    case "!=":
      if (rightType === "ref") return { kind: "differ" };
      if (rightType === "boolean") return { kind: "value", value: !right };
      if (rightType === "number") return { kind: "value", value: (Number(right) || 0) + 1 };
      if (rightType === "string") return { kind: "value", value: String(right || "") + "_other" };
      return { kind: "placeholder" };
    case "<":
      if (rightType === "number") return { kind: "value", value: Math.max(0, Number(right) - 1) };
      return { kind: "placeholder" };
    case "<=":
      if (rightType === "number") return { kind: "value", value: Number(right) };
      if (rightType === "ref") return { kind: "mirror" };
      return { kind: "placeholder" };
    case ">":
      if (rightType === "number") return { kind: "value", value: Number(right) + 1 };
      return { kind: "placeholder" };
    case ">=":
      if (rightType === "number") return { kind: "value", value: Number(right) };
      if (rightType === "ref") return { kind: "mirror" };
      return { kind: "placeholder" };
    case "in":
      if (Array.isArray(right) && right.length) return { kind: "value", value: right[0] };
      return { kind: "placeholder" };
    case "contains":
    case "startswith":
    case "endswith":
      return { kind: "value", value: typeof right === "string" ? right : "" };
    case "regex":
      return { kind: "placeholder" };
    case "exists":
      return { kind: "placeholder" };
    default:
      return { kind: "placeholder" };
  }
}

function applyAdvancedCondition(out, cond) {
  switch (cond.condType) {
    case "arith":
      // Can't synthesise both sides of an arithmetic expression reliably.
      // Set the right-hand ref/number if it's a plain ref we can resolve.
      if (cond.rightType === "ref" && typeof cond.right === "string") {
        if (getPath(out, cond.right) === undefined) setPath(out, cond.right, 0);
      }
      break;

    case "aggregate": {
      // Seed the collection with the required number of satisfying items.
      const n = typeof cond.right === "number" ? cond.right : 1;
      const col = cond.collection;
      if (!col) break;
      // Build a single seed item that satisfies the filter conditions.
      const item = {};
      for (const f of cond.filter || []) {
        if (!f.left || f.negate) continue;
        // Strip leading variable name (e.g. "item.") before setting on item.
        const dotIdx = f.left.indexOf(".");
        const key = dotIdx >= 0 ? f.left.slice(dotIdx + 1) : f.left;
        if (f.op === "==" && f.rightType !== "ref") item[key] = f.right;
        else if (f.op === "exists") item[key] = true;
      }
      // Seed count to satisfy >= / == comparison
      const existing = getPath(out, col);
      if (!Array.isArray(existing)) setPath(out, col, Array(n).fill(item));
      break;
    }

    case "every": {
      const col = cond.collection;
      if (!col) break;
      const item = {};
      for (const f of cond.conditions || []) {
        if (!f.left || f.negate) continue;
        const varPrefix = (cond.variable || "item") + ".";
        const key = f.left.startsWith(varPrefix) ? f.left.slice(varPrefix.length) : f.left;
        if (f.op === "==" && f.rightType !== "ref") item[key] = f.right;
        else if (f.op === "in" && Array.isArray(f.right) && f.right.length) item[key] = f.right[0];
        else if (f.op === "exists") item[key] = true;
        else if (f.op === "<=") item[key] = typeof f.right === "number" ? f.right : 0;
        else if (f.op === "<") item[key] = typeof f.right === "number" ? Math.max(0, f.right - 1) : 0;
        else if (f.op === ">=") item[key] = typeof f.right === "number" ? f.right : 0;
        else if (f.op === ">") item[key] = typeof f.right === "number" ? f.right + 1 : 1;
      }
      const existing = getPath(out, col);
      if (!Array.isArray(existing)) setPath(out, col, [item]);
      break;
    }

    case "builtin_left":
      // time.now_ns() comparisons — seed the right-hand timestamp field
      if (cond.rightType === "ref" && typeof cond.right === "string") {
        if (getPath(out, cond.right) === undefined) {
          const now = Date.now() * 1e6; // ms → ns approximation
          setPath(out, cond.right, now);
        }
      }
      break;

    case "object_get":
      // Seed the obj path with an object containing the key set to the default
      // so the policy has something to work with.
      if (cond.obj && getPath(out, cond.obj) === undefined) {
        const seed = {};
        if (cond.key !== undefined) {
          seed[cond.key] = cond.default !== undefined ? cond.default : null;
        }
        setPath(out, cond.obj, seed);
      }
      break;

    case "verification": {
      // Seed each ref-typed arg with a placeholder string so the sandbox
      // payload exposes the slot. Token / key / signature paths cannot be
      // synthesised to satisfy a real signature check — users plug in
      // fixture values.
      const placeholderFor = (path) => {
        const last = (path.split(".").pop() || "").toLowerCase();
        if (last.includes("token")) return "<paste signed JWT here>";
        if (last.includes("secret") || last.includes("hmac")) return "<hmac secret>";
        if (last.includes("public") || last.includes("pem") || last.includes("key")) return "<PEM-encoded public key>";
        if (last.includes("cert")) return "<PEM-encoded certificate chain>";
        if (last.includes("payload")) return "<bytes to hash>";
        if (last.includes("hex") || last.includes("signature") || last.includes("expected")) return "";
        return "";
      };
      for (const a of cond.args || []) {
        if (!a || a.type !== "ref" || typeof a.value !== "string") continue;
        if (getPath(out, a.value) === undefined) {
          setPath(out, a.value, placeholderFor(a.value));
        }
      }
      if (cond.compareTo && cond.compareTo.type === "ref" && typeof cond.compareTo.value === "string") {
        if (getPath(out, cond.compareTo.value) === undefined) {
          setPath(out, cond.compareTo.value, "");
        }
      }
      break;
    }

    case "raw":
      // Raw Rego — cannot introspect; no seed applied.
      break;

    default:
      break;
  }
}

function applyCondition(out, cond) {
  // Route advanced condType conditions to their own handler.
  if (cond.condType) { applyAdvancedCondition(out, cond); return; }

  // Negated conditions invert the rule logic; satisfying them requires a
  // value that makes the underlying expression false. For now we just skip
  // them — users can tweak the generated payload to fail what they want.
  if (cond.negate) return;

  const path = cond.left;
  if (!path) return;

  const isRef = cond.rightType === "ref" && typeof cond.right === "string";
  const decision = valueForCondition(cond);

  // Ref-typed comparisons drive BOTH sides — they must override any earlier
  // placeholder values, otherwise an `exists` condition seen first would
  // pin both paths to the same string and break a downstream `!=` check.
  if (isRef) {
    const leftExisting = getPath(out, path);
    const rightExisting = getPath(out, cond.right);
    const base = leftExisting ?? rightExisting ?? placeholderFor(path, "string");

    switch (decision.kind) {
      case "differ": {
        const lv = typeof base === "string" ? base + "_a" : base;
        const rv = typeof base === "string" ? base + "_b" : base;
        setPath(out, path, lv);
        setPath(out, cond.right, rv);
        return;
      }
      case "mirror": {
        setPath(out, path, base);
        setPath(out, cond.right, base);
        return;
      }
      default: {
        // For < / <= / > / >= against a ref, just keep both sides equal — the
        // caller can tune. Numeric +/-1 nudges aren't worth the complexity
        // since users see the values and can edit.
        setPath(out, path, base);
        if (getPath(out, cond.right) === undefined) setPath(out, cond.right, base);
        return;
      }
    }
  }

  // Non-ref conditions — only fill if not already set, so the first
  // satisfying value wins.
  if (getPath(out, path) !== undefined) return;

  let leftValue;
  switch (decision.kind) {
    case "value":
      leftValue = decision.value;
      break;
    case "placeholder":
    default:
      leftValue = placeholderFor(path, cond.rightType);
      break;
  }
  setPath(out, path, leftValue);
}

function getGroups(branch) {
  if (Array.isArray(branch.groups) && branch.groups.length) return branch.groups;
  return [{ mode: "and", conditions: branch.conditions || [] }];
}

// Build a sample input that satisfies all branches of the named rule.
// If no rule name is given, satisfies all branches of every rule.
//
// Branch semantics: branches are OR'd, but we walk ALL of them so every
// field referenced in the policy gets a seed value. First-written-wins for
// non-ref conditions, so conflicting branches don't overwrite each other.
// Inside a branch, groups are AND'd, so satisfy every group.
// AND group: satisfy every condition. OR group: satisfy ONE (the first).
export function buildSampleInput(policy, ruleName) {
  const rules = (policy?.rules || []).filter(
    (r) => !ruleName || r.name === ruleName
  );
  const out = {};

  for (const rule of rules) {
    const branches = rule.branches || [];
    for (const branch of branches) {
      for (const group of getGroups(branch)) {
        const conds = group.conditions || [];
        if (conds.length === 0) continue;
        if (group.mode === "or") {
          // Pick the first condition — that's enough to satisfy the OR group.
          applyCondition(out, conds[0]);
        } else {
          for (const cond of conds) {
            applyCondition(out, cond);
          }
        }
      }
    }
  }

  if (out.caller && typeof out.caller === "object" && !Array.isArray(out.caller)) {
    const defaultCaller = {
      id: "checkout-service",
      mode: "hmac",
      orgId: "default-org",
      tenant: "tenant-1",
      status: "active",
      scopeTags: ["payment", "checkout"]
    };
    out.caller = { ...defaultCaller, ...out.caller };
  }

  return out;
}
