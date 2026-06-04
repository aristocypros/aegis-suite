// regoCompiler.js
// Converts a JSON policy spec (the visual builder output) into a Rego module string.
//
// Spec shape:
// {
//   package: "namespace.policy",
//   imports: ["rego.v1"]?,
//   rules: [
//     {
//       name: "allow",
//       type: "boolean" | "object" | "string" | "number",
//       default: false,
//       returnValue?: any,            // value emitted when the rule matches (for non-boolean rules)
//       branches: [
//         {
//           description?: "...",
//           // Branches OR'd at the rule level (multi-head Rego). Inside a branch,
//           // groups are ANDed; conditions inside a group follow the group's mode
//           // ("and" → AND'd inline, "or" → emitted as a helper rule with multi heads).
//           groups?: [
//             { mode: "and" | "or", conditions: [{...}] }
//           ],
//           // Legacy shape — single implicit AND group.
//           conditions?: [
//             { left: "input.x", op: "==", right: "value", rightType: "string" | "number" | "boolean" | "ref" | "null" | "array", negate?: false }
//           ]
//         }
//       ]
//     }
//   ]
// }

const VALID_OPS = new Set([
  "==", "!=", "<", "<=", ">", ">=",
  "in", "contains", "startswith", "endswith", "regex",
  "exists",
  // String normalization
  "lower_eq", "upper_eq",
  // Aggregate builtins
  "count_gte", "count_lte", "sum_gte", "sum_lte",
  // Network
  "cidr_contains",
  // Type guards (unary)
  "is_number", "is_string", "is_array", "is_object",
  // Time builtins (unary — compare time.now_ns() to the left-hand field)
  "time_now_gte", "time_now_lte",
]);

const VALID_COND_TYPES = new Set(["arith", "aggregate", "every", "builtin_left", "object_get", "raw", "verification", "verify"]);

const VALID_RULE_KINDS = new Set(["partial_set", "result_object"]);

const VALID_FIELD_VALUE_TYPES = new Set(["ref", "string", "number", "boolean", "null"]);

const VALID_AGGREGATE_FNS = new Set(["count", "sum", "min", "max"]);

// Builtins permitted as the LEFT side of a `builtin_left` condition.
// Crypto/JWT functions are NOT included here — they live in VERIFICATION_FUNCS
// and route through the `verification` condType, which knows about their
// multi-arg shapes and return-tuple semantics.
const VALID_BUILTINS = new Set(["time.now_ns", "time.weekday", "time.date"]);

// Category dictates how the function is rendered:
//   bool   → single boolean expression  `fn(args...)`
//   tuple  → multi-line  `[bind...] := fn(args...)` (+ truthy guard if requireValid)
//   value  → `fn(args...) <op> rhs` (compare mode) or `bind := fn(args...)` (bind mode)
const VERIFICATION_FUNCS = {
  // JWT signature verification (token, key) → bool
  "io.jwt.verify_es256": { category: "bool",  arity: 2 },
  "io.jwt.verify_es384": { category: "bool",  arity: 2 },
  "io.jwt.verify_es512": { category: "bool",  arity: 2 },
  "io.jwt.verify_rs256": { category: "bool",  arity: 2 },
  "io.jwt.verify_rs384": { category: "bool",  arity: 2 },
  "io.jwt.verify_rs512": { category: "bool",  arity: 2 },
  "io.jwt.verify_ps256": { category: "bool",  arity: 2 },
  "io.jwt.verify_ps384": { category: "bool",  arity: 2 },
  "io.jwt.verify_ps512": { category: "bool",  arity: 2 },
  "io.jwt.verify_hs256": { category: "bool",  arity: 2 },
  "io.jwt.verify_hs384": { category: "bool",  arity: 2 },
  "io.jwt.verify_hs512": { category: "bool",  arity: 2 },
  // JWT decode (tuple returns)
  "io.jwt.decode_verify": { category: "tuple", arity: 2, returns: ["valid", "header", "payload"], requireValid: true },
  "io.jwt.decode":        { category: "tuple", arity: 1, returns: ["header", "payload", "sig"],   requireValid: false },
  // X.509
  "crypto.x509.parse_and_verify_certificates": { category: "tuple", arity: 1, returns: ["valid", "certs"], requireValid: true },
  "crypto.x509.parse_certificates":            { category: "value", arity: 1 },
  // HMAC
  "crypto.hmac.sha256": { category: "value", arity: 2 },
  "crypto.hmac.sha384": { category: "value", arity: 2 },
  "crypto.hmac.sha512": { category: "value", arity: 2 },
  "crypto.hmac.equal":  { category: "bool",  arity: 2 },
  // Hashes
  "crypto.sha256": { category: "value", arity: 1 },
  "crypto.sha1":   { category: "value", arity: 1, deprecated: true },
  "crypto.md5":    { category: "value", arity: 1, deprecated: true },
};

// High-level `verify` condType — a discriminated union wrapper over the
// low-level `verification` primitives. CRY-02. Kinds:
//   jwt   → io.jwt.decode_verify with constraints object
//   x509  → crypto.x509.parse_and_verify_certificates
//   raw   → crypto.hmac.<sha256|sha384|sha512> + crypto.hmac.equal (HMAC only)
// jws and asymmetric raw verify are intentionally deferred — OPA has no clean
// primitive for them.
const VERIFY_KINDS = new Set(["jwt", "x509", "raw"]);
const VERIFY_DEFERRED_KINDS = new Set(["jws"]);
// Exported so the CRY-03 trust store can validate uploaded keys against the
// exact same alg set the compiler accepts in policy spec `verify` conditions.
export const JWT_ALGS = new Set([
  "EdDSA",
  "ES256", "ES384", "ES512",
  "RS256", "RS384", "RS512",
  "PS256", "PS384", "PS512",
  "HS256", "HS384", "HS512",
]);
export const HMAC_ALGS = new Set(["HS256", "HS384", "HS512"]);
const ALG_TO_HMAC_FUNC = {
  HS256: "crypto.hmac.sha256",
  HS384: "crypto.hmac.sha384",
  HS512: "crypto.hmac.sha512",
};
const MAX_INLINE_PEM_LEN = 16384;
const MAX_INLINE_SECRET_LEN = 1024;
// Exported so CRY-03 can refuse to store a kid that wouldn't be addressable
// from a policy spec (the compiler emits `data.studio.keys[<kid>]` with the
// quoted literal, and the literal must match this regex).
export const SELECTOR_LITERAL_RE = /^[\w.-]+$/;

// Package roots that the OPA bundle owns (system_authz / studio_authz / the
// published data documents) plus the `__preview_` namespace used by the
// transient preview-evaluate push. A user policy whose first package segment
// collides with one of these would overlap a declared bundle root and make
// OPA reject the ENTIRE bundle as a root conflict — bricking the whole PDP
// fleet. Refuse such packages at compile and validate time. `__preview_`
// must stay reserved so the preview path can keep pushing temp modules
// OUTSIDE the bundle roots (see /api/preview-evaluate).
export const RESERVED_PACKAGE_ROOTS = new Set(["system", "studio", "platform_keys"]);

// Returns an error string if `pkg`'s first segment is reserved, else null.
export function reservedPackageRootError(pkg) {
  if (typeof pkg !== "string" || pkg.length === 0) return null;
  const root = pkg.split(".")[0];
  if (root.startsWith("__preview_")) {
    return `Reserved package root '__preview_*' (used internally for preview evaluation): ${pkg}`;
  }
  if (RESERVED_PACKAGE_ROOTS.has(root)) {
    return `Reserved package root '${root}' (owned by the OPA bundle): ${pkg}`;
  }
  return null;
}

const IDENT_RE = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
const OBJECT_KEY_RE = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
const CMP_OPS_SET = new Set(["==", "!=", "<", "<=", ">", ">="]);

// Whitelist for arithmetic expression left-hand sides:
// identifiers, dots, brackets, arithmetic operators, digits, spaces, parens
const ARITH_EXPR_RE = /^[a-zA-Z0-9_.()\[\] +\-*/%]+$/;

function indent(str, level = 1) {
  const pad = "    ".repeat(level);
  return str
    .split("\n")
    .map((l) => (l.length ? pad + l : l))
    .join("\n");
}

function escapeString(s) {
  return `"${String(s).replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n")}"`;
}

function isValidRegoRef(ref) {
  // Must start with input., data., or be a bare identifier path.
  return /^[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*|\[[^\]]+\])*$/.test(ref);
}

function renderValue(value, type) {
  if (type === "ref") {
    if (typeof value !== "string" || !isValidRegoRef(value)) {
      throw new Error(`Invalid Rego reference: ${value}`);
    }
    return value;
  }
  if (type === "null" || value === null) return "null";
  if (type === "boolean") return value ? "true" : "false";
  if (type === "number") {
    if (typeof value !== "number" && typeof value !== "string") {
      throw new Error(`Number value must be number or numeric string`);
    }
    const n = Number(value);
    if (Number.isNaN(n)) throw new Error(`Not a number: ${value}`);
    return String(n);
  }
  if (type === "string") return escapeString(value);
  if (type === "array") {
    if (!Array.isArray(value)) throw new Error(`Array value must be array`);
    return "[" + value.map((v) => renderArrayElem(v)).join(", ") + "]";
  }
  // Fallback: infer from JS type
  if (typeof value === "string") return escapeString(value);
  if (typeof value === "number") return String(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (value === null) return "null";
  if (Array.isArray(value)) return "[" + value.map(renderArrayElem).join(", ") + "]";
  return escapeString(String(value));
}

function renderArrayElem(v) {
  if (typeof v === "string") {
    // If it looks like a Rego reference, treat it as one
    if (v.startsWith("input.") || v.startsWith("data.")) return v;
    return escapeString(v);
  }
  if (typeof v === "number") return String(v);
  if (typeof v === "boolean") return v ? "true" : "false";
  if (v === null) return "null";
  return escapeString(String(v));
}

function renderCondition(cond) {
  const { left, op, right, rightType, negate } = cond;

  if (!left || typeof left !== "string") {
    throw new Error("Condition missing 'left' (path)");
  }
  if (!isValidRegoRef(left)) {
    throw new Error(`Invalid left-hand reference: ${left}`);
  }
  if (!VALID_OPS.has(op)) {
    throw new Error(`Unsupported operator: ${op}`);
  }

  let expr;

  switch (op) {
    case "==":
    case "!=":
    case "<":
    case "<=":
    case ">":
    case ">=":
      expr = `${left} ${op} ${renderValue(right, rightType)}`;
      break;
    case "in":
      expr = `${left} in ${renderValue(right, rightType || "array")}`;
      break;
    case "contains":
      expr = `contains(${left}, ${renderValue(right, "string")})`;
      break;
    case "startswith":
      expr = `startswith(${left}, ${renderValue(right, "string")})`;
      break;
    case "endswith":
      expr = `endswith(${left}, ${renderValue(right, "string")})`;
      break;
    case "regex":
      expr = `regex.match(${renderValue(right, "string")}, ${left})`;
      break;
    case "exists":
      expr = left;
      break;
    // String normalization
    case "lower_eq":
      expr = `lower(${left}) == ${renderValue(right, "string")}`;
      break;
    case "upper_eq":
      expr = `upper(${left}) == ${renderValue(right, "string")}`;
      break;
    // Aggregate builtins
    case "count_gte":
      expr = `count(${left}) >= ${renderValue(right, "number")}`;
      break;
    case "count_lte":
      expr = `count(${left}) <= ${renderValue(right, "number")}`;
      break;
    case "sum_gte":
      expr = `sum(${left}) >= ${renderValue(right, "number")}`;
      break;
    case "sum_lte":
      expr = `sum(${left}) <= ${renderValue(right, "number")}`;
      break;
    // Network
    case "cidr_contains":
      expr = `net.cidr_contains(${renderValue(right, "string")}, ${left})`;
      break;
    // Type guards (unary)
    case "is_number":
      expr = `is_number(${left})`;
      break;
    case "is_string":
      expr = `is_string(${left})`;
      break;
    case "is_array":
      expr = `is_array(${left})`;
      break;
    case "is_object":
      expr = `is_object(${left})`;
      break;
    // Time builtins: compare time.now_ns() to the left-hand timestamp field
    case "time_now_gte":
      expr = `time.now_ns() >= ${left}`;
      break;
    case "time_now_lte":
      expr = `time.now_ns() <= ${left}`;
      break;
    default:
      throw new Error(`Unhandled op ${op}`);
  }

  if (negate) {
    return `not ${expr}`;
  }
  return expr;
}

// ─── condType renderers ────────────────────────────────────────────────────

function renderArithCondition(cond) {
  const { leftExpr, op, right, rightType, negate } = cond;
  if (!leftExpr || typeof leftExpr !== "string") {
    throw new Error("arith condition missing 'leftExpr'");
  }
  if (!ARITH_EXPR_RE.test(leftExpr)) {
    throw new Error(`Invalid arithmetic expression: ${leftExpr}`);
  }
  const CMP_OPS = new Set(["==", "!=", "<", "<=", ">", ">="]);
  if (!CMP_OPS.has(op)) {
    throw new Error(`arith condition op must be a comparison, got: ${op}`);
  }
  const expr = `${leftExpr} ${op} ${renderValue(right, rightType)}`;
  return negate ? `not (${expr})` : expr;
}

function renderAggregateCondition(cond) {
  const { fn, collection, filter, op, right, rightType, negate } = cond;
  if (!VALID_AGGREGATE_FNS.has(fn)) {
    throw new Error(`Invalid aggregate fn: ${fn}`);
  }
  if (!collection || !isValidRegoRef(collection)) {
    throw new Error(`Invalid aggregate collection: ${collection}`);
  }
  const CMP_OPS = new Set(["==", "!=", "<", "<=", ">", ">="]);
  if (!CMP_OPS.has(op)) {
    throw new Error(`aggregate condition op must be a comparison, got: ${op}`);
  }

  let collectionExpr;
  if (Array.isArray(filter) && filter.length > 0) {
    // Filtered comprehension: [item | some item in collection; cond1; cond2; ...]
    const filterLines = filter.map((f) => renderCondition(f)).join("; ");
    collectionExpr = `[item | some item in ${collection}; ${filterLines}]`;
  } else {
    collectionExpr = collection;
  }

  const expr = `${fn}(${collectionExpr}) ${op} ${renderValue(right, rightType)}`;
  return negate ? `not (${expr})` : expr;
}

function renderEveryCondition(cond) {
  const { variable, collection, conditions, negate } = cond;
  if (!variable || !/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(variable)) {
    throw new Error(`Invalid every variable: ${variable}`);
  }
  if (!collection || !isValidRegoRef(collection)) {
    throw new Error(`Invalid every collection: ${collection}`);
  }
  const conds = Array.isArray(conditions) ? conditions : [];
  const innerLines = conds.map((c) => "    " + renderCondition(c)).join("\n");
  const block = `every ${variable} in ${collection} {\n${innerLines || "    true"}\n}`;
  return negate ? `not (${block})` : block;
}

function renderBuiltinLeftCondition(cond) {
  const { builtin, arg, component, op, right, rightType, negate } = cond;
  if (!VALID_BUILTINS.has(builtin)) {
    throw new Error(`Unsupported builtin: ${builtin}`);
  }
  const CMP_OPS = new Set(["==", "!=", "<", "<=", ">", ">="]);
  if (!CMP_OPS.has(op)) {
    throw new Error(`builtin_left condition op must be a comparison, got: ${op}`);
  }

  let leftExpr;
  switch (builtin) {
    case "time.now_ns":
      leftExpr = "time.now_ns()";
      break;
    case "time.weekday":
      if (!arg || !isValidRegoRef(arg)) throw new Error(`time.weekday requires arg`);
      leftExpr = `time.weekday(${arg})`;
      break;
    case "time.date":
      if (!arg || !isValidRegoRef(arg)) throw new Error(`time.date requires arg`);
      if (component === undefined) throw new Error(`time.date requires component (0=year,1=month,2=day)`);
      leftExpr = `time.date(${arg})[${component}]`;
      break;
    default:
      throw new Error(`Unhandled builtin: ${builtin}`);
  }

  const expr = `${leftExpr} ${op} ${renderValue(right, rightType)}`;
  return negate ? `not (${expr})` : expr;
}

function renderObjectGetCondition(cond) {
  const { obj, key, keyType, default: def, defaultType, op, right, rightType, negate } = cond;
  if (!obj || !isValidRegoRef(obj)) {
    throw new Error(`object_get: invalid obj '${obj}'`);
  }
  const VALID_OPS_OBJ = new Set(["==", "!=", "<", "<=", ">", ">=", "in"]);
  if (!VALID_OPS_OBJ.has(op)) {
    throw new Error(`object_get: unsupported op '${op}'`);
  }
  const keyExpr = renderValue(key, keyType || "string");
  const defExpr = renderValue(def, defaultType || "string");
  const call = `object.get(${obj}, ${keyExpr}, ${defExpr})`;
  let expr;
  if (op === "in") {
    expr = `${call} in ${renderValue(right, rightType || "array")}`;
  } else {
    expr = `${call} ${op} ${renderValue(right, rightType)}`;
  }
  return negate ? `not (${expr})` : expr;
}

function renderObjectLiteral(obj) {
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) {
    throw new Error("verification: object arg must be a non-array object");
  }
  const parts = [];
  for (const [k, v] of Object.entries(obj)) {
    if (!OBJECT_KEY_RE.test(k)) {
      throw new Error(`verification: object key '${k}' is not a Rego-safe identifier`);
    }
    let rendered;
    if (v && typeof v === "object" && !Array.isArray(v) && v.__ref) {
      if (!isValidRegoRef(v.__ref)) throw new Error(`verification: invalid object-arg ref '${v.__ref}'`);
      rendered = v.__ref;
    } else if (Array.isArray(v)) {
      rendered = "[" + v.map(renderArrayElem).join(", ") + "]";
    } else if (typeof v === "string") {
      rendered = escapeString(v);
    } else if (typeof v === "number" || typeof v === "boolean") {
      rendered = String(v);
    } else if (v === null) {
      rendered = "null";
    } else {
      throw new Error(`verification: unsupported object value for key '${k}'`);
    }
    parts.push(`${escapeString(k)}: ${rendered}`);
  }
  return `{${parts.join(", ")}}`;
}

function renderVerificationArg(arg, where) {
  if (!arg || typeof arg !== "object") {
    throw new Error(`${where}: arg must be an object {value, type}`);
  }
  const t = arg.type || "ref";
  if (t === "object") return renderObjectLiteral(arg.value);
  if (t === "ref") {
    if (typeof arg.value !== "string" || !isValidRegoRef(arg.value)) {
      throw new Error(`${where}: invalid ref '${arg.value}'`);
    }
    return arg.value;
  }
  if (t === "string" || t === "number" || t === "boolean" || t === "null" || t === "array") {
    return renderValue(arg.value, t);
  }
  throw new Error(`${where}: unsupported arg type '${t}'`);
}

function renderVerificationCondition(cond) {
  const fn = cond.function;
  const spec = VERIFICATION_FUNCS[fn];
  if (!spec) throw new Error(`Unsupported verification function: ${fn}`);

  const args = Array.isArray(cond.args) ? cond.args : [];
  if (args.length !== spec.arity) {
    throw new Error(`verification ${fn}: expected ${spec.arity} arg(s), got ${args.length}`);
  }
  const renderedArgs = args.map((a, i) => renderVerificationArg(a, `verification ${fn} arg ${i}`));
  const call = `${fn}(${renderedArgs.join(", ")})`;

  const lines = [];
  if (spec.deprecated) {
    lines.push(`# DEPRECATED: ${fn} — replace with crypto.sha256 or stronger`);
  }

  if (spec.category === "bool") {
    const expr = cond.negate ? `not ${call}` : call;
    lines.push(expr);
    return lines.join("\n");
  }

  if (spec.category === "tuple") {
    const binds = Array.isArray(cond.bind) ? cond.bind : spec.returns;
    if (binds.length !== spec.returns.length) {
      throw new Error(`verification ${fn}: expected ${spec.returns.length} bind name(s), got ${binds.length}`);
    }
    for (const b of binds) {
      if (typeof b !== "string" || !IDENT_RE.test(b)) {
        throw new Error(`verification ${fn}: invalid bind identifier '${b}'`);
      }
    }
    lines.push(`[${binds.join(", ")}] := ${call}`);
    if (spec.requireValid) {
      const guardVar = binds[0];
      lines.push(cond.negate ? `not ${guardVar}` : guardVar);
    } else if (cond.negate) {
      // Without a truthy guard there's nothing to negate — surface that.
      throw new Error(`verification ${fn}: cannot negate a decode-only call (no truthy guard)`);
    }
    return lines.join("\n");
  }

  if (spec.category === "value") {
    if (cond.bindAs !== undefined && cond.bindAs !== null && cond.bindAs !== "") {
      if (typeof cond.bindAs !== "string" || !IDENT_RE.test(cond.bindAs)) {
        throw new Error(`verification ${fn}: invalid bindAs identifier '${cond.bindAs}'`);
      }
      if (cond.compareOp) {
        throw new Error(`verification ${fn}: bindAs and compareOp are mutually exclusive`);
      }
      if (cond.negate) {
        throw new Error(`verification ${fn}: cannot negate a bind-only call`);
      }
      lines.push(`${cond.bindAs} := ${call}`);
      return lines.join("\n");
    }
    if (!cond.compareOp || !CMP_OPS_SET.has(cond.compareOp)) {
      throw new Error(`verification ${fn}: value-returning calls require compareOp or bindAs`);
    }
    if (!cond.compareTo || typeof cond.compareTo !== "object") {
      throw new Error(`verification ${fn}: missing compareTo {value, type}`);
    }
    const rhs = renderVerificationArg(cond.compareTo, `verification ${fn} compareTo`);
    const expr = `${call} ${cond.compareOp} ${rhs}`;
    lines.push(cond.negate ? `not (${expr})` : expr);
    return lines.join("\n");
  }

  throw new Error(`verification: unknown category '${spec.category}'`);
}

function renderRawCondition(cond) {
  if (!cond.rego || typeof cond.rego !== "string") {
    throw new Error("raw condition missing 'rego' string");
  }
  if (!/^[\x20-\x7E\n\r\t]+$/.test(cond.rego)) {
    throw new Error("raw condition 'rego' must contain only printable ASCII characters");
  }
  return cond.rego;
}

// ─── verify (CRY-02) ──────────────────────────────────────────────────────
// Module-level counter so __verify_*_N locals are unique within one compile()
// invocation. Reset at the top of compile().
let __verifyCounter = 0;

function isLikelyPem(s) {
  return /-----BEGIN [A-Z0-9 ]+-----[\s\S]+-----END [A-Z0-9 ]+-----/.test(s);
}

// Selector → Rego expression. A selector that looks like a Rego ref
// (input./data.) is emitted as a bracketed dynamic lookup; otherwise it
// must match SELECTOR_LITERAL_RE and is emitted as a quoted string index.
function selectorToKeyRef(selector, where) {
  if (typeof selector !== "string" || selector.length === 0) {
    throw new Error(`${where}: keyRef.selector must be a non-empty string`);
  }
  if (selector.startsWith("input.") || selector.startsWith("data.")) {
    if (!isValidRegoRef(selector)) {
      throw new Error(`${where}: keyRef.selector invalid ref '${selector}'`);
    }
    return `data.studio.keys[${selector}]`;
  }
  if (!SELECTOR_LITERAL_RE.test(selector)) {
    throw new Error(`${where}: keyRef.selector literal must match [\\w.-]+ (got '${selector}')`);
  }
  return `data.studio.keys[${escapeString(selector)}]`;
}

// Returns a value suitable for renderObjectLiteral: either a plain string
// (will be escapeString'd as a Rego string literal) or { __ref: "<rego>" }
// for an embedded Rego reference such as data.studio.keys[...].
function renderJwtKeyForConstraints(keyRef, alg, where) {
  if (!keyRef || typeof keyRef !== "object") {
    throw new Error(`${where}: missing keyRef`);
  }
  const isHmac = HMAC_ALGS.has(alg);
  const source = keyRef.source;
  if (source === "jwks_url") {
    throw new Error(`${where}: keyRef.source 'jwks_url' requires CRY-03 trust store (not yet implemented)`);
  }
  if (source === "inline_pem") {
    if (isHmac) throw new Error(`${where}: HMAC alg '${alg}' requires keyRef.source 'inline_secret' or 'data.studio.keys'`);
    if (typeof keyRef.pem !== "string" || keyRef.pem.length === 0) {
      throw new Error(`${where}: keyRef.pem must be a non-empty PEM block`);
    }
    if (keyRef.pem.length > MAX_INLINE_PEM_LEN) {
      throw new Error(`${where}: keyRef.pem exceeds ${MAX_INLINE_PEM_LEN} chars`);
    }
    if (!isLikelyPem(keyRef.pem)) {
      throw new Error(`${where}: keyRef.pem is not a valid PEM block`);
    }
    return keyRef.pem;
  }
  if (source === "inline_secret") {
    if (!isHmac) throw new Error(`${where}: keyRef.source 'inline_secret' only valid for HMAC algs (got '${alg}')`);
    if (typeof keyRef.secret !== "string" || keyRef.secret.length === 0) {
      throw new Error(`${where}: keyRef.secret must be a non-empty string`);
    }
    if (keyRef.secret.length > MAX_INLINE_SECRET_LEN) {
      throw new Error(`${where}: keyRef.secret exceeds ${MAX_INLINE_SECRET_LEN} chars`);
    }
    return keyRef.secret;
  }
  if (source === "data.studio.keys") {
    return { __ref: selectorToKeyRef(keyRef.selector, where) };
  }
  throw new Error(`${where}: keyRef.source must be 'inline_pem', 'inline_secret', or 'data.studio.keys' (got '${source}')`);
}

function renderRawHmacSecretExpr(keyRef, where) {
  if (!keyRef || typeof keyRef !== "object") {
    throw new Error(`${where}: missing keyRef`);
  }
  const source = keyRef.source;
  if (source === "jwks_url") {
    throw new Error(`${where}: keyRef.source 'jwks_url' requires CRY-03 trust store (not yet implemented)`);
  }
  if (source === "inline_secret") {
    if (typeof keyRef.secret !== "string" || keyRef.secret.length === 0) {
      throw new Error(`${where}: keyRef.secret must be a non-empty string`);
    }
    if (keyRef.secret.length > MAX_INLINE_SECRET_LEN) {
      throw new Error(`${where}: keyRef.secret exceeds ${MAX_INLINE_SECRET_LEN} chars`);
    }
    return escapeString(keyRef.secret);
  }
  if (source === "data.studio.keys") {
    return selectorToKeyRef(keyRef.selector, where);
  }
  throw new Error(`${where}: raw verify keyRef.source must be 'inline_secret' or 'data.studio.keys' (got '${source}')`);
}

function renderVerifyJwt(cond, n) {
  const where = `verify jwt`;
  if (!cond.tokenRef || !isValidRegoRef(cond.tokenRef)) {
    throw new Error(`${where}: invalid tokenRef`);
  }
  if (!JWT_ALGS.has(cond.alg)) {
    throw new Error(`${where}: invalid alg '${cond.alg}'`);
  }
  const isHmac = HMAC_ALGS.has(cond.alg);
  const keyValue = renderJwtKeyForConstraints(cond.keyRef, cond.alg, where);

  const constraintObj = { alg: cond.alg };
  if (isHmac) constraintObj.secret = keyValue;
  else constraintObj.cert = keyValue;

  const c = cond.constraints || {};
  if (c.iss !== undefined) {
    if (typeof c.iss !== "string") throw new Error(`${where}: constraints.iss must be a string`);
    constraintObj.iss = c.iss;
  }
  if (c.aud !== undefined) {
    if (typeof c.aud === "string") constraintObj.aud = c.aud;
    else if (Array.isArray(c.aud) && c.aud.every((x) => typeof x === "string")) constraintObj.aud = c.aud;
    else throw new Error(`${where}: constraints.aud must be string or array of strings`);
  }

  const constraintRego = renderObjectLiteral(constraintObj);
  const valid = `__verify_valid_${n}`;
  const header = `__verify_header_${n}`;
  const payload = `__verify_payload_${n}`;

  const lines = [
    `[${valid}, ${header}, ${payload}] := io.jwt.decode_verify(${cond.tokenRef}, ${constraintRego})`,
    valid,
  ];
  if (c.exp_required === true) lines.push(`${payload}.exp`);
  if (c.nbf_required === true) lines.push(`${payload}.nbf`);
  return lines.join("\n");
}

function renderVerifyX509(cond, n) {
  const where = `verify x509`;
  if (!cond.chainRef || !isValidRegoRef(cond.chainRef)) {
    throw new Error(`${where}: invalid chainRef`);
  }
  const valid = `__verify_valid_${n}`;
  const certs = `__verify_certs_${n}`;
  return [
    `[${valid}, ${certs}] := crypto.x509.parse_and_verify_certificates(${cond.chainRef})`,
    valid,
  ].join("\n");
}

function renderVerifyRaw(cond, n) {
  const where = `verify raw`;
  if (!HMAC_ALGS.has(cond.alg)) {
    throw new Error(`${where}: supports HMAC algorithms only (HS256/HS384/HS512), got '${cond.alg}'`);
  }
  if (!cond.payloadRef || !isValidRegoRef(cond.payloadRef)) {
    throw new Error(`${where}: invalid payloadRef`);
  }
  if (!cond.signatureRef || !isValidRegoRef(cond.signatureRef)) {
    throw new Error(`${where}: invalid signatureRef`);
  }
  const fn = ALG_TO_HMAC_FUNC[cond.alg];
  const secretExpr = renderRawHmacSecretExpr(cond.keyRef, where);
  const expected = `__verify_expected_${n}`;
  return [
    `${expected} := ${fn}(${cond.payloadRef}, ${secretExpr})`,
    `crypto.hmac.equal(${expected}, ${cond.signatureRef})`,
  ].join("\n");
}

function renderVerifyCondition(cond) {
  if (cond.negate === true) {
    throw new Error("verify condType does not support negate; invert the parent rule instead");
  }
  const kind = cond.kind;
  if (VERIFY_DEFERRED_KINDS.has(kind)) {
    throw new Error(`verify kind '${kind}' is not yet supported (deferred to future task)`);
  }
  if (!VERIFY_KINDS.has(kind)) {
    throw new Error(`verify: invalid kind '${kind}'`);
  }
  const n = ++__verifyCounter;
  if (kind === "jwt") return renderVerifyJwt(cond, n);
  if (kind === "x509") return renderVerifyX509(cond, n);
  if (kind === "raw") return renderVerifyRaw(cond, n);
  // unreachable
  throw new Error(`verify: unhandled kind '${kind}'`);
}

// Spec-shape validation mirroring renderVerifyCondition. Pushes errors but
// never throws; used by validate() so the UI can show structured feedback.
function validateVerifyConditionImpl(c, where, errors) {
  if (c.negate === true) {
    errors.push(`${where}: verify condType does not support negate; invert the parent rule instead`);
  }
  const kind = c.kind;
  if (VERIFY_DEFERRED_KINDS.has(kind)) {
    errors.push(`${where}: kind '${kind}' is not yet supported (deferred to future task)`);
    return;
  }
  if (!VERIFY_KINDS.has(kind)) {
    errors.push(`${where}: invalid kind '${kind}' (expected jwt | x509 | raw)`);
    return;
  }

  if (kind === "jwt") {
    if (!c.tokenRef || typeof c.tokenRef !== "string" || !isValidRegoRef(c.tokenRef)) {
      errors.push(`${where}: jwt verify invalid tokenRef`);
    }
    if (!JWT_ALGS.has(c.alg)) {
      errors.push(`${where}: jwt verify invalid alg '${c.alg}'`);
    }
    validateKeyRefImpl(c.keyRef, c.alg, kind, where, errors);
    validateConstraintsImpl(c.constraints, where, errors);
  } else if (kind === "x509") {
    if (!c.chainRef || typeof c.chainRef !== "string" || !isValidRegoRef(c.chainRef)) {
      errors.push(`${where}: x509 verify invalid chainRef`);
    }
  } else if (kind === "raw") {
    if (!HMAC_ALGS.has(c.alg)) {
      errors.push(`${where}: raw verify supports HMAC algorithms only (HS256/HS384/HS512), got '${c.alg}'`);
    }
    if (!c.payloadRef || typeof c.payloadRef !== "string" || !isValidRegoRef(c.payloadRef)) {
      errors.push(`${where}: raw verify invalid payloadRef`);
    }
    if (!c.signatureRef || typeof c.signatureRef !== "string" || !isValidRegoRef(c.signatureRef)) {
      errors.push(`${where}: raw verify invalid signatureRef`);
    }
    validateKeyRefImpl(c.keyRef, c.alg, kind, where, errors);
  }
}

function validateKeyRefImpl(keyRef, alg, kind, where, errors) {
  if (!keyRef || typeof keyRef !== "object" || Array.isArray(keyRef)) {
    errors.push(`${where}: missing keyRef object`);
    return;
  }
  const source = keyRef.source;
  if (source === "jwks_url") {
    errors.push(`${where}: keyRef.source 'jwks_url' requires CRY-03 trust store (not yet implemented)`);
    return;
  }
  if (kind === "raw") {
    if (source === "inline_secret") {
      if (typeof keyRef.secret !== "string" || keyRef.secret.length === 0) {
        errors.push(`${where}: keyRef.secret must be a non-empty string`);
      } else if (keyRef.secret.length > MAX_INLINE_SECRET_LEN) {
        errors.push(`${where}: keyRef.secret exceeds ${MAX_INLINE_SECRET_LEN} chars`);
      }
    } else if (source === "data.studio.keys") {
      validateSelectorImpl(keyRef.selector, where, errors);
    } else {
      errors.push(`${where}: raw verify keyRef.source must be 'inline_secret' or 'data.studio.keys' (got '${source}')`);
    }
    return;
  }
  // jwt
  const isHmac = HMAC_ALGS.has(alg);
  if (source === "inline_pem") {
    if (isHmac) {
      errors.push(`${where}: HMAC alg '${alg}' requires keyRef.source 'inline_secret' or 'data.studio.keys'`);
      return;
    }
    if (typeof keyRef.pem !== "string" || keyRef.pem.length === 0) {
      errors.push(`${where}: keyRef.pem must be a non-empty PEM block`);
    } else if (keyRef.pem.length > MAX_INLINE_PEM_LEN) {
      errors.push(`${where}: keyRef.pem exceeds ${MAX_INLINE_PEM_LEN} chars`);
    } else if (!isLikelyPem(keyRef.pem)) {
      errors.push(`${where}: keyRef.pem is not a valid PEM block`);
    }
  } else if (source === "inline_secret") {
    if (!isHmac) {
      errors.push(`${where}: keyRef.source 'inline_secret' only valid for HMAC algs (got '${alg}')`);
      return;
    }
    if (typeof keyRef.secret !== "string" || keyRef.secret.length === 0) {
      errors.push(`${where}: keyRef.secret must be a non-empty string`);
    } else if (keyRef.secret.length > MAX_INLINE_SECRET_LEN) {
      errors.push(`${where}: keyRef.secret exceeds ${MAX_INLINE_SECRET_LEN} chars`);
    }
  } else if (source === "data.studio.keys") {
    validateSelectorImpl(keyRef.selector, where, errors);
  } else {
    errors.push(`${where}: keyRef.source must be 'inline_pem', 'inline_secret', or 'data.studio.keys' (got '${source}')`);
  }
}

function validateSelectorImpl(selector, where, errors) {
  if (typeof selector !== "string" || selector.length === 0) {
    errors.push(`${where}: keyRef.selector must be a non-empty string`);
    return;
  }
  if (selector.startsWith("input.") || selector.startsWith("data.")) {
    if (!isValidRegoRef(selector)) {
      errors.push(`${where}: keyRef.selector invalid ref '${selector}'`);
    }
  } else if (!SELECTOR_LITERAL_RE.test(selector)) {
    errors.push(`${where}: keyRef.selector literal must match [\\w.-]+ (got '${selector}')`);
  }
}

function validateConstraintsImpl(c, where, errors) {
  if (c === undefined || c === null) return;
  if (typeof c !== "object" || Array.isArray(c)) {
    errors.push(`${where}: constraints must be an object`);
    return;
  }
  if (c.iss !== undefined && typeof c.iss !== "string") {
    errors.push(`${where}: constraints.iss must be a string`);
  }
  if (c.aud !== undefined) {
    const ok = typeof c.aud === "string" || (Array.isArray(c.aud) && c.aud.every((x) => typeof x === "string"));
    if (!ok) errors.push(`${where}: constraints.aud must be string or array of strings`);
  }
  if (c.exp_required !== undefined && typeof c.exp_required !== "boolean") {
    errors.push(`${where}: constraints.exp_required must be a boolean`);
  }
  if (c.nbf_required !== undefined && typeof c.nbf_required !== "boolean") {
    errors.push(`${where}: constraints.nbf_required must be a boolean`);
  }
}

// Dispatcher — routes on condType, falls back to standard renderCondition.
// Returns a string (single line or multi-line block for "every" or multi-line "raw").
function renderConditionByType(cond) {
  switch (cond.condType) {
    case "arith":        return renderArithCondition(cond);
    case "aggregate":    return renderAggregateCondition(cond);
    case "every":        return renderEveryCondition(cond);
    case "builtin_left": return renderBuiltinLeftCondition(cond);
    case "object_get":   return renderObjectGetCondition(cond);
    case "raw":          return renderRawCondition(cond);
    case "verification": return renderVerificationCondition(cond);
    case "verify":       return renderVerifyCondition(cond);
    default:             return renderCondition(cond);
  }
}

// Normalize a branch into a list of groups so the rest of the compiler can
// uniformly walk groups. A legacy `branch.conditions` array becomes one
// implicit AND group.
function getGroups(branch) {
  if (Array.isArray(branch.groups) && branch.groups.length) {
    return branch.groups.map((g) => ({
      mode: g.mode === "or" ? "or" : "and",
      conditions: Array.isArray(g.conditions) ? g.conditions : [],
    }));
  }
  return [{ mode: "and", conditions: branch.conditions || [] }];
}

function helperName(ruleName, branchIdx, groupIdx) {
  return `_${ruleName}_b${branchIdx}_g${groupIdx}`;
}

function renderBranch(rule, branch, branchIdx) {
  const lines = [];
  if (branch.description) {
    lines.push(`# ${branch.description}`);
  }

  // Build the rule head depending on kind/type
  let head;
  const ruleName = rule.name;

  if (rule.kind === "partial_set") {
    const val = branch.value !== undefined ? branch.value : "";
    const valType = branch.valueType || "string";
    head = `${ruleName} contains ${renderValue(val, valType)} if {`;
  } else if (rule.type === "boolean" || !rule.type) {
    head = `${ruleName} if {`;
  } else {
    // For object/string/number rules, we emit a value
    const val =
      branch.returnValue !== undefined ? branch.returnValue : rule.returnValue;
    const valType = branch.returnValueType || rule.returnValueType || rule.type;
    let rendered;
    if (valType === "object" && typeof val === "object") {
      rendered = JSON.stringify(val, null, 2)
        .replace(/^/gm, "")
        .replace(/^"([^"]+)":/gm, '"$1":'); // already JSON-ish, valid Rego
    } else {
      rendered = renderValue(val, valType);
    }
    head = `${ruleName} := ${rendered} if {`;
  }

  lines.push(head);

  // Walk the branch's groups: each group becomes either a sequence of inline
  // conditions (AND group) or a single helper-rule reference (OR group).
  const groups = getGroups(branch);
  const helpers = [];
  const bodyLines = [];

  groups.forEach((group, gIdx) => {
    const conds = group.conditions || [];
    if (conds.length === 0) return;

    if (group.mode === "or" && conds.length > 1) {
      const name = helperName(ruleName, branchIdx, gIdx);
      bodyLines.push({ kind: "line", text: name });
      for (const c of conds) {
        helpers.push({ name, conditions: [c] });
      }
    } else {
      for (const c of conds) {
        const rendered = renderConditionByType(c);
        // Multi-line rendered strings (every blocks, raw multi-line Rego) are
        // pushed as blocks so each line gets indented uniformly.
        bodyLines.push({ kind: rendered.includes("\n") ? "block" : "line", text: rendered });
      }
    }
  });

  if (bodyLines.length === 0) {
    lines.push("    true");
  } else {
    for (const b of bodyLines) {
      if (b.kind === "block") {
        // Multi-line block (e.g. "every") — indent every line by one level
        for (const l of b.text.split("\n")) {
          lines.push("    " + l);
        }
      } else {
        lines.push("    " + b.text);
      }
    }
  }
  lines.push("}");

  return { branchBlock: lines.join("\n"), helpers };
}

function renderHelpers(helpers) {
  if (!helpers.length) return "";
  // Group consecutive heads of the same helper together for readable output.
  const out = [];
  for (const h of helpers) {
    out.push(`${h.name} if {`);
    for (const c of h.conditions) {
      out.push("    " + renderConditionByType(c));
    }
    out.push("}");
  }
  return out.join("\n");
}

function renderResultObjectRule(rule) {
  const fields = Array.isArray(rule.fields) ? rule.fields : [];
  const lines = [];
  if (rule.description) {
    lines.push(`# ${rule.description}`);
  }
  if (fields.length === 0) {
    lines.push(`${rule.name} := {}`);
    return lines.join("\n");
  }
  lines.push(`${rule.name} := {`);
  fields.forEach((f, idx) => {
    if (!f.key || typeof f.key !== "string") {
      throw new Error(`result_object rule '${rule.name}': field ${idx} missing key`);
    }
    const valType = f.valueType || "ref";
    const rendered = renderValue(f.value, valType);
    const trail = idx < fields.length - 1 ? "," : "";
    const comment = f.comment ? ` # ${f.comment.replace(/\n/g, " ")}` : "";
    lines.push(`    ${escapeString(f.key)}: ${rendered}${trail}${comment}`);
  });
  lines.push(`}`);
  return lines.join("\n");
}

function renderRule(rule) {
  if (rule.kind === "result_object") {
    return renderResultObjectRule(rule);
  }

  const out = [];
  if (rule.description) {
    out.push(`# ${rule.description}`);
  }

  // Default declaration for boolean/value rules — not applicable to partial set rules
  if (rule.default !== undefined && rule.kind !== "partial_set") {
    const defType =
      rule.type === "boolean" || !rule.type ? "boolean" : rule.type;
    let defVal;
    if (defType === "boolean") {
      defVal = rule.default ? "true" : "false";
    } else if (defType === "string") {
      defVal = escapeString(rule.default);
    } else if (defType === "number") {
      defVal = String(rule.default);
    } else if (defType === "object") {
      defVal = JSON.stringify(rule.default);
    } else {
      defVal = JSON.stringify(rule.default);
    }
    out.push(`default ${rule.name} := ${defVal}`);
    out.push("");
  }

  const branches = rule.branches || [];
  if (branches.length === 0) {
    // No branches — just the default stays
    return out.join("\n");
  }

  const allHelpers = [];
  for (let i = 0; i < branches.length; i++) {
    const { branchBlock, helpers } = renderBranch(rule, branches[i], i);
    out.push(branchBlock);
    if (i < branches.length - 1) out.push("");
    allHelpers.push(...helpers);
  }

  if (allHelpers.length) {
    out.push("");
    out.push(renderHelpers(allHelpers));
  }

  return out.join("\n");
}

export function compile(spec) {
  __verifyCounter = 0;
  if (!spec || typeof spec !== "object") {
    throw new Error("Spec must be an object");
  }
  if (!spec.package || typeof spec.package !== "string") {
    throw new Error("Spec must have a 'package' string");
  }
  const reserved = reservedPackageRootError(spec.package);
  if (reserved) throw new Error(reserved);
  if (!Array.isArray(spec.rules)) {
    throw new Error("Spec must have a 'rules' array");
  }

  const lines = [];
  lines.push(`package ${spec.package}`);
  lines.push("");

  const imports = spec.imports && spec.imports.length ? spec.imports : ["rego.v1"];
  for (const imp of imports) {
    lines.push(`import ${imp}`);
  }
  lines.push("");

  if (spec.description) {
    lines.push(`# ${spec.description}`);
    lines.push("");
  }

  for (let i = 0; i < spec.rules.length; i++) {
    lines.push(renderRule(spec.rules[i]));
    if (i < spec.rules.length - 1) lines.push("");
  }

  return lines.join("\n") + "\n";
}

// Validation helper — returns { valid, errors, warnings }.
// Warnings are non-blocking (e.g. deprecated crypto.md5 / crypto.sha1 usage).
export function validate(spec) {
  const errors = [];
  const warnings = [];
  try {
    if (!spec || typeof spec !== "object") {
      errors.push("Spec must be an object");
      return { valid: false, errors, warnings };
    }
    if (!spec.package) errors.push("Missing 'package'");
    else if (!/^[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)*$/.test(spec.package)) {
      errors.push(`Invalid package path: ${spec.package}`);
    } else {
      const reserved = reservedPackageRootError(spec.package);
      if (reserved) errors.push(reserved);
    }
    if (!Array.isArray(spec.rules)) errors.push("Missing 'rules' array");
    else {
      spec.rules.forEach((r, ri) => {
        if (!r.name) errors.push(`Rule ${ri}: missing name`);
        else if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(r.name)) {
          errors.push(`Rule ${ri}: invalid name '${r.name}'`);
        }
        if (r.kind && !VALID_RULE_KINDS.has(r.kind)) {
          errors.push(`Rule ${ri}: invalid kind '${r.kind}'`);
        }
        if (r.kind === "result_object") {
          const fields = Array.isArray(r.fields) ? r.fields : [];
          fields.forEach((f, fi) => {
            const where = `Rule ${ri} field ${fi}`;
            if (!f.key || typeof f.key !== "string") {
              errors.push(`${where}: missing key`);
            } else if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(f.key)) {
              errors.push(`${where}: invalid key '${f.key}' (must be a Rego-safe identifier)`);
            }
            const vt = f.valueType || "ref";
            if (!VALID_FIELD_VALUE_TYPES.has(vt)) {
              errors.push(`${where}: invalid valueType '${vt}'`);
            }
            if (vt === "ref" && (typeof f.value !== "string" || !isValidRegoRef(f.value))) {
              errors.push(`${where}: invalid ref '${f.value}'`);
            }
          });
          return; // result_object rules have no branches
        }
        (r.branches || []).forEach((b, bi) => {
          if (r.kind === "partial_set" && b.value === undefined) {
            errors.push(`Rule ${ri} branch ${bi}: partial_set branch must have a 'value'`);
          }

          const groups = getGroups(b);
          groups.forEach((g, gi) => {
            if (g.mode !== "and" && g.mode !== "or") {
              errors.push(`Rule ${ri} branch ${bi} group ${gi}: invalid mode '${g.mode}'`);
            }
            (g.conditions || []).forEach((c, ci) => {
              const where = `Rule ${ri} branch ${bi} group ${gi} cond ${ci}`;
              const ct = c.condType;
              if (ct && !VALID_COND_TYPES.has(ct)) {
                errors.push(`${where}: invalid condType '${ct}'`);
                return;
              }
              if (ct === "arith") {
                if (!c.leftExpr) errors.push(`${where}: arith missing leftExpr`);
                else if (!ARITH_EXPR_RE.test(c.leftExpr)) errors.push(`${where}: invalid leftExpr`);
                if (!c.op) errors.push(`${where}: missing op`);
              } else if (ct === "aggregate") {
                if (!VALID_AGGREGATE_FNS.has(c.fn)) errors.push(`${where}: invalid aggregate fn '${c.fn}'`);
                if (!c.collection || !isValidRegoRef(c.collection)) errors.push(`${where}: invalid collection`);
                if (!c.op) errors.push(`${where}: missing op`);
              } else if (ct === "every") {
                if (!c.variable || !/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(c.variable)) errors.push(`${where}: invalid every variable`);
                if (!c.collection || !isValidRegoRef(c.collection)) errors.push(`${where}: invalid every collection`);
              } else if (ct === "builtin_left") {
                if (!VALID_BUILTINS.has(c.builtin)) errors.push(`${where}: invalid builtin '${c.builtin}'`);
                if (!c.op) errors.push(`${where}: missing op`);
              } else if (ct === "object_get") {
                if (!c.obj || !isValidRegoRef(c.obj)) errors.push(`${where}: object_get invalid obj`);
                if (c.key === undefined) errors.push(`${where}: object_get missing key`);
                if (c.default === undefined) errors.push(`${where}: object_get missing default`);
                if (!c.op) errors.push(`${where}: missing op`);
              } else if (ct === "raw") {
                if (!c.rego || typeof c.rego !== "string") errors.push(`${where}: raw missing rego string`);
              } else if (ct === "verification") {
                const vspec = VERIFICATION_FUNCS[c.function];
                if (!vspec) {
                  errors.push(`${where}: invalid verification function '${c.function}'`);
                } else {
                  const args = Array.isArray(c.args) ? c.args : [];
                  if (args.length !== vspec.arity) {
                    errors.push(`${where}: ${c.function} expects ${vspec.arity} arg(s), got ${args.length}`);
                  }
                  args.forEach((a, i) => {
                    if (!a || typeof a !== "object") {
                      errors.push(`${where}: arg ${i} must be {value, type}`);
                      return;
                    }
                    const t = a.type || "ref";
                    if (t === "ref" && (typeof a.value !== "string" || !isValidRegoRef(a.value))) {
                      errors.push(`${where}: arg ${i} invalid ref '${a.value}'`);
                    }
                    if (t === "object" && (!a.value || typeof a.value !== "object" || Array.isArray(a.value))) {
                      errors.push(`${where}: arg ${i} object must be a plain object`);
                    }
                  });
                  if (vspec.category === "tuple" && Array.isArray(c.bind)) {
                    if (c.bind.length !== vspec.returns.length) {
                      errors.push(`${where}: ${c.function} expects ${vspec.returns.length} bind name(s)`);
                    }
                    for (const b of c.bind) {
                      if (typeof b !== "string" || !IDENT_RE.test(b)) {
                        errors.push(`${where}: invalid bind name '${b}'`);
                      }
                    }
                  }
                  if (vspec.category === "value") {
                    const hasBind = c.bindAs !== undefined && c.bindAs !== null && c.bindAs !== "";
                    const hasCompare = !!c.compareOp;
                    if (hasBind && hasCompare) {
                      errors.push(`${where}: bindAs and compareOp are mutually exclusive`);
                    }
                    if (!hasBind && !hasCompare) {
                      errors.push(`${where}: value-returning ${c.function} requires compareOp or bindAs`);
                    }
                    if (hasBind && (typeof c.bindAs !== "string" || !IDENT_RE.test(c.bindAs))) {
                      errors.push(`${where}: invalid bindAs '${c.bindAs}'`);
                    }
                    if (hasCompare && !CMP_OPS_SET.has(c.compareOp)) {
                      errors.push(`${where}: invalid compareOp '${c.compareOp}'`);
                    }
                  }
                  if (vspec.deprecated) {
                    warnings.push(`${where}: ${c.function} is deprecated — prefer crypto.sha256 or stronger`);
                  }
                }
              } else if (ct === "verify") {
                validateVerifyConditionImpl(c, where, errors);
              } else {
                // Standard condition
                if (!c.left) errors.push(`${where}: missing left`);
                else if (!isValidRegoRef(c.left)) {
                  errors.push(`${where}: invalid path '${c.left}'`);
                }
                if (!c.op) errors.push(`${where}: missing op`);
                else if (!VALID_OPS.has(c.op)) {
                  errors.push(`${where}: invalid op '${c.op}'`);
                }
              }
            });
          });
        });
      });
    }
  } catch (e) {
    errors.push(e.message);
  }
  return { valid: errors.length === 0, errors, warnings };
}
