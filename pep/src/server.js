import express from "express";
import { performance } from "node:perf_hooks";
import {
  PdpHttpError,
  PdpTimeoutError,
  PdpUnreachableError,
} from "./pdpClient.js";

function isPlainObject(v) {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

// Walk a dotted path against an object. Returns true iff every segment exists.
// Arrays are considered "present" as long as the path resolves to any defined
// value — we don't try to descend into them.
function hasInputPath(input, dottedPath) {
  if (!isPlainObject(input)) return false;
  const segments = dottedPath.split(".");
  let cur = input;
  for (const seg of segments) {
    if (cur === null || cur === undefined) return false;
    if (typeof cur !== "object") return false;
    if (!Object.prototype.hasOwnProperty.call(cur, seg)) return false;
    cur = cur[seg];
  }
  return cur !== undefined;
}

function normaliseDecision(result) {
  if (typeof result === "boolean") return { allow: result };
  if (isPlainObject(result) && typeof result.allow === "boolean") {
    const out = { allow: result.allow };
    if (typeof result.reason === "string") out.reason = result.reason;
    return out;
  }
  return { allow: false };
}

function logDecision(logger, entry) {
  logger(JSON.stringify({ ts: new Date().toISOString(), ...entry }));
}

export function createApp({
  pdp,
  authMiddleware = null,
  accessStore = null,
  logInputs = false,
  logger = console.log,
}) {
  const app = express();
  app.disable("x-powered-by");
  // verify hook captures the raw request bytes for hmac-mode callers so the
  // signature check sees exactly what the client sent (Express parses and
  // re-serializes JSON, which is not byte-stable). The buffer is small —
  // bounded by the same 256kb cap as the parsed body.
  app.use(express.json({
    limit: "256kb",
    verify: (req, _res, buf) => {
      req.rawBody = buf;
    },
  }));

  // /healthz is intentionally NOT gated by the auth middleware so the
  // container's readiness probe works regardless of auth configuration.
  app.get("/healthz", async (_req, res) => {
    const opaReachable = await pdp.health().catch(() => false);
    res.status(200).json({ ok: true, opaReachable });
  });

  if (authMiddleware) {
    app.use(authMiddleware);
  }

  app.post("/authorize", async (req, res) => {
    const started = performance.now();
    const body = req.body ?? {};
    const policy = body.policy;
    const input = body.input === undefined ? {} : body.input;

    if (typeof policy !== "string" || policy.length === 0) {
      logDecision(logger, {
        event: "authorize",
        callerId: req.caller?.id,
        status: 400,
        allow: false,
        error: "policy_required",
      });
      return res
        .status(400)
        .json({ allow: false, error: "policy must be a non-empty string" });
    }
    if (!isPlainObject(input)) {
      logDecision(logger, {
        event: "authorize",
        callerId: req.caller?.id,
        status: 400,
        allow: false,
        policy,
        error: "input_not_object",
      });
      return res
        .status(400)
        .json({ allow: false, error: "input must be a JSON object" });
    }

    // ACL gate: caller must have been granted access to this policy by an
    // admin. Dev-anon (mode==="none") bypasses — it's already gated by
    // PEP_DEV_ALLOW_ANON + NODE_ENV != production at startup. The org
    // filter (callerOrgId) is defense-in-depth: a caller in org A cannot
    // reach a policy in org B even via a stale grant row.
    if (accessStore && req.caller && req.caller.mode !== "none") {
      let allowed;
      try {
        allowed = await accessStore.isAllowed(req.caller.id, policy, {
          callerOrgId: req.caller.orgId ?? null,
        });
      } catch (e) {
        logDecision(logger, {
          event: "authorize",
          callerId: req.caller?.id,
          status: 502,
          allow: false,
          policy,
          error: "acl_lookup_failed",
          message: e?.message,
        });
        return res.status(502).json({ allow: false, error: "acl_lookup_failed" });
      }
      if (!allowed) {
        logDecision(logger, {
          event: "authorize",
          callerId: req.caller?.id,
          status: 403,
          allow: false,
          policy,
          acl_decision: "out_of_scope",
        });
        return res.status(403).json({
          allow: false,
          error: "policy_not_in_scope",
          policy,
        });
      }
    }

    try {
      const result = await pdp.evaluate(policy, input);
      const decision = normaliseDecision(result);
      const elapsedMs = Math.round(performance.now() - started);
      const payload = { allow: decision.allow, result: result ?? null, elapsedMs };
      if (decision.reason) payload.reason = decision.reason;

      logDecision(logger, {
        event: "authorize",
        callerId: req.caller?.id,
        status: 200,
        policy,
        allow: decision.allow,
        elapsedMs,
        ...(accessStore && req.caller?.mode !== "none" ? { acl_decision: "in_scope" } : {}),
        ...(decision.reason ? { reason: decision.reason } : {}),
        ...(logInputs ? { input } : {}),
      });
      return res.status(200).json(payload);
    } catch (err) {
      const elapsedMs = Math.round(performance.now() - started);

      if (err?.code === "INVALID_POLICY_PATH") {
        logDecision(logger, {
          event: "authorize",
          status: 400,
          allow: false,
          policy,
          elapsedMs,
          error: "invalid_policy_path",
        });
        return res
          .status(400)
          .json({ allow: false, error: "invalid policy path" });
      }
      if (err instanceof PdpTimeoutError) {
        logDecision(logger, {
          event: "authorize",
          status: 504,
          allow: false,
          policy,
          elapsedMs,
          error: "pdp_timeout",
        });
        return res
          .status(504)
          .json({ allow: false, error: "pdp_timeout" });
      }
      if (err instanceof PdpUnreachableError || err instanceof PdpHttpError) {
        logDecision(logger, {
          event: "authorize",
          status: 502,
          allow: false,
          policy,
          elapsedMs,
          error: err.name,
          ...(err instanceof PdpHttpError ? { pdpStatus: err.status } : {}),
        });
        return res
          .status(502)
          .json({ allow: false, error: "pdp_unreachable" });
      }

      logDecision(logger, {
        event: "authorize",
        callerId: req.caller?.id,
        status: 502,
        allow: false,
        policy,
        elapsedMs,
        error: "unexpected",
        message: err?.message,
      });
      return res
        .status(502)
        .json({ allow: false, error: "pdp_unreachable" });
    }
  });

  // Policy discovery: given an input, return active policies whose required
  // input paths are all satisfied. The index is published to OPA at
  // data.studio.policy_index by the studio backend on every save / lock /
  // unlock and at startup; the PEP fetches it through the same OPA channel.
  //
  // Modes:
  //   strict (default) → only policies whose every requiredPath is satisfied
  //   score            → every policy with at least one matched path, ranked
  //                      by matched/required ratio. Each entry carries
  //                      matchedPaths, missingPaths, and score (0..1).
  //   catalog          → every policy in the caller's scope, regardless of
  //                      whether the current input matches its requiredPaths.
  //                      Useful for client self-onboarding ("what could I
  //                      call?") before they've shaped the input.
  app.post("/discover", async (req, res) => {
    const started = performance.now();
    const body = req.body ?? {};
    const input = body.input === undefined ? {} : body.input;
    const mode =
      req.query.mode === "score" ? "score" :
      req.query.mode === "catalog" ? "catalog" :
      "strict";

    if (!isPlainObject(input)) {
      logDecision(logger, {
        event: "discover",
        callerId: req.caller?.id,
        status: 400,
        mode,
        error: "input_not_object",
      });
      return res
        .status(400)
        .json({ candidates: [], error: "input must be a JSON object" });
    }

    let index;
    try {
      // Prefer the accessStore's cached index when available — same OPA
      // document, but reused across /authorize and /discover so we don't
      // pay a round-trip on every call.
      index = accessStore
        ? await accessStore.getPolicyIndex()
        : await pdp.fetchData("studio.policy_index");
    } catch (err) {
      const elapsedMs = Math.round(performance.now() - started);
      logDecision(logger, {
        event: "discover",
        callerId: req.caller?.id,
        status: 502,
        mode,
        elapsedMs,
        error: err?.name ?? "unexpected",
      });
      return res
        .status(502)
        .json({ candidates: [], error: "pdp_unreachable" });
    }

    // ACL filter: only show policies the caller has been granted. Dev-anon
    // bypasses (sees the full catalogue) — same gate as /authorize.
    let allowedIds = null;
    if (accessStore && req.caller && req.caller.mode !== "none") {
      try {
        allowedIds = await accessStore.getAllowedPolicyIds(req.caller.id);
      } catch (err) {
        const elapsedMs = Math.round(performance.now() - started);
        logDecision(logger, {
          event: "discover",
          callerId: req.caller?.id,
          status: 502,
          mode,
          elapsedMs,
          error: "acl_lookup_failed",
        });
        return res.status(502).json({ candidates: [], error: "acl_lookup_failed" });
      }
    }

    const allPolicies = Array.isArray(index?.policies) ? index.policies : [];

    // Org-scope filter: a caller in org A only sees policies in org A
    // or global policies (org_id null). Skipped for anonymous callers
    // (dev mode) and for callers with no orgId on the published row
    // (legacy data pre-RBAC migration — those see everything as before
    // until an admin reassigns them). Runs BEFORE the explicit ACL filter
    // so cross-org rows never enter the candidate pool, even if a stale
    // grant row references them.
    const callerOrgId =
      req.caller && req.caller.mode !== "none" ? (req.caller.orgId ?? null) : null;
    const orgScoped = callerOrgId
      ? allPolicies.filter((p) => p.org_id == null || p.org_id === callerOrgId)
      : allPolicies;

    const policies = allowedIds
      ? orgScoped.filter((p) => allowedIds.has(p.id))
      : orgScoped;
    const candidates = [];
    for (const p of policies) {
      const required = Array.isArray(p.requiredPaths) ? p.requiredPaths : [];

      // catalog mode skips the input-matching loop entirely — include every
      // in-scope policy with its requiredPaths so the client can see what
      // input shape each policy expects.
      if (mode === "catalog") {
        candidates.push({
          id: p.id,
          name: p.name,
          package: p.package,
          description: p.description,
          requiredPaths: required,
        });
        continue;
      }

      const matched = required.filter((path) => hasInputPath(input, path));
      const missing = required.filter((path) => !hasInputPath(input, path));

      if (mode === "strict") {
        if (missing.length === 0) {
          candidates.push({
            id: p.id,
            name: p.name,
            package: p.package,
            description: p.description,
            requiredPaths: required,
          });
        }
        continue;
      }

      // score mode: include any policy with at least one matched path
      // (or empty requiredPaths, which scores 1.0 vacuously).
      const score = required.length === 0 ? 1 : matched.length / required.length;
      if (score === 0) continue;
      candidates.push({
        id: p.id,
        name: p.name,
        package: p.package,
        description: p.description,
        requiredPaths: required,
        matchedPaths: matched,
        missingPaths: missing,
        score: Number(score.toFixed(4)),
      });
    }

    if (mode === "score") {
      candidates.sort((a, b) => {
        if (b.score !== a.score) return b.score - a.score;
        return (a.package || "").localeCompare(b.package || "");
      });
    } else if (mode === "catalog") {
      // Stable alphabetical by package for predictable client UX.
      candidates.sort((a, b) => (a.package || "").localeCompare(b.package || ""));
    }

    const elapsedMs = Math.round(performance.now() - started);
    logDecision(logger, {
      event: "discover",
      callerId: req.caller?.id,
      status: 200,
      mode,
      indexedTotal: allPolicies.length,
      inScope: policies.length,
      candidates: candidates.length,
      elapsedMs,
    });

    return res.status(200).json({
      mode,
      candidates,
      indexedAt: index?.generatedAt ?? null,
      indexedPolicies: policies.length,
      elapsedMs,
    });
  });

  app.use((req, res) => {
    res.status(404).json({ allow: false, error: "not_found" });
  });

  return app;
}
