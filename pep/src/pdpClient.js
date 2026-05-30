export class PdpUnreachableError extends Error {
  constructor(cause) {
    super(`PDP unreachable: ${cause?.message ?? cause}`);
    this.name = "PdpUnreachableError";
    this.cause = cause;
  }
}

export class PdpTimeoutError extends Error {
  constructor(timeoutMs) {
    super(`PDP request timed out after ${timeoutMs}ms`);
    this.name = "PdpTimeoutError";
    this.timeoutMs = timeoutMs;
  }
}

export class PdpHttpError extends Error {
  constructor(status, body) {
    super(`PDP returned HTTP ${status}`);
    this.name = "PdpHttpError";
    this.status = status;
    this.body = body;
  }
}

const POLICY_PATH_RE = /^[A-Za-z0-9_]+([./][A-Za-z0-9_]+)*$/;

export function normalisePolicyPath(policy) {
  if (typeof policy !== "string" || !POLICY_PATH_RE.test(policy)) {
    const err = new Error("invalid policy path");
    err.code = "INVALID_POLICY_PATH";
    throw err;
  }
  return policy.replace(/\./g, "/");
}

// Auth: `signer` is an async () => string returning a fresh JWT each ~30s
// (see auth/platformSigner.js). Cached internally by the signer; this
// client just awaits it per request. OPA's system_authz.rego verifies the
// signature, iss, aud, and exp.
export function createPdpClient({ opaUrl, signer, defaultTimeoutMs = 2000 }) {
  if (!opaUrl) throw new Error("createPdpClient: opaUrl is required");
  if (typeof signer !== "function") {
    throw new Error("createPdpClient: signer callable is required");
  }

  const baseUrl = opaUrl.replace(/\/+$/, "");

  async function authHeader() {
    return `Bearer ${await signer()}`;
  }

  async function evaluate(policy, input, { timeoutMs = defaultTimeoutMs } = {}) {
    const path = normalisePolicyPath(policy);
    const url = `${baseUrl}/v1/data/${path}`;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    let res;
    try {
      res = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: await authHeader(),
        },
        body: JSON.stringify({ input }),
        signal: controller.signal,
      });
    } catch (err) {
      if (err?.name === "AbortError") throw new PdpTimeoutError(timeoutMs);
      throw new PdpUnreachableError(err);
    } finally {
      clearTimeout(timer);
    }

    if (!res.ok) {
      let body;
      try { body = await res.text(); } catch { body = undefined; }
      throw new PdpHttpError(res.status, body);
    }

    let data;
    try {
      data = await res.json();
    } catch (err) {
      throw new PdpHttpError(res.status, `non-JSON body: ${err.message}`);
    }

    return data?.result;
  }

  async function fetchData(dataPath, { timeoutMs = defaultTimeoutMs } = {}) {
    const path = normalisePolicyPath(dataPath);
    const url = `${baseUrl}/v1/data/${path}`;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    let res;
    try {
      res = await fetch(url, {
        method: "GET",
        headers: { Authorization: await authHeader() },
        signal: controller.signal,
      });
    } catch (err) {
      if (err?.name === "AbortError") throw new PdpTimeoutError(timeoutMs);
      throw new PdpUnreachableError(err);
    } finally {
      clearTimeout(timer);
    }

    if (!res.ok) {
      let body;
      try { body = await res.text(); } catch { body = undefined; }
      throw new PdpHttpError(res.status, body);
    }

    let data;
    try { data = await res.json(); }
    catch (err) {
      throw new PdpHttpError(res.status, `non-JSON body: ${err.message}`);
    }
    return data?.result;
  }

  async function health({ timeoutMs = defaultTimeoutMs } = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      // /health is allowlisted in system_authz.rego — no auth needed.
      const res = await fetch(`${baseUrl}/health?bundles=false`, {
        method: "GET",
        signal: controller.signal,
      });
      return res.ok;
    } catch {
      return false;
    } finally {
      clearTimeout(timer);
    }
  }

  return { evaluate, fetchData, health };
}
