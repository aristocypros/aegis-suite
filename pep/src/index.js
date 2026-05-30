import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import { createPdpClient } from "./pdpClient.js";
import { createApp } from "./server.js";
import { createAuthDispatcher } from "./auth/index.js";
import { createAccessStore } from "./auth/accessStore.js";
import { createPepSigner } from "./auth/platformSigner.js";

function envInt(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n) || n <= 0) {
    console.error(`[aegis-sentry] invalid ${name}=${raw}; falling back to ${fallback}`);
    return fallback;
  }
  return n;
}

function envBool(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  return /^(1|true|yes|on)$/i.test(raw);
}

function envString(name) {
  const raw = process.env[name];
  return typeof raw === "string" && raw.length > 0 ? raw : null;
}

function envCsv(name) {
  const raw = process.env[name];
  if (typeof raw !== "string" || raw.length === 0) return [];
  return raw.split(",").map((s) => s.trim()).filter((s) => s.length > 0);
}

const PORT = envInt("PEP_PORT", 3002);
const OPA_URL = process.env.OPA_URL ?? "http://opa:8181";
const REQUEST_TIMEOUT_MS = envInt("PEP_REQUEST_TIMEOUT_MS", 2000);
const LOG_INPUTS = envBool("PEP_LOG_INPUTS", false);
const NODE_ENV = process.env.NODE_ENV || "development";

// TLS material is optional. When all three files are configured the PEP
// listens HTTPS with requestCert:true so per-caller mtls works; when
// missing it listens plain HTTP and any mtls-mode caller row is unusable
// (the dispatcher returns mode_not_configured for cert-bearing requests
// that never happen, and rejects mtls callers cleanly).
const TLS_CERT_PATH = envString("PEP_TLS_CERT");
const TLS_KEY_PATH = envString("PEP_TLS_KEY");
const TLS_CA_PATH = envString("PEP_TLS_CA");
const TLS_REQUESTED = TLS_CERT_PATH || TLS_KEY_PATH || TLS_CA_PATH;
let tlsCert = null;
let tlsKey = null;
let tlsCa = null;
if (TLS_REQUESTED) {
  if (!TLS_CERT_PATH || !TLS_KEY_PATH || !TLS_CA_PATH) {
    console.error(
      "[aegis-sentry] PEP_TLS_CERT/KEY/CA must all be set together (or all unset)"
    );
    process.exit(1);
  }
  try {
    tlsCert = fs.readFileSync(TLS_CERT_PATH);
    tlsKey = fs.readFileSync(TLS_KEY_PATH);
    tlsCa = fs.readFileSync(TLS_CA_PATH);
  } catch (e) {
    console.error(`[aegis-sentry] failed to load TLS material: ${e.message}`);
    process.exit(1);
  }
}
const TLS_ENABLED = Boolean(tlsCert && tlsKey && tlsCa);

// Bootstrap CN allowlist (mtls). Per-caller rows extend this set at runtime
// via the pep_callers admin surface.
const ALLOWED_CNS = envCsv("PEP_ALLOWED_CALLERS");

// JWT verifier requires the platform's iss/aud/jwks. These describe the
// platform's token shape (the studio backend's JWKS / iss / aud), not
// per-caller material — they stay platform-level even though individual
// jwt-mode caller rows decide which `sub`s are admissible.
const JWKS_URL = envString("PEP_JWKS_URL") ||
  "http://backend:3001/.well-known/jwks.json";
const JWT_ISSUER = envString("PEP_JWT_ISSUER");
const JWT_AUDIENCE = envString("PEP_JWT_AUDIENCE");

const HMAC_WINDOW_MS = envInt("PEP_HMAC_WINDOW_MS", 30_000);
const NONCE_CACHE_MAX = envInt("PEP_NONCE_CACHE_MAX", 50_000);
const CALLER_TTL_MS = envInt("PEP_CALLER_TTL_MS", 30_000);

// Dev-only: admits requests that present zero credentials as an anonymous
// caller. Refused under NODE_ENV=production so it can't quietly leak into
// prod-shaped runs.
const DEV_ALLOW_ANON = envBool("PEP_DEV_ALLOW_ANON", false);
if (DEV_ALLOW_ANON && NODE_ENV === "production") {
  console.error(
    "[aegis-sentry] PEP_DEV_ALLOW_ANON=true refuses to start with NODE_ENV=production. " +
      "Provision pep_callers rows for the real callers instead."
  );
  process.exit(1);
}
if (!DEV_ALLOW_ANON && NODE_ENV !== "production" && !TLS_ENABLED) {
  console.warn(
    "[aegis-sentry] running with no anonymous fallback and no TLS — every caller " +
      "must present a valid hmac or jwt credential matching a provisioned row."
  );
}

async function start() {
  // Build the OPA-auth JWT signer. Vault-only for now (kms cloud providers
  // are stubs upstream); the PEP holds its own token with sign+read scoped
  // to the pep-opa-auth-signing transit key.
  let pepSigner;
  try {
    pepSigner = await createPepSigner();
  } catch (e) {
    console.error(`[aegis-sentry] platform signer init failed: ${e.message}`);
    process.exit(1);
  }

  const pdp = createPdpClient({
    opaUrl: OPA_URL,
    signer: () => pepSigner.mint(),
    defaultTimeoutMs: REQUEST_TIMEOUT_MS,
  });

  const authMiddleware = await createAuthDispatcher({
    pdp,
    tlsEnabled: TLS_ENABLED,
    devAllowAnon: DEV_ALLOW_ANON,
    config: {
      allowedCns: ALLOWED_CNS,
      hmacWindowMs: HMAC_WINDOW_MS,
      nonceCacheMax: NONCE_CACHE_MAX,
      callerTtlMs: CALLER_TTL_MS,
      jwksUrl: JWKS_URL,
      jwtIssuer: JWT_ISSUER,
      jwtAudience: JWT_AUDIENCE,
    },
  });

  // Per-caller policy ACL — shared cache for /authorize enforcement and the
  // /discover filter. Warm up at boot so the first call doesn't pay an OPA
  // round-trip; failures fall back to the lazy refresh on first request.
  const accessStore = createAccessStore({ pdp, ttlMs: CALLER_TTL_MS });
  try {
    await accessStore.warmUp();
  } catch (e) {
    console.warn(`[aegis-sentry] caller-access store warm-up failed: ${e?.message || e}`);
  }

  const app = createApp({ pdp, authMiddleware, accessStore, logInputs: LOG_INPUTS });

  // HTTPS whenever TLS material is configured, plain HTTP otherwise. The
  // listener uses requestCert:true, rejectUnauthorized:false so non-mtls
  // callers (hmac/jwt) can connect over HTTPS without presenting a cert,
  // and mtls callers can present one that the dispatcher then verifies.
  const server = TLS_ENABLED
    ? https.createServer({
        cert: tlsCert,
        key: tlsKey,
        ca: tlsCa,
        requestCert: true,
        rejectUnauthorized: false,
      }, app)
    : http.createServer(app);

  server.listen(PORT, () => {
    console.log(
      JSON.stringify({
        ts: new Date().toISOString(),
        event: "pep.start",
        port: PORT,
        opaUrl: OPA_URL,
        requestTimeoutMs: REQUEST_TIMEOUT_MS,
        logInputs: LOG_INPUTS,
        tls: TLS_ENABLED,
        jwtConfigured: Boolean(JWT_ISSUER && JWT_AUDIENCE && JWKS_URL),
        devAllowAnon: DEV_ALLOW_ANON,
        nodeEnv: NODE_ENV,
      })
    );
  });

  function shutdown(signal) {
    console.log(
      JSON.stringify({ ts: new Date().toISOString(), event: "pep.shutdown", signal })
    );
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 5000).unref();
  }

  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}

start().catch((e) => {
  console.error(`[aegis-sentry] startup failed: ${e?.stack || e?.message || e}`);
  process.exit(1);
});
