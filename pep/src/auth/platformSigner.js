// pep/auth/platformSigner.js — mints short-lived EdDSA JWTs that the PEP
// uses to authenticate to OPA. Signs via Vault Transit; the private key
// never leaves Vault. Matches the JWT shape and constraints that the
// backend's opa-auth-signing key uses, but with aud=opa-studio-pep so OPA's
// system_authz.rego only admits the PEP to read paths.
//
// Why we don't share the backend's services/platformJwt.js: the PEP has no
// DB, no audit chain, no full KMS adapter; just one Vault token, one keyId,
// one curve. Keeping this self-contained means the PEP image stays small
// and there's no shared module to drift.
import crypto from "node:crypto";
import fs from "node:fs";

const TOKEN_TTL_SECONDS = 30;
const REFRESH_BUFFER_SECONDS = 5;

function b64urlJsonEncode(obj) {
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}

// Minimal Vault Transit client. Only two operations are needed: read the
// public key (to compute the kid for the JWT header) and sign an input.
function makeVaultClient({ addr, token }) {
  async function req(path, { method = "GET", body } = {}) {
    const url = `${addr.replace(/\/+$/, "")}/v1/${path.replace(/^\/+/, "")}`;
    const headers = { "X-Vault-Token": token };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const res = await fetch(url, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    if (!res.ok) {
      throw new Error(`vault ${method} ${path} -> ${res.status}: ${text}`);
    }
    return text ? JSON.parse(text) : null;
  }
  return { req };
}

// SPKI DER prefix for an Ed25519 public key. Vault returns the raw 32-byte
// pubkey; we wrap it with this prefix to get the SPKI DER bytes whose
// SHA-256 we use as the kid (matching the backend's fingerprint scheme).
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function spkiDerFromRawEd25519(raw32) {
  if (!Buffer.isBuffer(raw32) || raw32.length !== 32) {
    throw new Error(`expected 32-byte ed25519 pubkey, got ${raw32?.length}`);
  }
  return Buffer.concat([ED25519_SPKI_PREFIX, raw32]);
}

// Create a signer bound to a single Vault transit keyId. Caches the kid
// and the most recent JWT for TOKEN_TTL_SECONDS to amortize sign calls.
export async function createPepSigner({
  vaultAddr = process.env.VAULT_ADDR,
  vaultTokenFile = process.env.VAULT_TOKEN_FILE,
  keyId = process.env.KMS_KEY_ID_PEP_OPA_AUTH || "pep-opa-auth-signing",
  audience = "opa-studio-pep",
  issuer = "opa-policy-studio",
} = {}) {
  if (!vaultAddr) throw new Error("createPepSigner: VAULT_ADDR is required");
  if (!vaultTokenFile) throw new Error("createPepSigner: VAULT_TOKEN_FILE is required");

  let token;
  try {
    token = fs.readFileSync(vaultTokenFile, "utf8").trim();
  } catch (e) {
    throw new Error(`createPepSigner: failed to read ${vaultTokenFile}: ${e.message}`);
  }
  if (!token) throw new Error(`createPepSigner: ${vaultTokenFile} is empty`);

  const vault = makeVaultClient({ addr: vaultAddr, token });

  // Fetch the active pubkey for the configured keyId; derive the kid.
  async function fetchKid() {
    const resp = await vault.req(`transit/keys/${keyId}`);
    const data = resp?.data;
    if (!data || !data.keys) {
      throw new Error("createPepSigner: malformed transit/keys response");
    }
    const latest = data.latest_version ?? Math.max(...Object.keys(data.keys).map(Number));
    const entry = data.keys[String(latest)];
    if (!entry?.public_key) {
      throw new Error(`createPepSigner: no public_key for version ${latest}`);
    }
    const raw = Buffer.from(entry.public_key, "base64");
    const der = spkiDerFromRawEd25519(raw);
    const fp = crypto.createHash("sha256").update(der).digest();
    return fp.toString("hex");
  }

  let kid = await fetchKid();
  let cachedToken = null;
  let cachedExp = 0;

  async function sign(signingInputBuf) {
    const resp = await vault.req(`transit/sign/${keyId}`, {
      method: "POST",
      body: { input: signingInputBuf.toString("base64") },
    });
    const sig = resp?.data?.signature;
    if (typeof sig !== "string" || !sig.startsWith("vault:v")) {
      throw new Error("createPepSigner: malformed vault sign response");
    }
    const colon = sig.indexOf(":", "vault:".length);
    return Buffer.from(sig.slice(colon + 1), "base64");
  }

  async function mint() {
    const now = Math.floor(Date.now() / 1000);
    if (cachedToken && cachedExp - now >= REFRESH_BUFFER_SECONDS) {
      return cachedToken;
    }
    const header = { alg: "EdDSA", typ: "JWT", kid };
    const payload = {
      iss: issuer,
      aud: audience,
      sub: "pep",
      iat: now,
      exp: now + TOKEN_TTL_SECONDS,
    };
    const signingInput = `${b64urlJsonEncode(header)}.${b64urlJsonEncode(payload)}`;
    const sigBytes = await sign(Buffer.from(signingInput, "utf8"));
    cachedToken = `${signingInput}.${sigBytes.toString("base64url")}`;
    cachedExp = now + TOKEN_TTL_SECONDS;
    return cachedToken;
  }

  // Operators can refresh the kid after an external rotation. Cheap enough
  // to call from a periodic timer if desired; in practice the cached JWT
  // expires every 30s anyway so the next mint() naturally picks up the
  // new key.
  async function refreshKid() {
    kid = await fetchKid();
    cachedToken = null;
    cachedExp = 0;
    return kid;
  }

  return { mint, refreshKid, getKid: () => kid };
}
