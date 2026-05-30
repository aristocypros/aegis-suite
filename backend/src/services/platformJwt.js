// platformJwt.js — minimal EdDSA JWT signer/verifier backed by the KMS
// adapter. The private key never leaves the configured KMS provider; the
// signing function POSTs the canonical signing input to the provider and
// concatenates the returned signature. Verification is local (node:crypto)
// against a caller-supplied public-key resolver — typically the in-memory
// map kept by services/platformKeys.js.
//
// Why hand-roll vs. jsonwebtoken / jose:
//   - jsonwebtoken requires a local private-key buffer; it cannot delegate
//     signing to a KMS.
//   - jose has the right primitives but pulls in another dep just for an
//     ~80-line codec.
//   - The threat model is precise: explicit alg whitelist (EdDSA only),
//     mandatory `exp`, mandatory `kid`, kid -> pubkey resolved by a caller-
//     owned table (the audit chain attests to that table). Hand-rolling
//     surfaces every check.
import crypto from "node:crypto";

import * as kms from "./kms/index.js";

function b64urlJsonEncode(obj) {
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}

function b64urlJsonDecode(s) {
  return JSON.parse(Buffer.from(s, "base64url").toString("utf8"));
}

// Sign a payload as an EdDSA JWT. The header's `kid` is the SHA-256
// fingerprint (hex) of the SPKI DER pubkey — same key id used everywhere
// else in the platform.
export async function signJwtEdDSA({ keyId, payload }) {
  const signer = await kms.getSigner();
  const pub = await signer.getPublicKey(keyId);
  const header = {
    alg: "EdDSA",
    typ: "JWT",
    kid: pub.fingerprintSha256.toString("hex"),
  };
  const headerB64 = b64urlJsonEncode(header);
  const payloadB64 = b64urlJsonEncode(payload);
  const signingInput = `${headerB64}.${payloadB64}`;
  const { sigBytes } = await signer.sign(keyId, Buffer.from(signingInput, "utf8"));
  return `${signingInput}.${sigBytes.toString("base64url")}`;
}

export class JwtVerifyError extends Error {
  constructor(message) {
    super(message);
    this.name = "JwtVerifyError";
  }
}

// Verify an EdDSA JWT against a caller-supplied pubkey resolver. Throws
// JwtVerifyError on any failure. Returns the verified payload.
//
// pubkeyResolver(kid) -> KeyObject | null
//   KeyObject is a node:crypto public-key object (e.g. createPublicKey
//   ({ key: derBuffer, format: "der", type: "spki" })). Returning null is
//   how the caller signals "unknown key id; reject".
//
// audience may be a string or an array of strings; the token's `aud` claim
// must equal one of them.
export function verifyJwtEdDSA(token, {
  pubkeyResolver,
  audience,
  issuer,
  clockSkewSec = 5,
  now = Math.floor(Date.now() / 1000),
}) {
  if (typeof token !== "string") {
    throw new JwtVerifyError("token must be a string");
  }
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new JwtVerifyError("token must have 3 segments");
  }
  const [hB64, pB64, sigB64] = parts;

  let header, payload;
  try {
    header = b64urlJsonDecode(hB64);
  } catch {
    throw new JwtVerifyError("malformed header");
  }
  try {
    payload = b64urlJsonDecode(pB64);
  } catch {
    throw new JwtVerifyError("malformed payload");
  }

  // alg whitelist — explicit, refuses alg=none / HS* substitutions.
  if (header.alg !== "EdDSA") {
    throw new JwtVerifyError(`unexpected alg: ${header.alg}`);
  }
  if (typeof header.kid !== "string" || header.kid.length === 0) {
    throw new JwtVerifyError("missing kid in header");
  }

  const keyObject = pubkeyResolver(header.kid);
  if (!keyObject) {
    throw new JwtVerifyError(`unknown kid: ${header.kid}`);
  }

  const signingInput = Buffer.from(`${hB64}.${pB64}`, "utf8");
  let sigBytes;
  try {
    sigBytes = Buffer.from(sigB64, "base64url");
  } catch {
    throw new JwtVerifyError("malformed signature");
  }
  const sigOk = crypto.verify(null, signingInput, keyObject, sigBytes);
  if (!sigOk) {
    throw new JwtVerifyError("signature verification failed");
  }

  if (issuer && payload.iss !== issuer) {
    throw new JwtVerifyError(`iss mismatch: ${payload.iss}`);
  }
  if (audience) {
    const auds = Array.isArray(audience) ? audience : [audience];
    if (!auds.includes(payload.aud)) {
      throw new JwtVerifyError(`aud mismatch: ${payload.aud}`);
    }
  }
  if (typeof payload.exp !== "number") {
    throw new JwtVerifyError("missing exp");
  }
  if (now > payload.exp + clockSkewSec) {
    throw new JwtVerifyError("token expired");
  }
  if (typeof payload.nbf === "number" && now + clockSkewSec < payload.nbf) {
    throw new JwtVerifyError("token not yet valid");
  }
  return payload;
}
