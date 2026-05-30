// Ad-hoc helper to mint a JWT signed by the platform's audit-signing key
// (via the configured KmsSigner). Used by PEP-01 verification only — do not
// ship to production. Usage:
//   node scripts/mint-test-jwt.js --sub <caller> --iss <iss> --aud <aud>
//
// Output: a single line containing the JWT.
import * as kms from "../src/services/kms/index.js";

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  if (i < 0 || i + 1 >= process.argv.length) return fallback;
  return process.argv[i + 1];
}

function b64url(buf) {
  return Buffer.from(buf).toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

const sub = arg("sub", "demo");
const iss = arg("iss", "https://studio.local");
const aud = arg("aud", "pep");
const ttl = Number.parseInt(arg("ttl", "300"), 10);

const signer = await kms.getSigner();
const keyId = kms.getAuditKeyId();
const pub = await signer.getPublicKey(keyId);
const fp = pub.fingerprintSha256.toString("hex");

const now = Math.floor(Date.now() / 1000);
const header = { alg: "EdDSA", typ: "JWT", kid: fp };
const payload = {
  iss, aud, sub,
  iat: now,
  exp: now + ttl,
};
const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
const { sigBytes } = await signer.sign(keyId, Buffer.from(signingInput, "utf8"));
const token = `${signingInput}.${b64url(sigBytes)}`;
process.stdout.write(token);
