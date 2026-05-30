#!/usr/bin/env node
// opa-trust-init.js — one-shot that mints / reads the KMS-held platform
// signing pubkeys for the OPA-auth and PEP-OPA-auth purposes, then writes
// them to a shared volume that OPA mounts read-only at /policies/trust/.
// OPA loads the file at startup as data.platform_keys, which system_authz.rego
// consumes to verify the JWT every request carries.
//
// Runs as a separate docker-compose service so OPA can depend_on it
// (service_completed_successfully). Backend reconciles against the same
// file at boot via platformKeys.reconcileWithTrustFile().
//
// Idempotent — uses ensureKey on the underlying KMS provider. Subsequent
// boots simply re-read the pubkeys and overwrite the file with the same
// content. Atomic write via tmp + rename so OPA never observes a partial
// JSON.
import fs from "node:fs";
import path from "node:path";

import * as kms from "../src/services/kms/index.js";

const PURPOSES = ["opa-auth-signing", "pep-opa-auth-signing"];
const ENV_BY_PURPOSE = {
  "opa-auth-signing": "KMS_KEY_ID_OPA_AUTH",
  "pep-opa-auth-signing": "KMS_KEY_ID_PEP_OPA_AUTH",
};

function keyIdFor(purpose) {
  return process.env[ENV_BY_PURPOSE[purpose]] || purpose;
}

async function main() {
  const outPath = process.env.OPA_TRUST_OUTPUT
    || "/opa-trust/platform_keys.json";

  console.log(`[aegis-trust-init] writing ${outPath}`);

  const signer = await kms.getSigner();
  const purposes = {};
  for (const purpose of PURPOSES) {
    const keyId = keyIdFor(purpose);
    await signer.ensureKey({ keyId, algorithm: "ed25519" });
    const pub = await signer.getPublicKey(keyId);
    const fpHex = pub.fingerprintSha256.toString("hex");
    purposes[purpose] = { [fpHex]: pub.pem };
    console.log(
      `[aegis-trust-init] ${purpose}: keyId=${keyId} fp=${fpHex}`
    );
  }
  // Wrap under `platform_keys` so OPA loads it at data.platform_keys —
  // matching the path that publishPlatformKeys writes to at runtime via
  // PUT /v1/data/platform_keys.
  const doc = { platform_keys: purposes };

  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  const tmp = `${outPath}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(doc, null, 2));
  fs.renameSync(tmp, outPath);
  console.log(`[aegis-trust-init] wrote ${outPath} (${Object.keys(purposes).length} purposes)`);
}

main().catch((e) => {
  console.error(`[aegis-trust-init] FATAL: ${e.stack || e.message || e}`);
  process.exit(1);
});
