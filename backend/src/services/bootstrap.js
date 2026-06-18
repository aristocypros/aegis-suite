// bootstrap.js — first-boot initialization for the policy studio.
//
// On a fresh deployment (users table empty), this module atomically:
//   1. Generates a random initial admin password.
//   2. Registers the KmsSigner's active Ed25519 audit-signing key into
//      audit_signing_keys.
//   3. In one transaction (under the 'opa_studio_bootstrap' advisory lock)
//      inserts the admin user, the signing-key row, and the genesis audit
//      row (signed via the configured KmsSigner).
//   4. Writes the password to /data/initial_admin_password (mode 0600).
//   5. Prints a single banner with the password and the audit pubkey/fingerprint.
//
// The audit-signing key itself is created (or imported) earlier in
// audit.loadOrInitSigningKey(); by the time we get here, the KMS provider
// already holds the active key.
//
// The password file is deleted automatically on first password change. The
// audit signing key persists inside the KMS provider for the deployment's
// lifetime.
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import * as auth from "./auth.js";
import * as audit from "./audit.js";
import * as auditCrypto from "./auditCrypto.js";
import * as store from "./storage.js";

const DEFAULT_PASSWORD_PATH = "/data/initial_admin_password";
const PASSWORD_TMP_FALLBACK = path.join(os.tmpdir(), "opa_studio_initial_admin_password");

// Default org slug for the platform-level tenant that owns the root admin.
// Configurable so multi-instance deployments can rename it without code edits.
const DEFAULT_PLATFORM_ORG_SLUG = process.env.BOOTSTRAP_ORG_SLUG || "platform";
const DEFAULT_PLATFORM_ORG_NAME = process.env.BOOTSTRAP_ORG_NAME || "Platform";

// Built-in role catalogue. Seeded with org_id=NULL so any org can assign
// them. The `root` role is a marker — its power comes from users.is_root,
// which studio_authz checks first and bypasses the permission map. The
// other four are the standard ship-with set; admins can layer custom
// roles via /api/roles on top.
//
// Permission shape: { resource_type: [action, ...] }. Resource types map
// 1:1 to the discriminators in opa/studio_authz.rego (policy, trust_key,
// pep_caller, user, audit, org, role). Actions are the same verbs the
// authorize middleware already passes (create/read/update/delete plus
// resource-specific verbs like lock/unlock/revoke).
const BUILTIN_ROLES = [
  {
    name: "root",
    description: "Full platform access. Bypasses all permission checks via is_root.",
    permissions: {},
  },
  {
    name: "org_admin",
    description: "Manage users, policies, trust keys, and PEP callers within the org.",
    permissions: {
      user:          ["read", "create", "update", "delete"],
      policy:        ["read", "create", "update", "lock", "unlock"],
      trust_key:     ["read", "create", "update", "revoke", "delete"],
      pep_caller:    ["read", "create", "update", "revoke", "delete"],
      role:          ["read", "create", "update", "delete"],
      audit:         ["read"],
      caller_access: ["read", "create", "delete"],
    },
  },
  {
    name: "policy_author",
    description: "Author and update policies; read-only on everything else.",
    permissions: {
      user:       ["read"],
      policy:     ["read", "create", "update"],
      trust_key:  ["read"],
      pep_caller: ["read"],
    },
  },
  {
    name: "auditor",
    description: "Read-only across every resource in the org, including the audit log.",
    permissions: {
      user:       ["read"],
      policy:     ["read"],
      trust_key:  ["read"],
      pep_caller: ["read"],
      audit:      ["read"],
    },
  },
  {
    name: "viewer",
    description: "Read-only access to policies, trust keys, and PEP callers.",
    permissions: {
      policy:     ["read"],
      trust_key:  ["read"],
      pep_caller: ["read"],
    },
  },
];

function passwordFilePath() {
  return process.env.BOOTSTRAP_PASSWORD_FILE || DEFAULT_PASSWORD_PATH;
}

function printBanner({ username, password, passwordPath, org, role, audit }) {
  const bar = "=".repeat(72);
  const lines = [
    "",
    bar,
    "  AEGIS POLICY FABRIC · INITIAL ADMIN — first-boot credentials (shown once)",
    bar,
    `  username      : ${username}`,
    `  password      : ${password}`,
    `  password file : ${passwordPath}`,
    `  org           : ${org.name} (slug=${org.slug})`,
    `  role          : ${role.name} (is_root=true)`,
    "",
    "  Log in at Aegis Studio; you will be required to change",
    "  the password on first login. The on-disk password file is deleted",
    "  automatically after a successful password change.",
    "",
    bar,
    "  AEGIS TRUSTVAULT · AUDIT CHAIN — signing keypair attested at genesis",
    bar,
    `  pubkey b64    : ${audit.pubkeyB64}`,
    `  fingerprint   : ${audit.fpHex}`,
    `  signing store : ${audit.signingStore}`,
    `  chain head    : seq=${audit.headSeq}`,
    "",
    "  The private key lives in Aegis TrustVault (the KMS provider). Back up the provider's",
    "  durable storage alongside the database — losing it freezes the chain.",
    bar,
    "",
  ];
  for (const l of lines) console.log(l);
}

// Idempotent. Runs on every boot to make sure the platform org and built-in
// roles exist, and to promote any legacy 'admin'-role users (from a pre-RBAC
// deployment) to is_root with the platform org + root role pinned. Safe to
// call before bootstrapInitialAdmin: on a fresh DB it just creates the
// scaffolding; on an existing DB it migrates the original admin in place.
// Wrapped in _runWriteSession so the audited-table trigger admits the
// seeding writes (no human actor, no withAudit chain entry — this is a
// system-level reconciliation step like ensureSchema).
export async function ensurePlatformDefaults() {
  const client = await store.getPool().connect();
  try {
    await client.query("BEGIN");
    await store._setAuditSessionTx(client);
    await client.query(
      `SELECT pg_advisory_xact_lock(hashtext('opa_studio_platform_defaults'))`
    );

    // 1. Default org.
    let org = await store.getOrgBySlugTx(client, DEFAULT_PLATFORM_ORG_SLUG);
    let orgCreated = false;
    if (!org) {
      org = await store.insertOrgTx(client, {
        name: DEFAULT_PLATFORM_ORG_NAME,
        slug: DEFAULT_PLATFORM_ORG_SLUG,
      });
      orgCreated = true;
    }

    // 2. Built-in global roles. Each row is org_id=NULL so it's visible
    // across every org. Missing rows are inserted; existing rows are
    // left untouched (admins may have intentionally edited the seed
    // permissions, though for v1 we don't expose that on built-ins).
    const rolesCreated = [];
    const roleByName = {};
    for (const spec of BUILTIN_ROLES) {
      let role = await store.getRoleByNameTx(client, spec.name, null);
      if (!role) {
        role = await store.insertRoleTx(client, {
          orgId: null,
          name: spec.name,
          description: spec.description,
          permissions: spec.permissions,
          isBuiltin: true,
        });
        rolesCreated.push(spec.name);
      }
      roleByName[spec.name] = role;
    }

    // 3. Migrate legacy admins (pre-RBAC deployments only). On a fresh
    // boot the users table is still empty so this is a no-op; on an
    // upgrade boot it promotes the original 'admin'-role user(s) to
    // is_root with the platform org + root role pinned. Idempotent
    // because it filters on role_id IS NULL.
    const promoted = await store.promoteLegacyAdminsToRootTx(client, {
      orgId: org.id,
      roleId: roleByName.root.id,
    });

    await client.query("COMMIT");

    if (orgCreated || rolesCreated.length > 0 || promoted.length > 0) {
      const parts = [];
      if (orgCreated) parts.push(`org=${org.slug}`);
      if (rolesCreated.length) parts.push(`roles=[${rolesCreated.join(",")}]`);
      if (promoted.length) {
        parts.push(`promoted=[${promoted.map((p) => p.username).join(",")}]`);
      }
      console.log(`[platform-defaults] seeded ${parts.join(" ")}`);
    }

    return { org, roleByName, promoted };
  } catch (e) {
    try { await client.query("ROLLBACK"); } catch {}
    throw e;
  } finally {
    client.release();
  }
}

export async function bootstrapInitialAdmin() {
  if ((await store.countUsers()) > 0) {
    return { created: false, reason: "users-exist" };
  }

  // ensurePlatformDefaults must have run first so the platform org and
  // root role exist. server.js calls it before bootstrapInitialAdmin;
  // we re-check here so a misorder fails loudly instead of inserting a
  // root user with NULL org_id/role_id.
  const orgs = await store.listOrgs();
  const seededOrg = orgs.find((o) => o.slug === DEFAULT_PLATFORM_ORG_SLUG);
  if (!seededOrg) {
    throw new Error(
      "bootstrapInitialAdmin: platform org missing — call ensurePlatformDefaults first"
    );
  }

  const username = process.env.BOOTSTRAP_ADMIN_USERNAME || "admin";
  const password = crypto.randomBytes(18).toString("base64url");
  const passwordHash = await auth.hashPassword(password);

  const pool = store.getPool();
  const client = await pool.connect();
  let createdAdmin = null;
  let genesisSeq = null;
  let genesisHash = null;
  let signingPub = null;
  let rootRole = null;
  try {
    await client.query("BEGIN");
    await store._setAuditSessionTx(client);
    await client.query(
      `SELECT pg_advisory_xact_lock(hashtext('opa_studio_bootstrap'))`
    );
    const { rows: cnt } = await client.query(
      `SELECT COUNT(*)::int AS n FROM users`
    );
    if (cnt[0].n > 0) {
      await client.query("COMMIT");
      return { created: false, reason: "race-lost" };
    }

    // Resolve the root role inside the txn so any concurrent seed lands
    // before us via the advisory lock above (we don't hold the
    // platform_defaults lock here — different key — but both txns set
    // the audit-session marker and the role is created idempotently).
    rootRole = await store.getRoleByNameTx(client, "root", null);
    if (!rootRole) {
      throw new Error("bootstrapInitialAdmin: root role missing");
    }

    const { rows: adminRows } = await client.query(
      `INSERT INTO users (username, password_hash, role, must_change_password,
                          org_id, role_id, is_root)
       VALUES ($1, $2, 'admin', true, $3, $4, true)
       RETURNING id, username, role, org_id, role_id, is_root,
                 must_change_password, created_at`,
      [username, passwordHash, seededOrg.id, rootRole.id]
    );
    createdAdmin = adminRows[0];

    // Register the KMS provider's active public key in audit_signing_keys.
    // This makes the on-disk DB self-contained for verification — the chain
    // can be verified offline using only audit_log + audit_signing_keys,
    // even if the KMS provider is later unavailable.
    signingPub = await audit.registerSigningKeyTx(client);

    // Build the genesis payload.
    const payload = {
      ts: new Date().toISOString(),
      type: "genesis",
      schema_version: 1,
      admin: {
        id: createdAdmin.id,
        username: createdAdmin.username,
        role: createdAdmin.role,
        org_id: createdAdmin.org_id,
        role_id: createdAdmin.role_id,
        is_root: createdAdmin.is_root,
      },
      platform_org: { id: seededOrg.id, slug: seededOrg.slug, name: seededOrg.name },
      root_role: { id: rootRole.id, name: rootRole.name },
      pubkey_b64: signingPub.pubkeyDer.toString("base64"),
      signing_key_fp_hex: signingPub.fingerprintSha256.toString("hex"),
      bootstrap_at: createdAdmin.created_at.toISOString(),
    };
    const canonical = auditCrypto.canonicalize(payload);
    const hash = auditCrypto.entryHash(null, canonical);
    const { sigBytes } = await audit.signEntryHash(hash);

    const inserted = await store.appendAuditEntryTx(client, {
      prevHash: null,
      entryHash: hash,
      payload,
      payloadCanonical: canonical,
      signature: sigBytes,
      signingKeyFp: signingPub.fingerprintSha256,
      actorId: createdAdmin.id,
      actorUsername: createdAdmin.username,
      actorOrgId: seededOrg.id,
      action: "genesis",
      resourceType: "system",
      resourceId: null,
    });
    genesisSeq = inserted.seq;
    genesisHash = hash;

    await client.query("COMMIT");
  } catch (e) {
    try { await client.query("ROLLBACK"); } catch {}
    console.error(`[bootstrap] FATAL during genesis transaction: ${e.message}`);
    throw e;
  } finally {
    client.release();
  }

  // After the DB commit: write the password to disk. If that fails, the
  // password is still recoverable from the banner log line below.
  let passwordPath = passwordFilePath();
  try {
    fs.writeFileSync(passwordPath, password + "\n", { mode: 0o600 });
  } catch (e) {
    try {
      fs.writeFileSync(PASSWORD_TMP_FALLBACK, password + "\n", { mode: 0o600 });
      console.warn(
        `[BOOTSTRAP] Could not write to ${passwordPath}: ${e.message}. ` +
          `Wrote fallback ${PASSWORD_TMP_FALLBACK}.`
      );
      passwordPath = PASSWORD_TMP_FALLBACK;
    } catch (e2) {
      console.warn(
        `[BOOTSTRAP] Could not write password file (${e2.message}). ` +
          `The password is only in the log banner below.`
      );
      passwordPath = "<not written to disk>";
    }
  }

  printBanner({
    username,
    password,
    passwordPath,
    org: seededOrg,
    role: rootRole,
    audit: {
      pubkeyB64: signingPub.pubkeyDer.toString("base64"),
      fpHex: signingPub.fingerprintSha256.toString("hex"),
      signingStore: audit.getSigningStoreLabel(),
      headSeq: genesisSeq,
    },
  });
  return {
    created: true,
    username,
    passwordPath,
    org: { id: seededOrg.id, slug: seededOrg.slug, name: seededOrg.name },
    role: { id: rootRole.id, name: rootRole.name },
    audit: {
      fingerprint: signingPub.fingerprintSha256,
      headSeq: genesisSeq,
      headHash: genesisHash,
    },
  };
}

// Best-effort cleanup. Called after the bootstrapped admin completes the
// forced password change. Does NOT touch Vault.
export function deleteInitialAdminPasswordFile() {
  for (const p of [passwordFilePath(), PASSWORD_TMP_FALLBACK]) {
    try {
      if (fs.existsSync(p)) {
        fs.unlinkSync(p);
        console.log(`[BOOTSTRAP] Removed initial password file: ${p}`);
      }
    } catch (e) {
      console.warn(
        `[BOOTSTRAP] Failed to remove ${p}: ${e.message} (continuing).`
      );
    }
  }
}
