import pg from "pg";

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });

// Exported so the bootstrap module can open a single client + transaction
// that does admin-creation + audit-genesis atomically.
export function getPool() { return pool; }

export async function ensureSchema() {
  // pgcrypto provides digest(); gen_random_uuid() is core in PG 13+.
  await pool.query(`CREATE EXTENSION IF NOT EXISTS pgcrypto`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS policies (
      id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
      name        TEXT        NOT NULL,
      package     TEXT        NOT NULL,
      description TEXT        NOT NULL DEFAULT '',
      rules       JSONB       NOT NULL DEFAULT '[]',
      rego        TEXT        NOT NULL DEFAULT '',
      version     INTEGER     NOT NULL DEFAULT 1,
      locked      BOOLEAN     NOT NULL DEFAULT false,
      slug        TEXT        UNIQUE,
      created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    -- Idempotent migration for existing deployments: add the column if absent.
    ALTER TABLE policies
      ADD COLUMN IF NOT EXISTS locked BOOLEAN NOT NULL DEFAULT false;
    CREATE TABLE IF NOT EXISTS policy_versions (
      policy_id   UUID        NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
      version     INTEGER     NOT NULL,
      saved_at    TIMESTAMPTZ NOT NULL,
      spec        JSONB       NOT NULL,
      PRIMARY KEY (policy_id, version)
    );
    CREATE TABLE IF NOT EXISTS users (
      id                    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
      username              TEXT        NOT NULL UNIQUE,
      email                 TEXT        UNIQUE,
      password_hash         TEXT        NOT NULL,
      role                  TEXT        NOT NULL DEFAULT 'admin',
      must_change_password  BOOLEAN     NOT NULL DEFAULT false,
      disabled              BOOLEAN     NOT NULL DEFAULT false,
      last_login_at         TIMESTAMPTZ,
      created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS users_username_lower_idx ON users (lower(username));

    CREATE TABLE IF NOT EXISTS audit_log (
      seq               BIGSERIAL    PRIMARY KEY,
      prev_hash         BYTEA,
      entry_hash        BYTEA        NOT NULL UNIQUE,
      payload           JSONB        NOT NULL,
      payload_canonical TEXT         NOT NULL,
      signature         BYTEA        NOT NULL,
      signing_key_fp    BYTEA        NOT NULL,
      actor_id          UUID,
      actor_username    TEXT         NOT NULL,
      action            TEXT         NOT NULL,
      resource_type     TEXT         NOT NULL,
      resource_id       TEXT,
      created_at        TIMESTAMPTZ  NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS audit_log_action_idx
      ON audit_log(action);
    CREATE INDEX IF NOT EXISTS audit_log_resource_idx
      ON audit_log(resource_type, resource_id);

    CREATE TABLE IF NOT EXISTS audit_state (
      id        INT     PRIMARY KEY DEFAULT 1,
      head_seq  BIGINT  NOT NULL,
      head_hash BYTEA   NOT NULL,
      CONSTRAINT audit_state_singleton CHECK (id = 1)
    );

    CREATE TABLE IF NOT EXISTS audit_signing_keys (
      fp          BYTEA       PRIMARY KEY,
      pubkey      BYTEA       NOT NULL,
      algorithm   TEXT        NOT NULL DEFAULT 'ed25519',
      created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
      retired_at  TIMESTAMPTZ
    );

    -- CRY-03: platform-managed trust store published to OPA at data.studio.keys.
    -- Each row is a single named key (by kid). 'inline' rows carry the material
    -- directly; 'jwks_url' rows are refreshed by the background fetcher and the
    -- specific kid is picked out of the upstream JWKS document. Revoked rows
    -- are excluded from the published map within one publish interval, so live
    -- policies stop accepting tokens signed by the key promptly.
    CREATE TABLE IF NOT EXISTS policy_trust_keys (
      kid                   TEXT        PRIMARY KEY,
      alg                   TEXT        NOT NULL,
      jwk                   JSONB,
      pem                   TEXT,
      secret                TEXT,
      x5c                   JSONB,
      status                TEXT        NOT NULL DEFAULT 'active',
      tenant                TEXT,
      source_kind           TEXT        NOT NULL DEFAULT 'inline',
      jwks_url              TEXT,
      jwks_ttl_seconds      INTEGER,
      jwks_last_fetched_at  TIMESTAMPTZ,
      jwks_last_error       TEXT,
      created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
      CONSTRAINT policy_trust_keys_status_chk
        CHECK (status IN ('active','revoked')),
      CONSTRAINT policy_trust_keys_source_kind_chk
        CHECK (source_kind IN ('inline','jwks_url'))
    );
    CREATE INDEX IF NOT EXISTS policy_trust_keys_status_idx
      ON policy_trust_keys(status);
    CREATE INDEX IF NOT EXISTS policy_trust_keys_jwks_idx
      ON policy_trust_keys(source_kind) WHERE source_kind = 'jwks_url';

    -- PEP-01: callers permitted to hit the PEP /authorize and /discover
    -- surface. Each row declares ONE auth_mode (hmac | mtls | jwt); the PEP
    -- dispatches per-request based on which credential kind the caller
    -- presents and asserts it matches the row's declared mode. Published to
    -- OPA at data.studio.callers; the PEP reads that doc on every request.
    -- Revoke-then-delete invariant mirrors trust keys so the audit history
    -- of caller material stays intact.
    CREATE TABLE IF NOT EXISTS pep_callers (
      caller_id    TEXT        PRIMARY KEY,
      auth_mode    TEXT        NOT NULL,
      description  TEXT,
      hmac_secret  TEXT,
      allowed_cn   TEXT,
      jwt_subject  TEXT,
      status       TEXT        NOT NULL DEFAULT 'active',
      tenant       TEXT,
      created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
      revoked_at   TIMESTAMPTZ,
      CONSTRAINT pep_callers_status_chk CHECK (status IN ('active','revoked')),
      CONSTRAINT pep_callers_auth_mode_chk CHECK (auth_mode IN ('hmac','mtls','jwt')),
      -- A row's declared mode must carry the material that mode needs. The
      -- route layer validates this for friendlier error messages; the DB
      -- constraint is defense-in-depth so out-of-band inserts fail loudly.
      CONSTRAINT pep_callers_material_chk CHECK (
        (auth_mode = 'hmac' AND hmac_secret IS NOT NULL) OR
        (auth_mode = 'mtls' AND allowed_cn  IS NOT NULL) OR
        (auth_mode = 'jwt')
      )
    );
    CREATE INDEX IF NOT EXISTS pep_callers_status_idx ON pep_callers(status);
    CREATE INDEX IF NOT EXISTS pep_callers_auth_mode_idx ON pep_callers(auth_mode)
      WHERE status = 'active';
    -- mtls dispatch keys off the CN. Two active mtls rows with the same CN
    -- would be ambiguous, so reject at write time.
    CREATE UNIQUE INDEX IF NOT EXISTS pep_callers_mtls_cn_uniq
      ON pep_callers(allowed_cn)
      WHERE status = 'active' AND auth_mode = 'mtls';

    -- Per-caller policy access list. The PEP rejects /authorize and filters
    -- /discover against this table so a caller can only invoke the policies
    -- an admin has explicitly granted them. Grants are binary (row exists
    -- → granted; absent → denied); revoke is DELETE. Audit history of who
    -- granted/revoked what stays in the audit chain.
    CREATE TABLE IF NOT EXISTS pep_caller_policy_access (
      caller_id   TEXT        NOT NULL REFERENCES pep_callers(caller_id) ON DELETE CASCADE,
      policy_id   UUID        NOT NULL REFERENCES policies(id)           ON DELETE CASCADE,
      granted_by  UUID,
      granted_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY (caller_id, policy_id)
    );
    CREATE INDEX IF NOT EXISTS pep_caller_policy_access_caller_idx
      ON pep_caller_policy_access(caller_id);
    CREATE INDEX IF NOT EXISTS pep_caller_policy_access_policy_idx
      ON pep_caller_policy_access(policy_id);

    -- Free-form admin-defined labels. Policies carry tags; callers carry
    -- scope_tags. The PEP-ACL publisher computes the live caller-to-policies
    -- map at publish time as
    --   explicit grants UNION { p in policies : p.tags ∩ caller.scope_tags non-empty }
    -- so a new policy tagged with one of a caller scope tags auto-appears
    -- in the published doc on the next publish without an admin action.
    -- TEXT[] (not JSONB) so the && overlap operator + GIN works natively.
    ALTER TABLE policies   ADD COLUMN IF NOT EXISTS tags       TEXT[] NOT NULL DEFAULT '{}';
    ALTER TABLE pep_callers ADD COLUMN IF NOT EXISTS scope_tags TEXT[] NOT NULL DEFAULT '{}';
    CREATE INDEX IF NOT EXISTS policies_tags_gin
      ON policies USING GIN (tags);
    CREATE INDEX IF NOT EXISTS pep_callers_scope_tags_gin
      ON pep_callers USING GIN (scope_tags);

    -- Platform signing keys (separate from the audit-signing key in
    -- audit_signing_keys). Tracks the KMS-held Ed25519 keys that the backend
    -- and PEP use to authenticate to OPA and to sign user-session JWTs. Each
    -- purpose has at most one 'active' row (enforced by a partial unique
    -- index). Rotation: pending -> active, previous active -> retired.
    -- Revoke is allowed only on retired rows. Deletion is never allowed.
    CREATE TABLE IF NOT EXISTS platform_signing_keys (
      fp           BYTEA       PRIMARY KEY,
      pubkey       BYTEA       NOT NULL,
      algorithm    TEXT        NOT NULL DEFAULT 'ed25519',
      purpose      TEXT        NOT NULL,
      key_id       TEXT        NOT NULL,
      status       TEXT        NOT NULL DEFAULT 'active',
      created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
      activated_at TIMESTAMPTZ DEFAULT now(),
      retired_at   TIMESTAMPTZ,
      revoked_at   TIMESTAMPTZ,
      CONSTRAINT platform_signing_keys_purpose_chk
        CHECK (purpose IN ('opa-auth-signing','session-signing','pep-opa-auth-signing')),
      CONSTRAINT platform_signing_keys_status_chk
        CHECK (status IN ('pending','active','retired','revoked'))
    );
    CREATE UNIQUE INDEX IF NOT EXISTS platform_signing_keys_one_active_per_purpose
      ON platform_signing_keys(purpose) WHERE status = 'active';
    CREATE INDEX IF NOT EXISTS platform_signing_keys_purpose_status_idx
      ON platform_signing_keys(purpose, status);

    -- Organizations (flat — no hierarchy). The default 'platform' org is
    -- seeded at first boot for the root admin. Every non-root user belongs
    -- to exactly one org. Resources (policies, trust keys, PEP callers)
    -- carry org_id NULL (= global, root-managed) or a specific org_id
    -- (= owned by that org); sub-admins only see rows in their own org.
    CREATE TABLE IF NOT EXISTS orgs (
      id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
      name        TEXT         NOT NULL,
      slug        TEXT         NOT NULL UNIQUE,
      created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
      updated_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
    );

    -- Roles carry an action × resource_type permission matrix in JSONB,
    -- e.g. { "policy": ["read","create","update","lock"], "user": ["read"] }.
    -- Built-in roles (root, org_admin, policy_author, auditor, viewer) are
    -- seeded with org_id NULL so they're visible/assignable to any org.
    -- Custom roles defined by an org admin carry org_id pointing to their
    -- org. The 'root' role exists primarily as a marker — actual root
    -- power comes from users.is_root, which bypasses the permission map.
    CREATE TABLE IF NOT EXISTS roles (
      id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id        UUID         REFERENCES orgs(id) ON DELETE CASCADE,
      name          TEXT         NOT NULL,
      description   TEXT         NOT NULL DEFAULT '',
      permissions   JSONB        NOT NULL DEFAULT '{}',
      is_builtin    BOOLEAN      NOT NULL DEFAULT false,
      created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
      updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
    );
    -- Name uniqueness within scope: global roles unique by name; org-local
    -- roles unique by (org_id, name). Two partial indexes because UNIQUE
    -- treats NULLs as distinct, so a single composite UNIQUE wouldn't
    -- collide on duplicate global names.
    CREATE UNIQUE INDEX IF NOT EXISTS roles_global_name_uniq
      ON roles(name) WHERE org_id IS NULL;
    CREATE UNIQUE INDEX IF NOT EXISTS roles_org_name_uniq
      ON roles(org_id, name) WHERE org_id IS NOT NULL;

    -- RBAC columns on users (idempotent migration for existing deployments).
    -- org_id is NULL only for the root admin; role_id is NULL only for
    -- legacy rows pre-RBAC migration (those are promoted to root on boot
    -- by bootstrap.ensurePlatformDefaults). is_root is the authoritative
    -- bypass flag — checked first by studio_authz before any permission
    -- map is consulted.
    ALTER TABLE users ADD COLUMN IF NOT EXISTS org_id  UUID    REFERENCES orgs(id);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS role_id UUID    REFERENCES roles(id);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS is_root BOOLEAN NOT NULL DEFAULT false;
    CREATE INDEX IF NOT EXISTS users_org_id_idx  ON users(org_id);
    CREATE INDEX IF NOT EXISTS users_role_id_idx ON users(role_id);

    -- Resource ownership. NULL = global (only root sees / can manage);
    -- non-NULL = owned by that org. Existing rows on first migration get
    -- NULL → they're invisible to sub-admins until root reassigns them.
    -- That's intentional: cross-org isolation defaults closed.
    ALTER TABLE policies          ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES orgs(id);
    ALTER TABLE policy_trust_keys ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES orgs(id);
    ALTER TABLE pep_callers       ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES orgs(id);
    CREATE INDEX IF NOT EXISTS policies_org_id_idx          ON policies(org_id);
    CREATE INDEX IF NOT EXISTS policy_trust_keys_org_id_idx ON policy_trust_keys(org_id);
    CREATE INDEX IF NOT EXISTS pep_callers_org_id_idx       ON pep_callers(org_id);

    -- Audit log: org context of the actor at write time. NULL on pre-RBAC
    -- entries and on system actions; populated on every post-migration
    -- mutation by withAudit so org-scoped audit views are cheap.
    ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS actor_org_id UUID;
    CREATE INDEX IF NOT EXISTS audit_log_actor_org_idx ON audit_log(actor_org_id);
  `);

  // Defense-in-depth: forbid out-of-band writes to audited tables.
  //
  // The audit chain proves that audit_log is internally consistent, but
  // without an extra gate a privileged-DB-user (or a code path that forgot
  // withAudit) can mutate the data tables and the chain wouldn't notice.
  //
  // We require every INSERT/UPDATE/DELETE on an audited table to run in a
  // transaction that has called set_config('opa_studio.audit_session','on',true).
  // withAudit() and the explicit bootstrap/init transactions set this; raw
  // psql sessions don't. The trigger raises P0001 when the marker is absent.
  //
  // Non-audited writes that still touch audited tables (login timestamps,
  // background JWKS refreshes, seeding, bootstrap) go through _runWriteSession
  // which sets the marker explicitly — they are intentional non-audited writes
  // and the marker acknowledges that.
  await pool.query(`
    CREATE OR REPLACE FUNCTION _opa_studio_require_audit_session()
    RETURNS TRIGGER LANGUAGE plpgsql AS $fn$
    BEGIN
      IF current_setting('opa_studio.audit_session', true) IS DISTINCT FROM 'on' THEN
        RAISE EXCEPTION
          'audited_write_outside_managed_context: % on % — writes to audited tables must go through withAudit() or runWriteSession()',
          TG_OP, TG_TABLE_NAME
          USING ERRCODE = 'P0001';
      END IF;
      RETURN NULL;
    END;
    $fn$;
  `);
  // Triggers are dropped+recreated so they pick up function-signature
  // changes on subsequent boots. Each audited table gets ONE statement-level
  // BEFORE trigger; per-row would fire too often without changing the check.
  for (const tbl of [
    "policies",
    "policy_versions",
    "users",
    "audit_log",
    "audit_state",
    "audit_signing_keys",
    "policy_trust_keys",
    "pep_callers",
    "pep_caller_policy_access",
    "platform_signing_keys",
    "orgs",
    "roles",
  ]) {
    await pool.query(`
      DROP TRIGGER IF EXISTS ${tbl}_require_audit_session ON ${tbl};
      CREATE TRIGGER ${tbl}_require_audit_session
        BEFORE INSERT OR UPDATE OR DELETE ON ${tbl}
        FOR EACH STATEMENT
        EXECUTE FUNCTION _opa_studio_require_audit_session();
    `);
  }

  // Verifier function (CREATE OR REPLACE so it's idempotent on every boot).
  // Walks audit_log in seq order, recomputing entry_hash from prev_hash and
  // payload_canonical, and confirming the head pointer matches the tail.
  await pool.query(`
    CREATE OR REPLACE FUNCTION audit_verify_chain()
    RETURNS TABLE(seq BIGINT, ok BOOLEAN, reason TEXT) LANGUAGE plpgsql AS $fn$
    DECLARE
      expected_prev BYTEA := NULL;
      rec RECORD;
      computed BYTEA;
    BEGIN
      FOR rec IN SELECT al.seq, al.prev_hash, al.payload_canonical, al.entry_hash
                 FROM audit_log al ORDER BY al.seq ASC LOOP
        IF rec.prev_hash IS DISTINCT FROM expected_prev THEN
          seq := rec.seq; ok := false; reason := 'prev_hash linkage broken';
          RETURN NEXT; RETURN;
        END IF;
        computed := digest(coalesce(rec.prev_hash, decode(repeat('00', 32), 'hex'))
                           || convert_to(rec.payload_canonical, 'UTF8'),
                           'sha256');
        IF computed IS DISTINCT FROM rec.entry_hash THEN
          seq := rec.seq; ok := false; reason := 'entry_hash mismatch (payload tampered)';
          RETURN NEXT; RETURN;
        END IF;
        expected_prev := rec.entry_hash;
      END LOOP;
      IF expected_prev IS NULL THEN
        seq := 0; ok := true; reason := 'empty chain';
        RETURN NEXT; RETURN;
      END IF;
      PERFORM 1 FROM audit_state WHERE head_hash = expected_prev;
      IF NOT FOUND THEN
        seq := 0; ok := false; reason := 'audit_state.head_hash does not match chain tail';
        RETURN NEXT; RETURN;
      END IF;
      seq := 0; ok := true; reason := 'all chain links and head pointer verified';
      RETURN NEXT;
    END;
    $fn$;
  `);
}

export async function listPolicies(actor) {
  const scope = orgScopeWhere(actor);
  const { rows } = await pool.query(
    `SELECT id, name, package, description, rules, rego, version, locked, org_id, tags, created_at, updated_at
     FROM policies WHERE TRUE${scope.where} ORDER BY updated_at DESC`,
    scope.params
  );
  return rows.map(rowToPolicy);
}

export async function getPolicy(id, actor) {
  const scope = orgScopeWhere(actor, { paramStart: 2 });
  const { rows } = await pool.query(
    `SELECT * FROM policies WHERE id = $1${scope.where}`,
    [id, ...scope.params]
  );
  if (!rows.length) return null;
  const policy = rowToPolicy(rows[0]);
  const { rows: vrows } = await pool.query(
    `SELECT version, saved_at, spec FROM policy_versions
     WHERE policy_id = $1 ORDER BY version DESC`,
    [id]
  );
  policy.history = vrows.map(({ version, saved_at, spec }) => ({
    version,
    savedAt: saved_at,
    spec,
  }));
  return policy;
}

// Custom error thrown by savePolicyTx when the caller tries to overwrite a
// locked policy. server.js catches this and returns 409.
export class PolicyLockedError extends Error {
  constructor(id) {
    super(`Policy ${id} is locked; unlock it before modifying`);
    this.code = "POLICY_LOCKED";
  }
}

// Transactional variant. Runs against an open client (no BEGIN/COMMIT here).
// Returns { before, after } where before is the row (snake_case columns) that
// existed prior to upsert, or null on create. after is the saved policy in the
// usual camelCase shape, without history.
//
// Refuses to update a row whose locked=true. Lock state is changed only via
// setPolicyLockedTx() — never via this function.
export async function savePolicyTx(client, policy) {
  const { rows: existingRows } = await client.query(
    `SELECT id, name, package, description, rules, rego, version, locked, org_id, tags, created_at, updated_at
     FROM policies WHERE id = $1`,
    [policy.id]
  );
  const before = existingRows[0] || null;
  if (before?.locked) {
    throw new PolicyLockedError(policy.id);
  }
  const isNew = !before;
  const newVersion = isNew ? 1 : before.version + 1;
  const createdAt = isNew ? new Date() : before.created_at;

  if (!isNew) {
    const { rows: vcount } = await client.query(
      `SELECT COUNT(*)::int AS n FROM policy_versions WHERE policy_id = $1`,
      [policy.id]
    );
    if (vcount[0].n === 0) {
      await client.query(
        `INSERT INTO policy_versions (policy_id, version, saved_at, spec) VALUES ($1,$2,$3,$4)`,
        [
          policy.id,
          before.version,
          before.updated_at,
          JSON.stringify({
            name: before.name,
            package: before.package,
            description: before.description,
            rules: before.rules,
            rego: before.rego,
          }),
        ]
      );
    }
  }

  // org_id is set only on INSERT. Update path explicitly does NOT touch
  // org_id so an org-admin renaming a policy can't accidentally rehome
  // it. To move a policy across orgs we'd add a dedicated route in a
  // later step (or root can drop+recreate). Null = global / root-owned.
  await client.query(
    `INSERT INTO policies (id, name, package, description, rules, rego, version,
                            org_id, created_at, updated_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,now())
     ON CONFLICT (id) DO UPDATE SET
       name=$2, package=$3, description=$4, rules=$5, rego=$6,
       version=$7, updated_at=now()`,
    [
      policy.id,
      policy.name,
      policy.package,
      policy.description || "",
      JSON.stringify(policy.rules || []),
      policy.rego || "",
      newVersion,
      policy.orgId ?? null,
      createdAt,
    ]
  );

  await client.query(
    `INSERT INTO policy_versions (policy_id, version, saved_at, spec) VALUES ($1,$2,now(),$3)`,
    [
      policy.id,
      newVersion,
      JSON.stringify({
        name: policy.name,
        package: policy.package,
        description: policy.description || "",
        rules: policy.rules || [],
        rego: policy.rego || "",
      }),
    ]
  );

  await client.query(
    `DELETE FROM policy_versions
     WHERE policy_id = $1
       AND version NOT IN (
         SELECT version FROM policy_versions WHERE policy_id = $1
         ORDER BY version DESC LIMIT 50
       )`,
    [policy.id]
  );

  const { rows: afterRows } = await client.query(
    `SELECT id, name, package, description, rules, rego, version, locked, org_id, tags, created_at, updated_at
     FROM policies WHERE id = $1`,
    [policy.id]
  );
  return { before, after: rowToPolicy(afterRows[0]) };
}

export async function savePolicy(policy) {
  await _runWriteSession((client) => savePolicyTx(client, policy));
  return getPolicy(policy.id);
}

// Returns the row that was deleted (full content, snake_case), or null.
export async function deletePolicyTx(client, id) {
  const { rows } = await client.query(
    `DELETE FROM policies WHERE id = $1
     RETURNING id, name, package, description, rules, rego, version, created_at, updated_at`,
    [id]
  );
  return rows[0] || null;
}

export async function deletePolicy(id) {
  return _runWriteSession(async (client) => {
    const { rowCount } = await client.query(
      `DELETE FROM policies WHERE id = $1`, [id]
    );
    return rowCount > 0;
  });
}

// Toggle the locked flag, bump version, and snapshot a version row.
// Returns { before, after, changed } where:
//   before: the snake_case row prior to the change (null if policy missing)
//   after:  the camelCase policy AFTER the change (null if policy missing)
//   changed: true if locked actually flipped (false on idempotent no-op)
//
// Lock is conceptually an "update" — it goes through the same version-history
// machinery as a content edit, so the audit chain has a record of it AND the
// History tab in the UI shows the lock event.
export async function setPolicyLockedTx(client, id, locked) {
  const { rows: existingRows } = await client.query(
    `SELECT id, name, package, description, rules, rego, version, locked, org_id, tags, created_at, updated_at
     FROM policies WHERE id = $1`,
    [id]
  );
  const before = existingRows[0] || null;
  if (!before) return { before: null, after: null, changed: false };
  if (!!before.locked === !!locked) {
    return { before, after: rowToPolicy(before), changed: false };
  }
  const newVersion = before.version + 1;

  // Backfill: if there are no version rows yet, snapshot pre-lock state.
  const { rows: vcount } = await client.query(
    `SELECT COUNT(*)::int AS n FROM policy_versions WHERE policy_id = $1`,
    [id]
  );
  if (vcount[0].n === 0) {
    await client.query(
      `INSERT INTO policy_versions (policy_id, version, saved_at, spec) VALUES ($1,$2,$3,$4)`,
      [
        id,
        before.version,
        before.updated_at,
        JSON.stringify({
          name: before.name,
          package: before.package,
          description: before.description,
          rules: before.rules,
          rego: before.rego,
          locked: !!before.locked,
        }),
      ]
    );
  }

  await client.query(
    `UPDATE policies SET locked = $1, version = $2, updated_at = now() WHERE id = $3`,
    [!!locked, newVersion, id]
  );

  await client.query(
    `INSERT INTO policy_versions (policy_id, version, saved_at, spec) VALUES ($1,$2,now(),$3)`,
    [
      id,
      newVersion,
      JSON.stringify({
        name: before.name,
        package: before.package,
        description: before.description,
        rules: before.rules,
        rego: before.rego,
        locked: !!locked,
      }),
    ]
  );

  await client.query(
    `DELETE FROM policy_versions
     WHERE policy_id = $1
       AND version NOT IN (
         SELECT version FROM policy_versions WHERE policy_id = $1
         ORDER BY version DESC LIMIT 50
       )`,
    [id]
  );

  const { rows: afterRows } = await client.query(
    `SELECT id, name, package, description, rules, rego, version, locked, org_id, tags, created_at, updated_at
     FROM policies WHERE id = $1`,
    [id]
  );
  return { before, after: rowToPolicy(afterRows[0]), changed: true };
}

export async function bulkSeed(policies) {
  return _runWriteSession(async (client) => {
    let added = 0;
    for (const p of policies) {
      const { rowCount } = await client.query(
        `INSERT INTO policies (id, name, package, description, rules, rego, version, slug, created_at, updated_at)
         VALUES (gen_random_uuid(),$1,$2,$3,$4,$5,1,$6,now(),now())
         ON CONFLICT (slug) DO NOTHING`,
        [
          p.name,
          p.package,
          p.description || "",
          JSON.stringify(p.rules || []),
          p.rego || "",
          p.slug,
        ]
      );
      if (rowCount > 0) added++;
    }
    return added;
  });
}

export async function getPolicyVersions(id) {
  // Extract spec.locked from JSONB so the History UI can show a per-version
  // lock badge without a round-trip per row. Older snapshots taken before
  // the lock feature lack the field — coalesce to false.
  const { rows } = await pool.query(
    `SELECT version, saved_at,
            COALESCE((spec->>'locked')::boolean, false) AS locked
       FROM policy_versions
      WHERE policy_id = $1
      ORDER BY version DESC`,
    [id]
  );
  if (!rows.length) {
    const { rows: p } = await pool.query(`SELECT id FROM policies WHERE id = $1`, [id]);
    if (!p.length) return null;
  }
  return rows.map(({ version, saved_at, locked }) => ({
    version,
    savedAt: saved_at,
    locked: !!locked,
  }));
}

export async function getPolicyVersion(id, versionNum) {
  const { rows } = await pool.query(
    `SELECT version, saved_at, spec FROM policy_versions
     WHERE policy_id = $1 AND version = $2`,
    [id, versionNum]
  );
  if (!rows.length) return null;
  return { version: rows[0].version, savedAt: rows[0].saved_at, spec: rows[0].spec };
}

// No-op — retained so any existing call sites don't break
export async function migrateVersions() { return 0; }

function rowToPolicy(row) {
  return {
    id: row.id,
    name: row.name,
    package: row.package,
    description: row.description,
    rules: row.rules,
    rego: row.rego,
    version: row.version,
    locked: !!row.locked,
    orgId: row.org_id ?? null,
    tags: Array.isArray(row.tags) ? row.tags : [],
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

// ─── Users ─────────────────────────────────────────────────────────────────

function rowToUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    username: row.username,
    email: row.email,
    role: row.role,
    orgId: row.org_id ?? null,
    roleId: row.role_id ?? null,
    isRoot: !!row.is_root,
    mustChangePassword: row.must_change_password,
    disabled: row.disabled,
    lastLoginAt: row.last_login_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export async function countUsers() {
  const { rows } = await pool.query(`SELECT COUNT(*)::int AS n FROM users`);
  return rows[0].n;
}

export async function countAdmins() {
  const { rows } = await pool.query(
    `SELECT COUNT(*)::int AS n FROM users WHERE role = 'admin' AND disabled = false`
  );
  return rows[0].n;
}

export async function listUsers(actor) {
  const scope = orgScopeWhere(actor);
  const { rows } = await pool.query(
    `SELECT id, username, email, role, org_id, role_id, is_root,
            must_change_password, disabled,
            last_login_at, created_at, updated_at
       FROM users WHERE TRUE${scope.where}
       ORDER BY created_at ASC`,
    scope.params
  );
  return rows.map(rowToUser);
}

// Returns the raw row (including password_hash) for auth verification.
// Callers MUST NOT return this object to clients.
export async function getUserByUsernameWithHash(username) {
  const { rows } = await pool.query(
    `SELECT * FROM users WHERE lower(username) = lower($1)`,
    [username]
  );
  return rows[0] || null;
}

export async function getUserById(id) {
  const { rows } = await pool.query(`SELECT * FROM users WHERE id = $1`, [id]);
  if (!rows.length) return null;
  return { ...rowToUser(rows[0]), passwordHash: rows[0].password_hash };
}

// Fetch a user along with their effective permissions resolved from
// the joined role row. Used by authenticate.js (every authenticated
// request) and /api/auth/me. roleName/roleDescription are surfaced
// so the frontend can show a friendly label without an extra round
// trip. permissions = {} for users with no role_id assigned (legacy
// non-admin rows that never got promoted; root bypass makes this
// effectively unreachable for active deployments).
export async function getUserAuthContext(id) {
  const { rows } = await pool.query(
    `SELECT u.*, r.name AS role_name, r.description AS role_description,
            r.permissions AS role_permissions, r.is_builtin AS role_is_builtin
       FROM users u
       LEFT JOIN roles r ON r.id = u.role_id
      WHERE u.id = $1`,
    [id]
  );
  if (!rows.length) return null;
  const row = rows[0];
  const base = rowToUser(row);
  return {
    ...base,
    roleName: row.role_name || null,
    roleDescription: row.role_description || "",
    roleIsBuiltin: !!row.role_is_builtin,
    permissions: row.role_permissions || {},
  };
}

export async function createUser({
  username,
  email = null,
  passwordHash,
  role = "admin",
  mustChangePassword = false,
}) {
  const { rows } = await pool.query(
    `INSERT INTO users (username, email, password_hash, role, must_change_password)
     VALUES ($1, $2, $3, $4, $5)
     RETURNING *`,
    [username, email, passwordHash, role, mustChangePassword]
  );
  return rowToUser(rows[0]);
}

export async function updateUserPassword(id, passwordHash, mustChangePassword) {
  await _runWriteSession((client) => client.query(
    `UPDATE users
        SET password_hash = $1,
            must_change_password = $2,
            updated_at = now()
      WHERE id = $3`,
    [passwordHash, mustChangePassword, id]
  ));
}

export async function updateUserRole(id, role) {
  await _runWriteSession((client) => client.query(
    `UPDATE users SET role = $1, updated_at = now() WHERE id = $2`,
    [role, id]
  ));
}

export async function setUserDisabled(id, disabled) {
  await _runWriteSession((client) => client.query(
    `UPDATE users SET disabled = $1, updated_at = now() WHERE id = $2`,
    [disabled, id]
  ));
}

// Non-audited write: every login updates last_login_at. Wrapped in
// _runWriteSession so the audited-table trigger admits the write — the
// intent is "non-audited but acknowledged", not "rogue out-of-band edit".
export async function touchUserLogin(id) {
  await _runWriteSession((client) => client.query(
    `UPDATE users SET last_login_at = now(), updated_at = now() WHERE id = $1`,
    [id]
  ));
}

export async function deleteUser(id) {
  return _runWriteSession(async (client) => {
    const { rowCount } = await client.query(
      `DELETE FROM users WHERE id = $1`, [id]
    );
    return rowCount > 0;
  });
}

// Atomic bootstrap: only inserts the admin row if the table is still empty.
// Returns the created user, or null if another replica won the race.
export async function transactionalCreateAdminIfEmpty({
  username,
  passwordHash,
  role = "admin",
  mustChangePassword = true,
}) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await _setAuditSessionTx(client);
    // Advisory lock keyed on a stable tag so concurrent boots serialize.
    await client.query(
      `SELECT pg_advisory_xact_lock(hashtext('opa_studio_bootstrap'))`
    );
    const { rows: countRows } = await client.query(
      `SELECT COUNT(*)::int AS n FROM users`
    );
    if (countRows[0].n > 0) {
      await client.query("COMMIT");
      return null;
    }
    const { rows } = await client.query(
      `INSERT INTO users (username, password_hash, role, must_change_password)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [username, passwordHash, role, mustChangePassword]
    );
    await client.query("COMMIT");
    return rowToUser(rows[0]);
  } catch (e) {
    await client.query("ROLLBACK");
    throw e;
  } finally {
    client.release();
  }
}

// ─── Users — transactional variants for audited mutations ──────────────────
// Each returns the row in raw snake_case, INCLUDING password_hash where the
// column exists. Callers MUST strip password_hash before audit / response.

export async function createUserTx(client, {
  username,
  email = null,
  passwordHash,
  role = "admin",
  mustChangePassword = false,
  orgId = null,
  roleId = null,
  isRoot = false,
}) {
  const { rows } = await client.query(
    `INSERT INTO users (username, email, password_hash, role, must_change_password,
                         org_id, role_id, is_root)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
     RETURNING *`,
    [username, email, passwordHash, role, mustChangePassword, orgId, roleId, isRoot]
  );
  return rows[0];
}

export async function updateUserPasswordTx(client, id, passwordHash, mustChangePassword) {
  const { rows } = await client.query(
    `UPDATE users
        SET password_hash = $1,
            must_change_password = $2,
            updated_at = now()
      WHERE id = $3
      RETURNING *`,
    [passwordHash, mustChangePassword, id]
  );
  return rows[0] || null;
}

export async function updateUserRoleTx(client, id, role) {
  const { rows } = await client.query(
    `UPDATE users SET role = $1, updated_at = now() WHERE id = $2 RETURNING *`,
    [role, id]
  );
  return rows[0] || null;
}

export async function setUserDisabledTx(client, id, disabled) {
  const { rows } = await client.query(
    `UPDATE users SET disabled = $1, updated_at = now() WHERE id = $2 RETURNING *`,
    [disabled, id]
  );
  return rows[0] || null;
}

export async function deleteUserTx(client, id) {
  const { rows } = await client.query(
    `DELETE FROM users WHERE id = $1 RETURNING *`,
    [id]
  );
  return rows[0] || null;
}

export async function getUserByIdTx(client, id) {
  const { rows } = await client.query(`SELECT * FROM users WHERE id = $1`, [id]);
  return rows[0] || null;
}

// Strip password_hash from a raw users row before it goes into the audit log
// or out to the API. Returns the same camelCase shape as rowToUser plus email.
export function userRowForAudit(row) {
  if (!row) return null;
  return {
    id: row.id,
    username: row.username,
    email: row.email,
    role: row.role,
    orgId: row.org_id ?? null,
    roleId: row.role_id ?? null,
    isRoot: !!row.is_root,
    mustChangePassword: row.must_change_password,
    disabled: row.disabled,
    lastLoginAt: row.last_login_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

// Strip mutable fields from a raw policies row so before/after diffs in the
// audit log cover the full content. Includes Rego text; excludes nothing.
export function policyRowForAudit(row) {
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    package: row.package,
    description: row.description,
    rules: row.rules,
    rego: row.rego,
    version: row.version,
    locked: !!row.locked,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

// ─── Orgs & roles (RBAC scaffolding) ───────────────────────────────────────
// These power the multi-tenant authz model. Built-in roles + the default
// 'platform' org are seeded by bootstrap.ensurePlatformDefaults on every
// boot; custom rows are created via /api/orgs and /api/roles. All writes
// are audited through withAudit; the ensure path uses _runWriteSession
// because the seed itself is a system action without a human actor.

function rowToOrg(row) {
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    slug: row.slug,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function rowToRole(row) {
  if (!row) return null;
  return {
    id: row.id,
    orgId: row.org_id ?? null,
    name: row.name,
    description: row.description || "",
    permissions: row.permissions || {},
    isBuiltin: !!row.is_builtin,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export async function countOrgs() {
  const { rows } = await pool.query(`SELECT COUNT(*)::int AS n FROM orgs`);
  return rows[0].n;
}

export async function countRoles() {
  const { rows } = await pool.query(`SELECT COUNT(*)::int AS n FROM roles`);
  return rows[0].n;
}

export async function listOrgs() {
  const { rows } = await pool.query(
    `SELECT * FROM orgs ORDER BY created_at ASC`
  );
  return rows.map(rowToOrg);
}

export async function getOrgById(id) {
  const { rows } = await pool.query(`SELECT * FROM orgs WHERE id = $1`, [id]);
  return rowToOrg(rows[0] || null);
}

export async function getOrgBySlugTx(client, slug) {
  const { rows } = await client.query(
    `SELECT * FROM orgs WHERE slug = $1`, [slug]
  );
  return rowToOrg(rows[0] || null);
}

export async function getOrgByIdTx(client, id) {
  const { rows } = await client.query(`SELECT * FROM orgs WHERE id = $1`, [id]);
  return rowToOrg(rows[0] || null);
}

export async function insertOrgTx(client, { name, slug }) {
  const { rows } = await client.query(
    `INSERT INTO orgs (name, slug) VALUES ($1, $2) RETURNING *`,
    [name, slug]
  );
  return rowToOrg(rows[0]);
}

export async function updateOrgTx(client, id, { name, slug }) {
  const { rows } = await client.query(
    `UPDATE orgs
        SET name = COALESCE($2, name),
            slug = COALESCE($3, slug),
            updated_at = now()
      WHERE id = $1
      RETURNING *`,
    [id, name ?? null, slug ?? null]
  );
  return rowToOrg(rows[0] || null);
}

// Refuses to delete an org that still owns users, policies, trust keys,
// PEP callers, or custom roles. Returns { deleted: true } on success,
// { deleted: false, blockers: { users, policies, ... } } otherwise.
// Hard delete (no soft-delete column); the audit chain preserves history.
export async function deleteOrgTx(client, id) {
  const blockers = {};
  for (const [label, sql] of [
    ["users",      `SELECT COUNT(*)::int AS n FROM users WHERE org_id = $1`],
    ["policies",   `SELECT COUNT(*)::int AS n FROM policies WHERE org_id = $1`],
    ["trust_keys", `SELECT COUNT(*)::int AS n FROM policy_trust_keys WHERE org_id = $1`],
    ["pep_callers",`SELECT COUNT(*)::int AS n FROM pep_callers WHERE org_id = $1`],
    ["roles",      `SELECT COUNT(*)::int AS n FROM roles WHERE org_id = $1`],
  ]) {
    const { rows } = await client.query(sql, [id]);
    if (rows[0].n > 0) blockers[label] = rows[0].n;
  }
  if (Object.keys(blockers).length > 0) {
    return { deleted: false, blockers };
  }
  const { rowCount } = await client.query(`DELETE FROM orgs WHERE id = $1`, [id]);
  return { deleted: rowCount > 0 };
}

export async function listRoles({ orgId } = {}) {
  // orgId = null → globals only; orgId = <uuid> → globals + that org's locals
  // orgId = undefined → everything (root view)
  let sql, params;
  if (orgId === undefined) {
    sql = `SELECT * FROM roles ORDER BY is_builtin DESC, name ASC`;
    params = [];
  } else if (orgId === null) {
    sql = `SELECT * FROM roles WHERE org_id IS NULL ORDER BY name ASC`;
    params = [];
  } else {
    sql = `SELECT * FROM roles
            WHERE org_id IS NULL OR org_id = $1
            ORDER BY is_builtin DESC, name ASC`;
    params = [orgId];
  }
  const { rows } = await pool.query(sql, params);
  return rows.map(rowToRole);
}

export async function getRoleById(id) {
  const { rows } = await pool.query(`SELECT * FROM roles WHERE id = $1`, [id]);
  return rowToRole(rows[0] || null);
}

export async function getRoleByNameTx(client, name, orgId = null) {
  const { rows } = await client.query(
    orgId === null
      ? `SELECT * FROM roles WHERE name = $1 AND org_id IS NULL`
      : `SELECT * FROM roles WHERE name = $1 AND org_id = $2`,
    orgId === null ? [name] : [name, orgId]
  );
  return rowToRole(rows[0] || null);
}

export async function insertRoleTx(client, {
  orgId = null, name, description = "", permissions = {}, isBuiltin = false,
}) {
  const { rows } = await client.query(
    `INSERT INTO roles (org_id, name, description, permissions, is_builtin)
     VALUES ($1, $2, $3, $4::jsonb, $5)
     RETURNING *`,
    [orgId, name, description, JSON.stringify(permissions), isBuiltin]
  );
  return rowToRole(rows[0]);
}

export async function getRoleByIdTx(client, id) {
  const { rows } = await client.query(`SELECT * FROM roles WHERE id = $1`, [id]);
  return rowToRole(rows[0] || null);
}

export async function updateRoleTx(client, id, { name, description, permissions }) {
  const { rows } = await client.query(
    `UPDATE roles
        SET name        = COALESCE($2, name),
            description = COALESCE($3, description),
            permissions = COALESCE($4::jsonb, permissions),
            updated_at  = now()
      WHERE id = $1
      RETURNING *`,
    [
      id,
      name ?? null,
      description ?? null,
      permissions === undefined ? null : JSON.stringify(permissions),
    ]
  );
  return rowToRole(rows[0] || null);
}

// Refuses to delete a role still assigned to any user. Built-in roles are
// rejected at the route layer (defense in depth — caller checks too).
export async function deleteRoleTx(client, id) {
  const { rows: usage } = await client.query(
    `SELECT COUNT(*)::int AS n FROM users WHERE role_id = $1`, [id]
  );
  if (usage[0].n > 0) {
    return { deleted: false, blockers: { users: usage[0].n } };
  }
  const { rowCount } = await client.query(`DELETE FROM roles WHERE id = $1`, [id]);
  return { deleted: rowCount > 0 };
}

// Build a WHERE-fragment that scopes a query to the actor's org. Pass
// the actor returned by the authenticate middleware (or any object with
// isRoot/orgId fields). Returns an empty fragment for root actors and
// for callers that omit the actor entirely (internal system loops like
// publishPolicyIndex / OPA startup restore — those must see every row).
//
// Non-root actors get `AND <column> = $N` with their org_id, which
// EXCLUDES global rows (org_id IS NULL). v1 policy: only root sees
// global rows; we'll loosen this in a later step if customers need
// permission-granted reads on globals.
//
// `column` defaults to "org_id"; pass an aliased name (e.g. "u.org_id")
// when joining. `paramStart` is the next bind index so callers can
// position the placeholder after their existing params.
export function orgScopeWhere(actor, { column = "org_id", paramStart = 1 } = {}) {
  if (!actor || actor.isRoot) {
    return { where: "", params: [], next: paramStart };
  }
  return {
    where: ` AND ${column} = $${paramStart}`,
    params: [actor.orgId],
    next: paramStart + 1,
  };
}

// Resolve the org_id of an existing row for an org-scoped resource type.
// Used by the authorize middleware to pass input.resource.org_id (or
// is_global) into OPA so studio.authz can enforce cross-org isolation.
//
// Returns:
//   null                          — resource type has no org concept (audit,
//                                   password, evaluation, template, etc.);
//                                   the caller should skip org plumbing
//   { found: false }              — row doesn't exist; let the route 404
//   { found: true, orgId: null }  — row exists but is global (org_id IS NULL);
//                                   caller should pass is_global:true to OPA
//   { found: true, orgId: '<u>' } — row exists and is owned by that org
//
// The id parameter is the resource's primary key in its native shape:
// UUID for policy/user, kid string for trust_key, caller_id string for
// pep_caller / caller_access. The mapping is intentionally narrow — adding
// a new org-scoped resource type means extending this switch explicitly.
export async function getResourceOrgInfo(resourceType, id) {
  if (id === undefined || id === null) return null;
  let sql;
  switch (resourceType) {
    case "policy":
      sql = `SELECT org_id FROM policies WHERE id = $1`;
      break;
    case "user":
      sql = `SELECT org_id FROM users WHERE id = $1`;
      break;
    case "trust_key":
      sql = `SELECT org_id FROM policy_trust_keys WHERE kid = $1`;
      break;
    case "pep_caller":
    case "caller_access":
      // caller_access rows are scoped through their parent caller's org.
      sql = `SELECT org_id FROM pep_callers WHERE caller_id = $1`;
      break;
    case "role":
      sql = `SELECT org_id FROM roles WHERE id = $1`;
      break;
    case "org":
      // Orgs are root-only — surface as global so non-root is rejected.
      sql = `SELECT id AS org_id FROM orgs WHERE id = $1`;
      break;
    default:
      return null;
  }
  const { rows } = await pool.query(sql, [id]);
  if (!rows.length) return { found: false };
  return { found: true, orgId: rows[0].org_id ?? null };
}

// Promote any user with role='admin' that hasn't been migrated yet (no
// role_id assigned, is_root still false). Used by ensurePlatformDefaults
// to upgrade existing deployments to the RBAC model on first boot after
// the migration: legacy admins keep their power as is_root=true and get
// pinned to the platform org with the root role.
export async function promoteLegacyAdminsToRootTx(client, { orgId, roleId }) {
  const { rows } = await client.query(
    `UPDATE users
        SET is_root = true,
            org_id  = COALESCE(org_id,  $1),
            role_id = COALESCE(role_id, $2),
            updated_at = now()
      WHERE role = 'admin'
        AND is_root = false
        AND disabled = false
        AND role_id IS NULL
      RETURNING id, username`,
    [orgId, roleId]
  );
  return rows;
}

// ─── Audit log ─────────────────────────────────────────────────────────────

export async function getAuditHead() {
  const { rows } = await pool.query(
    `SELECT head_seq, head_hash FROM audit_state WHERE id = 1`
  );
  if (!rows.length) return null;
  return { seq: Number(rows[0].head_seq), hash: rows[0].head_hash };
}

export async function getAuditEntry(seq) {
  const { rows } = await pool.query(
    `SELECT seq, prev_hash, entry_hash, payload, payload_canonical, signature,
            signing_key_fp, actor_id, actor_username, actor_org_id, action,
            resource_type, resource_id, created_at
       FROM audit_log
      WHERE seq = $1`,
    [seq]
  );
  if (!rows.length) return null;
  return rowToAudit(rows[0]);
}

export async function listAudit({ limit = 50, beforeSeq, action, resourceId, actor } = {}) {
  const conds = [];
  const args = [];
  if (typeof beforeSeq === "number" && Number.isFinite(beforeSeq)) {
    args.push(beforeSeq);
    conds.push(`seq < $${args.length}`);
  }
  if (typeof action === "string" && action) {
    args.push(action);
    conds.push(`action = $${args.length}`);
  }
  if (typeof resourceId === "string" && resourceId) {
    args.push(resourceId);
    conds.push(`resource_id = $${args.length}`);
  }
  // Non-root callers see only entries whose actor was in their org.
  // Entries written before the actor_org_id column was populated (step 10)
  // have NULL and are invisible to sub-admins; root sees the full chain.
  if (actor && !actor.isRoot) {
    args.push(actor.orgId);
    conds.push(`actor_org_id = $${args.length}`);
  }
  const where = conds.length ? `WHERE ${conds.join(" AND ")}` : "";
  args.push(Math.max(1, Math.min(500, limit)));
  const limitParam = `$${args.length}`;
  const { rows } = await pool.query(
    `SELECT seq, prev_hash, entry_hash, payload, payload_canonical, signature,
            signing_key_fp, actor_id, actor_username, actor_org_id, action,
            resource_type, resource_id, created_at
       FROM audit_log
       ${where}
       ORDER BY seq DESC
       LIMIT ${limitParam}`,
    args
  );
  return rows.map(rowToAudit);
}

export async function getAllAuditChainRows() {
  const { rows } = await pool.query(
    `SELECT seq, prev_hash, entry_hash, payload_canonical, signature, signing_key_fp
       FROM audit_log
       ORDER BY seq ASC`
  );
  return rows;
}

// Insert an audit entry under an open client. Caller MUST hold the audit
// advisory lock (taken in withAudit). Updates audit_state in the same txn.
export async function appendAuditEntryTx(client, {
  prevHash,
  entryHash,
  payload,
  payloadCanonical,
  signature,
  signingKeyFp,
  actorId,
  actorUsername,
  actorOrgId = null,
  action,
  resourceType,
  resourceId,
}) {
  const { rows } = await client.query(
    `INSERT INTO audit_log
       (prev_hash, entry_hash, payload, payload_canonical, signature,
        signing_key_fp, actor_id, actor_username, actor_org_id, action,
        resource_type, resource_id)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
     RETURNING seq, created_at`,
    [
      prevHash,
      entryHash,
      JSON.stringify(payload),
      payloadCanonical,
      signature,
      signingKeyFp,
      actorId,
      actorUsername,
      actorOrgId,
      action,
      resourceType,
      resourceId,
    ]
  );
  const seq = Number(rows[0].seq);
  await client.query(
    `INSERT INTO audit_state (id, head_seq, head_hash)
     VALUES (1, $1, $2)
     ON CONFLICT (id) DO UPDATE SET head_seq = $1, head_hash = $2`,
    [seq, entryHash]
  );
  return { seq, createdAt: rows[0].created_at };
}

export async function insertSigningKeyTx(client, { fp, pubkey, algorithm = "ed25519" }) {
  await client.query(
    `INSERT INTO audit_signing_keys (fp, pubkey, algorithm) VALUES ($1, $2, $3)
     ON CONFLICT (fp) DO NOTHING`,
    [fp, pubkey, algorithm]
  );
}

export async function listSigningKeys() {
  const { rows } = await pool.query(
    `SELECT fp, pubkey, algorithm, created_at, retired_at
       FROM audit_signing_keys
       ORDER BY created_at ASC`
  );
  return rows;
}

export async function getActiveSigningKey() {
  const { rows } = await pool.query(
    `SELECT fp, pubkey, algorithm FROM audit_signing_keys
      WHERE retired_at IS NULL
      ORDER BY created_at DESC
      LIMIT 1`
  );
  return rows[0] || null;
}

// Wraps audit_verify_chain(). Returns the first row the function emits; that
// row is either the structural break (ok=false, seq=N) or the final ok=true.
export async function verifyChainStructural() {
  const { rows } = await pool.query(`SELECT * FROM audit_verify_chain()`);
  if (!rows.length) return { ok: true, reason: "empty chain" };
  const r = rows[0];
  return {
    ok: r.ok === true,
    seq: r.seq != null ? Number(r.seq) : null,
    reason: r.reason,
  };
}

function rowToAudit(row) {
  return {
    seq: Number(row.seq),
    prevHash: row.prev_hash, // Buffer or null
    entryHash: row.entry_hash, // Buffer
    payload: row.payload,
    payloadCanonical: row.payload_canonical,
    signature: row.signature,
    signingKeyFp: row.signing_key_fp,
    actorId: row.actor_id,
    actorUsername: row.actor_username,
    actorOrgId: row.actor_org_id ?? null,
    action: row.action,
    resourceType: row.resource_type,
    resourceId: row.resource_id,
    createdAt: row.created_at,
  };
}

// ─── Trust keys (CRY-03) ───────────────────────────────────────────────────
// Used by routes/trustKeys.js for CRUD and by services/jwksFetcher.js for
// background refresh. The publisher in server.js reads listTrustKeys() and
// emits the active rows' publish material to OPA at data.studio.keys.

function rowToTrustKey(row) {
  if (!row) return null;
  return {
    kid: row.kid,
    alg: row.alg,
    jwk: row.jwk,
    pem: row.pem,
    secret: row.secret,
    x5c: row.x5c,
    status: row.status,
    tenant: row.tenant,
    orgId: row.org_id ?? null,
    sourceKind: row.source_kind,
    jwksUrl: row.jwks_url,
    jwksTtlSeconds: row.jwks_ttl_seconds,
    jwksLastFetchedAt: row.jwks_last_fetched_at,
    jwksLastError: row.jwks_last_error,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

// Strip the HMAC `secret` column before sending a row to the API or audit
// log. Asymmetric `pem`/`jwk` are public material and stay.
export function trustKeyRowForAudit(row) {
  if (!row) return null;
  const safe = rowToTrustKey(row);
  if (safe.secret) safe.secret = "[REDACTED]";
  return safe;
}

export async function listTrustKeys(actor) {
  const scope = orgScopeWhere(actor);
  const { rows } = await pool.query(
    `SELECT * FROM policy_trust_keys WHERE TRUE${scope.where} ORDER BY created_at ASC`,
    scope.params
  );
  return rows.map(rowToTrustKey);
}

// Background JWKS refresh path — always sees every active jwks-url row
// regardless of org. The fetcher is a system loop with no user actor.
export async function listActiveJwksUrlTrustKeys() {
  const { rows } = await pool.query(
    `SELECT * FROM policy_trust_keys
      WHERE status = 'active' AND source_kind = 'jwks_url'`
  );
  return rows.map(rowToTrustKey);
}

export async function getTrustKey(kid, actor) {
  const scope = orgScopeWhere(actor, { paramStart: 2 });
  const { rows } = await pool.query(
    `SELECT * FROM policy_trust_keys WHERE kid = $1${scope.where}`,
    [kid, ...scope.params]
  );
  return rows[0] ? rowToTrustKey(rows[0]) : null;
}

export async function getTrustKeyTx(client, kid) {
  const { rows } = await client.query(
    `SELECT * FROM policy_trust_keys WHERE kid = $1`,
    [kid]
  );
  return rows[0] ? rowToTrustKey(rows[0]) : null;
}

export class TrustKeyNotRevokedError extends Error {
  constructor(kid) {
    super(`Trust key ${kid} must be revoked before it can be deleted`);
    this.code = "TRUST_KEY_NOT_REVOKED";
  }
}

export async function createTrustKeyTx(client, row) {
  const {
    kid, alg,
    jwk = null, pem = null, secret = null, x5c = null,
    tenant = null,
    orgId = null,
    sourceKind = "inline",
    jwksUrl = null,
    jwksTtlSeconds = null,
  } = row;
  const { rows } = await client.query(
    `INSERT INTO policy_trust_keys
       (kid, alg, jwk, pem, secret, x5c, status, tenant, org_id,
        source_kind, jwks_url, jwks_ttl_seconds)
     VALUES ($1,$2,$3,$4,$5,$6,'active',$7,$8,$9,$10,$11)
     RETURNING *`,
    [
      kid, alg,
      jwk ? JSON.stringify(jwk) : null,
      pem, secret,
      x5c ? JSON.stringify(x5c) : null,
      tenant, orgId, sourceKind, jwksUrl, jwksTtlSeconds,
    ]
  );
  return { before: null, after: rowToTrustKey(rows[0]) };
}

export async function updateTrustKeyTx(client, kid, patch) {
  const { rows: existingRows } = await client.query(
    `SELECT * FROM policy_trust_keys WHERE kid = $1`,
    [kid]
  );
  const before = existingRows[0] || null;
  if (!before) return { before: null, after: null };

  // Allow updating: alg, jwk, pem, secret, x5c, tenant, jwks_url, jwks_ttl_seconds.
  // kid, status, source_kind, and jwks_last_* are managed through dedicated paths.
  const fields = [];
  const args = [];
  const add = (col, val) => {
    args.push(val);
    fields.push(`${col} = $${args.length}`);
  };
  if (patch.alg !== undefined) add("alg", patch.alg);
  if (patch.jwk !== undefined) add("jwk", patch.jwk ? JSON.stringify(patch.jwk) : null);
  if (patch.pem !== undefined) add("pem", patch.pem);
  if (patch.secret !== undefined) add("secret", patch.secret);
  if (patch.x5c !== undefined) add("x5c", patch.x5c ? JSON.stringify(patch.x5c) : null);
  if (patch.tenant !== undefined) add("tenant", patch.tenant);
  if (patch.jwksUrl !== undefined) add("jwks_url", patch.jwksUrl);
  if (patch.jwksTtlSeconds !== undefined) add("jwks_ttl_seconds", patch.jwksTtlSeconds);

  if (fields.length === 0) {
    return { before: rowToTrustKey(before), after: rowToTrustKey(before) };
  }

  args.push(kid);
  const kidPos = `$${args.length}`;
  const { rows } = await client.query(
    `UPDATE policy_trust_keys SET ${fields.join(", ")}, updated_at = now()
      WHERE kid = ${kidPos}
      RETURNING *`,
    args
  );
  return { before: rowToTrustKey(before), after: rowToTrustKey(rows[0]) };
}

export async function revokeTrustKeyTx(client, kid) {
  const { rows: existingRows } = await client.query(
    `SELECT * FROM policy_trust_keys WHERE kid = $1`,
    [kid]
  );
  const before = existingRows[0] || null;
  if (!before) return { before: null, after: null };
  if (before.status === "revoked") {
    return { before: rowToTrustKey(before), after: rowToTrustKey(before) };
  }
  const { rows } = await client.query(
    `UPDATE policy_trust_keys SET status = 'revoked', updated_at = now()
      WHERE kid = $1
      RETURNING *`,
    [kid]
  );
  return { before: rowToTrustKey(before), after: rowToTrustKey(rows[0]) };
}

export async function deleteTrustKeyTx(client, kid) {
  const { rows: existingRows } = await client.query(
    `SELECT * FROM policy_trust_keys WHERE kid = $1`,
    [kid]
  );
  const before = existingRows[0] || null;
  if (!before) return { before: null, after: null };
  if (before.status !== "revoked") {
    throw new TrustKeyNotRevokedError(kid);
  }
  await client.query(`DELETE FROM policy_trust_keys WHERE kid = $1`, [kid]);
  return { before: rowToTrustKey(before), after: null };
}

// Used by the background JWKS fetcher to refresh material in place. Not
// audited per AUD-07 (high-volume background path): the publish event itself
// is observable via stdout logs, and revocation/creation flows are audited.
export async function touchTrustKeyJwks(kid, { jwk, pem, x5c, error }) {
  return _runWriteSession(async (client) => {
    const { rows } = await client.query(
      `UPDATE policy_trust_keys
          SET jwk                  = $1,
              pem                  = $2,
              x5c                  = $3,
              jwks_last_fetched_at = now(),
              jwks_last_error      = $4,
              updated_at           = now()
        WHERE kid = $5 AND source_kind = 'jwks_url'
        RETURNING *`,
      [
        jwk ? JSON.stringify(jwk) : null,
        pem,
        x5c ? JSON.stringify(x5c) : null,
        error || null,
        kid,
      ]
    );
    return rows[0] ? rowToTrustKey(rows[0]) : null;
  });
}

// Used by the background JWKS fetcher when fetch fails. Keeps the previous
// jwk/pem (last known good) and only records the error.
export async function recordTrustKeyJwksError(kid, error) {
  await _runWriteSession((client) => client.query(
    `UPDATE policy_trust_keys
        SET jwks_last_fetched_at = now(),
            jwks_last_error      = $1,
            updated_at           = now()
      WHERE kid = $2 AND source_kind = 'jwks_url'`,
    [error || "unknown", kid]
  ));
}

// ─── PEP callers (PEP-01) ──────────────────────────────────────────────────
// Used by routes/pepCallers.js for CRUD and by the publisher in server.js,
// which emits active rows to OPA at data.studio.callers. The PEP reads that
// document to authenticate inbound /authorize and /discover requests.

function rowToPepCaller(row) {
  if (!row) return null;
  return {
    callerId: row.caller_id,
    authMode: row.auth_mode,
    description: row.description,
    hmacSecret: row.hmac_secret,
    allowedCn: row.allowed_cn,
    jwtSubject: row.jwt_subject,
    status: row.status,
    tenant: row.tenant,
    orgId: row.org_id ?? null,
    scopeTags: Array.isArray(row.scope_tags) ? row.scope_tags : [],
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    revokedAt: row.revoked_at,
  };
}

// Strip the HMAC secret before serving via the API or the audit log. Accepts
// either the raw DB row (snake_case) or a row that has already been mapped
// via rowToPepCaller (camelCase). The secret is only returned once — at
// create / rotate time — by the route layer, outside this helper.
export function pepCallerRowForAudit(row) {
  if (!row) return null;
  const mapped = row.caller_id !== undefined ? rowToPepCaller(row) : { ...row };
  if (mapped.hmacSecret) mapped.hmacSecret = "[REDACTED]";
  return mapped;
}

export async function listPepCallers(actor) {
  const scope = orgScopeWhere(actor);
  const { rows } = await pool.query(
    `SELECT * FROM pep_callers WHERE TRUE${scope.where} ORDER BY created_at ASC`,
    scope.params
  );
  return rows.map(rowToPepCaller);
}

export async function getPepCaller(callerId, actor) {
  const scope = orgScopeWhere(actor, { paramStart: 2 });
  const { rows } = await pool.query(
    `SELECT * FROM pep_callers WHERE caller_id = $1${scope.where}`,
    [callerId, ...scope.params]
  );
  return rows[0] ? rowToPepCaller(rows[0]) : null;
}

export async function getPepCallerTx(client, callerId) {
  const { rows } = await client.query(
    `SELECT * FROM pep_callers WHERE caller_id = $1`,
    [callerId]
  );
  return rows[0] ? rowToPepCaller(rows[0]) : null;
}

export class PepCallerNotRevokedError extends Error {
  constructor(callerId) {
    super(`PEP caller ${callerId} must be revoked before it can be deleted`);
    this.code = "PEP_CALLER_NOT_REVOKED";
  }
}

export async function createPepCallerTx(client, {
  callerId,
  authMode,
  description = null,
  hmacSecret = null,
  allowedCn = null,
  jwtSubject = null,
  tenant = null,
  orgId = null,
}) {
  const { rows } = await client.query(
    `INSERT INTO pep_callers
       (caller_id, auth_mode, description, hmac_secret, allowed_cn,
        jwt_subject, status, tenant, org_id)
     VALUES ($1,$2,$3,$4,$5,$6,'active',$7,$8)
     RETURNING *`,
    [callerId, authMode, description, hmacSecret, allowedCn, jwtSubject, tenant, orgId]
  );
  return { before: null, after: rowToPepCaller(rows[0]) };
}

export async function updatePepCallerTx(client, callerId, patch) {
  const { rows: existingRows } = await client.query(
    `SELECT * FROM pep_callers WHERE caller_id = $1`,
    [callerId]
  );
  const before = existingRows[0] || null;
  if (!before) return { before: null, after: null };

  const fields = [];
  const args = [];
  const add = (col, val) => {
    args.push(val);
    fields.push(`${col} = $${args.length}`);
  };
  if (patch.description !== undefined) add("description", patch.description);
  if (patch.hmacSecret !== undefined) add("hmac_secret", patch.hmacSecret);
  if (patch.allowedCn !== undefined) add("allowed_cn", patch.allowedCn);
  if (patch.jwtSubject !== undefined) add("jwt_subject", patch.jwtSubject);
  if (patch.tenant !== undefined) add("tenant", patch.tenant);

  if (fields.length === 0) {
    return { before: rowToPepCaller(before), after: rowToPepCaller(before) };
  }

  args.push(callerId);
  const idPos = `$${args.length}`;
  const { rows } = await client.query(
    `UPDATE pep_callers SET ${fields.join(", ")}, updated_at = now()
      WHERE caller_id = ${idPos}
      RETURNING *`,
    args
  );
  return { before: rowToPepCaller(before), after: rowToPepCaller(rows[0]) };
}

export async function revokePepCallerTx(client, callerId) {
  const { rows: existingRows } = await client.query(
    `SELECT * FROM pep_callers WHERE caller_id = $1`,
    [callerId]
  );
  const before = existingRows[0] || null;
  if (!before) return { before: null, after: null };
  if (before.status === "revoked") {
    return { before: rowToPepCaller(before), after: rowToPepCaller(before) };
  }
  const { rows } = await client.query(
    `UPDATE pep_callers
        SET status = 'revoked', revoked_at = now(), updated_at = now()
      WHERE caller_id = $1
      RETURNING *`,
    [callerId]
  );
  return { before: rowToPepCaller(before), after: rowToPepCaller(rows[0]) };
}

export async function deletePepCallerTx(client, callerId) {
  const { rows: existingRows } = await client.query(
    `SELECT * FROM pep_callers WHERE caller_id = $1`,
    [callerId]
  );
  const before = existingRows[0] || null;
  if (!before) return { before: null, after: null };
  if (before.status !== "revoked") {
    throw new PepCallerNotRevokedError(callerId);
  }
  await client.query(`DELETE FROM pep_callers WHERE caller_id = $1`, [callerId]);
  return { before: rowToPepCaller(before), after: null };
}

// ─── PEP caller policy access (ACL) ────────────────────────────────────────
// Each row grants one caller permission to call one policy. The PEP rejects
// /authorize and filters /discover against the published view at
// data.studio.caller_access. Grants are binary — row exists or doesn't;
// audit chain captures every grant/revoke.

function rowToCallerAccess(row) {
  if (!row) return null;
  return {
    callerId:       row.caller_id,
    policyId:       row.policy_id,
    grantedBy:      row.granted_by,
    grantedAt:      row.granted_at,
    // Joined columns (only present on list queries):
    policyName:     row.policy_name ?? undefined,
    policyPackage:  row.policy_package ?? undefined,
    policyLocked:   row.policy_locked ?? undefined,
  };
}

// Strip nothing — there is no secret material on these rows. Helper exists
// for shape consistency with the other audit-row helpers.
export function callerAccessRowForAudit({ callerId, policyId, policyIds, grantedBy }) {
  if (Array.isArray(policyIds)) {
    return { callerId, policyIds, grantedBy };
  }
  return { callerId, policyId, grantedBy };
}

export async function listAllCallerAccess() {
  const { rows } = await pool.query(
    `SELECT caller_id, policy_id, granted_by, granted_at
       FROM pep_caller_policy_access
       ORDER BY caller_id, granted_at ASC`
  );
  return rows.map(rowToCallerAccess);
}

export async function listCallerAccessForCaller(callerId) {
  const { rows } = await pool.query(
    `SELECT a.caller_id, a.policy_id, a.granted_by, a.granted_at,
            p.name    AS policy_name,
            p.package AS policy_package,
            p.locked  AS policy_locked
       FROM pep_caller_policy_access a
       JOIN policies p ON p.id = a.policy_id
       WHERE a.caller_id = $1
       ORDER BY p.package ASC, p.name ASC`,
    [callerId]
  );
  return rows.map(rowToCallerAccess);
}

export async function listCallerAccessForPolicy(policyId) {
  const { rows } = await pool.query(
    `SELECT caller_id, policy_id, granted_by, granted_at
       FROM pep_caller_policy_access
       WHERE policy_id = $1
       ORDER BY caller_id ASC`,
    [policyId]
  );
  return rows.map(rowToCallerAccess);
}

export async function grantCallerAccessTx(client, { callerId, policyId, grantedBy }) {
  // Idempotent — re-granting an existing pair is a no-op. We still surface
  // whether the row was newly created so the audit body can be precise.
  const { rows } = await client.query(
    `INSERT INTO pep_caller_policy_access (caller_id, policy_id, granted_by)
     VALUES ($1, $2, $3)
     ON CONFLICT (caller_id, policy_id) DO NOTHING
     RETURNING caller_id, policy_id, granted_by, granted_at`,
    [callerId, policyId, grantedBy]
  );
  return { created: rows.length > 0, row: rowToCallerAccess(rows[0]) };
}

export async function revokeCallerAccessTx(client, { callerId, policyId }) {
  const { rows } = await client.query(
    `DELETE FROM pep_caller_policy_access
       WHERE caller_id = $1 AND policy_id = $2
       RETURNING caller_id, policy_id, granted_by, granted_at`,
    [callerId, policyId]
  );
  return { deleted: rows.length > 0, row: rowToCallerAccess(rows[0]) };
}

// ─── Tags (policy.tags + pep_caller.scope_tags) ────────────────────────────
// Free-form admin-defined labels. The PEP-ACL publisher unions explicit
// grants with policies whose tags overlap a caller's scope_tags, so tagged
// new policies auto-appear in callers' allowlists on the next publish.

const TAG_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;

// Centralised normaliser — call before write. Lowercases, trims, dedupes,
// sorts (stable diffs in audit), validates each entry against TAG_RE.
export function normaliseTags(input) {
  if (input === undefined || input === null) return [];
  if (!Array.isArray(input)) {
    throw new Error("tags must be an array of strings");
  }
  const seen = new Set();
  for (const raw of input) {
    if (typeof raw !== "string") {
      throw new Error("each tag must be a string");
    }
    const norm = raw.trim().toLowerCase();
    if (!TAG_RE.test(norm)) {
      throw new Error(
        `invalid tag '${raw}': must match /^[a-z0-9][a-z0-9_-]{0,63}$/`
      );
    }
    seen.add(norm);
  }
  return [...seen].sort();
}

// Apply an {add, remove} delta to an existing tag array, returning the new
// canonical (sorted, deduped, validated) array. The route layer hands the
// delta straight from the request body so the audit row captures intent.
export function applyTagDelta(current, { add, remove }) {
  const next = new Set(Array.isArray(current) ? current : []);
  for (const t of normaliseTags(add ?? [])) next.add(t);
  for (const t of normaliseTags(remove ?? [])) next.delete(t);
  return [...next].sort();
}

export async function updatePolicyTagsTx(client, policyId, nextTags) {
  const { rows: beforeRows } = await client.query(
    `SELECT id, tags FROM policies WHERE id = $1`,
    [policyId]
  );
  const before = beforeRows[0];
  if (!before) return { before: null, after: null };
  const { rows } = await client.query(
    `UPDATE policies
       SET tags = $1, updated_at = now()
     WHERE id = $2
     RETURNING id, tags`,
    [nextTags, policyId]
  );
  return {
    before: { policyId, tags: Array.isArray(before.tags) ? before.tags : [] },
    after:  { policyId, tags: rows[0].tags },
  };
}

export async function updateCallerScopeTagsTx(client, callerId, nextTags) {
  const { rows: beforeRows } = await client.query(
    `SELECT caller_id, scope_tags FROM pep_callers WHERE caller_id = $1`,
    [callerId]
  );
  const before = beforeRows[0];
  if (!before) return { before: null, after: null };
  const { rows } = await client.query(
    `UPDATE pep_callers
       SET scope_tags = $1, updated_at = now()
     WHERE caller_id = $2
     RETURNING caller_id, scope_tags`,
    [nextTags, callerId]
  );
  return {
    before: { callerId, scopeTags: Array.isArray(before.scope_tags) ? before.scope_tags : [] },
    after:  { callerId, scopeTags: rows[0].scope_tags },
  };
}

// Union of every tag currently in use across policies and callers. Powers
// the autocomplete chip-input in both UIs. Cheap query; no audit.
export async function listAllTags() {
  const { rows } = await pool.query(`
    SELECT DISTINCT t FROM (
      SELECT UNNEST(tags)       AS t FROM policies
      UNION
      SELECT UNNEST(scope_tags) AS t FROM pep_callers
    ) u
    WHERE t IS NOT NULL AND t <> ''
    ORDER BY t ASC
  `);
  return rows.map((r) => r.t);
}

// Inputs into the live publisher: which policies carry a given caller's
// scope_tags. Used by publishCallerAccess to compute the union.
export async function listPoliciesWithTagOverlap(scopeTags) {
  if (!Array.isArray(scopeTags) || scopeTags.length === 0) return [];
  const { rows } = await pool.query(
    `SELECT id, tags FROM policies
      WHERE locked = false AND tags && $1::text[]`,
    [scopeTags]
  );
  return rows.map((r) => ({
    policyId: r.id,
    tags: Array.isArray(r.tags) ? r.tags : [],
  }));
}

// ─── Platform signing keys ─────────────────────────────────────────────────
// KMS-held Ed25519 keys that the backend and PEP use to authenticate to OPA
// and to sign user-session JWTs. Per-purpose lifecycle is pending -> active
// -> retired -> revoked. At most one active row per purpose (partial unique
// index). Rotation moves the previous active to retired; revoke only flips
// retired -> revoked. There is no deletion.

function rowToPlatformKey(row) {
  if (!row) return null;
  return {
    fpHex: row.fp.toString("hex"),
    pubkeyDerB64: row.pubkey.toString("base64"),
    algorithm: row.algorithm,
    purpose: row.purpose,
    keyId: row.key_id,
    status: row.status,
    createdAt: row.created_at,
    activatedAt: row.activated_at,
    retiredAt: row.retired_at,
    revokedAt: row.revoked_at,
  };
}

export function platformKeyRowForAudit(row) {
  return rowToPlatformKey(row);
}

export async function listPlatformKeys() {
  const { rows } = await pool.query(
    `SELECT fp, pubkey, algorithm, purpose, key_id, status,
            created_at, activated_at, retired_at, revoked_at
       FROM platform_signing_keys
       ORDER BY purpose ASC, created_at ASC`
  );
  return rows.map(rowToPlatformKey);
}

export async function listActivePlatformKeys() {
  const { rows } = await pool.query(
    `SELECT fp, pubkey, algorithm, purpose, key_id, status,
            created_at, activated_at, retired_at, revoked_at
       FROM platform_signing_keys
       WHERE status IN ('active','retired')
       ORDER BY purpose ASC, created_at ASC`
  );
  return rows.map(rowToPlatformKey);
}

export async function getActivePlatformKey(purpose) {
  const { rows } = await pool.query(
    `SELECT fp, pubkey, algorithm, purpose, key_id, status,
            created_at, activated_at, retired_at, revoked_at
       FROM platform_signing_keys
       WHERE purpose = $1 AND status = 'active'
       LIMIT 1`,
    [purpose]
  );
  return rows[0] ? rowToPlatformKey(rows[0]) : null;
}

export async function getPlatformKeyByFp(fpHex) {
  const fp = Buffer.from(fpHex, "hex");
  const { rows } = await pool.query(
    `SELECT fp, pubkey, algorithm, purpose, key_id, status,
            created_at, activated_at, retired_at, revoked_at
       FROM platform_signing_keys WHERE fp = $1`,
    [fp]
  );
  return rows[0] ? rowToPlatformKey(rows[0]) : null;
}

export async function getActivePlatformKeyTx(client, purpose) {
  const { rows } = await client.query(
    `SELECT fp, pubkey, algorithm, purpose, key_id, status,
            created_at, activated_at, retired_at, revoked_at
       FROM platform_signing_keys
       WHERE purpose = $1 AND status = 'active'
       LIMIT 1`,
    [purpose]
  );
  return rows[0] ? rowToPlatformKey(rows[0]) : null;
}

export async function insertPlatformKeyTx(client, {
  fp, pubkey, algorithm = "ed25519", purpose, keyId, status = "active",
}) {
  const { rows } = await client.query(
    `INSERT INTO platform_signing_keys
       (fp, pubkey, algorithm, purpose, key_id, status, activated_at)
     VALUES ($1, $2, $3, $4, $5, $6,
             CASE WHEN $6 = 'active' THEN now() ELSE NULL END)
     ON CONFLICT (fp) DO NOTHING
     RETURNING fp, pubkey, algorithm, purpose, key_id, status,
               created_at, activated_at, retired_at, revoked_at`,
    [fp, pubkey, algorithm, purpose, keyId, status]
  );
  return rowToPlatformKey(rows[0]);
}

export async function retirePlatformKeyTx(client, fp) {
  const { rows } = await client.query(
    `UPDATE platform_signing_keys
        SET status = 'retired', retired_at = now()
      WHERE fp = $1 AND status = 'active'
      RETURNING fp, pubkey, algorithm, purpose, key_id, status,
                created_at, activated_at, retired_at, revoked_at`,
    [fp]
  );
  return rows[0] ? rowToPlatformKey(rows[0]) : null;
}

export async function activatePlatformKeyTx(client, fp) {
  const { rows } = await client.query(
    `UPDATE platform_signing_keys
        SET status = 'active', activated_at = now()
      WHERE fp = $1 AND status = 'pending'
      RETURNING fp, pubkey, algorithm, purpose, key_id, status,
                created_at, activated_at, retired_at, revoked_at`,
    [fp]
  );
  return rows[0] ? rowToPlatformKey(rows[0]) : null;
}

export class PlatformKeyNotRetiredError extends Error {
  constructor(fpHex) {
    super(`Platform key ${fpHex} must be retired before it can be revoked`);
    this.code = "PLATFORM_KEY_NOT_RETIRED";
  }
}

export async function revokePlatformKeyTx(client, fp) {
  const { rows: existing } = await client.query(
    `SELECT status FROM platform_signing_keys WHERE fp = $1`,
    [fp]
  );
  if (!existing.length) return null;
  if (existing[0].status === "revoked") {
    const { rows } = await client.query(
      `SELECT fp, pubkey, algorithm, purpose, key_id, status,
              created_at, activated_at, retired_at, revoked_at
         FROM platform_signing_keys WHERE fp = $1`,
      [fp]
    );
    return rowToPlatformKey(rows[0]);
  }
  if (existing[0].status !== "retired") {
    throw new PlatformKeyNotRetiredError(fp.toString("hex"));
  }
  const { rows } = await client.query(
    `UPDATE platform_signing_keys
        SET status = 'revoked', revoked_at = now()
      WHERE fp = $1
      RETURNING fp, pubkey, algorithm, purpose, key_id, status,
                created_at, activated_at, retired_at, revoked_at`,
    [fp]
  );
  return rowToPlatformKey(rows[0]);
}

// ─── withAudit — single chokepoint for audited mutations ───────────────────
//
// Usage:
//   const response = await store.withAudit(req.user, {
//     action: "policy.update",
//     resourceType: "policy",
//     resourceId: id,
//     beforeFetcher: (c) => c.query(...).then(r => r.rows[0] || null),
//   }, async (client) => {
//     await opa.putPolicy(...);
//     const after = await store.savePolicyTx(client, ...);
//     return { response, auditAfter: after.after };
//   });
//
// withAudit:
//   1. opens a client + BEGIN
//   2. takes pg_advisory_xact_lock on the audit chain
//   3. fetches the before snapshot
//   4. invokes fn(client) which must do the mutation and return
//      { response, auditAfter }
//   5. calls audit.appendAudit() under the same client
//   6. COMMITS
//   7. returns response
let auditAppendImpl = null;
export function _registerAuditAppend(impl) {
  auditAppendImpl = impl;
}

// Sets the per-transaction audit-session marker required by the triggers
// installed in ensureSchema. Callers MUST already be inside a transaction
// (BEGIN issued) — the marker is scoped to the current tx (third arg true).
//
// All other modules that need to write an audited table outside withAudit
// either call this directly after their own BEGIN (bootstrap, audit init)
// or go through _runWriteSession() below.
export async function _setAuditSessionTx(client) {
  await client.query(
    `SELECT set_config('opa_studio.audit_session', 'on', true)`
  );
}

// Open a short-lived transactional write context for the small set of
// non-withAudit writes that still touch audited tables: bulk seeding,
// login-timestamp touches, JWKS background refresh, dead-code non-Tx
// helpers. The session marker is set inside the txn so the audited-table
// triggers permit the write.
export async function _runWriteSession(fn) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await _setAuditSessionTx(client);
    const result = await fn(client);
    await client.query("COMMIT");
    return result;
  } catch (e) {
    try { await client.query("ROLLBACK"); } catch {}
    throw e;
  } finally {
    client.release();
  }
}

export async function withAudit(actor, descriptor, fn) {
  if (!auditAppendImpl) {
    throw new Error("withAudit called before audit service registered");
  }
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await _setAuditSessionTx(client);
    await client.query(
      `SELECT pg_advisory_xact_lock(hashtext('opa_studio_audit_chain'))`
    );
    const before = descriptor.beforeFetcher
      ? await descriptor.beforeFetcher(client)
      : null;
    const result = await fn(client);
    const after = result?.auditAfter ?? null;
    await auditAppendImpl(client, {
      actor,
      action: descriptor.action,
      resourceType: descriptor.resourceType,
      resourceId:
        descriptor.resourceId ??
        (after && after.id) ??
        (before && before.id) ??
        null,
      before,
      after,
    });
    await client.query("COMMIT");
    return result?.response;
  } catch (e) {
    try { await client.query("ROLLBACK"); } catch {}
    throw e;
  } finally {
    client.release();
  }
}
