# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Aegis Policy Fabric (the "Aegis Suite"): a visual builder that compiles JSON policy specs to Rego, deploys them to OPA, and serves them via a generic Policy Enforcement Point — **Aegis Sentry**. The suite components are **Aegis Studio** (frontend UI), **Aegis Core** (backend control plane), **Aegis Sentry** (the PEP), and **Aegis TrustVault** (the KMS/Vault crypto engine). NOTE: these are display/brand names only — the code, container service keys, DB tables, Rego packages, env vars, and JWT claims still use the original `studio` / `pep` / `backend` / `vault` identifiers and MUST stay that way.

**OPA distribution is BUNDLE PULL, not push.** The backend supports a global bundle (`GET /bundle/aegis.tar.gz`) and organization-scoped tenant bundles (`GET /bundle/orgs/:orgId/aegis.tar.gz`) for physical tenant isolation. OPA replicas poll their respective endpoints to converge on policies and data — see [services/opaBundle.js](backend/src/services/opaBundle.js) and the "OPA state distribution" section below. The services that run under `docker-compose.yml`:


| Service           | Port            | Role                                                                                          |
|-------------------|-----------------|-----------------------------------------------------------------------------------------------|
| `opa`             | 8181            | OPA server. Boots with ONLY `opa/config.yaml` (`--config-file --authentication=token --authorization=basic`) and **pulls** a bearer-authed bundle from the backend's `/bundle` or `/bundle/orgs/:orgId` endpoint every 10-20s. No policies/data/trust files are mounted — authz Rego + policies + `data.studio.*` + `data.platform_keys` all arrive in the bundle. `depends_on: backend (healthy)`. |
| `postgres`        | 5433 → 5432     | Stores users, orgs, roles, policies, policy_versions, audit_log, audit_state, audit_signing_keys, platform_signing_keys. |
| `vault`           | (internal)      | **Aegis TrustVault.** HashiCorp Vault (server mode, file backend). Holds every Ed25519 signing key (audit chain, OPA-auth, session, PEP-OPA-auth) in the Transit secrets engine. |
| `vault-init`      | (one-shot, then sidecar) | Init/unseal sidecar. Mints the per-service transit-signer tokens (`backend_token`, `pep_token`) plus the `opa_bundle_token` shared secret (mode 0644 so the non-root OPA container can read it) into `vault_secrets`. (`opa_trust_init_token` is still minted for backward-compat but unused — the `opa-trust-init` sidecar was removed in the bundle-pull migration.) |
| `backend`         | 3001            | **Aegis Core.** Express API: compiles specs → Rego, builds + serves the OPA bundle, manages users, audit chain, platform signing keys. |
| `pep`             | 3002            | **Aegis Sentry.** Generic Express `/authorize` + `/discover` in front of OPA. No DB; caller auth is per-request, dispatched on each `pep_callers` row's `auth_mode` (mtls/hmac/jwt), with `PEP_DEV_ALLOW_ANON` gating dev anonymous access (PEP-01). Signs every OPA request with its own KMS-held Ed25519 key. |
| `frontend`        | 3000 → nginx:80 | **Aegis Studio.** React/Vite SPA; nginx proxies `/api` → backend.                             |

## Running and developing

```bash
# First-time setup
cp .env.example .env
# No required secrets to fill — there are NO shared bearer tokens or signing
# secrets in .env. All signing material lives in KMS (Vault by default) and
# is minted lazily on first boot.

docker compose up --build               # Full stack
docker compose up -d backend opa postgres   # Stack without UI for backend dev
docker compose logs -f backend          # First-boot admin password + audit pubkey are logged here
```

On the FIRST boot with the default `KMS_PROVIDER=vault`, `vault-init` initializes Vault (1-of-1 unseal share), enables Transit, writes the per-service signer tokens into the `vault_secrets` volume (`backend_token` for audit + opa-auth + session + **pep-opa-auth key creation/rotation** — read+update, never sign; `pep_token` sign-only on the PEP's OPA-auth key), and generates the `opa_bundle_token` shared secret. The backend then instantiates the KmsSigner, ensures the opa-auth-signing + session-signing **+ pep-opa-auth-signing** Ed25519 keys exist in Vault (the last one used to be created by the now-removed `opa-trust-init` sidecar; the backend creates it now), registers public keys in `audit_signing_keys` and `platform_signing_keys`, creates the initial admin user, signs the genesis audit row, and **warms the OPA bundle** (which carries `data.platform_keys` built from those pubkeys). Only once the backend is healthy does OPA start and pull the bundle; until a bundle activates, OPA's `--authorization=basic` is fail-closed (denies all gated REST). The admin password is printed in a banner to `docker compose logs backend` AND written to `/data/initial_admin_password` inside the backend container (mounted volume `bootstrap_secret`). The password file is deleted automatically when the bootstrapped admin completes their forced password change. NO private key (audit, session, opa-auth, pep-opa-auth) ever touches the backend or PEP filesystem — they live only inside the KMS provider.

Local-only dev (outside Docker — each package is plain `node --watch`):

```bash
cd backend  && npm install && npm run dev   # :3001, needs DATABASE_URL, KMS_* env, OPA_URL
cd frontend && npm install && npm run dev   # :3000, Vite dev server, proxies /api → :3001
cd pep      && npm install && npm run dev   # :3002, needs OPA_URL + KMS access for pep-opa-auth-signing
```

There is no test suite, lint config, or build script beyond `vite build` in `frontend/`. Don't invent one.

### Common manual checks

```bash
# OPA health (allowlisted in system_authz; no auth needed)
curl http://localhost:8181/health

# Inspect the bundle OPA pulls (bearer = opa_bundle_token). The ETag is the
# bundle revision; `docker compose logs opa | grep activated` shows the last
# revision OPA actually loaded — they should match.
TOK=$(docker compose exec -T backend cat /vault/secrets/opa_bundle_token)
curl -D - -o /tmp/aegis.tar.gz -H "Authorization: Bearer $TOK" \
  http://localhost:3001/bundle/aegis.tar.gz && tar tzf /tmp/aegis.tar.gz
# Or inspect an organization-scoped bundle:
curl -D - -o /tmp/aegis.tar.gz -H "Authorization: Bearer $TOK" \
  http://localhost:3001/bundle/orgs/<org-uuid>/aegis.tar.gz && tar tzf /tmp/aegis.tar.gz

# Verify the audit chain end-to-end (returns signatures-checked count)
curl -H "Authorization: Bearer <admin JWT>" http://localhost:3001/api/audit/verify

# List platform signing keys and their lifecycle state
curl -H "Authorization: Bearer <admin JWT>" http://localhost:3001/api/platform-keys

# Cross-check the live OPA trust document against the DB (drift detection)
curl -H "Authorization: Bearer <admin JWT>" http://localhost:3001/api/platform-keys/opa-state

# PEP discovery (no auth on the PEP surface — gated by network)
curl -XPOST http://localhost:3002/discover -H 'content-type: application/json' \
  -d '{"input":{"user":{"tier":"pro"},"amount":50000,"approval":{"signed":false}}}'
```

## Architecture — the big picture

### Two layers of authorization at the OPA boundary

OPA itself is gated by `opa/system_authz.rego`: every REST request must carry a short-lived EdDSA JWT in `Authorization: Bearer …`, signed by a KMS-held Ed25519 key (either `opa-auth-signing` for the backend or `pep-opa-auth-signing` for the PEP). The policy verifies the signature via `io.jwt.decode_verify` against a PEM bundle built from `data.platform_keys`, then checks `iss == "opa-policy-studio"` and an audience-based write gate (`aud=opa-studio-backend` is required for any non-GET/HEAD method; reads also accept `aud=opa-studio-pep`). `data.platform_keys` (and `system_authz.rego` itself) now arrive **inside the bundle** OPA pulls from the backend; rotation re-publishes the pubkey by invalidating + rebuilding the bundle, and the rotation route waits for OPA to activate the new revision before flipping the active signer (see "Platform signing keys"). `/health` is allowlisted so probes don't need a token. NOTE: the live decision **queries** the backend still makes to OPA (`POST /v1/data/studio/authz` from the authorize middleware, `/api/evaluate/:id`, `/api/preview-evaluate`, the platform-keys drift read) are unchanged — only the WRITE/distribution path moved to the bundle.

Backend mutation routes are gated by `opa/studio_authz.rego`, evaluated through [authorize.js](backend/src/middleware/authorize.js). The studio passes three integrity signals alongside `user/action/resource`:
- `input.audit` — audit-chain head state (broken chain → mutations frozen).
- `input.opa_trust` — backend's view of the OPA-auth key vs. KMS+DB.
- `input.jwt_signer` — backend's view of the session-signing key vs. KMS+DB.

Any one of them being not-ok freezes mutations even though the backend code would otherwise allow them. Both `system_authz.rego` and `studio_authz.rego` live in `./opa/` (mounted read-only into the **backend** at `/app/opa`, `OPA_AUTHZ_DIR`); the bundle builder reads them and folds them into the bundle. They are not user-editable via the studio UI.

`authorize(action, resourceType, opts?)` extracts `resource.id` from `req.params.id` by default. For routes whose resource id is NOT in the URL — currently only `/api/auth/change-password`, which targets the caller's own user — pass an explicit resolver: `authorize("update", "password", { resourceId: req => req.user.id })`. The matching `studio.authz` rule allows the call only when `input.resource.id == input.user.id` AND `trust_ok` (all three signals), so a chain-broken gate covers self-service password change just like every other mutating route.

`studio.authz` recognizes `resource.type` values `policy | user | audit | template | evaluation | password | trust_key | pep_caller | caller_access | platform_key | org | role`. The catch-all "no rule grants ..." `reason` includes a `not self_service_password_attempt` guard so non-admin self-service password attempts hit the dedicated reason rules rather than producing two outputs — Rego complete rules (`reason := "..."`) reject conflicting assignments with `eval_conflict_error`. If you add a new mutating action/resource pair, keep `reason` rule conditions mutually exclusive (per role at minimum), or switch to a partial set (`reasons contains "..." if {...}`).

### OPA state distribution — bundle pull (NOT push)

The backend does **not** push policies/data into OPA. It assembles a gzipped-tar bundle in [services/opaBundle.js](backend/src/services/opaBundle.js) and serves it at `GET /bundle/aegis.tar.gz` (global bundle) or `GET /bundle/orgs/:orgId/aegis.tar.gz` (organization-scoped tenant bundle); every OPA replica polls its URL (`opa/config.yaml`, 10-20s, ETag/304) and converges. This design allows running **multiple stateless OPA replicas** with consistent enforcement, enabling dedicated physical tenant isolation.

- **Bundle contents:** `system_authz.rego` + `studio_authz.rego`, active compiled policy modules (filtered by `orgId` for tenant bundles), and the data docs `studio/policy_index`, `studio/keys`, `studio/callers`, `studio/caller_access`, `platform_keys`. A `.manifest` declares explicit `roots`, recomputed every build, excluding preview namespaces.
- **Cache + invalidation:** the bundles are cached in-process by `orgId` and lazily rebuilt. Mutations call `invalidateBundle(reason, orgId)`. Platform key updates invalidate all org bundle caches. The router factories and CRUD controllers pass `orgId` to invalidate specific organization bundles.
- **Endpoint auth (SECURITY):** the bundle carries cleartext secrets, so `/bundle` (both global and org-scoped) is bearer-authed with a constant-time comparison against `opa_bundle_token`. It is mounted before user authentication, fail-closed, and must stay internal-only — **never** proxy `/bundle` through nginx.
- **Eventual consistency:** changes propagate within one poll (~10-20s) plus the PEP's own caller-cache TTL. Policy lock is eventual, not an instant kill-switch.
- **Boot ordering is inverted:** OPA `depends_on: backend (healthy)` and pulls the bundle.
- **OPA Fleet Tracking:** The backend dynamically records connection counts, sync status, and policies loaded per OPA container in [services/opaTracker.js](backend/src/services/opaTracker.js). Root/super admins can inspect this live data via the **OPA Fleet Status** dashboard UI.

### RBAC + multi-tenancy

The studio is now multi-tenant. `studio_authz.rego` enforces two layers on every mutation:

1. **Root bypass** (`is_effective_root` = `input.user.is_root` OR `input.user.role == "admin"` for legacy compat) — root acts everywhere, subject to the same `trust_ok` integrity gate.
2. **Non-root**: `has_permission` (`input.action ∈ input.user.permissions[input.resource.type]`) AND `org_scope_ok` (loaded row's `org_id == user.org_id`, or `target_org_id == user.org_id` on create, or no specific org context for lists). Global rows (`org_id IS NULL`) are root-only.

`orgs` are flat (no hierarchy); `roles` carry a JSONB permission matrix (`{ resource_type: [action, ...] }`) and an optional `org_id` (NULL = global/built-in). Built-in roles (`root`, `org_admin`, `policy_author`, `auditor`, `viewer`) are seeded by [bootstrap.ensurePlatformDefaults](backend/src/services/bootstrap.js) every boot; the same function also promotes any pre-RBAC `role='admin'` users to `is_root` and pins them to the default `platform` org. Resources (`policies`, `policy_trust_keys`, `pep_callers`) carry `org_id` (NULL = global). `users` carry `org_id`, `role_id`, `is_root`.

The authorize middleware ([authorize.js](backend/src/middleware/authorize.js)) loads the target row's org via `store.getResourceOrgInfo(type, id)` and passes `input.resource.org_id` (or `is_global: true` for null) to OPA. `targetOrgId` resolver opts handle create-time cross-org checks; `resourceIdParam` / `lookupAs` opts handle routes whose id param isn't `:id` or whose lookup table differs from the resource type.

List endpoints in [storage.js](backend/src/services/storage.js) use `orgScopeWhere(actor)` to filter by `org_id` for non-root actors; single-row GETs `404` on cross-org so existence isn't leaked. Internal callers (publish loops, OPA restore, JWKS fetcher) omit the actor argument and see everything.

`/api/orgs` (root-only CRUD) and `/api/roles` ([routes/orgs.js](backend/src/routes/orgs.js), [routes/roles.js](backend/src/routes/roles.js)) manage tenants and role catalogues; both are `withAudit`-wrapped. The role route enforces a **self-escalation guard**: PUT refuses 409 `SELF_ROLE_EDIT_REFUSED` when `req.user.roleId === id`, and both POST and PUT refuse 403 `PERMISSION_ESCALATION_REFUSED` (with the offending `missing: {resourceType, action}`) when the proposed permission set isn't a subset of the actor's own. Root bypasses both checks.

The JWT payload now carries `is_root`, `org_id`, `role_id`, `role_name`, and `permissions` for frontend first-paint UI gating; [authenticate.js](backend/src/middleware/authenticate.js) re-resolves the full context from the DB on every request via `store.getUserAuthContext(id)` — the backend never trusts the JWT for authorization. Frontend uses `can(user, action, resourceType)` from [auth.js](frontend/src/lib/auth.js) to gate menus and buttons; `useOrgs()` in [lib/useOrgs.js](frontend/src/lib/useOrgs.js) caches the org list for admin modals.

OPA-published documents (`policy_index`, `data.studio.callers`) carry `org_id` so the PEP can filter `/discover` and `/authorize` by the caller's org — a caller in org A only sees policies in org A or globals; cross-org access is refused (`policy_not_in_scope`) even if a stale grant row exists ([pep/src/auth/accessStore.js](pep/src/auth/accessStore.js)).

### Platform signing keys

Every JWT the platform issues (user sessions, backend→OPA, PEP→OPA) is signed with a KMS-held Ed25519 key. The lifecycle table `platform_signing_keys` holds only fingerprints + lifecycle state (`pending → active → retired → revoked`), enforced by a partial unique index that keeps at most one `active` row per purpose. [services/platformKeys.js](backend/src/services/platformKeys.js) is the reconciler: at boot it mints all three purposes (`opa-auth-signing`, `session-signing`, `pep-opa-auth-signing`) via `kms.getSigner().ensureKey()` and registers them in the DB through `withAudit` (action `platform_key.bootstrap`). `data.platform_keys` is published to OPA via the bundle (`buildOpaPublishDocument`, active+retired pubkeys); drift between the DB and what OPA serves is surfaced on demand by `GET /api/platform-keys/opa-state`. Fingerprint mismatch sets a per-purpose `trustBroken` flag surfaced via `isTrustOk()`; mutations freeze. Rotation creates a new transit key version and demotes the prior active row to retired in one `withAudit` transaction; revoke flips retired → revoked. There is no deletion path (same revoke-only invariant as trust keys). **Rotation is poll-aware** ([routes/platformKeys.js](backend/src/routes/platformKeys.js)): after the audited rotate it invalidates + eagerly rebuilds the bundle, then WAITS for OPA to activate a revision carrying the new pubkey (`waitForOpaPlatformKey`, polling `opa.getData("platform_keys")`) BEFORE calling `commitRotation()` to flip the in-memory signer — so the backend never signs with a key OPA doesn't yet trust. On timeout it returns 202 (signer not flipped, old key still valid); re-issuing rotate detects the pending key and re-checks activation instead of minting another. [routes/platformKeys.js](backend/src/routes/platformKeys.js) exposes admin CRUD; the **Platform keys** menu item in the topbar is the UI. [services/platformJwt.js](backend/src/services/platformJwt.js) is a small EdDSA JWT codec that delegates signing to the KMS adapter and verifies locally via `node:crypto.verify`, with an explicit `algorithms: ['EdDSA']` whitelist and mandatory `kid` lookup (defends against alg-confusion).

### Compiler: JSON spec → Rego

[regoCompiler.js](backend/src/services/regoCompiler.js) is the heart of the studio. It walks a JSON spec (`{ package, rules: [{ name, type, default, branches: [{ groups: [{ mode: "and"|"or", conditions: [...] }] }] }] }`) and emits Rego v1. Branch-level OR is multi-head Rego; group-level OR inside a branch becomes a helper rule with multi-head bodies. Beyond standard `left/op/right` comparisons, conditions support eight `condType` variants — `arith`, `aggregate`, `every`, `builtin_left`, `object_get`, `raw`, `verification`, `verify` — each with its own renderer. All references are validated against `isValidRegoRef`, `ARITH_EXPR_RE`, and per-op whitelists; the compiler is the security boundary that keeps user-authored conditions from producing arbitrary Rego.

The `verification` condType compiles to OPA's crypto/JWT builtins (see `VERIFICATION_FUNCS` in regoCompiler.js): `io.jwt.verify_{es,rs,ps,hs}{256,384,512}`, `io.jwt.decode_verify`, `io.jwt.decode`, `crypto.x509.parse_{,and_verify_}certificates`, `crypto.hmac.{sha256,sha384,sha512,equal}`, `crypto.{sha256,sha1,md5}`. Each function has a `category`: `bool` renders a single boolean expression; `tuple` emits a multi-line `[bind...] := fn(args)` followed by a truthy guard when `requireValid`; `value` either compares the result (`fn(args) == rhs`) or binds it (`name := fn(args)`). Object args (e.g. `decode_verify` constraints) are validated against `OBJECT_KEY_RE`. `crypto.md5` / `crypto.sha1` are accepted but flagged deprecated — see below.

The `verify` condType (CRY-02) is a higher-level discriminated-union wrapper over `verification`. The user picks a `kind` (`jwt` | `x509` | `raw`), an `alg`, a `keyRef` (`inline_pem` / `inline_secret` / `data.studio.keys` with literal or `input.*` selector), and JWT `constraints` (`iss`, `aud`, `exp_required`, `nbf_required`); the compiler emits `io.jwt.decode_verify` + truthy guard + optional `payload.exp` / `payload.nbf` presence checks (jwt), `crypto.x509.parse_and_verify_certificates` + guard (x509), or `crypto.hmac.<sha256|sha384|sha512>` + `crypto.hmac.equal` (raw, HMAC-only). Locals are uniquely named via a per-compile `__verifyCounter`. `verify` is strictly boolean — `negate: true` is rejected (invert the parent rule instead). Deferred at the compiler level: `kind: "jws"`, asymmetric `raw`, and policy-side `keyRef.source: "jwks_url"`.

`keyRef.source: "data.studio.keys"` is backed by the CRY-03 platform trust store. Admins add rows via the **Trust keys** menu item (or `POST /api/trust-keys`); each row carries a `kid` (must match `SELECTOR_LITERAL_RE` so the compiler can emit `data.studio.keys["<kid>"]`), an `alg`, and either inline material (`pem`/`jwk`/`secret` for HMAC) or a `jwks_url`. The backend canonicalizes asymmetric uploads by round-tripping through `node:crypto.createPublicKey` (so JWK → PEM and PEM → JWK always agree); the bundle builder emits `{ [kid]: pemString | hmacSecretString }` at `data.studio.keys` (via `publishValueFromRow`). Every trust-key mutation calls `invalidateBundle`, so the change reaches OPA on the next poll. Revoking a row removes it from the next bundle, so live policies stop accepting tokens signed by that key within one poll interval. The JWKS-URL BYO path is served by [jwksFetcher.js](backend/src/services/jwksFetcher.js), a `setInterval`-based poller (default 30s, `TRUST_KEYS_FETCH_INTERVAL_MS`) that fetches each row's URL when its per-row TTL has elapsed, derives PEM from the matching kid's JWK entry, updates in place, and `invalidateBundle`s on change — failures preserve last known-good and record `jwks_last_error`. Background refreshes deliberately bypass `withAudit` per AUD-07's high-volume rationale; admin-initiated CRUD (create / update / revoke / refresh / delete) all go through the audited chain. Rows are revoke-first, delete-only-when-revoked, mirroring the policy lock pattern so the audit history of the trust material remains intact.

`validate(spec)` mirrors the compiler's structural checks without rendering and returns `{ valid, errors, warnings }` — used by `POST /api/validate` and called before every save/preview. The `warnings` array surfaces non-blocking issues (currently: deprecated crypto primitives). `compile` additionally injects a `# DEPRECATED: ...` comment line into the emitted Rego at each deprecated call site, so the warning is visible in the Rego tab even when callers don't forward the validate response. When changing the compiler, update both `compile` and `validate` together; the policy discovery index in [policyIndex.js](backend/src/services/policyIndex.js) also walks the same spec shape to extract `input.*` paths.

### Audit chain — the integrity backbone

Every mutation (policy create/update/lock/unlock, user CRUD, password change/reset) goes through `store.withAudit(actor, descriptor, fn)` in [storage.js](backend/src/services/storage.js). That wrapper:

1. Opens a pg client + `BEGIN`, takes `pg_advisory_xact_lock('opa_studio_audit_chain')`.
2. Runs `descriptor.beforeFetcher(client)` to snapshot the row.
3. Invokes `fn(client)` which mutates the DB (and OPA if applicable) and returns `{ response, auditAfter }`.
4. Calls `audit.appendAudit()` inside the same transaction — canonicalizes payload, links to `prev_hash`, computes `entry_hash = SHA256(prev || payload_canonical)`, signs with Ed25519, inserts the row, and updates `audit_state` head pointer.
5. `COMMIT`.

[audit.js](backend/src/services/audit.js) signs every entry through a pluggable `KmsSigner` adapter selected at boot by `KMS_PROVIDER` (default `vault`). Provider modules live in [backend/src/services/kms/](backend/src/services/kms/) — `vault.js` (HashiCorp Vault Transit; the default), `file.js` (DEV-only, refuses `NODE_ENV=production`), and stubs for `aws`/`gcp`/`azure`/`pkcs11` that throw `KmsProviderNotImplemented` at instantiation. Core code (audit, bootstrap) imports only `getSigner()` from [kms/index.js](backend/src/services/kms/index.js); concrete providers are never imported elsewhere. The `KmsSigner` interface: `ensureKey`, `getPublicKey` (returns `{pubkeyDer, pem, jwk, fingerprintSha256, keyVersion}`), `sign`, `verify` (local, against cached pubkey), `rotate` (stubbed), `importKey` (BYOK), plus `capabilities()` and `providerName()`. The factory enforces `ed25519 ∈ capabilities.algorithms` and fails closed on misconfiguration. The vault adapter still uses the same `vault_secrets` volume + `VAULT_TOKEN_FILE` token delivery; the private key never leaves the provider.

Boot is `audit.loadOrInitSigningKey()`, called once before bootstrap. Three paths: (a) fresh DB → `signer.ensureKey()` creates an Ed25519 key in the provider; (b) existing deployment first picking up audit support → generate (or reuse) the provider key and write a "deployment_genesis" row; (c) existing chain → fetch the provider's active public key, assert its SHA-256 fingerprint matches the active `audit_signing_keys` row. The vault-only legacy migration: an on-disk PEM at `/data/audit_signing_key` (from pre-KMS builds) is auto-imported via the vault adapter's wrap-and-import `importKey` and then deleted. Bootstrap emits the genesis row via `audit.signEntryHash` and labels the banner with `audit.getSigningStoreLabel()` (e.g. `vault://transit/audit-signing`, `file:///data/dev_kms/audit-signing`).

**BYOK.** Customers ship their own Ed25519 PKCS#8 PEM via `KMS_BYOK_SOURCE=file:/path/key.pem` or `env:VAR_NAME` (parsed by [kms/byok.js](backend/src/services/kms/byok.js); `pkcs11:` / `jwk:` are reserved and currently throw). BYOK runs in `loadOrInitSigningKey` BEFORE `ensureKey` so the customer key is imported into the provider before any auto-generation. Idempotent on fingerprint match; mismatch (against the provider's existing key or the active `audit_signing_keys` row) fails closed via `_markBroken`. `KMS_BYOK_REQUIRED=true` refuses to boot without a source. Out-of-band staging: `node scripts/import-key.js --source <uri> [--key-id <id>] [--provider <name>]` (also `npm run import-key` from `backend/`) — the CLI imports into the provider but never writes the DB; the next backend boot reconciles. BYOK takes precedence over the legacy `/data/audit_signing_key` migration when both are present.

The chain is verified two ways: structurally in PL/pgSQL via `audit_verify_chain()` (re-hashes every row and confirms `audit_state.head_hash` matches the tail), and cryptographically in Node via `audit.verifyFullChain()` which loads public keys from the `audit_signing_keys` table (keyed by fingerprint) and verifies every signature locally. `audit.headIsValid()` is called by the authorize middleware on every mutating request; it also verifies locally (the KMS provider is NOT contacted on the verify path). `studio.authz` refuses when `input.audit.ok` is false. If the provider is unreachable, verification still works — only signing (i.e. new mutations) is blocked.

**Implication for any new mutating route**: it MUST run through `withAudit` with appropriate `action`/`resourceType`, otherwise the audit chain stays intact but loses coverage for that path.

**DB-side guard against out-of-band writes.** A statement-level `BEFORE INSERT OR UPDATE OR DELETE` trigger (`_opa_studio_require_audit_session`) is installed by `ensureSchema` on every audited table (`policies`, `policy_versions`, `users`, `audit_log`, `audit_state`, `audit_signing_keys`, `policy_trust_keys`, `pep_callers`, `pep_caller_policy_access`, `platform_signing_keys`, `orgs`, `roles`). It raises `P0001 audited_write_outside_managed_context` unless the current transaction has set `opa_studio.audit_session = 'on'`. `withAudit` sets it after `BEGIN` via `_setAuditSessionTx(client)`; the bootstrap and audit-init transactions do the same. Intentional non-audited writes that still touch audited tables (login timestamps, JWKS background refresh, template seed, dead non-`Tx` helpers) go through `_runWriteSession(fn)` — opens a client, BEGIN, sets the marker, runs `fn(client)`, COMMITs. Raw psql writes are rejected; a code path that forgets either wrapper fails loudly at the first INSERT. Note: this is a *process-discipline* gate (any session can `SET opa_studio.audit_session = 'on'`), not an adversarial one — the cryptographic chain itself is the real tamper gate.

Audit rows carry `actor_org_id` (populated by `withAudit` from the actor's `orgId`); `listAudit` filters by it for non-root actors so sub-admins see only mutations made by users in their own org. The payload also embeds `actor.org_id` and `actor.is_root` for offline forensics. Pre-RBAC entries with NULL `actor_org_id` remain visible only to root.

### Policies are never hard-deleted

`DELETE /api/policies/:id` returns 405 by design. Admins lock instead (`POST /api/policies/:id/lock`). Locking drops the policy from the next bundle (both `buildPolicyIndex` and the module list exclude locked policies) so it stops enforcing fleet-wide, but keeps it in the DB with full version history; unlocking re-includes it. Both actions bump version, snapshot a `policy_versions` row, and emit a signed audit entry. `studio.authz` has a `policy_delete_blocked` rule as defense in depth. **Lock is eventual** (≤ one bundle poll), not an instant kill — see "OPA state distribution".

The bundle invalidation happens AFTER the DB commit, intentionally — a transient bundle-build failure doesn't poison the audit chain. There is no startup "restore N policies to OPA" loop anymore; startup just warms the bundle once (`opaBundle.buildBundle()`) and OPA pulls it.

### Policy discovery index

Backend extracts the set of `input.*` paths referenced by each active policy's spec (`buildPolicyIndex` in [policyIndex.js](backend/src/services/policyIndex.js)) and carries the index in the bundle at `data.studio.policy_index`; every save/lock/unlock `invalidateBundle`s. The PEP's `/discover` endpoint fetches this index and, given a caller `input`, returns the policies whose required paths are all satisfied (strict) or ranked by ratio (score mode). The PEP and backend share OPA as the rendezvous point; the PEP never talks to the studio backend or the DB. (`buildPolicyIndex` emits `generatedAt: null` so the bundle revision is deterministic — the PEP's `/discover` `indexedAt` is therefore null.)

Failure mode: `invalidateBundle` is cheap and the bundle is lazily rebuilt; a transient build failure just means OPA keeps the previous revision and the next poll re-fetches. The startup warm build re-establishes the index on every boot.

### PEP caller authentication (PEP-01)

The PEP runs all three caller-auth modes (`mtls | hmac | jwt`) simultaneously and dispatches per request based on the credential presented and the matching `pep_callers` row's own `auth_mode` — the wiring is set up once at boot in [pep/src/index.js](pep/src/index.js) over the auth modules under [pep/src/auth/](pep/src/auth/). Anonymous (credential-less) requests are admitted as `anonymous` only when `PEP_DEV_ALLOW_ANON=true`, which refuses to start under `NODE_ENV=production`. Sending two credentials at once (e.g. `X-Studio-Sig` + `Authorization: Bearer`) is rejected `401 ambiguous_credentials`. HMAC mode validates `X-Studio-Sig: caller=...,ts=...,nonce=...,sig=...` against an `HMAC-SHA256(secret, ts.nonce.path.body)` over the raw request bytes (captured via `express.json({ verify })`); replay protection is an LRU keyed by `${callerId}:${nonce}` with TTL = 2× the timestamp skew window, so a reused nonce returns 409 while every other failure mode returns 401. MTLS mode requires `https.createServer({ requestCert:true, rejectUnauthorized:false })` and rejects in-app for a stable JSON 401 instead of a TLS alert; the CN must appear in `PEP_ALLOWED_CALLERS` (bootstrap CSV) or in a provisioned `pep_callers.allowed_cn` row. JWT mode verifies bearer tokens offline against the platform JWKS at `PEP_JWKS_URL` (default `http://backend:3001/.well-known/jwks.json`), enforcing `iss`/`aud`, and looks up the `sub` claim in the caller table (rows may pin via `jwt_subject`; otherwise `sub` must equal `caller_id`).

Caller identities live in the backend's `pep_callers` table and are managed through [backend/src/routes/pepCallers.js](backend/src/routes/pepCallers.js) (admin-only, wrapped in `withAudit`). HMAC secrets are generated server-side and returned **once** at create / rotate time; subsequent reads return `[REDACTED]` and the row's plaintext stays inside the bundle's `data.studio.callers` doc. The active set is carried in the bundle at `data.studio.callers` (built in `opaBundle.collect`); every caller mutation `invalidateBundle`s, and the PEP reads it through `pdp.fetchData("studio.callers")` with a short TTL cache ([pep/src/auth/callerStore.js](pep/src/auth/callerStore.js)). Because the bundle contains these cleartext secrets, the `/bundle` endpoint is bearer-authed and internal-only (see "OPA state distribution"). Revoke-then-delete (delete refuses 409 until the row is revoked) mirrors the trust-keys invariant — the audit history of caller material stays intact across deletions. The backend's public `GET /.well-known/jwks.json` exposes the platform Ed25519 audit-signing key as a JWK so downstream verifiers and the PEP (jwt mode) can validate decisions offline.

### Frontend client and 401 handling

[api.js](frontend/src/lib/api.js) is a thin fetch wrapper that attaches the JWT from `auth.js` and, on any 401, calls `clearToken()` which emits an `auth-change` event. `App.jsx` subscribes to that event and falls back to `<LoginPage>`. Don't add server-state libraries — the app is plain `useState` + `useEffect`.

The PolicyEditor has five tabs (Visual Builder, Diagram, Rego, Sandbox, History). The Sandbox uses `POST /api/preview-evaluate`, which compiles to a `__preview_<timestamp>` package, evaluates, then deletes — so it never collides with the deployed module.

### Premium Developer Tools (Phase 8 Upgrades)
- **High-Scale Sidebar Drill-Down**: Supports three-level tree nesting (`Org ➔ Package ➔ Policy`) with quick-action cloning, pagination, and `⌘K` global search override to bypass tree hierarchy.
- **Minimalist Visual Composer**: Text-only builder controls (no icons), deep cloning of rules/branches/logic groups, side outline drawer canvas navigator, and `_sampleInput` autocomplete sensing dropdowns.
- **Chronological Flow Tracer**: Player playback controller (Play/Pause/Prev/Next/Reset), Kahn's topological sort sequence parser, dynamic LR/TB routing handles, active glowing neon path sweep animations, and viewport panning locator.
- **Sandbox Playgrounds**: Scenarios profile CRUD storage (`localStorage` persisted), a unified database-driven **Mock PEP Caller** selector dropdown with automatic payload injection and JWT claims sync, a native `SubtleCrypto` HMAC HS256 client-side mock JWT token signer with base64url safety, and automatic rule execution coverage gauges.
- **Design System Contrast Polish**: All premium overlays and popovers (such as the Cryptographic Trust & Integrity HUD) use solid backdrops (opacity `0.98` / `0.15`-`0.18` states) to maintain high contrast and eliminate text bleeding.

## Conventions worth knowing

- **Backend modules are ES modules** (`"type": "module"`). All `.js`, no TypeScript. No bundler — Node runs `src/server.js` directly.
- **Async errors surface as 500 JSON**. [server.js](backend/src/server.js) side-effect-imports `express-async-errors` at the top (MUST stay above `import express`) so async route rejections forward to the terminal `app.use((err,req,res)=>res.status(500).json(...))` registered just before `app.listen`. A `process.on("unhandledRejection")` handler remains as a fallback for rejections that originate outside a request lifecycle (fire-and-forget `invalidateBundle`, the JWKS background fetcher). Don't add per-route try/catch for the sole purpose of forwarding errors — the global handler covers it.
- **Transactional storage variants** end in `Tx` and accept an open `client`: `savePolicyTx`, `updateUserPasswordTx`, etc. The non-`Tx` variants open their own pool client via `_runWriteSession` (sets the audit-session marker) and are only safe to use OUTSIDE `withAudit`. Any new write touching an audited table must go through one of these — direct `pool.query("INSERT/UPDATE/DELETE …")` will be rejected by the DB trigger.
- **Sensitive fields**: `userRowForAudit` and `policyRowForAudit` are the only functions that strip `password_hash`/`raw row` shape before audit insertion or API response. Use them whenever an audited mutation reads a `users` or `policies` row.
- **List filtering convention**: every `list*` / `get*` in [storage.js](backend/src/services/storage.js) accepts an optional `actor` argument and uses `orgScopeWhere(actor)` to add `AND org_id = $N` for non-root. User-facing routes MUST pass `req.user`; internal callers (the bundle builder, JWKS fetcher, post-mutation reloads) omit it. Single-row GETs that 404 on missing-row also 404 on cross-org so existence isn't leaked.
- **New org-scoped resources**: when adding one, extend the dispatcher in `store.getResourceOrgInfo(resourceType, id)` and add a case to `orgScopeWhere`-using `list*` / `get*` helpers. The authorize middleware will then load `org_id` automatically.
- **The compiler emits Rego v1** by default (`import rego.v1`). Old `default` declarations + `rule if { ... }` heads are required.
- **Frontend ↔ backend path**: in production, nginx in the frontend container proxies `/api` → `backend:3001`. In dev, Vite proxies `/api` → `localhost:3001`. Don't hardcode hosts in `frontend/src/`.
