#!/bin/sh
# vault/bootstrap.sh — Vault setup + unseal watcher for ALL platform signing
# keys (audit-chain + opa-auth + pep-opa-auth + session) plus the opa-trust-init
# read-only token used by the sidecar that writes /opa-trust/platform_keys.json.
#
# Runs as a long-lived sidecar. On a virgin Vault:
#   1. operator init (1-of-1 shares) → /vault/secrets/init.json (mode 0600).
#   2. operator unseal with that key.
#   3. enable the transit secrets engine at the default path.
#   4. write three policies:
#        opa-studio-backend  — sign+create+import on audit, opa-auth, session
#                              (wildcards keep room for rotated key names)
#        opa-trust-init      — read+create on opa-auth + pep-opa-auth (one-shot)
#        pep-signer          — sign-only on pep-opa-auth
#   5. mint three long-TTL periodic tokens bound to those policies →
#        /vault/secrets/backend_token
#        /vault/secrets/opa_trust_init_token
#        /vault/secrets/pep_token
#
# Then enters a watch loop: every WATCH_INTERVAL seconds, re-unseals Vault if
# it has become sealed (Vault re-seals on container restart and there is no
# auto-unseal mechanism in this OSS sandbox). All steps are idempotent.
#
# The signing keys themselves are created lazily by the consumers (backend
# for audit + session, opa-trust-init for opa-auth + pep-opa-auth), not here,
# because BYOK-import of a pre-existing PEM has to happen in-process.
set -eu

WATCH_INTERVAL="${WATCH_INTERVAL:-10}"

export VAULT_ADDR="${VAULT_ADDR:-http://vault:8200}"
SECRETS_DIR="/vault/secrets"
INIT_FILE="${SECRETS_DIR}/init.json"
BACKEND_TOKEN_FILE="${SECRETS_DIR}/backend_token"
OPA_TRUST_INIT_TOKEN_FILE="${SECRETS_DIR}/opa_trust_init_token"
PEP_TOKEN_FILE="${SECRETS_DIR}/pep_token"

mkdir -p "${SECRETS_DIR}"
chmod 700 "${SECRETS_DIR}" 2>/dev/null || true

# ── Wait for vault to accept TCP connections ─────────────────────────────────
ready=""
i=0
while [ "${i}" -lt 60 ]; do
  rc=0
  vault status >/dev/null 2>&1 || rc=$?
  if [ "${rc}" != "1" ]; then ready=1; break; fi
  i=$((i + 1))
  sleep 1
done
if [ -z "${ready}" ]; then
  echo "[aegis-trustvault-init] FATAL: vault never became reachable at ${VAULT_ADDR}" >&2
  exit 1
fi

# ── Step 1: init (only if not yet initialized) ────────────────────────────────
INITIALIZED=$(vault status -format=json 2>/dev/null | grep -o '"initialized": *true' || true)
if [ -z "${INITIALIZED}" ]; then
  echo "[aegis-trustvault-init] initializing vault (1-of-1)"
  vault operator init -key-shares=1 -key-threshold=1 -format=json > "${INIT_FILE}"
  chmod 600 "${INIT_FILE}"
  echo "[aegis-trustvault-init] wrote ${INIT_FILE}"
else
  echo "[aegis-trustvault-init] vault already initialized"
  if [ ! -f "${INIT_FILE}" ]; then
    echo "[aegis-trustvault-init] FATAL: vault is initialized but ${INIT_FILE} missing — cannot unseal" >&2
    exit 1
  fi
fi

INIT_FLAT=$(tr -d '\n' < "${INIT_FILE}")
UNSEAL_KEY=$(printf "%s" "${INIT_FLAT}" | sed -n 's/.*"unseal_keys_b64"[[:space:]]*:[[:space:]]*\[[[:space:]]*"\([^"]*\)".*/\1/p')
ROOT_TOKEN=$(printf "%s" "${INIT_FLAT}" | sed -n 's/.*"root_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
if [ -z "${UNSEAL_KEY}" ] || [ -z "${ROOT_TOKEN}" ]; then
  echo "[aegis-trustvault-init] FATAL: missing unseal key or root token in ${INIT_FILE}" >&2
  exit 1
fi

# ── Step 2: unseal (idempotent — no-op if already unsealed) ──────────────────
SEALED=$(vault status -format=json 2>/dev/null | grep -o '"sealed": *true' || true)
if [ -n "${SEALED}" ]; then
  echo "[aegis-trustvault-init] unsealing"
  vault operator unseal "${UNSEAL_KEY}" >/dev/null
fi

export VAULT_TOKEN="${ROOT_TOKEN}"

# ── Step 3: enable transit (idempotent) ──────────────────────────────────────
if vault secrets list -format=json 2>/dev/null | grep -q '"transit/"'; then
  echo "[aegis-trustvault-init] transit already enabled"
else
  echo "[aegis-trustvault-init] enabling transit"
  vault secrets enable transit >/dev/null
fi

# ── Step 4: write policies ───────────────────────────────────────────────────
# `opa-studio-backend` covers every key the BACKEND process signs with:
#   - audit-signing                  → audit chain
#   - opa-auth-signing*              → JWTs to OPA (backend aud)
#   - session-signing*               → user-session JWTs
# Wildcards under each base name accommodate rotated keys: rotation creates
# new transit keys named `<base>-<unix-epoch>` (services/platformKeys.js).
cat > "${SECRETS_DIR}/opa-studio-backend.hcl" <<'EOF'
path "transit/sign/audit-signing" { capabilities = ["update"] }
path "transit/keys/audit-signing" { capabilities = ["read", "update"] }
path "transit/keys/audit-signing/import" { capabilities = ["update"] }

path "transit/sign/opa-auth-signing*" { capabilities = ["update"] }
path "transit/keys/opa-auth-signing*" { capabilities = ["read", "update"] }
path "transit/keys/opa-auth-signing*/import" { capabilities = ["update"] }
path "transit/keys/opa-auth-signing*/rotate" { capabilities = ["update"] }

path "transit/sign/session-signing*" { capabilities = ["update"] }
path "transit/keys/session-signing*" { capabilities = ["read", "update"] }
path "transit/keys/session-signing*/import" { capabilities = ["update"] }
path "transit/keys/session-signing*/rotate" { capabilities = ["update"] }

# Backend tracks the PEP-OPA-auth pubkey in platform_signing_keys so the
# audit chain attests its lifecycle, but never signs with it — read only.
path "transit/keys/pep-opa-auth-signing*" { capabilities = ["read"] }

path "transit/wrapping_key" { capabilities = ["read"] }
EOF

# `opa-trust-init` is the one-shot that writes /opa-trust/platform_keys.json.
# Needs read on the existing keys, plus update to ensureKey on first boot.
# Cannot sign anything (the file only contains public material).
cat > "${SECRETS_DIR}/opa-trust-init.hcl" <<'EOF'
path "transit/keys/opa-auth-signing*" { capabilities = ["read", "update"] }
path "transit/keys/pep-opa-auth-signing*" { capabilities = ["read", "update"] }
EOF

# `pep-signer` is the PEP process: sign-only on its dedicated key. Cannot
# create or import. Read on the key (needed to fetch the active pubkey kid
# for the JWT header).
cat > "${SECRETS_DIR}/pep-signer.hcl" <<'EOF'
path "transit/sign/pep-opa-auth-signing*" { capabilities = ["update"] }
path "transit/keys/pep-opa-auth-signing*" { capabilities = ["read"] }
EOF

echo "[aegis-trustvault-init] writing policies"
vault policy write opa-studio-backend "${SECRETS_DIR}/opa-studio-backend.hcl" >/dev/null
vault policy write opa-trust-init   "${SECRETS_DIR}/opa-trust-init.hcl"   >/dev/null
vault policy write pep-signer       "${SECRETS_DIR}/pep-signer.hcl"       >/dev/null

# ── Step 5: mint periodic tokens ─────────────────────────────────────────────
mint_token() {
  policy="$1"
  out_file="$2"
  display="$3"
  if [ -f "${out_file}" ]; then
    echo "[aegis-trustvault-init] ${display} token already present"
    return 0
  fi
  echo "[aegis-trustvault-init] minting ${display} token (policy=${policy})"
  tok=$(vault token create \
    -policy="${policy}" \
    -no-default-policy \
    -period=720h \
    -display-name="${display}" \
    -format=json \
    | grep -o '"client_token": *"[^"]*"' \
    | sed 's/.*"\([^"]*\)"$/\1/')
  if [ -z "${tok}" ]; then
    echo "[aegis-trustvault-init] FATAL: failed to mint ${display} token" >&2
    exit 1
  fi
  printf "%s" "${tok}" > "${out_file}"
  chmod 600 "${out_file}"
  echo "[aegis-trustvault-init] wrote ${out_file}"
}

mint_token "opa-studio-backend" "${BACKEND_TOKEN_FILE}"        "opa-studio-backend"
mint_token "opa-trust-init"     "${OPA_TRUST_INIT_TOKEN_FILE}" "opa-trust-init"
mint_token "pep-signer"         "${PEP_TOKEN_FILE}"            "opa-studio-pep"

echo "[aegis-trustvault-init] setup complete; entering unseal watch loop (interval=${WATCH_INTERVAL}s)"

# ── Watch loop ──────────────────────────────────────────────────────────────
while true; do
  sleep "${WATCH_INTERVAL}"
  rc=0
  status_json=$(vault status -format=json 2>/dev/null) || rc=$?
  if [ "${rc}" = "1" ]; then
    continue
  fi
  if printf "%s" "${status_json}" | grep -q '"sealed": *true'; then
    echo "[aegis-trustvault-init] vault is sealed; unsealing"
    vault operator unseal "${UNSEAL_KEY}" >/dev/null 2>&1 || \
      echo "[aegis-trustvault-init] unseal attempt failed (will retry next tick)" >&2
  fi
done
