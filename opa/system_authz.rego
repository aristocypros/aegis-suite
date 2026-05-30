# system.authz — gates ALL OPA REST API requests.
#
# Loaded by OPA at startup via `--authorization=basic`. The backend and the
# PEP each carry a short-lived EdDSA JWT minted by their own KMS-held key
# (services/platformKeys.js + services/platformJwt.js). The platform pubkeys
# are loaded into OPA at boot from /trust/platform_keys.json by the
# opa-trust-init sidecar; rotation re-publishes them via PUT
# /v1/data/platform_keys.
#
# Two trust domains, distinguished by JWT `aud`:
#   opa-studio-backend   — full access (reads + mutations)
#   opa-studio-pep       — reads only on data API
#
# Liveness / metrics endpoints (`/health`, `/metrics`) are allowlisted so
# probes from outside the trust domain don't need a token.

package system.authz

default allow := false

# ── Allowlist: liveness probes & static metadata ────────────────────────────
allow if {
    is_public_path
    input.method == "GET"
}

is_public_path if { input.path == ["health"] }
is_public_path if { input.path == ["metrics"] }
is_public_path if { input.path == [] }

# ── Authenticated path: signed JWT in input.identity ────────────────────────
# `io.jwt.decode_verify` does not accept Ed25519 keys via its `cert`
# constraint (the constraint is documented as RSA/ECDSA only, and the
# builtin returns valid=false even on a good Ed25519 signature — confirmed
# on OPA 1.16.1). So we do the verification in pieces:
#   1. Decode the header to learn the kid.
#   2. Look up the matching PEM in data.platform_keys.
#   3. Verify the signature with io.jwt.verify_eddsa.
#   4. Decode the payload (already trusted because step 3 verified) and
#      enforce iss / aud / exp manually.
allow if {
    input.identity != ""
    [header, payload, _] := io.jwt.decode(input.identity)
    header.alg == "EdDSA"
    is_string(header.kid)
    pem := lookup_pem(header.kid)
    pem != ""
    io.jwt.verify_eddsa(input.identity, pem)
    payload.iss == "opa-policy-studio"
    aud_allowed(payload.aud)
    is_number(payload.exp)
    payload.exp > time.now_ns() / 1000000000
}

# Walk all purposes in data.platform_keys looking for the kid.
lookup_pem(kid) := pem if {
    some purpose
    pem := data.platform_keys[purpose][kid]
}

# Audience policy:
#   - GET / HEAD: either aud OK (read-only).
#   - POST /v1/data/*: either aud OK (this is policy evaluation — body
#     carries `input`, no data is written).
#   - Everything else (PUT data, PATCH data, POST /v1/policies, etc.):
#     backend aud only.
# Keeps the PEP confined to evaluation + read — a compromised PEP signing
# key cannot push policies or rewrite data.studio.keys.
aud_allowed(aud) if {
    is_read_method
    aud == "opa-studio-backend"
}
aud_allowed(aud) if {
    is_read_method
    aud == "opa-studio-pep"
}
aud_allowed(aud) if {
    is_eval_method
    aud == "opa-studio-backend"
}
aud_allowed(aud) if {
    is_eval_method
    aud == "opa-studio-pep"
}
aud_allowed("opa-studio-backend") if {
    not is_read_method
    not is_eval_method
}

is_read_method if { input.method == "GET" }
is_read_method if { input.method == "HEAD" }

# Policy evaluation: POST /v1/data/<path>. Read-shaped (body is input, no
# state changes). The OPA REST surface for writes is PUT /v1/data/<path>
# and POST /v1/policies/<id>, both of which still require backend aud.
is_eval_method if {
    input.method == "POST"
    count(input.path) >= 2
    input.path[0] == "v1"
    input.path[1] == "data"
}
