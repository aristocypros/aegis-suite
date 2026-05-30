# studio.authz — application-layer authorization for the policy studio.
#
# v2 model (RBAC + multi-tenancy):
#   - users.is_root bypass: a root user can do anything (subject to the same
#     integrity signals that v1 already enforced).
#   - Non-root users get permissions from their role's permission map
#     (action × resource_type) and are confined to their own org for
#     org-owned resources. Cross-org access is denied.
#
# Backward compat: a user with the legacy string `role == "admin"` is treated
# as root even if is_root has not yet been set (the bootstrap.ensurePlatform
# Defaults step promotes them on the next boot). Reasons are emitted as "root"
# regardless of which compatibility path matched.
#
# Input shape:
#   {
#     "user": {
#       "id": "...", "username": "...", "role": "admin",
#       "org_id": "<uuid>"|null, "role_id": "<uuid>"|null,
#       "is_root": true|false,
#       "permissions": { "policy": ["read","create",...], ... },
#       "disabled": false
#     },
#     "action":   "create" | "read" | "update" | "delete" | "manage",
#     "resource": {
#       "type": "policy" | "user" | "audit" | "template" | "evaluation"
#             | "password" | "trust_key" | "pep_caller" | "caller_access"
#             | "platform_key" | "org" | "role",
#       "id": "...",                       # present for single-row reads/updates/deletes
#       "org_id": "<uuid>"|undefined,      # set by middleware when a row was loaded
#       "target_org_id": "<uuid>"|undefined,  # set by middleware on create
#       "is_global": true|undefined        # set when middleware loaded a row with org_id IS NULL
#     },
#     "audit":      { "ok": true,  "reason": "" },
#     "opa_trust":  { "ok": true,  "reason": "" },
#     "jwt_signer": { "ok": true,  "reason": "" }
#   }
#
# Loaded by OPA at startup from a mounted file. Cannot be modified via the
# studio UI (system-managed; the `policies` table doesn't reach this module).

package studio.authz

default allow := false
default role_label := "<unassigned>"

mutating_action("create")
mutating_action("update")
mutating_action("delete")

# Defense-in-depth: policies and platform keys are never hard-deleted.
policy_delete_blocked if {
    input.action == "delete"
    input.resource.type == "policy"
}
platform_key_delete_blocked if {
    input.action == "delete"
    input.resource.type == "platform_key"
}

# Integrity-signal helpers. Each defaults to ok when the field is omitted,
# so read-only callers can elide them.
audit_ok if { not input.audit }
audit_ok if { input.audit.ok == true }
opa_trust_ok if { not input.opa_trust }
opa_trust_ok if { input.opa_trust.ok == true }
jwt_signer_ok if { not input.jwt_signer }
jwt_signer_ok if { input.jwt_signer.ok == true }

trust_ok if {
    audit_ok
    opa_trust_ok
    jwt_signer_ok
}

# A user counts as root if is_root is set OR they carry the legacy 'admin'
# role string (covers the window between RBAC migration and the next boot
# when ensurePlatformDefaults promotes them).
is_effective_root if { input.user.is_root }
is_effective_root if { input.user.role == "admin" }

# ─── Permission resolution (non-root) ────────────────────────────────────
# True when the caller's role grants the requested action on the resource
# type. permissions = { "policy": ["read","create",...], ... }; absent
# resource-type keys yield no permission.
has_permission if {
    perms := input.user.permissions[input.resource.type]
    perms[_] == input.action
}

# Org scoping. Three positive paths; falsy by default for non-root.
#   1. No specific org context — list / aggregate read / create-without-
#      target. Per-row filtering happens in the backend's SQL layer; this
#      rule just lets the call reach the handler.
#   2. Middleware loaded an existing row and its org_id matches the caller.
#   3. Middleware named a target_org_id (e.g. on create) that matches.
# A row marked input.resource.is_global=true is NOT covered — only root
# can act on global resources.
org_scope_ok if {
    not input.resource.org_id
    not input.resource.target_org_id
    not input.resource.is_global
}
org_scope_ok if {
    is_string(input.user.org_id)
    is_string(input.resource.org_id)
    input.resource.org_id == input.user.org_id
}
org_scope_ok if {
    is_string(input.user.org_id)
    is_string(input.resource.target_org_id)
    input.resource.target_org_id == input.user.org_id
}

# ─── Allow rules ─────────────────────────────────────────────────────────

# Root: non-mutating action — always allowed (integrity status does not
# gate reads; an operator must be able to inspect a broken state).
allow if {
    is_effective_root
    not input.user.disabled
    not mutating_action(input.action)
    not policy_delete_blocked
    not platform_key_delete_blocked
}

# Root: mutating action — only when ALL integrity signals are ok.
allow if {
    is_effective_root
    not input.user.disabled
    mutating_action(input.action)
    trust_ok
    not policy_delete_blocked
    not platform_key_delete_blocked
}

# Non-root: non-mutating action with permission and matching org scope.
allow if {
    not is_effective_root
    not input.user.disabled
    not mutating_action(input.action)
    has_permission
    org_scope_ok
    not policy_delete_blocked
    not platform_key_delete_blocked
}

# Non-root: mutating action — permission + scope + integrity all required.
allow if {
    not is_effective_root
    not input.user.disabled
    mutating_action(input.action)
    has_permission
    org_scope_ok
    trust_ok
    not policy_delete_blocked
    not platform_key_delete_blocked
}

# Self-service password change. ANY non-disabled user may change THEIR OWN
# password when integrity is ok. The studio backend enforces self-targeting
# by passing req.user.id as resource.id; this rule double-checks
# resource.id == user.id so a forged backend call cannot bypass it.
allow if {
    not input.user.disabled
    input.action == "update"
    input.resource.type == "password"
    input.resource.id == input.user.id
    trust_ok
}

# ─── Reasons (mutually exclusive) ────────────────────────────────────────
# A complete rule can have only one output per evaluation. Each `reason :=`
# below is guarded so at most one matches a given input. Reasons are surfaced
# in the 403 body by the backend authorize middleware.

# Human-friendly role label for non-root reasons.
role_label := input.user.role_name if { input.user.role_name }

# Root reasons.
reason := "root: read access" if {
    is_effective_root
    not input.user.disabled
    not mutating_action(input.action)
    not policy_delete_blocked
    not platform_key_delete_blocked
}

reason := "root: full crud (integrity ok)" if {
    is_effective_root
    not input.user.disabled
    mutating_action(input.action)
    trust_ok
    not policy_delete_blocked
    not platform_key_delete_blocked
}

reason := sprintf("audit chain broken: %v", [input.audit.reason]) if {
    is_effective_root
    not input.user.disabled
    mutating_action(input.action)
    not audit_ok
    not policy_delete_blocked
    not platform_key_delete_blocked
}

reason := sprintf("opa trust broken: %v", [input.opa_trust.reason]) if {
    is_effective_root
    not input.user.disabled
    mutating_action(input.action)
    audit_ok
    not opa_trust_ok
    not policy_delete_blocked
    not platform_key_delete_blocked
}

reason := sprintf("jwt signer broken: %v", [input.jwt_signer.reason]) if {
    is_effective_root
    not input.user.disabled
    mutating_action(input.action)
    audit_ok
    opa_trust_ok
    not jwt_signer_ok
    not policy_delete_blocked
    not platform_key_delete_blocked
}

# Non-root reasons — guarded by `not is_effective_root` and a self-service-
# password exclusion so they don't conflict with the rules below.

reason := sprintf("role %v: read access on %v", [role_label, input.resource.type]) if {
    not is_effective_root
    not input.user.disabled
    not mutating_action(input.action)
    has_permission
    org_scope_ok
    not policy_delete_blocked
    not platform_key_delete_blocked
    not self_service_password_attempt
}

reason := sprintf("role %v: mutation on %v (integrity ok)", [role_label, input.resource.type]) if {
    not is_effective_root
    not input.user.disabled
    mutating_action(input.action)
    has_permission
    org_scope_ok
    trust_ok
    not policy_delete_blocked
    not platform_key_delete_blocked
    not self_service_password_attempt
}

reason := sprintf("audit chain broken: %v", [input.audit.reason]) if {
    not is_effective_root
    not input.user.disabled
    mutating_action(input.action)
    has_permission
    org_scope_ok
    not audit_ok
    not policy_delete_blocked
    not platform_key_delete_blocked
    not self_service_password_attempt
}

reason := sprintf("opa trust broken: %v", [input.opa_trust.reason]) if {
    not is_effective_root
    not input.user.disabled
    mutating_action(input.action)
    has_permission
    org_scope_ok
    audit_ok
    not opa_trust_ok
    not policy_delete_blocked
    not platform_key_delete_blocked
    not self_service_password_attempt
}

reason := sprintf("jwt signer broken: %v", [input.jwt_signer.reason]) if {
    not is_effective_root
    not input.user.disabled
    mutating_action(input.action)
    has_permission
    org_scope_ok
    audit_ok
    opa_trust_ok
    not jwt_signer_ok
    not policy_delete_blocked
    not platform_key_delete_blocked
    not self_service_password_attempt
}

reason := sprintf("role %v: cross-org denial on %v", [role_label, input.resource.type]) if {
    not is_effective_root
    not input.user.disabled
    has_permission
    not org_scope_ok
    not policy_delete_blocked
    not platform_key_delete_blocked
    not self_service_password_attempt
}

reason := sprintf("role %v: no permission for %v on %v", [role_label, input.action, input.resource.type]) if {
    not is_effective_root
    not input.user.disabled
    not has_permission
    not policy_delete_blocked
    not platform_key_delete_blocked
    not self_service_password_attempt
}

# Self-service password reasons (preserved from v1, gated by not-root so
# they don't conflict with the root reasons above).
reason := "self-service password change (integrity ok)" if {
    not is_effective_root
    not input.user.disabled
    input.action == "update"
    input.resource.type == "password"
    input.resource.id == input.user.id
    trust_ok
}

reason := sprintf("audit chain broken: %v", [input.audit.reason]) if {
    not is_effective_root
    not input.user.disabled
    input.action == "update"
    input.resource.type == "password"
    input.resource.id == input.user.id
    not audit_ok
}

# Global deny reasons (precede everything else when triggered).
reason := "policies cannot be deleted; lock or unlock the policy instead" if {
    policy_delete_blocked
    not input.user.disabled
}

reason := "platform keys cannot be deleted; rotate then revoke instead" if {
    platform_key_delete_blocked
    not input.user.disabled
}

reason := "user account is disabled" if {
    input.user.disabled
}

# Helper: a caller is trying to change their OWN password. Used to exclude
# the self-service path from the non-root rules above so two reason outputs
# in one query don't error as eval_conflict_error.
self_service_password_attempt if {
    input.action == "update"
    input.resource.type == "password"
    input.resource.id == input.user.id
}
