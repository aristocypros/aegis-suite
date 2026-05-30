// templates/saasMultitenant.js
// Policy templates for multitenant SaaS digital-asset platforms.
// Covers Tenants, Orgs, Domains, Groups, Roles, and Users — the full IAM stack.

export const templates = [

  // ─────────────────────────────────────────────────────────────────────────
  // TENANT ISOLATION
  // ─────────────────────────────────────────────────────────────────────────
  {
    id: "mt-tenant-isolation",
    name: "Tenant Resource Isolation",
    category: "Multitenancy",
    description:
      "Core tenant scoping gate: users can only access resources within their own tenant. " +
      "Tenant must be active and not suspended. " +
      "Platform admins get a read-only override (MFA required) for operational support.",
    package: "saas.multitenancy.tenant_isolation",
    rules: [
      // ── Defensive: required-input type checks ──
      // Both branches reference input.user and input.action; require those to be well-formed.
      // Branch-specific fields (tenant.*, platform_role/mfa) are not required globally — missing them
      // simply fails the relevant branch (correct deny). malformed_inputs surfaces the bare minimum.
      {
        name: "malformed_inputs",
        kind: "partial_set",
        description: "Set of malformed-input reasons. Non-empty → allow denies and the caller sees the reasons.",
        branches: [
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.user.tenant_id is missing or not a string",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_string(object.get(object.get(input, "user", {}), "tenant_id", null))` }] }],
          },
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.user.active is missing or not a boolean",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_boolean(object.get(object.get(input, "user", {}), "active", null))` }] }],
          },
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.action is missing or not a string",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_string(object.get(input, "action", null))` }] }],
          },
        ],
      },
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "User in same tenant, both active, tenant not suspended",
            conditions: [
              { condType: "arith", leftExpr: "count(malformed_inputs)", op: "==", right: 0, rightType: "number" },
              { left: "input.user.tenant_id",  op: "==", right: "input.resource.tenant_id", rightType: "ref" },
              { left: "input.user.active",      op: "==", right: true,     rightType: "boolean" },
              { left: "input.tenant.status",    op: "==", right: "active", rightType: "string" },
              { left: "input.tenant.suspended", op: "==", right: false,    rightType: "boolean" },
            ],
          },
          {
            description: "Platform admin read-only cross-tenant override (MFA required)",
            conditions: [
              { condType: "arith", leftExpr: "count(malformed_inputs)", op: "==", right: 0, rightType: "number" },
              { left: "input.user.platform_role", op: "==", right: "platform_admin",              rightType: "string" },
              { left: "input.user.mfa_verified",  op: "==", right: true,                          rightType: "boolean" },
              { left: "input.action",             op: "in", right: ["read", "list", "audit"],      rightType: "array" },
            ],
          },
        ],
      },
      {
        name: "result",
        kind: "result_object",
        description: "Decision document — bundles the verdict and any malformed-input reasons for the caller's audit log.",
        fields: [
          { key: "allow",             value: "allow",            valueType: "ref" },
          { key: "rejection_reasons", value: "malformed_inputs", valueType: "ref" },
        ],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────────────────
  // TENANT PROVISIONING & LIFECYCLE
  // ─────────────────────────────────────────────────────────────────────────
  {
    id: "mt-tenant-provisioning",
    name: "Tenant Provisioning & Lifecycle",
    category: "Multitenancy",
    description:
      "Controls who can create, update, archive, and deactivate tenants. " +
      "Creation is platform-admin-only with quota enforcement. " +
      "Updates are owned by the tenant owner. Archival/deactivation requires platform admin sign-off with a recorded reason.",
    package: "saas.multitenancy.tenant_provisioning",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Create: platform admin + MFA + tenant quota not breached",
            conditions: [
              { left: "input.action",                   op: "==", right: "create",           rightType: "string" },
              { left: "input.actor.platform_role",      op: "==", right: "platform_admin",   rightType: "string" },
              { left: "input.actor.mfa_verified",       op: "==", right: true,               rightType: "boolean" },
              { left: "input.platform.tenant_count",    op: "<",  right: "input.platform.tenant_quota", rightType: "ref" },
            ],
          },
          {
            description: "Update: tenant owner within their own tenant, account active",
            conditions: [
              { left: "input.action",             op: "==", right: "update",        rightType: "string" },
              { left: "input.actor.role",         op: "==", right: "tenant_owner",  rightType: "string" },
              { left: "input.actor.tenant_id",    op: "==", right: "input.target_tenant.id", rightType: "ref" },
              { left: "input.actor.active",       op: "==", right: true,            rightType: "boolean" },
            ],
          },
          {
            description: "Archive or deactivate: platform admin + approval signed + reason on file",
            conditions: [
              { left: "input.action",              op: "in",  right: ["deactivate", "archive"], rightType: "array" },
              { left: "input.actor.platform_role", op: "==", right: "platform_admin",          rightType: "string" },
              { left: "input.actor.mfa_verified",  op: "==", right: true,                      rightType: "boolean" },
              { left: "input.approval.signed",     op: "==", right: true,                      rightType: "boolean" },
              { left: "input.approval.reason",     op: "exists" },
            ],
          },
        ],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────────────────
  // ORGANIZATION MEMBER ACCESS  (AND-of-ORs)
  // ─────────────────────────────────────────────────────────────────────────
  {
    id: "mt-org-member-access",
    name: "Organization Member Access",
    category: "Multitenancy",
    description:
      "Resource access gated on org membership within a tenant. " +
      "Uses AND-of-ORs: (org_admin OR org_member OR org_viewer) AND (tenant + org scope + user active). " +
      "Write actions require at least org_member; archive/manage actions require org_admin.",
    package: "saas.multitenancy.org_member_access",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Read/list: any org role, full tenant + org scope enforced",
            groups: [
              {
                mode: "or",
                conditions: [
                  { left: "input.user.org_role", op: "==", right: "org_admin",  rightType: "string" },
                  { left: "input.user.org_role", op: "==", right: "org_member", rightType: "string" },
                  { left: "input.user.org_role", op: "==", right: "org_viewer", rightType: "string" },
                ],
              },
              {
                mode: "and",
                conditions: [
                  { left: "input.user.tenant_id", op: "==", right: "input.resource.tenant_id", rightType: "ref" },
                  { left: "input.user.org_id",    op: "==", right: "input.resource.org_id",    rightType: "ref" },
                  { left: "input.user.active",    op: "==", right: true,                       rightType: "boolean" },
                  { left: "input.org.active",     op: "==", right: true,                       rightType: "boolean" },
                  { left: "input.action",         op: "in", right: ["read", "list", "describe"], rightType: "array" },
                ],
              },
            ],
          },
          {
            description: "Write/update: org_admin or org_member, same tenant + org",
            groups: [
              {
                mode: "or",
                conditions: [
                  { left: "input.user.org_role", op: "==", right: "org_admin",  rightType: "string" },
                  { left: "input.user.org_role", op: "==", right: "org_member", rightType: "string" },
                ],
              },
              {
                mode: "and",
                conditions: [
                  { left: "input.user.tenant_id", op: "==", right: "input.resource.tenant_id", rightType: "ref" },
                  { left: "input.user.org_id",    op: "==", right: "input.resource.org_id",    rightType: "ref" },
                  { left: "input.user.active",    op: "==", right: true,                       rightType: "boolean" },
                  { left: "input.org.active",     op: "==", right: true,                       rightType: "boolean" },
                  { left: "input.action",         op: "in", right: ["create", "update", "write"], rightType: "array" },
                ],
              },
            ],
          },
          {
            description: "Archive/manage members: org_admin only, same tenant + org",
            groups: [
              {
                mode: "and",
                conditions: [
                  { left: "input.user.org_role",  op: "==", right: "org_admin",                                    rightType: "string" },
                  { left: "input.user.tenant_id", op: "==", right: "input.resource.tenant_id",                     rightType: "ref" },
                  { left: "input.user.org_id",    op: "==", right: "input.resource.org_id",                        rightType: "ref" },
                  { left: "input.user.active",    op: "==", right: true,                                           rightType: "boolean" },
                  { left: "input.action",         op: "in", right: ["archive", "manage_members"],                  rightType: "array" },
                ],
              },
            ],
          },
        ],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────────────────
  // DOMAIN-SCOPED RESOURCE ACCESS
  // ─────────────────────────────────────────────────────────────────────────
  {
    id: "mt-domain-resource-gate",
    name: "Domain-Scoped Resource Access",
    category: "Multitenancy",
    description:
      "Resources belong to domains within an org. Access requires domain membership and a compatible domain role, " +
      "or a cross-domain elevated role (org_admin / tenant_admin) within the same tenant. " +
      "Archived and restricted domains are blocked.",
    package: "saas.multitenancy.domain_access",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Domain member — tenant + org + domain scope all match, domain active",
            groups: [
              {
                mode: "and",
                conditions: [
                  { left: "input.user.tenant_id", op: "==", right: "input.resource.tenant_id", rightType: "ref" },
                  { left: "input.user.org_id",    op: "==", right: "input.resource.org_id",    rightType: "ref" },
                  { left: "input.user.domain_id", op: "==", right: "input.resource.domain_id", rightType: "ref" },
                  { left: "input.user.active",    op: "==", right: true,                       rightType: "boolean" },
                  { left: "input.domain.status",  op: "==", right: "active",                   rightType: "string" },
                ],
              },
              {
                mode: "or",
                conditions: [
                  { left: "input.action",          op: "in",  right: ["read", "list"],                                       rightType: "array" },
                  { left: "input.user.domain_role", op: "in", right: ["domain_editor", "domain_admin"], rightType: "array" },
                ],
              },
            ],
          },
          {
            description: "Cross-domain elevated role: org_admin or tenant_admin, same tenant, domain not restricted",
            groups: [
              {
                mode: "and",
                conditions: [
                  { left: "input.user.tenant_id",   op: "==", right: "input.resource.tenant_id", rightType: "ref" },
                  { left: "input.user.active",      op: "==", right: true,                       rightType: "boolean" },
                  { left: "input.domain.restricted", op: "==", right: false,                     rightType: "boolean" },
                ],
              },
              {
                mode: "or",
                conditions: [
                  { left: "input.user.role", op: "==", right: "org_admin",    rightType: "string" },
                  { left: "input.user.role", op: "==", right: "tenant_admin", rightType: "string" },
                ],
              },
            ],
          },
        ],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────────────────
  // GROUP-BASED PERMISSION ENFORCEMENT  (set intersection)
  // ─────────────────────────────────────────────────────────────────────────
  {
    id: "mt-group-permission-check",
    name: "Group Permission Enforcement",
    category: "Multitenancy",
    description:
      "Permission is derived from group membership. Uses set intersection to verify the user's group " +
      "grants at least one required permission for the requested action. " +
      "User, group, and org must all be active within the same tenant. " +
      "A super_admin role bypasses the group check.",
    package: "saas.multitenancy.group_permissions",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Group grants at least one required permission (set intersection non-empty)",
            groups: [
              {
                mode: "and",
                conditions: [
                  { left: "input.user.active",    op: "==", right: true,                       rightType: "boolean" },
                  { left: "input.group.active",   op: "==", right: true,                       rightType: "boolean" },
                  { left: "input.user.tenant_id", op: "==", right: "input.resource.tenant_id", rightType: "ref" },
                  { left: "input.user.group_id",  op: "==", right: "input.group.id",           rightType: "ref" },
                  {
                    condType: "raw",
                    rego: `granted_perms  := {p | some p in input.group.permissions}
required_perms := {p | some p in input.required_permissions}
count(granted_perms & required_perms) > 0`,
                  },
                ],
              },
            ],
          },
          {
            description: "Super-admin bypass — explicit super_admin role in the user's roles set",
            groups: [
              {
                mode: "and",
                conditions: [
                  { left: "input.user.active",    op: "==", right: true,                       rightType: "boolean" },
                  { left: "input.user.tenant_id", op: "==", right: "input.resource.tenant_id", rightType: "ref" },
                  { condType: "raw", rego: `"super_admin" in input.user.roles` },
                ],
              },
            ],
          },
        ],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────────────────
  // ROLE ASSIGNMENT GUARD  (privilege-escalation prevention)
  // ─────────────────────────────────────────────────────────────────────────
  {
    id: "mt-role-assignment-guard",
    name: "Role Assignment Guard",
    category: "Multitenancy",
    description:
      "Controls who can assign or revoke roles. Assignments must stay within the same tenant; " +
      "an assigner can only grant roles equal to or below their own privilege level. " +
      "Self-assignment is blocked. Platform admins can assign cross-tenant (requires MFA + audit ticket).",
    package: "saas.multitenancy.role_assignment",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Org admin assigns member/viewer roles — same tenant + same org, no self-assign",
            conditions: [
              { left: "input.action",               op: "in",  right: ["assign_role", "revoke_role"],                                            rightType: "array" },
              { left: "input.assigner.role",         op: "==", right: "org_admin",                                                               rightType: "string" },
              { left: "input.assigner.tenant_id",    op: "==", right: "input.target_user.tenant_id",                                             rightType: "ref" },
              { left: "input.assigner.org_id",       op: "==", right: "input.target_user.org_id",                                                rightType: "ref" },
              { left: "input.target_role.name",      op: "in",  right: ["org_member", "org_viewer", "domain_editor", "domain_viewer"],            rightType: "array" },
              { left: "input.assigner.id",           op: "!=", right: "input.target_user.id",                                                    rightType: "ref" },
            ],
          },
          {
            description: "Tenant owner assigns any non-owner role — same tenant, MFA, no self-assign",
            conditions: [
              { left: "input.action",            op: "in",  right: ["assign_role", "revoke_role"],                                                                         rightType: "array" },
              { left: "input.assigner.role",     op: "==", right: "tenant_owner",                                                                                          rightType: "string" },
              { left: "input.assigner.tenant_id", op: "==", right: "input.target_user.tenant_id",                                                                          rightType: "ref" },
              { left: "input.assigner.mfa_verified", op: "==", right: true,                                                                                                rightType: "boolean" },
              { left: "input.target_role.name",  op: "in",  right: ["org_admin", "org_member", "org_viewer", "tenant_admin", "domain_admin", "domain_editor", "domain_viewer"], rightType: "array" },
              { left: "input.assigner.id",       op: "!=", right: "input.target_user.id",                                                                                  rightType: "ref" },
            ],
          },
          {
            description: "Platform admin — cross-tenant role assignment, MFA + audit ticket required",
            conditions: [
              { left: "input.action",              op: "in",  right: ["assign_role", "revoke_role"], rightType: "array" },
              { left: "input.assigner.platform_role", op: "==", right: "platform_admin",            rightType: "string" },
              { left: "input.assigner.mfa_verified",  op: "==", right: true,                        rightType: "boolean" },
              { left: "input.audit.ticket_id",        op: "exists" },
            ],
          },
        ],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────────────────
  // USER LIFECYCLE MANAGEMENT
  // ─────────────────────────────────────────────────────────────────────────
  {
    id: "mt-user-lifecycle",
    name: "User Lifecycle Management",
    category: "Multitenancy",
    description:
      "Controls invite, activate, deactivate, archive, and promote actions on user accounts. " +
      "Each action requires a specific actor role and scope. " +
      "Actors cannot modify users with a higher privilege level, and self-mutations are blocked.",
    package: "saas.multitenancy.user_lifecycle",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Invite: org_admin or above, same tenant, seat quota not exceeded",
            conditions: [
              { left: "input.action",              op: "==", right: "invite",                                              rightType: "string" },
              { left: "input.actor.role",          op: "in", right: ["org_admin", "tenant_admin", "tenant_owner"],        rightType: "array" },
              { left: "input.actor.tenant_id",     op: "==", right: "input.target_tenant.id",                             rightType: "ref" },
              { left: "input.actor.active",        op: "==", right: true,                                                 rightType: "boolean" },
              { left: "input.tenant.seats_used",   op: "<",  right: "input.tenant.seats_quota",                           rightType: "ref" },
            ],
          },
          {
            description: "Activate: org_admin or above, same tenant, not self",
            conditions: [
              { left: "input.action",          op: "==", right: "activate",                                            rightType: "string" },
              { left: "input.actor.role",      op: "in", right: ["org_admin", "tenant_admin", "tenant_owner"],         rightType: "array" },
              { left: "input.actor.tenant_id", op: "==", right: "input.target_user.tenant_id",                         rightType: "ref" },
              { left: "input.actor.active",    op: "==", right: true,                                                  rightType: "boolean" },
              { left: "input.actor.id",        op: "!=", right: "input.target_user.id",                                rightType: "ref" },
            ],
          },
          {
            description: "Deactivate: org_admin or above, same tenant, not self, target is non-admin",
            conditions: [
              { left: "input.action",             op: "==", right: "deactivate",                                           rightType: "string" },
              { left: "input.actor.role",         op: "in", right: ["org_admin", "tenant_admin", "tenant_owner"],          rightType: "array" },
              { left: "input.actor.tenant_id",    op: "==", right: "input.target_user.tenant_id",                          rightType: "ref" },
              { left: "input.actor.id",           op: "!=", right: "input.target_user.id",                                 rightType: "ref" },
              { left: "input.target_user.role",   op: "in", right: ["org_member", "org_viewer", "domain_editor", "domain_viewer"], rightType: "array" },
            ],
          },
          {
            description: "Archive: tenant_owner + MFA, same tenant, not self",
            conditions: [
              { left: "input.action",          op: "==", right: "archive",       rightType: "string" },
              { left: "input.actor.role",      op: "==", right: "tenant_owner",  rightType: "string" },
              { left: "input.actor.tenant_id", op: "==", right: "input.target_user.tenant_id", rightType: "ref" },
              { left: "input.actor.mfa_verified", op: "==", right: true,         rightType: "boolean" },
              { left: "input.actor.id",        op: "!=", right: "input.target_user.id",        rightType: "ref" },
            ],
          },
          {
            description: "Promote: tenant_owner + MFA, same tenant, not self, target role is an admin tier",
            conditions: [
              { left: "input.action",          op: "==", right: "promote",       rightType: "string" },
              { left: "input.actor.role",      op: "==", right: "tenant_owner",  rightType: "string" },
              { left: "input.actor.tenant_id", op: "==", right: "input.target_user.tenant_id", rightType: "ref" },
              { left: "input.actor.mfa_verified", op: "==", right: true,         rightType: "boolean" },
              { left: "input.actor.id",        op: "!=", right: "input.target_user.id",        rightType: "ref" },
              { left: "input.new_role",        op: "in", right: ["org_admin", "tenant_admin", "domain_admin"], rightType: "array" },
            ],
          },
        ],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────────────────
  // CROSS-ORG RESOURCE SHARING
  // ─────────────────────────────────────────────────────────────────────────
  {
    id: "mt-cross-org-sharing",
    name: "Cross-Org Resource Sharing",
    category: "Multitenancy",
    description:
      "Within the same tenant, one org can share resources with another via a sharing agreement. " +
      "Read access requires only an active share agreement. " +
      "Write access additionally requires at least 2 approvals on the agreement (filtered count).",
    package: "saas.multitenancy.cross_org_sharing",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Cross-org read: active share agreement, resource marked shared, same tenant",
            groups: [
              {
                mode: "and",
                conditions: [
                  { left: "input.user.tenant_id",              op: "==", right: "input.resource.tenant_id", rightType: "ref" },
                  { left: "input.user.active",                 op: "==", right: true,                       rightType: "boolean" },
                  { left: "input.resource.shared",             op: "==", right: true,                       rightType: "boolean" },
                  { left: "input.share_agreement.active",      op: "==", right: true,                       rightType: "boolean" },
                  { left: "input.share_agreement.from_org_id", op: "==", right: "input.resource.org_id",    rightType: "ref" },
                  { left: "input.share_agreement.to_org_id",  op: "==", right: "input.user.org_id",         rightType: "ref" },
                  { left: "input.action",                      op: "in", right: ["read", "list"],            rightType: "array" },
                ],
              },
            ],
          },
          {
            description: "Cross-org write: share agreement includes write access + quorum of 2 approvals",
            groups: [
              {
                mode: "and",
                conditions: [
                  { left: "input.user.tenant_id",              op: "==", right: "input.resource.tenant_id", rightType: "ref" },
                  { left: "input.user.active",                 op: "==", right: true,                       rightType: "boolean" },
                  { left: "input.resource.shared",             op: "==", right: true,                       rightType: "boolean" },
                  { left: "input.share_agreement.active",      op: "==", right: true,                       rightType: "boolean" },
                  { left: "input.share_agreement.write_access", op: "==", right: true,                      rightType: "boolean" },
                  { left: "input.action",                      op: "in", right: ["create", "update"],        rightType: "array" },
                  {
                    condType: "aggregate",
                    fn: "count",
                    collection: "input.share_agreement.approvers",
                    filter: [
                      { left: "item.approved", op: "==", right: true, rightType: "boolean" },
                    ],
                    op: ">=",
                    right: 2,
                    rightType: "number",
                  },
                ],
              },
            ],
          },
        ],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────────────────
  // MULTITENANT ACCESS VIOLATION COLLECTOR  (partial set)
  // ─────────────────────────────────────────────────────────────────────────
  {
    id: "mt-access-violations",
    name: "Multitenant Access Violation Collector",
    category: "Multitenancy",
    description:
      "Accumulates all violated access-control gates into a set using partial set rules. " +
      "Covers: tenant mismatch, inactive user, org non-membership, domain restriction, " +
      "permission denial (set intersection), and archived resource. " +
      "The allow rule derives from violations being empty.",
    package: "saas.multitenancy.access_violations",
    rules: [
      {
        name: "violations",
        kind: "partial_set",
        branches: [
          // ── Defensive: required-input type checks ──
          // Missing tenant/org/permission fields silently skip their dedicated violations
          // (the `!=` ops evaluate to undefined). Force an explicit malformed_request instead.
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.user.tenant_id is missing or not a string",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_string(object.get(object.get(input, "user", {}), "tenant_id", null))` }] }],
          },
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.user.active is missing or not a boolean",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_boolean(object.get(object.get(input, "user", {}), "active", null))` }] }],
          },
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.user.org_id is missing or not a string",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_string(object.get(object.get(input, "user", {}), "org_id", null))` }] }],
          },
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.user.domain_id is missing or not a string",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_string(object.get(object.get(input, "user", {}), "domain_id", null))` }] }],
          },
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.user.permissions is missing or not an array",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_array(object.get(object.get(input, "user", {}), "permissions", null))` }] }],
          },
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.resource.tenant_id is missing or not a string",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_string(object.get(object.get(input, "resource", {}), "tenant_id", null))` }] }],
          },
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.resource.org_id is missing or not a string",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_string(object.get(object.get(input, "resource", {}), "org_id", null))` }] }],
          },
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.resource.domain_id is missing or not a string",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_string(object.get(object.get(input, "resource", {}), "domain_id", null))` }] }],
          },
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.resource.cross_org_shared is missing or not a boolean",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_boolean(object.get(object.get(input, "resource", {}), "cross_org_shared", null))` }] }],
          },
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.resource.archived is missing or not a boolean",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_boolean(object.get(object.get(input, "resource", {}), "archived", null))` }] }],
          },
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.domain.restricted is missing or not a boolean",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_boolean(object.get(object.get(input, "domain", {}), "restricted", null))` }] }],
          },
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.required_permissions is missing or not an array",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_array(object.get(input, "required_permissions", null))` }] }],
          },
          {
            value: "tenant_mismatch",
            valueType: "string",
            description: "User's tenant does not match resource's tenant",
            conditions: [
              { left: "input.user.tenant_id", op: "!=", right: "input.resource.tenant_id", rightType: "ref" },
            ],
          },
          {
            value: "user_inactive",
            valueType: "string",
            description: "User account is inactive or suspended",
            conditions: [
              { left: "input.user.active", op: "!=", right: true, rightType: "boolean" },
            ],
          },
          {
            value: "org_not_member",
            valueType: "string",
            description: "User does not belong to the resource's org and no cross-org share is active",
            conditions: [
              { left: "input.user.org_id",              op: "!=", right: "input.resource.org_id", rightType: "ref" },
              { left: "input.resource.cross_org_shared", op: "!=", right: true,                   rightType: "boolean" },
            ],
          },
          {
            value: "domain_restricted",
            valueType: "string",
            description: "Resource domain is restricted and user is not a domain member",
            conditions: [
              { left: "input.domain.restricted", op: "==", right: true,                        rightType: "boolean" },
              { left: "input.user.domain_id",    op: "!=", right: "input.resource.domain_id",  rightType: "ref" },
            ],
          },
          {
            value: "permission_denied",
            valueType: "string",
            description: "User's effective permissions do not satisfy any required permission",
            groups: [
              {
                mode: "and",
                conditions: [
                  {
                    condType: "raw",
                    rego: `granted  := {p | some p in input.user.permissions}
required := {p | some p in input.required_permissions}
count(granted & required) == 0`,
                  },
                ],
              },
            ],
          },
          {
            value: "resource_archived",
            valueType: "string",
            description: "Target resource has been archived",
            conditions: [
              { left: "input.resource.archived", op: "==", right: true, rightType: "boolean" },
            ],
          },
        ],
      },
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "No access violations — all gates pass",
            groups: [
              {
                mode: "and",
                conditions: [
                  { condType: "arith", leftExpr: "count(violations)", op: "==", right: 0, rightType: "number" },
                ],
              },
            ],
          },
        ],
      },
      {
        name: "result",
        kind: "result_object",
        description: "Decision document — bundles the verdict and the rejection-reason set for the caller's audit log.",
        fields: [
          { key: "allow",             value: "allow",      valueType: "ref" },
          { key: "rejection_reasons", value: "violations", valueType: "ref" },
        ],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────────────────
  // PLATFORM ADMIN BREAK-GLASS ACCESS
  // ─────────────────────────────────────────────────────────────────────────
  {
    id: "mt-platform-admin-access",
    name: "Platform Admin Break-Glass Access",
    category: "Multitenancy",
    description:
      "Emergency cross-tenant access for platform support engineers. " +
      "Requires platform_admin role, MFA, an open support ticket, at least one supervisor co-sign " +
      "(filtered aggregate count), and restricts to read-only actions. " +
      "A companion audit_required rule always fires for any platform admin action.",
    package: "saas.multitenancy.platform_admin_access",
    rules: [
      // ── Defensive: required-input type checks ──
      // Break-glass is high-risk; surface malformed_inputs so callers can't mistake a deny for a policy decision
      // when they actually forgot a required field. Every branch condition references one of these paths.
      {
        name: "malformed_inputs",
        kind: "partial_set",
        description: "Set of malformed-input reasons. Non-empty → allow denies and the caller sees the reasons.",
        branches: [
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.actor.platform_role is missing or not a string",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_string(object.get(object.get(input, "actor", {}), "platform_role", null))` }] }],
          },
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.actor.active is missing or not a boolean",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_boolean(object.get(object.get(input, "actor", {}), "active", null))` }] }],
          },
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.actor.mfa_verified is missing or not a boolean",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_boolean(object.get(object.get(input, "actor", {}), "mfa_verified", null))` }] }],
          },
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.ticket.status is missing or not a string",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_string(object.get(object.get(input, "ticket", {}), "status", null))` }] }],
          },
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.ticket.id is missing or not a string",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_string(object.get(object.get(input, "ticket", {}), "id", null))` }] }],
          },
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.action is missing or not a string",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_string(object.get(input, "action", null))` }] }],
          },
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.ticket.approvals is missing or not an array",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_array(object.get(object.get(input, "ticket", {}), "approvals", null))` }] }],
          },
        ],
      },
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Break-glass: platform admin + MFA + open ticket + supervisor approved + read-only",
            groups: [
              {
                mode: "and",
                conditions: [
                  { condType: "arith", leftExpr: "count(malformed_inputs)", op: "==", right: 0, rightType: "number" },
                  { left: "input.actor.platform_role", op: "==", right: "platform_admin",                         rightType: "string" },
                  { left: "input.actor.active",        op: "==", right: true,                                     rightType: "boolean" },
                  { left: "input.actor.mfa_verified",  op: "==", right: true,                                     rightType: "boolean" },
                  { left: "input.ticket.status",       op: "==", right: "open",                                   rightType: "string" },
                  { left: "input.ticket.id",           op: "exists" },
                  { left: "input.action",              op: "in", right: ["read", "list", "audit", "describe"],    rightType: "array" },
                  {
                    condType: "aggregate",
                    fn: "count",
                    collection: "input.ticket.approvals",
                    filter: [
                      { left: "item.role",     op: "==", right: "supervisor", rightType: "string" },
                      { left: "item.approved", op: "==", right: true,         rightType: "boolean" },
                    ],
                    op: ">=",
                    right: 1,
                    rightType: "number",
                  },
                ],
              },
            ],
          },
        ],
      },
      {
        name: "audit_required",
        type: "boolean",
        default: true,
        description: "All platform admin actions must be logged — evaluates true whenever the actor is a platform admin",
        branches: [
          {
            description: "Actor is a platform admin — always trigger audit logging",
            conditions: [
              { left: "input.actor.platform_role", op: "==", right: "platform_admin", rightType: "string" },
            ],
          },
        ],
      },
      {
        name: "result",
        kind: "result_object",
        description: "Decision document — bundles the verdict and any malformed-input reasons for the caller's audit log.",
        fields: [
          { key: "allow",             value: "allow",            valueType: "ref" },
          { key: "rejection_reasons", value: "malformed_inputs", valueType: "ref" },
          { key: "audit_required",   value: "audit_required",    valueType: "ref" },
        ],
      },
    ],
  },
];

export const sampleInputs = {
  "mt-tenant-isolation": {
    user:     { tenant_id: "tenant-abc", active: true, platform_role: null, mfa_verified: false },
    resource: { tenant_id: "tenant-abc" },
    tenant:   { status: "active", suspended: false },
    action:   "read",
  },

  "mt-tenant-provisioning": {
    action:        "create",
    actor:         { platform_role: "platform_admin", mfa_verified: true, role: "platform_admin", tenant_id: null, active: true, id: "admin-001" },
    platform:      { tenant_count: 42, tenant_quota: 100 },
    target_tenant: { id: "tenant-xyz" },
    approval:      { signed: false, reason: null },
  },

  "mt-org-member-access": {
    user:     { tenant_id: "tenant-abc", org_id: "org-001", org_role: "org_member", active: true },
    resource: { tenant_id: "tenant-abc", org_id: "org-001" },
    org:      { active: true },
    action:   "read",
  },

  "mt-domain-resource-gate": {
    user:     { tenant_id: "tenant-abc", org_id: "org-001", domain_id: "domain-us", domain_role: "domain_editor", role: "org_member", active: true },
    resource: { tenant_id: "tenant-abc", org_id: "org-001", domain_id: "domain-us" },
    domain:   { status: "active", restricted: false },
    action:   "read",
  },

  "mt-group-permission-check": {
    user:                  { active: true, tenant_id: "tenant-abc", group_id: "grp-traders", roles: [] },
    group:                 { id: "grp-traders", active: true, permissions: ["view_portfolio", "submit_order", "view_reports"] },
    resource:              { tenant_id: "tenant-abc" },
    required_permissions:  ["submit_order"],
  },

  "mt-role-assignment-guard": {
    action:      "assign_role",
    assigner:    { role: "org_admin", tenant_id: "tenant-abc", org_id: "org-001", mfa_verified: true, id: "user-admin", platform_role: null },
    target_user: { tenant_id: "tenant-abc", org_id: "org-001", id: "user-bob" },
    target_role: { name: "org_member" },
    audit:       { ticket_id: null },
  },

  "mt-user-lifecycle": {
    action:        "invite",
    actor:         { role: "org_admin", tenant_id: "tenant-abc", active: true, mfa_verified: true, id: "admin-001" },
    target_tenant: { id: "tenant-abc" },
    target_user:   { tenant_id: "tenant-abc", role: "org_member", id: "user-new" },
    tenant:        { seats_used: 8, seats_quota: 50 },
    new_role:      null,
  },

  "mt-cross-org-sharing": {
    user:     { tenant_id: "tenant-abc", org_id: "org-002", active: true },
    resource: { tenant_id: "tenant-abc", org_id: "org-001", shared: true, cross_org_shared: true },
    share_agreement: {
      active:       true,
      from_org_id:  "org-001",
      to_org_id:    "org-002",
      write_access: false,
      approvers: [
        { name: "alice", approved: true },
        { name: "bob",   approved: true },
      ],
    },
    action: "read",
  },

  "mt-access-violations": {
    user:     { tenant_id: "tenant-abc", org_id: "org-001", domain_id: "domain-us", active: true, permissions: ["view_portfolio", "submit_order"] },
    resource: { tenant_id: "tenant-abc", org_id: "org-001", domain_id: "domain-us", shared: false, cross_org_shared: false, archived: false },
    domain:   { restricted: false },
    required_permissions: ["submit_order"],
  },

  "mt-platform-admin-access": {
    action: "read",
    actor:  { platform_role: "platform_admin", active: true, mfa_verified: true, id: "admin-001" },
    ticket: {
      id:     "TICKET-4892",
      status: "open",
      approvals: [
        { role: "supervisor", approved: true, approver_id: "sup-007" },
      ],
    },
  },
};
