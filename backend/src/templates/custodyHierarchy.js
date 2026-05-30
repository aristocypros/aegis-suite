// templates/custodyHierarchy.js
// Policy templates for an institutional digital-asset custody platform.
// Covers the onboarding hierarchy: Legal Entity → Business Unit → Portfolio → Vault → Wallet,
// plus quorum-based onboarding approvals and per-step creation gates.

export const templates = [

  // ─────────────────────────────────────────────────────────────────────────
  // ONBOARDING REQUEST VALIDITY
  // ─────────────────────────────────────────────────────────────────────────
  {
    id: "custody-onboarding-request",
    name: "Custody Onboarding Request Validity",
    category: "Custody",
    description:
      "Validates a custody-onboarding request bundle covering the full hierarchy " +
      "(legal entity, business unit, portfolio, vault, wallet). " +
      "Requires a platform admin with MFA, an approved jurisdiction, sane quorum bounds, " +
      "and a whitelist of at most 100 addresses.",
    package: "custody.onboarding.request_validity",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Platform admin (MFA) submits a fully populated, in-bounds onboarding request",
            groups: [
              {
                mode: "and",
                conditions: [
                  { left: "input.actor.platform_role",            op: "==", right: "platform_admin",                              rightType: "string" },
                  { left: "input.actor.mfa_verified",             op: "==", right: true,                                          rightType: "boolean" },
                  { left: "input.request.legal_entity.name",      op: "exists" },
                  { left: "input.request.legal_entity.jurisdiction", op: "in", right: ["US-DE", "US-NY", "UK", "SG", "CH", "AE"], rightType: "array" },
                  { left: "input.request.business_unit.name",     op: "exists" },
                  { left: "input.request.portfolio.name",         op: "exists" },
                  { left: "input.request.vault.name",             op: "exists" },
                  { left: "input.request.wallet.chain",           op: "exists" },
                  { left: "input.request.quorum_m",               op: ">=", right: 1, rightType: "number" },
                  { left: "input.request.quorum_m",               op: "<=", right: 7, rightType: "number" },
                  {
                    condType: "aggregate",
                    fn: "count",
                    collection: "input.request.vault.whitelist",
                    op: "<=",
                    right: 100,
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
  // ONBOARDING APPROVAL QUORUM  (violations + companion allow)
  // ─────────────────────────────────────────────────────────────────────────
  {
    id: "custody-onboarding-quorum",
    name: "Custody Onboarding Approval Quorum",
    category: "Custody",
    description:
      "Verifies the approval quorum for an onboarding request. " +
      "Accumulates violations into a partial set: insufficient approvals, missing MFA on an approver, " +
      "wrong approver role, duplicate approver, or an explicit reject. " +
      "The allow rule fires only when no violations are present.",
    package: "custody.onboarding.approval_quorum",
    rules: [
      {
        name: "violations",
        kind: "partial_set",
        branches: [
          // ── Defensive: required-input type checks ──
          // Without these, a missing field makes downstream comparisons evaluate to undefined
          // and silently skip their violation — flipping count(violations)==0 to allow=true.
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.request.quorum_m is missing or not a number",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_number(object.get(object.get(input, "request", {}), "quorum_m", null))` }] }],
          },
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.request.approvals is missing or not an array",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_array(object.get(object.get(input, "request", {}), "approvals", null))` }] }],
          },
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.request.requester_user_id is missing or not a string",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_string(object.get(object.get(input, "request", {}), "requester_user_id", null))` }] }],
          },
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.request.prior_level_approvers is missing or not an array",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_array(object.get(object.get(input, "request", {}), "prior_level_approvers", null))` }] }],
          },
          {
            value: "quorum_below_threshold",
            valueType: "string",
            description: "Number of NON-SELF approve decisions is less than the required quorum_m (self-votes are silently excluded — separation of duties)",
            groups: [
              {
                mode: "and",
                conditions: [
                  {
                    condType: "aggregate",
                    fn: "count",
                    collection: "input.request.approvals",
                    filter: [
                      { left: "item.decision",         op: "==", right: "approve",                           rightType: "string" },
                      { left: "item.approver_user_id", op: "!=", right: "input.request.requester_user_id", rightType: "ref" },
                    ],
                    op: "<",
                    right: "input.request.quorum_m",
                    rightType: "ref",
                  },
                ],
              },
            ],
          },
          {
            value: "approver_missing_mfa",
            valueType: "string",
            description: "At least one approver did not complete MFA",
            groups: [
              {
                mode: "and",
                conditions: [
                  {
                    condType: "aggregate",
                    fn: "count",
                    collection: "input.request.approvals",
                    filter: [
                      { left: "item.decision",      op: "==", right: "approve", rightType: "string" },
                      { left: "item.approver_mfa",  op: "!=", right: true,      rightType: "boolean" },
                    ],
                    op: ">",
                    right: 0,
                    rightType: "number",
                  },
                ],
              },
            ],
          },
          {
            value: "approver_wrong_role",
            valueType: "string",
            description: "At least one approver does not hold the onboarding_approver role",
            groups: [
              {
                mode: "and",
                conditions: [
                  {
                    condType: "aggregate",
                    fn: "count",
                    collection: "input.request.approvals",
                    filter: [
                      { left: "item.decision",      op: "==", right: "approve",             rightType: "string" },
                      { left: "item.approver_role", op: "!=", right: "onboarding_approver", rightType: "string" },
                    ],
                    op: ">",
                    right: 0,
                    rightType: "number",
                  },
                ],
              },
            ],
          },
          {
            value: "duplicate_approver",
            valueType: "string",
            description: "Same approver appears more than once in the approve set",
            groups: [
              {
                mode: "and",
                conditions: [
                  {
                    condType: "raw",
                    rego: `approve_ids := {a.approver_user_id | some a in input.request.approvals; a.decision == "approve"}
approve_rows := [a | some a in input.request.approvals; a.decision == "approve"]
count(approve_ids) != count(approve_rows)`,
                  },
                ],
              },
            ],
          },
          {
            value: "explicit_reject_present",
            valueType: "string",
            description: "At least one approver explicitly rejected the request",
            groups: [
              {
                mode: "and",
                conditions: [
                  {
                    condType: "aggregate",
                    fn: "count",
                    collection: "input.request.approvals",
                    filter: [
                      { left: "item.decision", op: "==", right: "reject", rightType: "string" },
                    ],
                    op: ">",
                    right: 0,
                    rightType: "number",
                  },
                ],
              },
            ],
          },
          {
            value: "cross_level_approval",
            valueType: "string",
            description: "Approver also signed at a prior cascade level (separation of duties)",
            groups: [
              {
                mode: "and",
                conditions: [
                  {
                    condType: "raw",
                    rego: `some prior in input.request.prior_level_approvers
some current in input.request.approvals
current.decision == "approve"
current.approver_user_id == prior`,
                  },
                ],
              },
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
            description: "No quorum violations — request meets the approval bar",
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
  // LEGAL ENTITY CREATE
  // ─────────────────────────────────────────────────────────────────────────
  {
    id: "custody-legal-entity-create",
    name: "Custody Legal Entity Create",
    category: "Custody",
    description:
      "Gates creation of a Legal Entity (top of the custody hierarchy). " +
      "Requires a platform admin with MFA, an approved request status, " +
      "an allowed jurisdiction, and a non-empty entity name.",
    package: "custody.legal_entity.create",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Platform admin (MFA) creates an approved legal entity in an allowed jurisdiction",
            groups: [
              {
                mode: "and",
                conditions: [
                  { left: "input.actor.platform_role",               op: "==", right: "platform_admin", rightType: "string" },
                  { left: "input.actor.mfa_verified",                op: "==", right: true,             rightType: "boolean" },
                  { left: "input.request.status",                    op: "==", right: "approved",       rightType: "string" },
                  { left: "input.request.legal_entity.jurisdiction", op: "in", right: ["US-DE", "US-NY", "UK", "SG", "CH", "AE"], rightType: "array" },
                  { left: "input.request.legal_entity.name",         op: "exists" },
                ],
              },
            ],
          },
        ],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────────────────
  // BUSINESS UNIT CREATE
  // ─────────────────────────────────────────────────────────────────────────
  {
    id: "custody-business-unit-create",
    name: "Custody Business Unit Create",
    category: "Custody",
    description:
      "Gates creation of a Business Unit under an active Legal Entity. " +
      "Requires an org admin at the legal entity level, an allowed business-unit kind, and a non-empty name.",
    package: "custody.business_unit.create",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Legal-entity org admin creates a typed BU under an active legal entity",
            groups: [
              {
                mode: "and",
                conditions: [
                  { left: "input.actor.legal_entity_role", op: "==", right: "org_admin",                                        rightType: "string" },
                  { left: "input.legal_entity.active",     op: "==", right: true,                                                rightType: "boolean" },
                  { left: "input.business_unit.kind",      op: "in", right: ["retail", "institutional", "prop_trading", "ops"], rightType: "array" },
                  { left: "input.business_unit.name",      op: "exists" },
                ],
              },
            ],
          },
        ],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────────────────
  // PORTFOLIO CREATE
  // ─────────────────────────────────────────────────────────────────────────
  {
    id: "custody-portfolio-create",
    name: "Custody Portfolio Create",
    category: "Custody",
    description:
      "Gates creation of a Portfolio under an active Business Unit. " +
      "Requires a BU admin, an allowed portfolio kind, a named beneficial owner, and a non-empty portfolio name.",
    package: "custody.portfolio.create",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "BU admin creates a typed portfolio with a beneficial owner under an active BU",
            groups: [
              {
                mode: "and",
                conditions: [
                  { left: "input.actor.business_unit_role", op: "==", right: "bu_admin",                              rightType: "string" },
                  { left: "input.business_unit.active",     op: "==", right: true,                                    rightType: "boolean" },
                  { left: "input.portfolio.kind",           op: "in", right: ["fund", "client_account", "internal"], rightType: "array" },
                  { left: "input.portfolio.beneficial_owner", op: "exists" },
                  { left: "input.portfolio.name",           op: "exists" },
                ],
              },
            ],
          },
        ],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────────────────
  // VAULT CREATE
  // ─────────────────────────────────────────────────────────────────────────
  {
    id: "custody-vault-create",
    name: "Custody Vault Create",
    category: "Custody",
    description:
      "Gates creation of a Vault under a Portfolio. " +
      "Requires a portfolio admin with MFA, a valid m-of-n quorum (m ≤ n, n in [2,7]), " +
      "a daily-limit cap of $10M, and at least one whitelisted address.",
    package: "custody.vault.create",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Portfolio admin (MFA) creates a bounded m-of-n vault with at least one whitelisted address",
            groups: [
              {
                mode: "and",
                conditions: [
                  { left: "input.actor.portfolio_role", op: "==", right: "portfolio_admin",     rightType: "string" },
                  { left: "input.actor.mfa_verified",   op: "==", right: true,                  rightType: "boolean" },
                  { left: "input.vault.quorum_m",       op: ">=", right: 1,                     rightType: "number" },
                  { left: "input.vault.quorum_n",       op: ">=", right: 2,                     rightType: "number" },
                  { left: "input.vault.quorum_n",       op: "<=", right: 7,                     rightType: "number" },
                  { left: "input.vault.quorum_m",       op: "<=", right: "input.vault.quorum_n", rightType: "ref" },
                  { left: "input.vault.daily_limit_usd", op: "<=", right: 10000000,             rightType: "number" },
                  {
                    condType: "aggregate",
                    fn: "count",
                    collection: "input.vault.whitelist",
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
    ],
  },

  // ─────────────────────────────────────────────────────────────────────────
  // WALLET CREATE  (chain+address regex via helper rule)
  // ─────────────────────────────────────────────────────────────────────────
  {
    id: "custody-wallet-create",
    name: "Custody Wallet Create",
    category: "Custody",
    description:
      "Gates creation of a Wallet under a Vault. " +
      "Requires a vault admin, an allowed chain, and a chain-specific address format. " +
      "Address validation is delegated to a chain_addr_valid helper rule that has one branch per supported chain.",
    package: "custody.wallet.create",
    rules: [
      {
        name: "chain_addr_valid",
        type: "boolean",
        default: false,
        description: "True when the wallet's address matches the regex for its declared chain",
        branches: [
          {
            description: "Ethereum — 0x-prefixed 40-hex-character address",
            groups: [
              {
                mode: "and",
                conditions: [
                  {
                    condType: "raw",
                    rego: `input.wallet.chain == "ethereum"
regex.match(` + "`^0x[a-fA-F0-9]{40}$`" + `, input.wallet.address)`,
                  },
                ],
              },
            ],
          },
          {
            description: "Bitcoin — bech32 (bc1...) or legacy base58check (1.../3...) address",
            groups: [
              {
                mode: "and",
                conditions: [
                  {
                    condType: "raw",
                    rego: `input.wallet.chain == "bitcoin"
regex.match(` + "`^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$`" + `, input.wallet.address)`,
                  },
                ],
              },
            ],
          },
          {
            description: "Solana — base58 string of 32–44 characters",
            groups: [
              {
                mode: "and",
                conditions: [
                  {
                    condType: "raw",
                    rego: `input.wallet.chain == "solana"
regex.match(` + "`^[1-9A-HJ-NP-Za-km-z]{32,44}$`" + `, input.wallet.address)`,
                  },
                ],
              },
            ],
          },
          {
            description: "Polygon — 0x-prefixed 40-hex-character address (EVM-compatible)",
            groups: [
              {
                mode: "and",
                conditions: [
                  {
                    condType: "raw",
                    rego: `input.wallet.chain == "polygon"
regex.match(` + "`^0x[a-fA-F0-9]{40}$`" + `, input.wallet.address)`,
                  },
                ],
              },
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
            description: "Vault admin creates a wallet on a supported chain with a well-formed address",
            groups: [
              {
                mode: "and",
                conditions: [
                  { left: "input.actor.vault_role", op: "==", right: "vault_admin",                                     rightType: "string" },
                  { left: "input.wallet.chain",     op: "in", right: ["ethereum", "bitcoin", "solana", "polygon"],      rightType: "array" },
                  { left: "chain_addr_valid",       op: "==", right: true,                                              rightType: "boolean" },
                ],
              },
            ],
          },
        ],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────────────────
  // WITHDRAWAL REQUEST VALIDITY  (violations + companion allow)
  // ─────────────────────────────────────────────────────────────────────────
  {
    id: "custody-withdrawal-request",
    name: "Custody Withdrawal — Request Validity",
    category: "Custody",
    description:
      "Synchronous gate for a wallet → external-address transfer. " +
      "Enforces vault admin + MFA, whitelist, daily limit, 60s timelock, chain-format regex, " +
      "and non-zero amount. Partial-set violations with companion allow.",
    package: "custody.withdrawal.request_validity",
    rules: [
      {
        name: "chain_addr_valid",
        type: "boolean",
        default: false,
        description: "True when the destination address matches the regex for its declared chain",
        branches: [
          {
            description: "Ethereum — 0x-prefixed 40-hex-character address",
            groups: [
              {
                mode: "and",
                conditions: [
                  {
                    condType: "raw",
                    rego: `input.request.chain == "ethereum"
regex.match(` + "`^0x[a-fA-F0-9]{40}$`" + `, input.request.destination_address)`,
                  },
                ],
              },
            ],
          },
          {
            description: "Bitcoin — bech32 (bc1...) or legacy base58check (1.../3...) address",
            groups: [
              {
                mode: "and",
                conditions: [
                  {
                    condType: "raw",
                    rego: `input.request.chain == "bitcoin"
regex.match(` + "`^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$`" + `, input.request.destination_address)`,
                  },
                ],
              },
            ],
          },
          {
            description: "Solana — base58 string of 32–44 characters",
            groups: [
              {
                mode: "and",
                conditions: [
                  {
                    condType: "raw",
                    rego: `input.request.chain == "solana"
regex.match(` + "`^[1-9A-HJ-NP-Za-km-z]{32,44}$`" + `, input.request.destination_address)`,
                  },
                ],
              },
            ],
          },
          {
            description: "Polygon — 0x-prefixed 40-hex-character address (EVM-compatible)",
            groups: [
              {
                mode: "and",
                conditions: [
                  {
                    condType: "raw",
                    rego: `input.request.chain == "polygon"
regex.match(` + "`^0x[a-fA-F0-9]{40}$`" + `, input.request.destination_address)`,
                  },
                ],
              },
            ],
          },
        ],
      },
      {
        name: "violations",
        kind: "partial_set",
        branches: [
          // ── Defensive: required-input type checks ──
          // Missing or wrong-typed fields silently skip downstream violations; force malformed_request.
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.actor.vault_role is missing or not a string",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_string(object.get(object.get(input, "actor", {}), "vault_role", null))` }] }],
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
            description: "input.request.amount is missing or not a number",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_number(object.get(object.get(input, "request", {}), "amount", null))` }] }],
          },
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.request.destination_address is missing or not a string",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_string(object.get(object.get(input, "request", {}), "destination_address", null))` }] }],
          },
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.request.chain is missing or not a string",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_string(object.get(object.get(input, "request", {}), "chain", null))` }] }],
          },
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.vault.daily_limit_usd is missing or not a number",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_number(object.get(object.get(input, "vault", {}), "daily_limit_usd", null))` }] }],
          },
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.vault.whitelist_addresses is missing or not an array",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_array(object.get(object.get(input, "vault", {}), "whitelist_addresses", null))` }] }],
          },
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.vault.last_withdrawal_at_ns is missing or not a number",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_number(object.get(object.get(input, "vault", {}), "last_withdrawal_at_ns", null))` }] }],
          },
          {
            value: "not_vault_admin",
            valueType: "string",
            description: "Actor is not a vault admin",
            groups: [
              {
                mode: "and",
                conditions: [
                  { left: "input.actor.vault_role", op: "!=", right: "vault_admin", rightType: "string" },
                ],
              },
            ],
          },
          {
            value: "missing_mfa",
            valueType: "string",
            description: "Actor did not complete MFA",
            groups: [
              {
                mode: "and",
                conditions: [
                  { left: "input.actor.mfa_verified", op: "!=", right: true, rightType: "boolean" },
                ],
              },
            ],
          },
          {
            value: "amount_invalid",
            valueType: "string",
            description: "Amount is zero or negative",
            groups: [
              {
                mode: "and",
                conditions: [
                  { left: "input.request.amount", op: "<=", right: 0, rightType: "number" },
                ],
              },
            ],
          },
          {
            value: "amount_exceeds_limit",
            valueType: "string",
            description: "Requested amount exceeds the vault's daily limit",
            groups: [
              {
                mode: "and",
                conditions: [
                  { left: "input.request.amount", op: ">", right: "input.vault.daily_limit_usd", rightType: "ref" },
                ],
              },
            ],
          },
          {
            value: "address_not_whitelisted",
            valueType: "string",
            description: "Destination address is not in the vault's whitelist",
            groups: [
              {
                mode: "and",
                conditions: [
                  {
                    left: "input.request.destination_address",
                    op: "in",
                    right: "input.vault.whitelist_addresses",
                    rightType: "ref",
                    negate: true,
                  },
                ],
              },
            ],
          },
          {
            value: "timelock_violation",
            valueType: "string",
            description: "Less than 60 seconds since the vault's last withdrawal",
            groups: [
              {
                mode: "and",
                conditions: [
                  {
                    condType: "arith",
                    leftExpr: "time.now_ns() - input.vault.last_withdrawal_at_ns",
                    op: "<",
                    right: 60000000000,
                    rightType: "number",
                  },
                ],
              },
            ],
          },
          {
            value: "invalid_chain_format",
            valueType: "string",
            description: "Destination address does not match its declared chain format",
            groups: [
              {
                mode: "and",
                conditions: [
                  { left: "chain_addr_valid", op: "!=", right: true, rightType: "boolean" },
                ],
              },
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
            description: "No validity violations — withdrawal request is well-formed and within bounds",
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
        description: "Decision document — bundles the boolean verdict, the rejection-reason set, and the originating request id for logging/audit.",
        fields: [
          { key: "allow",             value: "allow",            valueType: "ref" },
          { key: "rejection_reasons", value: "violations",       valueType: "ref" },
          // request_id intentionally omitted from the result document — referencing input.request.id directly
          // would make the whole result fail to construct on malformed input (where input.request may be missing),
          // hiding the malformed_request violations from the caller. The caller already holds the original input,
          // so it can pair the decision with its own request id for audit purposes.
        ],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────────────────
  // WITHDRAWAL APPROVAL QUORUM  (mirrors onboarding-quorum + self_approval)
  // ─────────────────────────────────────────────────────────────────────────
  {
    id: "custody-withdrawal-quorum",
    name: "Custody Withdrawal — Approval Quorum",
    category: "Custody",
    description:
      "Verifies the approval quorum for a withdrawal request. " +
      "Mirrors the onboarding quorum but requires the `withdrawal_approver` role and " +
      "blocks self-approval. Allow rule fires only when no violations are present.",
    package: "custody.withdrawal.approval_quorum",
    rules: [
      {
        name: "violations",
        kind: "partial_set",
        branches: [
          // ── Defensive: required-input type checks ──
          // Missing fields silently skip downstream violations; force an explicit malformed_request.
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.request.quorum_m is missing or not a number",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_number(object.get(object.get(input, "request", {}), "quorum_m", null))` }] }],
          },
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.request.approvals is missing or not an array",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_array(object.get(object.get(input, "request", {}), "approvals", null))` }] }],
          },
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.request.requester_user_id is missing or not a string",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_string(object.get(object.get(input, "request", {}), "requester_user_id", null))` }] }],
          },
          {
            value: "quorum_below_threshold",
            valueType: "string",
            description: "Number of NON-SELF approve decisions is less than the required quorum_m (self-votes are silently excluded — separation of duties)",
            groups: [
              {
                mode: "and",
                conditions: [
                  {
                    condType: "aggregate",
                    fn: "count",
                    collection: "input.request.approvals",
                    filter: [
                      { left: "item.decision",         op: "==", right: "approve",                           rightType: "string" },
                      { left: "item.approver_user_id", op: "!=", right: "input.request.requester_user_id", rightType: "ref" },
                    ],
                    op: "<",
                    right: "input.request.quorum_m",
                    rightType: "ref",
                  },
                ],
              },
            ],
          },
          {
            value: "approver_missing_mfa",
            valueType: "string",
            description: "At least one approver did not complete MFA",
            groups: [
              {
                mode: "and",
                conditions: [
                  {
                    condType: "aggregate",
                    fn: "count",
                    collection: "input.request.approvals",
                    filter: [
                      { left: "item.decision",      op: "==", right: "approve", rightType: "string" },
                      { left: "item.approver_mfa",  op: "!=", right: true,      rightType: "boolean" },
                    ],
                    op: ">",
                    right: 0,
                    rightType: "number",
                  },
                ],
              },
            ],
          },
          {
            value: "approver_wrong_role",
            valueType: "string",
            description: "At least one approver does not hold the withdrawal_approver role",
            groups: [
              {
                mode: "and",
                conditions: [
                  {
                    condType: "aggregate",
                    fn: "count",
                    collection: "input.request.approvals",
                    filter: [
                      { left: "item.decision",      op: "==", right: "approve",             rightType: "string" },
                      { left: "item.approver_role", op: "!=", right: "withdrawal_approver", rightType: "string" },
                    ],
                    op: ">",
                    right: 0,
                    rightType: "number",
                  },
                ],
              },
            ],
          },
          {
            value: "duplicate_approver",
            valueType: "string",
            description: "Same approver appears more than once in the approve set",
            groups: [
              {
                mode: "and",
                conditions: [
                  {
                    condType: "raw",
                    rego: `approve_ids := {a.approver_user_id | some a in input.request.approvals; a.decision == "approve"}
approve_rows := [a | some a in input.request.approvals; a.decision == "approve"]
count(approve_ids) != count(approve_rows)`,
                  },
                ],
              },
            ],
          },
          {
            value: "explicit_reject_present",
            valueType: "string",
            description: "At least one approver explicitly rejected the request",
            groups: [
              {
                mode: "and",
                conditions: [
                  {
                    condType: "aggregate",
                    fn: "count",
                    collection: "input.request.approvals",
                    filter: [
                      { left: "item.decision", op: "==", right: "reject", rightType: "string" },
                    ],
                    op: ">",
                    right: 0,
                    rightType: "number",
                  },
                ],
              },
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
            description: "No quorum violations — withdrawal meets the approval bar",
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
  // WITHDRAWAL EXECUTE  (simple gate, called by workflow before execution)
  // ─────────────────────────────────────────────────────────────────────────
  {
    id: "custody-withdrawal-execute",
    name: "Custody Withdrawal — Execute",
    category: "Custody",
    description:
      "Final pre-execution gate for a withdrawal. " +
      "Requires the request to be in 'approved' status, the amount to match what was approved, " +
      "and the wallet to not be frozen.",
    package: "custody.withdrawal.execute",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Approved request with unchanged amount executes against a non-frozen wallet",
            groups: [
              {
                mode: "and",
                conditions: [
                  { left: "input.request.status",          op: "==", right: "approved",                        rightType: "string" },
                  { left: "input.request.amount",          op: "==", right: "input.request.approved_amount", rightType: "ref" },
                  { left: "input.wallet.frozen",           op: "==", right: false,                             rightType: "boolean" },
                ],
              },
            ],
          },
        ],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────────────────
  // EMERGENCY OVERRIDE  (break-glass, violations + companion allow)
  // ─────────────────────────────────────────────────────────────────────────
  {
    id: "custody-emergency-override",
    name: "Custody Emergency Override (Break-Glass)",
    category: "Custody",
    description:
      "Synchronous gate for a time-bound emergency override. " +
      "Requires a platform admin with MFA, a substantive justification (≥ 20 chars), " +
      "an allowed scope, a duration cap of 10 minutes, and either business hours or a co-signer. " +
      "Partial-set violations with companion allow.",
    package: "custody.emergency.override",
    rules: [
      {
        name: "violations",
        kind: "partial_set",
        branches: [
          // ── Defensive: required-input type checks ──
          // Break-glass is the highest-risk policy; missing inputs MUST fail closed via malformed_request.
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.actor.platform_role is missing or not a string",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_string(object.get(object.get(input, "actor", {}), "platform_role", null))` }] }],
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
            description: "input.request.reason is missing or not a string",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_string(object.get(object.get(input, "request", {}), "reason", null))` }] }],
          },
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.request.scope is missing or not a string",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_string(object.get(object.get(input, "request", {}), "scope", null))` }] }],
          },
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.request.duration_seconds is missing or not a number",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_number(object.get(object.get(input, "request", {}), "duration_seconds", null))` }] }],
          },
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.request.business_hours is missing or not a boolean",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_boolean(object.get(object.get(input, "request", {}), "business_hours", null))` }] }],
          },
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.request.cosigner_approvals is missing or not an array",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_array(object.get(object.get(input, "request", {}), "cosigner_approvals", null))` }] }],
          },
          {
            value: "not_platform_admin",
            valueType: "string",
            description: "Actor is not a platform admin",
            groups: [
              {
                mode: "and",
                conditions: [
                  { left: "input.actor.platform_role", op: "!=", right: "platform_admin", rightType: "string" },
                ],
              },
            ],
          },
          {
            value: "missing_mfa",
            valueType: "string",
            description: "Actor did not complete MFA",
            groups: [
              {
                mode: "and",
                conditions: [
                  { left: "input.actor.mfa_verified", op: "!=", right: true, rightType: "boolean" },
                ],
              },
            ],
          },
          {
            value: "reason_too_short",
            valueType: "string",
            description: "Justification reason is shorter than 20 characters",
            groups: [
              {
                mode: "and",
                conditions: [
                  {
                    condType: "arith",
                    leftExpr: "count(input.request.reason)",
                    op: "<",
                    right: 20,
                    rightType: "number",
                  },
                ],
              },
            ],
          },
          {
            value: "invalid_scope",
            valueType: "string",
            description: "Override scope is not in the allowed set",
            groups: [
              {
                mode: "and",
                conditions: [
                  {
                    left: "input.request.scope",
                    op: "in",
                    right: ["vault_unfreeze", "limit_override", "whitelist_emergency_add"],
                    rightType: "array",
                    negate: true,
                  },
                ],
              },
            ],
          },
          {
            value: "duration_too_long",
            valueType: "string",
            description: "Override duration exceeds the 10-minute cap",
            groups: [
              {
                mode: "and",
                conditions: [
                  { left: "input.request.duration_seconds", op: ">", right: 600, rightType: "number" },
                ],
              },
            ],
          },
          {
            value: "after_hours_no_cosigner",
            valueType: "string",
            description: "Override invoked after business hours without a co-signer approval",
            groups: [
              {
                mode: "and",
                conditions: [
                  { left: "input.request.business_hours", op: "==", right: false, rightType: "boolean" },
                  {
                    condType: "aggregate",
                    fn: "count",
                    collection: "input.request.cosigner_approvals",
                    op: "<",
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
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "No override violations — emergency grant may be issued",
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
];

export const sampleInputs = {
  "custody-onboarding-request": {
    actor: { id: "u-1", platform_role: "platform_admin", mfa_verified: true },
    request: {
      legal_entity:  { name: "Aristo Capital LLC", jurisdiction: "US-DE" },
      business_unit: { name: "Prop Desk", kind: "prop_trading" },
      portfolio:     { name: "Flagship Fund", beneficial_owner: "ACME LP", kind: "fund" },
      vault:         { name: "Cold Vault A", quorum_m: 2, quorum_n: 3, daily_limit_usd: 1000000, whitelist: ["0xfeedfacefeedfacefeedfacefeedfacefeedface"] },
      wallet:        { chain: "ethereum", address: "0xfeedfacefeedfacefeedfacefeedfacefeedface" },
      quorum_m: 2,
    },
  },

  "custody-onboarding-quorum": {
    request: {
      quorum_m: 2,
      // SoD inputs (backward-compatible — when absent, the new violations don't fire):
      //   - requester_user_id: who submitted the request; cannot self-approve
      //   - prior_level_approvers: user ids who approved at a prior cascade level
      requester_user_id: "u-1",
      prior_level_approvers: [],
      approvals: [
        { approver_user_id: "u-2", approver_role: "onboarding_approver", approver_mfa: true, decision: "approve" },
        { approver_user_id: "u-3", approver_role: "onboarding_approver", approver_mfa: true, decision: "approve" },
      ],
    },
  },

  "custody-legal-entity-create": {
    actor: { id: "u-1", platform_role: "platform_admin", mfa_verified: true },
    request: {
      status: "approved",
      legal_entity: { name: "Aristo Capital LLC", jurisdiction: "US-DE" },
    },
  },

  "custody-business-unit-create": {
    actor:         { id: "u-1", legal_entity_role: "org_admin" },
    legal_entity:  { id: "le-1", active: true },
    business_unit: { name: "Prop Desk", kind: "prop_trading" },
  },

  "custody-portfolio-create": {
    actor:         { id: "u-1", business_unit_role: "bu_admin" },
    business_unit: { id: "bu-1", active: true },
    portfolio:     { name: "Flagship Fund", kind: "fund", beneficial_owner: "ACME LP" },
  },

  "custody-vault-create": {
    actor: { id: "u-1", portfolio_role: "portfolio_admin", mfa_verified: true },
    vault: {
      name: "Cold Vault A",
      quorum_m: 2,
      quorum_n: 3,
      daily_limit_usd: 1000000,
      whitelist: ["0xfeedfacefeedfacefeedfacefeedfacefeedface"],
    },
  },

  "custody-wallet-create": {
    actor:  { id: "u-1", vault_role: "vault_admin" },
    wallet: { chain: "ethereum", address: "0xfeedfacefeedfacefeedfacefeedfacefeedface" },
  },

  "custody-withdrawal-request": {
    actor: { user_id: "u-1", vault_role: "vault_admin", mfa_verified: true },
    request: {
      id: "req-w-001",
      amount: 500000,
      destination_address: "0xfeedfacefeedfacefeedfacefeedfacefeedface",
      chain: "ethereum",
    },
    vault: {
      daily_limit_usd: 1000000,
      whitelist_addresses: ["0xfeedfacefeedfacefeedfacefeedfacefeedface"],
      // 0 means "no prior withdrawal" — time.now_ns() - 0 is always >> 60s so timelock is satisfied.
      last_withdrawal_at_ns: 0,
    },
  },

  "custody-withdrawal-quorum": {
    request: {
      quorum_m: 2,
      requester_user_id: "u-1",
      approvals: [
        { approver_user_id: "u-2", approver_role: "withdrawal_approver", approver_mfa: true, decision: "approve" },
        { approver_user_id: "u-3", approver_role: "withdrawal_approver", approver_mfa: true, decision: "approve" },
      ],
    },
  },

  "custody-withdrawal-execute": {
    request: { status: "approved", amount: 500000, approved_amount: 500000 },
    wallet:  { frozen: false },
  },

  "custody-emergency-override": {
    actor: { user_id: "u-1", platform_role: "platform_admin", mfa_verified: true },
    request: {
      reason: "vault stuck on x — need to unfreeze for ops",
      scope: "vault_unfreeze",
      duration_seconds: 300,
      business_hours: true,
      cosigner_approvals: [],
    },
  },
};
