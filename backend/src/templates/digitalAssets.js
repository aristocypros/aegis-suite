// templates/digitalAssets.js
// Pre-built policy templates covering the digital-asset spectrum.
// Each is a fully-formed JSON spec that compiles to runnable Rego.

export const templates = [
  // ──────────────────────────────────────────────────────────────────────────
  // KYC / AML BASELINE
  // ──────────────────────────────────────────────────────────────────────────
  {
    id: "kyc-aml-baseline",
    name: "KYC / AML Baseline",
    category: "Compliance",
    description:
      "Block any transaction unless the user has completed KYC, is not on a sanctions list, and is below their per-user risk-score threshold.",
    package: "digital_assets.kyc_aml",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        description: "User must clear KYC, sanctions, and risk gates",
        branches: [
          {
            description: "All gates pass simultaneously",
            conditions: [
              { left: "input.user.kyc_status", op: "==", right: "verified", rightType: "string" },
              { left: "input.user.sanctioned", op: "==", right: false, rightType: "boolean" },
              { left: "input.user.risk_score", op: "<=", right: 70, rightType: "number" },
            ],
          },
        ],
      },
      {
        name: "deny_reasons",
        type: "object",
        default: {},
        description: "Set of failed gates for explainability",
        branches: [],
      },
    ],
  },

  // ──────────────────────────────────────────────────────────────────────────
  // TRANSACTION LIMITS BY TIER
  // ──────────────────────────────────────────────────────────────────────────
  {
    id: "tx-limits-tiered",
    name: "Tiered Transaction Limits",
    category: "TradFi",
    description:
      "Per-tier daily transaction caps. Retail < $10k, Pro < $250k, Institutional unlimited. Off-hours apply tighter caps.",
    package: "digital_assets.tx_limits",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Retail tier under $10k",
            conditions: [
              { left: "input.user.tier", op: "==", right: "retail", rightType: "string" },
              { left: "input.amount", op: "<=", right: 10000, rightType: "number" },
            ],
          },
          {
            description: "Pro tier under $250k",
            conditions: [
              { left: "input.user.tier", op: "==", right: "pro", rightType: "string" },
              { left: "input.amount", op: "<=", right: 250000, rightType: "number" },
            ],
          },
          {
            description: "Institutional tier — no cap, but must have approval",
            conditions: [
              { left: "input.user.tier", op: "==", right: "institutional", rightType: "string" },
              { left: "input.approval.signed", op: "==", right: true, rightType: "boolean" },
            ],
          },
        ],
      },
    ],
  },

  // ──────────────────────────────────────────────────────────────────────────
  // SANCTIONS SCREENING
  // ──────────────────────────────────────────────────────────────────────────
  {
    id: "sanctions-screening",
    name: "Sanctions Screening (OFAC/EU/UN)",
    category: "Compliance",
    description:
      "Reject any transaction touching a sanctioned jurisdiction, address, or counterparty. Lists supplied via input.lists.*",
    package: "digital_assets.sanctions",
    rules: [
      {
        name: "deny",
        type: "boolean",
        default: false,
        description: "Triggers if any sanctioned entity is involved",
        branches: [
          {
            description: "Sender wallet on sanctions list",
            conditions: [
              { left: "input.tx.from_address", op: "in", right: "input.lists.sanctioned_addresses", rightType: "ref" },
            ],
          },
          {
            description: "Recipient wallet on sanctions list",
            conditions: [
              { left: "input.tx.to_address", op: "in", right: "input.lists.sanctioned_addresses", rightType: "ref" },
            ],
          },
          {
            description: "User country in sanctioned list",
            conditions: [
              { left: "input.user.country", op: "in", right: "input.lists.sanctioned_countries", rightType: "ref" },
            ],
          },
          {
            description: "Counterparty matches a sanctioned name",
            conditions: [
              { left: "input.counterparty.name", op: "in", right: "input.lists.sanctioned_names", rightType: "ref" },
            ],
          },
        ],
      },
    ],
  },

  // ──────────────────────────────────────────────────────────────────────────
  // STABLECOIN MINTING
  // ──────────────────────────────────────────────────────────────────────────
  {
    id: "stablecoin-mint",
    name: "Stablecoin Mint Authorization",
    category: "Stablecoins",
    description:
      "Authorize a mint only if the requester is an approved minter, the reserve ratio is healthy, and the mint stays within the daily ceiling.",
    package: "digital_assets.stablecoin.mint",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Approved minter, reserves healthy, within ceiling",
            conditions: [
              { left: "input.requester.role", op: "==", right: "minter", rightType: "string" },
              { left: "input.requester.approved", op: "==", right: true, rightType: "boolean" },
              { left: "input.reserves.ratio", op: ">=", right: 1.0, rightType: "number" },
              { left: "input.mint.amount", op: "<=", right: "input.limits.daily_remaining", rightType: "ref" },
              { left: "input.mint.amount", op: ">", right: 0, rightType: "number" },
            ],
          },
        ],
      },
      {
        name: "requires_multisig",
        type: "boolean",
        default: false,
        description: "Mints over $5M require 3-of-5 multisig",
        branches: [
          {
            conditions: [
              { left: "input.mint.amount", op: ">", right: 5000000, rightType: "number" },
            ],
          },
        ],
      },
    ],
  },

  // ──────────────────────────────────────────────────────────────────────────
  // STABLECOIN REDEMPTION
  // ──────────────────────────────────────────────────────────────────────────
  {
    id: "stablecoin-redeem",
    name: "Stablecoin Redemption Gate",
    category: "Stablecoins",
    description:
      "Allow redemption when the holder is whitelisted, the system isn't paused, and slippage is acceptable.",
    package: "digital_assets.stablecoin.redeem",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Standard redemption flow",
            conditions: [
              { left: "input.holder.whitelisted", op: "==", right: true, rightType: "boolean" },
              { left: "input.system.paused", op: "==", right: false, rightType: "boolean" },
              { left: "input.redeem.slippage_bps", op: "<=", right: 50, rightType: "number" },
              { left: "input.redeem.amount", op: "<=", right: "input.holder.balance", rightType: "ref" },
            ],
          },
        ],
      },
    ],
  },

  // ──────────────────────────────────────────────────────────────────────────
  // DEFI PROTOCOL ACCESS
  // ──────────────────────────────────────────────────────────────────────────
  {
    id: "defi-protocol-access",
    name: "DeFi Protocol Access Control",
    category: "DeFi",
    description:
      "Restrict access to a DeFi protocol based on wallet provenance, geo-fencing, and protocol risk classification.",
    package: "digital_assets.defi.access",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Whitelisted wallet from allowed jurisdiction",
            conditions: [
              { left: "input.wallet.verified", op: "==", right: true, rightType: "boolean" },
              { left: "input.wallet.country", op: "in", right: ["US", "GB", "DE", "FR", "JP", "SG", "CH"], rightType: "array" },
              { left: "input.protocol.risk_tier", op: "<=", right: 3, rightType: "number" },
            ],
          },
          {
            description: "High-risk protocols open only to accredited / pro users",
            conditions: [
              { left: "input.wallet.verified", op: "==", right: true, rightType: "boolean" },
              { left: "input.protocol.risk_tier", op: ">=", right: 4, rightType: "number" },
              { left: "input.user.accredited", op: "==", right: true, rightType: "boolean" },
            ],
          },
        ],
      },
    ],
  },

  // ──────────────────────────────────────────────────────────────────────────
  // CUSTODY WITHDRAWAL APPROVAL
  // ──────────────────────────────────────────────────────────────────────────
  {
    id: "custody-withdrawal",
    name: "Custody Withdrawal — M-of-N Approval",
    category: "Institutional",
    description:
      "Withdrawals require N approvers. Threshold scales with amount. Whitelisted destinations only.",
    package: "digital_assets.custody.withdrawal",
    rules: [
      // ── Defensive: required-input type checks ──
      // The three allow branches each branch on input.amount; a missing amount silently fails all three
      // (correct deny, but no surfaced reason). Expose malformed_inputs so callers know to fix the request.
      {
        name: "malformed_inputs",
        kind: "partial_set",
        description: "Set of malformed-input reasons. Non-empty → allow denies and the caller sees the reasons.",
        branches: [
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.amount is missing or not a number",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_number(object.get(input, "amount", null))` }] }],
          },
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.approvals.count is missing or not a number",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_number(object.get(object.get(input, "approvals", {}), "count", null))` }] }],
          },
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.destination.whitelisted is missing or not a boolean",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_boolean(object.get(object.get(input, "destination", {}), "whitelisted", null))` }] }],
          },
        ],
      },
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Small withdrawal: 2 approvers, whitelisted destination",
            conditions: [
              { condType: "arith", leftExpr: "count(malformed_inputs)", op: "==", right: 0, rightType: "number" },
              { left: "input.amount", op: "<=", right: 100000, rightType: "number" },
              { left: "input.approvals.count", op: ">=", right: 2, rightType: "number" },
              { left: "input.destination.whitelisted", op: "==", right: true, rightType: "boolean" },
            ],
          },
          {
            description: "Mid-tier withdrawal: 3 approvers + compliance sign-off",
            conditions: [
              { condType: "arith", leftExpr: "count(malformed_inputs)", op: "==", right: 0, rightType: "number" },
              { left: "input.amount", op: ">", right: 100000, rightType: "number" },
              { left: "input.amount", op: "<=", right: 5000000, rightType: "number" },
              { left: "input.approvals.count", op: ">=", right: 3, rightType: "number" },
              { left: "input.compliance.signed", op: "==", right: true, rightType: "boolean" },
              { left: "input.destination.whitelisted", op: "==", right: true, rightType: "boolean" },
            ],
          },
          {
            description: "Large withdrawal: 5 approvers, board sign-off, cooling period elapsed",
            conditions: [
              { condType: "arith", leftExpr: "count(malformed_inputs)", op: "==", right: 0, rightType: "number" },
              { left: "input.amount", op: ">", right: 5000000, rightType: "number" },
              { left: "input.approvals.count", op: ">=", right: 5, rightType: "number" },
              { left: "input.board.signed", op: "==", right: true, rightType: "boolean" },
              { left: "input.cooling_period_hours_elapsed", op: ">=", right: 24, rightType: "number" },
              { left: "input.destination.whitelisted", op: "==", right: true, rightType: "boolean" },
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

  // ──────────────────────────────────────────────────────────────────────────
  // TRAVEL RULE
  // ──────────────────────────────────────────────────────────────────────────
  {
    id: "travel-rule",
    name: "FATF Travel Rule",
    category: "Compliance",
    description:
      "Transactions over the FATF threshold must include originator + beneficiary VASP information.",
    package: "digital_assets.travel_rule",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Below FATF threshold — pass through",
            conditions: [
              { left: "input.tx.amount_usd", op: "<", right: 1000, rightType: "number" },
            ],
          },
          {
            description: "Above threshold but full originator/beneficiary metadata present",
            conditions: [
              { left: "input.tx.amount_usd", op: ">=", right: 1000, rightType: "number" },
              { left: "input.originator.name", op: "exists" },
              { left: "input.originator.address", op: "exists" },
              { left: "input.originator.vasp_id", op: "exists" },
              { left: "input.beneficiary.name", op: "exists" },
              { left: "input.beneficiary.account", op: "exists" },
              { left: "input.beneficiary.vasp_id", op: "exists" },
            ],
          },
        ],
      },
    ],
  },

  // ──────────────────────────────────────────────────────────────────────────
  // CROSS-BORDER PAYMENTS
  // ──────────────────────────────────────────────────────────────────────────
  {
    id: "cross-border-payment",
    name: "Cross-Border Payment Rules",
    category: "TradFi",
    description:
      "Cross-border payments: corridor allowed, currencies supported, FX rate within tolerance, settlement window valid.",
    package: "digital_assets.cross_border",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Approved corridor and supported currency pair",
            conditions: [
              { left: "input.corridor", op: "in", right: ["US-EU", "US-UK", "US-SG", "EU-UK", "EU-SG", "UK-SG"], rightType: "array" },
              { left: "input.currency.from", op: "in", right: ["USD", "EUR", "GBP", "SGD", "USDC", "EURC"], rightType: "array" },
              { left: "input.currency.to", op: "in", right: ["USD", "EUR", "GBP", "SGD", "USDC", "EURC"], rightType: "array" },
              { left: "input.fx.deviation_bps", op: "<=", right: 25, rightType: "number" },
              { left: "input.settlement.t_plus", op: "<=", right: 2, rightType: "number" },
            ],
          },
        ],
      },
    ],
  },

  // ──────────────────────────────────────────────────────────────────────────
  // TOKEN TRANSFER RESTRICTION (ERC-3643 STYLE)
  // ──────────────────────────────────────────────────────────────────────────
  {
    id: "security-token-transfer",
    name: "Security Token Transfer (ERC-3643)",
    category: "TradFi",
    description:
      "Permissioned security token: investor must hold valid identity claim, comply with lock-up, and respect cap-table limits.",
    package: "digital_assets.security_token",
    rules: [
      {
        name: "allow_transfer",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Both parties verified; lock-up cleared; cap-table not breached",
            conditions: [
              { left: "input.from.identity_verified", op: "==", right: true, rightType: "boolean" },
              { left: "input.to.identity_verified", op: "==", right: true, rightType: "boolean" },
              { left: "input.from.claims.accredited", op: "==", right: true, rightType: "boolean" },
              { left: "input.to.claims.accredited", op: "==", right: true, rightType: "boolean" },
              { left: "input.lockup.days_remaining", op: "<=", right: 0, rightType: "number" },
              { left: "input.captable.holders_after", op: "<=", right: 99, rightType: "number" },
            ],
          },
        ],
      },
    ],
  },

  // ──────────────────────────────────────────────────────────────────────────
  // GOVERNANCE VOTING
  // ──────────────────────────────────────────────────────────────────────────
  {
    id: "governance-vote",
    name: "DAO Governance Voting Rights",
    category: "DeFi",
    description:
      "Votes require minimum stake, registered wallet, and stake-weighted snapshot at proposal start.",
    package: "digital_assets.governance",
    rules: [
      {
        name: "allow_vote",
        type: "boolean",
        default: false,
        branches: [
          {
            conditions: [
              { left: "input.voter.registered", op: "==", right: true, rightType: "boolean" },
              { left: "input.voter.snapshot_balance", op: ">=", right: 100, rightType: "number" },
              { left: "input.proposal.status", op: "==", right: "active", rightType: "string" },
              { left: "input.voter.has_voted", op: "==", right: false, rightType: "boolean" },
            ],
          },
        ],
      },
      {
        name: "vote_weight",
        type: "number",
        default: 0,
        description: "Quadratic vote weight = sqrt(snapshot_balance)",
        branches: [],
      },
    ],
  },

  // ──────────────────────────────────────────────────────────────────────────
  // SETTLEMENT WINDOW
  // ──────────────────────────────────────────────────────────────────────────
  {
    id: "settlement-window",
    name: "Trade Settlement Window",
    category: "Institutional",
    description:
      "Settlement only during exchange hours, on business days, with sufficient inventory and counterparty in good standing.",
    package: "digital_assets.settlement",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            conditions: [
              { left: "input.market.is_open", op: "==", right: true, rightType: "boolean" },
              { left: "input.market.is_business_day", op: "==", right: true, rightType: "boolean" },
              { left: "input.inventory.available", op: ">=", right: "input.trade.quantity", rightType: "ref" },
              { left: "input.counterparty.standing", op: "==", right: "good", rightType: "string" },
              { left: "input.counterparty.credit_remaining", op: ">=", right: "input.trade.notional", rightType: "ref" },
            ],
          },
        ],
      },
    ],
  },

  // ──────────────────────────────────────────────────────────────────────────
  // RBAC — STARTER
  // ──────────────────────────────────────────────────────────────────────────
  {
    id: "rbac-starter",
    name: "RBAC Starter (Generic)",
    category: "Generic",
    description:
      "Generic role-based access control template — adapt for any system.",
    package: "generic.rbac",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Admins can do anything",
            conditions: [
              { left: "input.user.role", op: "==", right: "admin", rightType: "string" },
            ],
          },
          {
            description: "Editors can read or write",
            conditions: [
              { left: "input.user.role", op: "==", right: "editor", rightType: "string" },
              { left: "input.action", op: "in", right: ["read", "write"], rightType: "array" },
            ],
          },
          {
            description: "Viewers can only read",
            conditions: [
              { left: "input.user.role", op: "==", right: "viewer", rightType: "string" },
              { left: "input.action", op: "==", right: "read", rightType: "string" },
            ],
          },
        ],
      },
    ],
  },

  // ──────────────────────────────────────────────────────────────────────────
  // MAKER-CHECKER APPROVAL  (Separation of duties)
  // ──────────────────────────────────────────────────────────────────────────
  {
    id: "maker-checker-approval",
    name: "Maker-Checker Approval",
    category: "Approvals",
    description:
      "Separation of duties: the user who initiated the action cannot also approve it. Both must be active employees and the checker must sign within the dual-control window.",
    package: "digital_assets.approvals.maker_checker",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Maker and checker are distinct active employees and checker has signed in time",
            conditions: [
              { left: "input.maker.id", op: "exists" },
              { left: "input.checker.id", op: "exists" },
              { left: "input.maker.id", op: "!=", right: "input.checker.id", rightType: "ref" },
              { left: "input.maker.active", op: "==", right: true, rightType: "boolean" },
              { left: "input.checker.active", op: "==", right: true, rightType: "boolean" },
              { left: "input.checker.signed", op: "==", right: true, rightType: "boolean" },
              { left: "input.checker.signed_within_minutes", op: "<=", right: 60, rightType: "number" },
              { left: "input.action.risk_tier", op: "in", right: ["low", "medium", "high"], rightType: "array" },
            ],
          },
        ],
      },
    ],
  },

  // ──────────────────────────────────────────────────────────────────────────
  // NESTED QUORUM APPROVAL  (Multi-tier quorum gates)
  // ──────────────────────────────────────────────────────────────────────────
  {
    id: "nested-quorum-approval",
    name: "Nested Quorum Approval",
    category: "Approvals",
    description:
      "Multi-tier approval where each tier independently meets a quorum. Each branch represents an amount tier; gates ANDed within a branch, branches ORed across the rule.",
    package: "digital_assets.approvals.nested_quorum",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Tier 1 (≤ $250k): Ops 2-of-3 quorum only",
            conditions: [
              { left: "input.amount", op: "<=", right: 250000, rightType: "number" },
              { left: "input.tier_ops.approvals_count", op: ">=", right: 2, rightType: "number" },
            ],
          },
          {
            description: "Tier 2 (≤ $10M): Ops 2-of-3 ∧ Risk 1-of-2 ∧ compliance sign-off",
            conditions: [
              { left: "input.amount", op: ">", right: 250000, rightType: "number" },
              { left: "input.amount", op: "<=", right: 10000000, rightType: "number" },
              { left: "input.tier_ops.approvals_count", op: ">=", right: 2, rightType: "number" },
              { left: "input.tier_risk.approvals_count", op: ">=", right: 1, rightType: "number" },
              { left: "input.compliance.signed", op: "==", right: true, rightType: "boolean" },
            ],
          },
          {
            description: "Tier 3 (> $10M): Ops 2-of-3 ∧ Risk 1-of-2 ∧ Board 1-of-3 ∧ cooling period elapsed",
            conditions: [
              { left: "input.amount", op: ">", right: 10000000, rightType: "number" },
              { left: "input.tier_ops.approvals_count", op: ">=", right: 2, rightType: "number" },
              { left: "input.tier_risk.approvals_count", op: ">=", right: 1, rightType: "number" },
              { left: "input.tier_board.approvals_count", op: ">=", right: 1, rightType: "number" },
              { left: "input.cooling_period_hours_elapsed", op: ">=", right: 24, rightType: "number" },
            ],
          },
        ],
      },
    ],
  },

  // ──────────────────────────────────────────────────────────────────────────
  // TREASURY REBALANCE
  // ──────────────────────────────────────────────────────────────────────────
  {
    id: "treasury-rebalance",
    name: "Treasury Rebalance Guardrails",
    category: "Treasury",
    description:
      "Constrain treasury rebalances: per-asset-class allocation bands, single-counterparty exposure cap, idle-cash floor, execution within rebalance window.",
    package: "digital_assets.treasury.rebalance",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Allocation within bands, exposure cap respected, idle-cash floor preserved",
            conditions: [
              { left: "input.allocation.cash_pct_after", op: ">=", right: 5, rightType: "number" },
              { left: "input.allocation.t_bills_pct_after", op: "<=", right: 70, rightType: "number" },
              { left: "input.allocation.crypto_pct_after", op: "<=", right: 25, rightType: "number" },
              { left: "input.allocation.stablecoin_pct_after", op: "<=", right: 40, rightType: "number" },
              { left: "input.counterparty.exposure_pct_after", op: "<=", right: 20, rightType: "number" },
              { left: "input.counterparty.rating", op: "in", right: ["A", "AA", "AAA"], rightType: "array" },
              { left: "input.window.is_rebalance_day", op: "==", right: true, rightType: "boolean" },
              { left: "input.policy.signed_by_cfo", op: "==", right: true, rightType: "boolean" },
            ],
          },
        ],
      },
    ],
  },

  // ──────────────────────────────────────────────────────────────────────────
  // OTC SWAP EXECUTION  (ISDA-style pre-trade)
  // ──────────────────────────────────────────────────────────────────────────
  {
    id: "otc-swap-execution",
    name: "OTC Swap Execution (ISDA Pre-Trade)",
    category: "Trading",
    description:
      "Pre-trade gate for OTC swaps: counterparty whitelisted under signed ISDA, price within market band, initial margin posted, notional within counterparty limit.",
    package: "digital_assets.trading.otc_swap",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "All ISDA, pricing, collateral, and exposure gates pass",
            conditions: [
              { left: "input.counterparty.whitelisted", op: "==", right: true, rightType: "boolean" },
              { left: "input.counterparty.isda_signed", op: "==", right: true, rightType: "boolean" },
              { left: "input.counterparty.csa_in_place", op: "==", right: true, rightType: "boolean" },
              { left: "input.trade.price_deviation_bps", op: "<=", right: 50, rightType: "number" },
              { left: "input.trade.notional_usd", op: "<=", right: "input.counterparty.notional_limit_usd", rightType: "ref" },
              { left: "input.collateral.initial_margin_posted", op: "==", right: true, rightType: "boolean" },
              { left: "input.collateral.haircut_pct", op: "<=", right: 8, rightType: "number" },
              { left: "input.product.type", op: "in", right: ["irs", "fx_swap", "tr_swap", "perp_swap"], rightType: "array" },
            ],
          },
        ],
      },
    ],
  },

  // ──────────────────────────────────────────────────────────────────────────
  // TOKEN LIFECYCLE  (mint / burn / freeze)
  // ──────────────────────────────────────────────────────────────────────────
  {
    id: "token-lifecycle-control",
    name: "Token Lifecycle Control",
    category: "Tokens",
    description:
      "Authorize token mint/burn/freeze actions: action is permitted, actor holds the right role, supply cap not breached, target holder not on the freeze list.",
    package: "digital_assets.tokens.lifecycle",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Mint: authorized minter and supply remains under cap",
            conditions: [
              { left: "input.action", op: "==", right: "mint", rightType: "string" },
              { left: "input.actor.role", op: "==", right: "minter", rightType: "string" },
              { left: "input.actor.authorized", op: "==", right: true, rightType: "boolean" },
              { left: "input.supply.after", op: "<=", right: "input.supply.cap", rightType: "ref" },
              { left: "input.target.frozen", op: "==", right: false, rightType: "boolean" },
            ],
          },
          {
            description: "Burn: authorized burner with sufficient balance",
            conditions: [
              { left: "input.action", op: "==", right: "burn", rightType: "string" },
              { left: "input.actor.role", op: "in", right: ["burner", "minter"], rightType: "array" },
              { left: "input.actor.authorized", op: "==", right: true, rightType: "boolean" },
              { left: "input.target.balance", op: ">=", right: "input.amount", rightType: "ref" },
            ],
          },
          {
            description: "Freeze: compliance role with signed regulatory or court order",
            conditions: [
              { left: "input.action", op: "==", right: "freeze", rightType: "string" },
              { left: "input.actor.role", op: "==", right: "compliance", rightType: "string" },
              { left: "input.order.signed", op: "==", right: true, rightType: "boolean" },
              { left: "input.order.type", op: "in", right: ["regulatory", "court", "internal_compliance"], rightType: "array" },
            ],
          },
        ],
      },
    ],
  },

  // ──────────────────────────────────────────────────────────────────────────
  // MARGIN & COLLATERAL HEALTH
  // ──────────────────────────────────────────────────────────────────────────
  {
    id: "margin-collateral-health",
    name: "Margin & Collateral Health",
    category: "Risk",
    description:
      "Block trades or withdrawals that would breach LTV, use unapproved collateral, or fire while a margin call cure window is active.",
    package: "digital_assets.risk.margin",
    rules: [
      // ── Defensive: required-input type checks ──
      // Both branches reference input.position.ltv_after and input.margin_call.open; require those universally.
      // Branch-specific fields (collateral.*, action, cure_window) intentionally aren't required globally — a
      // request that only satisfies the cure branch shouldn't be rejected for missing collateral details.
      {
        name: "malformed_inputs",
        kind: "partial_set",
        description: "Set of malformed-input reasons. Non-empty → allow denies and the caller sees the reasons.",
        branches: [
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.position.ltv_after is missing or not a number",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_number(object.get(object.get(input, "position", {}), "ltv_after", null))` }] }],
          },
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.margin_call.open is missing or not a boolean",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_boolean(object.get(object.get(input, "margin_call", {}), "open", null))` }] }],
          },
        ],
      },
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "LTV under threshold, approved collateral, no active liquidation, no open margin call",
            conditions: [
              { condType: "arith", leftExpr: "count(malformed_inputs)", op: "==", right: 0, rightType: "number" },
              { left: "input.position.ltv_after", op: "<=", right: 0.65, rightType: "number" },
              { left: "input.collateral.type", op: "in", right: ["USDC", "USDT", "BTC", "ETH", "TBILL"], rightType: "array" },
              { left: "input.collateral.haircut_pct", op: "<=", right: 15, rightType: "number" },
              { left: "input.position.liquidation_active", op: "==", right: false, rightType: "boolean" },
              { left: "input.margin_call.open", op: "==", right: false, rightType: "boolean" },
            ],
          },
          {
            description: "Margin-call cure: top-up that brings LTV back inside threshold during the cure window",
            conditions: [
              { condType: "arith", leftExpr: "count(malformed_inputs)", op: "==", right: 0, rightType: "number" },
              { left: "input.action", op: "==", right: "top_up", rightType: "string" },
              { left: "input.margin_call.open", op: "==", right: true, rightType: "boolean" },
              { left: "input.margin_call.cure_window_minutes_remaining", op: ">", right: 0, rightType: "number" },
              { left: "input.position.ltv_after", op: "<=", right: 0.55, rightType: "number" },
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

  // ──────────────────────────────────────────────────────────────────────────
  // CROSS-CHAIN BRIDGE TRANSFER
  // ──────────────────────────────────────────────────────────────────────────
  {
    id: "bridge-cross-chain",
    name: "Cross-Chain Bridge Guardrails",
    category: "DeFi",
    description:
      "Cross-chain bridge transfers: source/destination chain pair allowed, daily aggregate cap not breached, peg deviation within tolerance, bridge contract not paused.",
    package: "digital_assets.defi.bridge",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Allowed chain pair, within caps, peg healthy, bridge live",
            conditions: [
              { left: "input.source_chain", op: "in", right: ["ethereum", "polygon", "arbitrum", "base", "optimism", "solana"], rightType: "array" },
              { left: "input.dest_chain", op: "in", right: ["ethereum", "polygon", "arbitrum", "base", "optimism", "solana"], rightType: "array" },
              { left: "input.source_chain", op: "!=", right: "input.dest_chain", rightType: "ref" },
              { left: "input.bridge.paused", op: "==", right: false, rightType: "boolean" },
              { left: "input.transfer.amount_usd", op: "<=", right: 500000, rightType: "number" },
              { left: "input.bridge.daily_volume_usd_after", op: "<=", right: 10000000, rightType: "number" },
              { left: "input.peg.deviation_bps", op: "<=", right: 30, rightType: "number" },
              { left: "input.user.kyc_status", op: "==", right: "verified", rightType: "string" },
            ],
          },
        ],
      },
    ],
  },

  // ──────────────────────────────────────────────────────────────────────────
  // VESTING & TIMELOCK RELEASE
  // ──────────────────────────────────────────────────────────────────────────
  {
    id: "vesting-timelock-release",
    name: "Vesting / Timelock Release",
    category: "Operations",
    description:
      "Release vested tokens only after the cliff has passed, the unlock timestamp is reached, the beneficiary is KYC-current, and no clawback is active.",
    package: "digital_assets.ops.vesting",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Cliff elapsed, unlock reached, beneficiary in good standing, requested ≤ vested",
            conditions: [
              { left: "input.now_ts", op: ">=", right: "input.schedule.cliff_ts", rightType: "ref" },
              { left: "input.now_ts", op: ">=", right: "input.schedule.next_unlock_ts", rightType: "ref" },
              { left: "input.beneficiary.kyc_status", op: "==", right: "verified", rightType: "string" },
              { left: "input.beneficiary.terminated_for_cause", op: "==", right: false, rightType: "boolean" },
              { left: "input.clawback.active", op: "==", right: false, rightType: "boolean" },
              { left: "input.request.amount", op: "<=", right: "input.schedule.vested_amount", rightType: "ref" },
            ],
          },
        ],
      },
    ],
  },

  // ──────────────────────────────────────────────────────────────────────────
  // ORACLE PRICE FEED VALIDITY
  // ──────────────────────────────────────────────────────────────────────────
  {
    id: "oracle-price-validity",
    name: "Oracle Price Feed Validity",
    category: "Risk",
    description:
      "Trust an oracle price only when the feed is fresh, multiple reporters agree, deviation from a reference is bounded, and the circuit breaker has not tripped.",
    package: "digital_assets.risk.oracle",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Heartbeat fresh, enough reporters, deviation bounded, breaker untripped",
            conditions: [
              { left: "input.feed.staleness_seconds", op: "<=", right: 60, rightType: "number" },
              { left: "input.feed.reporter_count", op: ">=", right: 3, rightType: "number" },
              { left: "input.feed.deviation_bps_vs_reference", op: "<=", right: 75, rightType: "number" },
              { left: "input.feed.circuit_breaker_tripped", op: "==", right: false, rightType: "boolean" },
              { left: "input.asset.symbol", op: "exists" },
            ],
          },
        ],
      },
    ],
  },

  // ──────────────────────────────────────────────────────────────────────────
  // EMERGENCY KILL-SWITCH
  // ──────────────────────────────────────────────────────────────────────────
  {
    id: "emergency-kill-switch",
    name: "Emergency Kill-Switch",
    category: "Operations",
    description:
      "Block all activity while an incident is active. The only path to allow is a break-glass resume signed by both the CISO and the CTO with a justification on file.",
    package: "digital_assets.ops.kill_switch",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "No incident active and system healthy",
            conditions: [
              { left: "input.incident.active", op: "==", right: false, rightType: "boolean" },
              { left: "input.system.health", op: "==", right: "green", rightType: "string" },
            ],
          },
          {
            description: "Break-glass resume: dual sign-off (CISO + CTO) with justification recorded",
            conditions: [
              { left: "input.action", op: "==", right: "resume", rightType: "string" },
              { left: "input.signoff.ciso", op: "==", right: true, rightType: "boolean" },
              { left: "input.signoff.cto", op: "==", right: true, rightType: "boolean" },
              { left: "input.signoff.ciso_id", op: "!=", right: "input.signoff.cto_id", rightType: "ref" },
              { left: "input.justification.recorded", op: "==", right: true, rightType: "boolean" },
            ],
          },
        ],
      },
    ],
  },

  // ──────────────────────────────────────────────────────────────────────────
  // REGULATORY REPORTING TRIGGER
  // ──────────────────────────────────────────────────────────────────────────
  {
    id: "regulatory-reporting-trigger",
    name: "Regulatory Reporting Trigger",
    category: "Compliance",
    description:
      "Flag transactions that trip a reporting obligation: BSA/CTR, SAR risk, MiCA significant CASP, EMIR derivative, or FinCEN crypto threshold.",
    package: "digital_assets.compliance.reporting",
    rules: [
      {
        name: "report_required",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "BSA Currency Transaction Report (CTR) — cash-equivalent ≥ $10,000",
            conditions: [
              { left: "input.tx.cash_equivalent_usd", op: ">=", right: 10000, rightType: "number" },
              { left: "input.tx.jurisdiction", op: "==", right: "US", rightType: "string" },
            ],
          },
          {
            description: "Suspicious Activity Report (SAR) — risk flag set or structuring suspected",
            conditions: [
              { left: "input.tx.risk_flagged", op: "==", right: true, rightType: "boolean" },
            ],
          },
          {
            description: "MiCA significant transfer — CASP-to-CASP ≥ €1,000 within EEA",
            conditions: [
              { left: "input.tx.amount_eur", op: ">=", right: 1000, rightType: "number" },
              { left: "input.tx.jurisdiction", op: "in", right: ["EU", "EEA"], rightType: "array" },
              { left: "input.tx.casp_to_casp", op: "==", right: true, rightType: "boolean" },
            ],
          },
          {
            description: "EMIR — derivative trade requires trade-repository reporting",
            conditions: [
              { left: "input.product.type", op: "in", right: ["irs", "fx_swap", "tr_swap", "future", "option"], rightType: "array" },
              { left: "input.tx.jurisdiction", op: "in", right: ["EU", "EEA", "UK"], rightType: "array" },
            ],
          },
        ],
      },
    ],
  },

  // ──────────────────────────────────────────────────────────────────────────
  // PRE-TRADE RISK CHECK  (fat-finger / position / loss-limit)
  // ──────────────────────────────────────────────────────────────────────────
  {
    id: "pre-trade-risk-check",
    name: "Pre-Trade Risk Check",
    category: "Trading",
    description:
      "Block orders that would breach fat-finger, position, daily-loss, or order-rate limits before they reach the venue.",
    package: "digital_assets.trading.pre_trade_risk",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Order within all pre-trade risk envelopes",
            conditions: [
              { left: "input.order.notional_usd", op: "<=", right: "input.limits.fat_finger_usd", rightType: "ref" },
              { left: "input.order.qty", op: "<=", right: "input.limits.fat_finger_qty", rightType: "ref" },
              { left: "input.order.price_deviation_bps", op: "<=", right: 200, rightType: "number" },
              { left: "input.position.size_after", op: "<=", right: "input.limits.position_max", rightType: "ref" },
              { left: "input.daily.realized_pnl_usd", op: ">=", right: "input.limits.daily_loss_floor_usd", rightType: "ref" },
              { left: "input.rate.orders_last_minute", op: "<=", right: 60, rightType: "number" },
              { left: "input.symbol", op: "in", right: ["BTC-USD", "ETH-USD", "SOL-USD", "USDC-USD"], rightType: "array" },
            ],
          },
        ],
      },
    ],
  },

  // ──────────────────────────────────────────────────────────────────────────
  // LENDING / LOAN ORIGINATION
  // ──────────────────────────────────────────────────────────────────────────
  {
    id: "lending-origination",
    name: "Crypto Lending Origination",
    category: "Risk",
    description:
      "Approve a new collateralised loan: borrower KYC, approved collateral, origination LTV, term within bounds, sufficient liquidity in the loan book.",
    package: "digital_assets.risk.lending_origination",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "All origination gates pass and risk score acceptable",
            conditions: [
              { left: "input.borrower.kyc_status", op: "==", right: "verified", rightType: "string" },
              { left: "input.borrower.risk_score", op: "<=", right: 60, rightType: "number" },
              { left: "input.borrower.outstanding_loans_count", op: "<", right: 5, rightType: "number" },
              { left: "input.collateral.type", op: "in", right: ["BTC", "ETH", "USDC", "TBILL", "STETH"], rightType: "array" },
              { left: "input.loan.ltv_origination", op: "<=", right: 0.5, rightType: "number" },
              { left: "input.loan.term_days", op: ">=", right: 7, rightType: "number" },
              { left: "input.loan.term_days", op: "<=", right: 365, rightType: "number" },
              { left: "input.loan.principal_usd", op: "<=", right: "input.book.available_liquidity_usd", rightType: "ref" },
              { left: "input.loan.rate_apr", op: ">=", right: "input.book.min_rate_apr", rightType: "ref" },
            ],
          },
        ],
      },
    ],
  },

  // ──────────────────────────────────────────────────────────────────────────
  // NFT ROYALTY & TRANSFER
  // ──────────────────────────────────────────────────────────────────────────
  {
    id: "nft-royalty-transfer",
    name: "NFT Transfer & Royalty Enforcement",
    category: "Tokens",
    description:
      "Allow an NFT transfer when the marketplace honours the on-chain royalty, the buyer is sanctions-clear, the lockup has elapsed, and the collection is not paused.",
    package: "digital_assets.tokens.nft_transfer",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Royalty paid in full, marketplace whitelisted, lockup elapsed, parties clear",
            conditions: [
              { left: "input.collection.paused", op: "==", right: false, rightType: "boolean" },
              { left: "input.marketplace.whitelisted", op: "==", right: true, rightType: "boolean" },
              { left: "input.royalty.paid_bps", op: ">=", right: "input.collection.royalty_bps", rightType: "ref" },
              { left: "input.token.locked_until_ts", op: "<=", right: "input.now_ts", rightType: "ref" },
              { left: "input.from.sanctioned", op: "==", right: false, rightType: "boolean" },
              { left: "input.to.sanctioned", op: "==", right: false, rightType: "boolean" },
              { left: "input.token.id", op: "exists" },
            ],
          },
          {
            description: "Compliance-mandated forced transfer (court order on file)",
            conditions: [
              { left: "input.action", op: "==", right: "forced_transfer", rightType: "string" },
              { left: "input.order.signed", op: "==", right: true, rightType: "boolean" },
              { left: "input.order.type", op: "in", right: ["court", "regulatory"], rightType: "array" },
            ],
          },
        ],
      },
    ],
  },

  // ──────────────────────────────────────────────────────────────────────────
  // INSIDER TRADING BLACKOUT
  // ──────────────────────────────────────────────────────────────────────────
  {
    id: "insider-trading-blackout",
    name: "Insider Trading Blackout",
    category: "Compliance",
    description:
      "Restrict trading by insiders during blackout windows or while on the restricted list, with a narrow 10b5-1 plan exception.",
    package: "digital_assets.compliance.blackout",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Trader is not an insider — normal market access",
            conditions: [
              { left: "input.trader.is_insider", op: "==", right: false, rightType: "boolean" },
            ],
          },
          {
            description: "Insider, outside blackout window and not on restricted list",
            conditions: [
              { left: "input.trader.is_insider", op: "==", right: true, rightType: "boolean" },
              { left: "input.window.in_blackout", op: "==", right: false, rightType: "boolean" },
              { left: "input.trader.on_restricted_list", op: "==", right: false, rightType: "boolean" },
              { left: "input.symbol", op: "exists" },
            ],
          },
          {
            description: "Insider trading under a pre-approved 10b5-1 plan",
            conditions: [
              { left: "input.trader.is_insider", op: "==", right: true, rightType: "boolean" },
              { left: "input.plan.is_10b5_1", op: "==", right: true, rightType: "boolean" },
              { left: "input.plan.compliance_signed", op: "==", right: true, rightType: "boolean" },
              { left: "input.plan.cooldown_days_elapsed", op: ">=", right: 30, rightType: "number" },
              { left: "input.order.symbol", op: "==", right: "input.plan.symbol", rightType: "ref" },
              { left: "input.order.qty", op: "<=", right: "input.plan.qty_remaining", rightType: "ref" },
            ],
          },
        ],
      },
    ],
  },

  // ──────────────────────────────────────────────────────────────────────────
  // FUND SUBSCRIPTION / REDEMPTION GATE
  // ──────────────────────────────────────────────────────────────────────────
  {
    id: "fund-subscription-redemption",
    name: "Fund Subscription / Redemption Gate",
    category: "Institutional",
    description:
      "Enforce subscription cutoff, redemption notice period, NAV freshness, gating thresholds, and accreditation for institutional funds (private credit, hedge fund, tokenised RWA).",
    package: "digital_assets.institutional.fund_flows",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Subscription before cutoff, accredited investor, fund open, NAV fresh",
            conditions: [
              { left: "input.action", op: "==", right: "subscribe", rightType: "string" },
              { left: "input.fund.status", op: "==", right: "open", rightType: "string" },
              { left: "input.investor.accredited", op: "==", right: true, rightType: "boolean" },
              { left: "input.investor.kyc_status", op: "==", right: "verified", rightType: "string" },
              { left: "input.now_ts", op: "<", right: "input.fund.next_cutoff_ts", rightType: "ref" },
              { left: "input.nav.staleness_hours", op: "<=", right: 24, rightType: "number" },
              { left: "input.subscription.amount_usd", op: ">=", right: "input.fund.min_ticket_usd", rightType: "ref" },
            ],
          },
          {
            description: "Redemption with notice period observed and gate not active",
            conditions: [
              { left: "input.action", op: "==", right: "redeem", rightType: "string" },
              { left: "input.fund.gate_active", op: "==", right: false, rightType: "boolean" },
              { left: "input.redemption.notice_days_observed", op: ">=", right: "input.fund.notice_period_days", rightType: "ref" },
              { left: "input.redemption.amount_units", op: "<=", right: "input.investor.units_held", rightType: "ref" },
              { left: "input.redemption.amount_pct_of_nav", op: "<=", right: 5, rightType: "number" },
              { left: "input.nav.staleness_hours", op: "<=", right: 24, rightType: "number" },
            ],
          },
        ],
      },
    ],
  },

  // ──────────────────────────────────────────────────────────────────────────
  // RBAC MATRIX  (demonstrates OR-groups inside an AND branch)
  // ──────────────────────────────────────────────────────────────────────────
  {
    id: "rbac-matrix",
    name: "RBAC Matrix (AND of ORs)",
    category: "Approvals",
    description:
      "Authorise an action when (role is privileged) AND (action is read-style) AND (resource is in scope). Each clause is an OR-group of alternatives — a worked example of the AND-of-ORs pattern.",
    package: "digital_assets.approvals.rbac_matrix",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Privileged role × read-style action × in-scope resource",
            groups: [
              {
                mode: "or",
                conditions: [
                  { left: "input.user.role", op: "==", right: "admin", rightType: "string" },
                  { left: "input.user.role", op: "==", right: "owner", rightType: "string" },
                  { left: "input.user.role", op: "==", right: "auditor", rightType: "string" },
                ],
              },
              {
                mode: "or",
                conditions: [
                  { left: "input.action", op: "==", right: "read", rightType: "string" },
                  { left: "input.action", op: "==", right: "list", rightType: "string" },
                  { left: "input.action", op: "==", right: "describe", rightType: "string" },
                ],
              },
              {
                mode: "and",
                conditions: [
                  { left: "input.resource.tenant_id", op: "==", right: "input.user.tenant_id", rightType: "ref" },
                  { left: "input.resource.classification", op: "in", right: ["public", "internal"], rightType: "array" },
                ],
              },
            ],
          },
        ],
      },
    ],
  },

  // ──────────────────────────────────────────────────────────────────────────
  // SMART-CONTRACT UPGRADE GOVERNANCE
  // ──────────────────────────────────────────────────────────────────────────
  {
    id: "smart-contract-upgrade",
    name: "Smart-Contract Upgrade Governance",
    category: "DeFi",
    description:
      "Allow a contract upgrade only when timelock has elapsed, the proposer is on the authorized list, the multi-sig quorum is met, and a recent independent audit is on file.",
    package: "digital_assets.defi.upgrade",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Timelock elapsed, authorized proposer, multi-sig quorum met, audit attested within 90 days",
            conditions: [
              { left: "input.timelock.elapsed", op: "==", right: true, rightType: "boolean" },
              { left: "input.timelock.delay_hours_observed", op: ">=", right: 48, rightType: "number" },
              { left: "input.proposer.authorized", op: "==", right: true, rightType: "boolean" },
              { left: "input.multisig.signatures_count", op: ">=", right: 4, rightType: "number" },
              { left: "input.multisig.threshold", op: ">=", right: 4, rightType: "number" },
              { left: "input.audit.attested", op: "==", right: true, rightType: "boolean" },
              { left: "input.audit.age_days", op: "<=", right: 90, rightType: "number" },
              { left: "input.upgrade.target_chain", op: "in", right: ["ethereum", "polygon", "arbitrum", "base", "optimism"], rightType: "array" },
            ],
          },
        ],
      },
    ],
  },

  // ──────────────────────────────────────────────────────────────────────────
  // ADVANCED CAPABILITY SHOWCASE TEMPLATES
  // ──────────────────────────────────────────────────────────────────────────

  // 1. Arithmetic expressions — fee/rate validation
  {
    id: "fee-rate-check",
    name: "Fee Rate Check",
    category: "Trading",
    description:
      "Validates that the fee charged on a transaction does not exceed the maximum allowed. Uses arithmetic expressions: fee = amount × rate_bps / 10000 must be ≤ max_fee.",
    package: "digital_assets.trading.fee_rate_check",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Fee does not exceed maximum and amount is within daily limit",
            groups: [
              {
                mode: "and",
                conditions: [
                  { left: "input.amount", op: "exists" },
                  { left: "input.rate_bps", op: "exists" },
                  { left: "input.max_fee", op: "exists" },
                  { left: "input.amount", op: ">=", right: 1, rightType: "number" },
                  {
                    condType: "arith",
                    leftExpr: "input.amount * input.rate_bps / 10000",
                    op: "<=",
                    right: "input.max_fee",
                    rightType: "ref",
                  },
                  { left: "input.amount", op: "<=", right: "input.daily_limit", rightType: "ref" },
                ],
              },
            ],
          },
        ],
      },
    ],
  },

  // 2. Universal quantifier — batch transaction validation
  {
    id: "batch-tx-limits",
    name: "Batch Transaction Limits",
    category: "Operations",
    description:
      "All transactions in a batch must individually be within the per-transaction limit and have a cleared status. Uses the 'every' universal quantifier.",
    package: "digital_assets.operations.batch_tx_limits",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Every transaction in the batch is cleared and within per-tx cap",
            groups: [
              {
                mode: "and",
                conditions: [
                  { left: "input.batch_id", op: "exists" },
                  { left: "input.transactions", op: "is_array" },
                  { left: "input.per_tx_limit", op: "exists" },
                  {
                    condType: "every",
                    variable: "tx",
                    collection: "input.transactions",
                    conditions: [
                      { left: "tx.amount", op: ">", right: 0, rightType: "number" },
                      { left: "tx.amount", op: "<=", right: "input.per_tx_limit", rightType: "ref" },
                      { left: "tx.status", op: "==", right: "cleared", rightType: "string" },
                    ],
                  },
                ],
              },
            ],
          },
        ],
      },
    ],
  },

  // 3. Aggregate sum — daily volume cap
  {
    id: "daily-volume-cap",
    name: "Daily Volume Cap",
    category: "Risk",
    description:
      "Rejects a transaction if adding it to today's volume would breach the daily cap. Uses sum() aggregate over the day's transaction amounts.",
    package: "digital_assets.risk.daily_volume_cap",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Today's total volume plus this transaction stays within the cap",
            groups: [
              {
                mode: "and",
                conditions: [
                  { left: "input.amount", op: ">", right: 0, rightType: "number" },
                  { left: "input.daily_cap", op: "exists" },
                  { left: "input.amount", op: "<=", right: "input.daily_cap", rightType: "ref" },
                  {
                    condType: "aggregate",
                    fn: "sum",
                    collection: "input.today_amounts",
                    op: "<=",
                    right: "input.daily_cap",
                    rightType: "ref",
                  },
                ],
              },
            ],
          },
        ],
      },
    ],
  },

  // 4. Aggregate count with filter — live multi-sig quorum
  {
    id: "multi-sig-quorum-live",
    name: "Multi-Sig Quorum (Live)",
    category: "Approvals",
    description:
      "Requires at least 3 valid signatures out of those submitted. Uses a filtered count aggregate: count(signatures where valid==true) ≥ 3.",
    package: "digital_assets.approvals.multi_sig_quorum_live",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "At least 3 valid signatures present and amount within threshold",
            groups: [
              {
                mode: "and",
                conditions: [
                  { left: "input.signatures", op: "is_array" },
                  { left: "input.amount", op: "<=", right: "input.quorum_limit", rightType: "ref" },
                  {
                    condType: "aggregate",
                    fn: "count",
                    collection: "input.signatures",
                    filter: [
                      { left: "item.valid", op: "==", right: true, rightType: "boolean" },
                    ],
                    op: ">=",
                    right: 3,
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

  // 5. Builtin left — live vesting unlock (time.now_ns)
  {
    id: "vesting-unlock-live",
    name: "Vesting Unlock (Live Clock)",
    category: "Operations",
    description:
      "Releases vested tokens only when the OPA server's wall clock has passed the unlock timestamp. Uses time.now_ns() compared directly to the unlock field — no pre-computed timestamp needed.",
    package: "digital_assets.operations.vesting_unlock_live",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Cliff elapsed, beneficiary KYC live, no clawback, unlock time passed",
            groups: [
              {
                mode: "and",
                conditions: [
                  { left: "input.beneficiary.kyc_status", op: "==", right: "verified", rightType: "string" },
                  { left: "input.clawback_active", op: "==", right: false, rightType: "boolean" },
                  { left: "input.cliff_elapsed", op: "==", right: true, rightType: "boolean" },
                  {
                    condType: "builtin_left",
                    builtin: "time.now_ns",
                    op: ">=",
                    right: "input.unlock_ts_ns",
                    rightType: "ref",
                  },
                ],
              },
            ],
          },
        ],
      },
    ],
  },

  // 6. Time builtin — business-hours trading gate
  {
    id: "business-hours-trading",
    name: "Business Hours Trading Gate",
    category: "Trading",
    description:
      "Restricts trading to weekdays (Mon–Fri) between 08:00 and 17:00 UTC. Uses time.weekday() for the day check and standard numeric comparison for the hour field (caller supplies hour-of-day).",
    package: "digital_assets.trading.business_hours",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Weekday AND within trading hours AND within per-session limit",
            groups: [
              {
                mode: "and",
                conditions: [
                  { left: "input.hour_utc", op: ">=", right: 8, rightType: "number" },
                  { left: "input.hour_utc", op: "<", right: 17, rightType: "number" },
                  { left: "input.amount", op: "<=", right: "input.session_limit", rightType: "ref" },
                ],
              },
              {
                mode: "or",
                conditions: [
                  {
                    condType: "builtin_left",
                    builtin: "time.weekday",
                    arg: "input.ts_ns",
                    op: "==",
                    right: "Monday",
                    rightType: "string",
                  },
                  {
                    condType: "builtin_left",
                    builtin: "time.weekday",
                    arg: "input.ts_ns",
                    op: "==",
                    right: "Tuesday",
                    rightType: "string",
                  },
                  {
                    condType: "builtin_left",
                    builtin: "time.weekday",
                    arg: "input.ts_ns",
                    op: "==",
                    right: "Wednesday",
                    rightType: "string",
                  },
                  {
                    condType: "builtin_left",
                    builtin: "time.weekday",
                    arg: "input.ts_ns",
                    op: "==",
                    right: "Thursday",
                    rightType: "string",
                  },
                  {
                    condType: "builtin_left",
                    builtin: "time.weekday",
                    arg: "input.ts_ns",
                    op: "==",
                    right: "Friday",
                    rightType: "string",
                  },
                ],
              },
            ],
          },
        ],
      },
    ],
  },

  // 7. String normalization — case-insensitive asset symbol
  {
    id: "asset-symbol-normalized",
    name: "Asset Symbol (Case-Insensitive)",
    category: "Compliance",
    description:
      "Accepts a trade only if the asset symbol normalises to an approved token, using lower() for case-insensitive matching. Demonstrates the lower_eq and upper_eq operators.",
    package: "digital_assets.compliance.asset_symbol_normalized",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Symbol (case-normalised) is an approved token and amount is within tier limit",
            groups: [
              {
                mode: "and",
                conditions: [
                  { left: "input.user.kyc_status", op: "==", right: "verified", rightType: "string" },
                  { left: "input.amount", op: ">", right: 0, rightType: "number" },
                  { left: "input.amount", op: "<=", right: 5000000, rightType: "number" },
                ],
              },
              {
                mode: "or",
                conditions: [
                  { left: "input.asset_symbol", op: "lower_eq", right: "eth", rightType: "string" },
                  { left: "input.asset_symbol", op: "lower_eq", right: "btc", rightType: "string" },
                  { left: "input.asset_symbol", op: "lower_eq", right: "usdc", rightType: "string" },
                  { left: "input.asset_symbol", op: "lower_eq", right: "usdt", rightType: "string" },
                ],
              },
            ],
          },
        ],
      },
    ],
  },

  // 8. Network — CIDR IP allowlist
  {
    id: "ip-allowlist-access",
    name: "IP Allowlist (CIDR)",
    category: "Generic",
    description:
      "Restricts API or custody access to requests originating from within an approved CIDR range. Uses net.cidr_contains() for subnet membership. Two branches cover internal corporate and a secondary DR subnet.",
    package: "digital_assets.access.ip_allowlist",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Primary corporate network",
            groups: [
              {
                mode: "and",
                conditions: [
                  { left: "input.client_ip", op: "exists" },
                  { left: "input.client_ip", op: "cidr_contains", right: "10.0.0.0/8", rightType: "string" },
                  { left: "input.user.role", op: "in", right: ["trader", "admin", "compliance"], rightType: "array" },
                ],
              },
            ],
          },
          {
            description: "DR / secondary network",
            groups: [
              {
                mode: "and",
                conditions: [
                  { left: "input.client_ip", op: "exists" },
                  { left: "input.client_ip", op: "cidr_contains", right: "172.16.0.0/12", rightType: "string" },
                  { left: "input.user.role", op: "in", right: ["admin"], rightType: "array" },
                ],
              },
            ],
          },
        ],
      },
    ],
  },

  // 9. Type guards — defensive input validation
  {
    id: "input-type-guard",
    name: "Input Type Guard",
    category: "Generic",
    description:
      "Validates the shape of the input document before any numeric policy runs. Ensures amount, user_id, and metadata are the expected types. Prevents type-confusion exploits and compiler errors.",
    package: "digital_assets.guards.input_types",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Input has the correct types for all required fields",
            groups: [
              {
                mode: "and",
                conditions: [
                  { left: "input.amount",      op: "is_number" },
                  { left: "input.user_id",     op: "is_string" },
                  { left: "input.amount",      op: ">",  right: 0,          rightType: "number" },
                  { left: "input.amount",      op: "<=", right: 10000000,   rightType: "number" },
                  { left: "input.user_id",     op: "!=", right: "",         rightType: "string" },
                ],
              },
            ],
          },
          {
            description: "Structured payload variant — metadata must be an object",
            groups: [
              {
                mode: "and",
                conditions: [
                  { left: "input.amount",      op: "is_number" },
                  { left: "input.user_id",     op: "is_string" },
                  { left: "input.metadata",    op: "is_object" },
                  { left: "input.line_items",  op: "is_array" },
                  { left: "input.amount",      op: ">",  right: 0,        rightType: "number" },
                  { left: "input.metadata.version", op: "exists" },
                ],
              },
            ],
          },
        ],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────────────────
  // TIER 2 — EXPERT MODE TEMPLATES
  // Partial set rules, object builtins, set operations, JWT/crypto
  // ─────────────────────────────────────────────────────────────────────────

  // 1. Partial set rule — risk violations collector
  {
    id: "partial-risk-violations",
    name: "Partial Set: Risk Violations",
    category: "Compliance",
    description:
      "Accumulates compliance violations into a set using OPA partial set rules. " +
      "Each branch produces a distinct violation code; allow is derived as violations being empty.",
    package: "digital_assets.compliance.risk_violations",
    rules: [
      {
        name: "violations",
        kind: "partial_set",
        branches: [
          {
            value: "amount_exceeds_limit",
            valueType: "string",
            description: "Trade amount exceeds per-trade limit",
            conditions: [
              { left: "input.amount", op: ">", right: "input.trade_limit", rightType: "ref" },
            ],
          },
          {
            value: "kyc_not_verified",
            valueType: "string",
            description: "Counterparty KYC status is not verified",
            conditions: [
              { left: "input.counterparty.kyc_status", op: "!=", right: "verified", rightType: "string" },
            ],
          },
          {
            value: "asset_not_allowed",
            valueType: "string",
            description: "Asset is not on the approved trading list",
            conditions: [
              { left: "input.asset", op: "in", right: ["BTC", "ETH", "USDC", "USDT", "SOL"], rightType: "array", negate: true },
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
            description: "No violations — all checks pass",
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

  // 2. object.get — safe config/metadata access with fallback defaults
  {
    id: "object-safe-config",
    name: "Object.get: Safe Config Access",
    category: "Generic",
    description:
      "Demonstrates safe key access with fallback defaults using object.get(). " +
      "Prevents policy failures when optional input fields are absent.",
    package: "digital_assets.generic.object_safe_config",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "Risk level within allowed values (default: low), amount within config max",
            groups: [
              {
                mode: "and",
                conditions: [
                  { left: "input.user.active", op: "==", right: true, rightType: "boolean" },
                  {
                    condType: "object_get",
                    obj: "input.config",
                    key: "risk_level",
                    keyType: "string",
                    default: "low",
                    defaultType: "string",
                    op: "in",
                    right: ["low", "medium"],
                    rightType: "array",
                  },
                  {
                    condType: "object_get",
                    obj: "input.config",
                    key: "max_tx_usd",
                    keyType: "string",
                    default: 100000,
                    defaultType: "number",
                    op: ">=",
                    right: "input.amount",
                    rightType: "ref",
                  },
                ],
              },
            ],
          },
        ],
      },
    ],
  },

  // 3. Set operations — role intersection using condType: "raw"
  {
    id: "set-permission-check",
    name: "Set Intersection: Permission Check",
    category: "Generic",
    description:
      "Verifies that the user holds at least one required role using Rego set intersection (&). " +
      "Expert-mode template: edit conditions in the JSON Spec tab.",
    package: "digital_assets.generic.set_permission",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "User is active and holds at least one required role (set intersection non-empty)",
            groups: [
              {
                mode: "and",
                conditions: [
                  { left: "input.user.active", op: "==", right: true, rightType: "boolean" },
                  {
                    condType: "raw",
                    rego: `user_roles := {r | some r in input.user.roles}
required_roles := {"trade", "execute"}
count(user_roles & required_roles) > 0`,
                  },
                ],
              },
            ],
          },
          {
            description: "Admin bypass — explicit admin role always grants access",
            groups: [
              {
                mode: "and",
                conditions: [
                  { left: "input.user.active", op: "==", right: true, rightType: "boolean" },
                  { condType: "raw", rego: `"admin" in input.user.roles` },
                ],
              },
            ],
          },
        ],
      },
    ],
  },

  // 4. JWT claims verification using condType: "raw"
  {
    id: "jwt-claims-verify",
    name: "JWT Claims Verification",
    category: "Generic",
    description:
      "Structurally decodes a JWT and verifies subject and expiry claims using io.jwt.decode(). " +
      "Expert-mode template: edit in the JSON Spec tab.",
    package: "digital_assets.generic.jwt_claims",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        branches: [
          {
            description: "JWT decodes successfully, subject matches user_id, token not expired",
            groups: [
              {
                mode: "and",
                conditions: [
                  { left: "input.jwt_token", op: "exists" },
                  { left: "input.user_id", op: "exists" },
                  {
                    condType: "raw",
                    rego: `[_, payload, _] := io.jwt.decode(input.jwt_token)
payload.sub == input.user_id
payload.exp > time.now_ns() / 1000000000`,
                  },
                ],
              },
            ],
          },
        ],
      },
    ],
  },

  // 5. Partial set rule — batch validation violations
  {
    id: "partial-batch-validation",
    name: "Partial Set: Batch Validation",
    category: "Operations",
    description:
      "Collects all batch validation failures into a set using partial set rules. " +
      "Checks batch size, submitter authorization, and individual transaction count.",
    package: "digital_assets.operations.batch_validation",
    rules: [
      {
        name: "batch_violations",
        kind: "partial_set",
        branches: [
          {
            value: "empty_batch",
            valueType: "string",
            description: "Batch contains no transactions",
            groups: [
              {
                mode: "and",
                conditions: [
                  { condType: "aggregate", fn: "count", collection: "input.transactions", op: "==", right: 0, rightType: "number" },
                ],
              },
            ],
          },
          {
            value: "batch_too_large",
            valueType: "string",
            description: "Batch exceeds maximum allowed size",
            groups: [
              {
                mode: "and",
                conditions: [
                  { condType: "aggregate", fn: "count", collection: "input.transactions", op: ">", right: "input.max_batch_size", rightType: "ref" },
                ],
              },
            ],
          },
          {
            value: "unauthorized_submitter",
            valueType: "string",
            description: "Submitter is not authorized to submit batches",
            conditions: [
              { left: "input.submitter.authorized", op: "!=", right: true, rightType: "boolean" },
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
            description: "No batch violations detected",
            groups: [
              {
                mode: "and",
                conditions: [
                  { condType: "arith", leftExpr: "count(batch_violations)", op: "==", right: 0, rightType: "number" },
                ],
              },
            ],
          },
        ],
      },
      {
        name: "result",
        kind: "result_object",
        description: "Decision document — bundles the verdict and the rejection-reason set (batch_violations) for the caller's audit log.",
        fields: [
          { key: "allow",             value: "allow",            valueType: "ref" },
          { key: "rejection_reasons", value: "batch_violations", valueType: "ref" },
        ],
      },
    ],
  },
];

// Each template gets a sample input for the sandbox to make demoing trivial
export const sampleInputs = {
  "kyc-aml-baseline": {
    user: { kyc_status: "verified", sanctioned: false, risk_score: 25 },
  },
  "tx-limits-tiered": {
    user: { tier: "pro" },
    amount: 50000,
    approval: { signed: false },
  },
  "sanctions-screening": {
    tx: { from_address: "0xabc", to_address: "0xdef" },
    user: { country: "US" },
    counterparty: { name: "ACME Corp" },
    lists: {
      sanctioned_addresses: ["0xbad1", "0xbad2"],
      sanctioned_countries: ["IR", "KP", "CU"],
      sanctioned_names: ["BadActor LLC"],
    },
  },
  "stablecoin-mint": {
    requester: { role: "minter", approved: true },
    reserves: { ratio: 1.02 },
    mint: { amount: 1000000 },
    limits: { daily_remaining: 10000000 },
  },
  "stablecoin-redeem": {
    holder: { whitelisted: true, balance: 50000 },
    system: { paused: false },
    redeem: { slippage_bps: 12, amount: 10000 },
  },
  "defi-protocol-access": {
    wallet: { verified: true, country: "DE" },
    protocol: { risk_tier: 2 },
    user: { accredited: false },
  },
  "custody-withdrawal": {
    amount: 250000,
    approvals: { count: 3 },
    compliance: { signed: true },
    board: { signed: false },
    destination: { whitelisted: true },
    cooling_period_hours_elapsed: 0,
  },
  "travel-rule": {
    tx: { amount_usd: 5000 },
    originator: { name: "Alice", address: "1 Main St", vasp_id: "VASP-A" },
    beneficiary: { name: "Bob", account: "ACC-001", vasp_id: "VASP-B" },
  },
  "cross-border-payment": {
    corridor: "US-EU",
    currency: { from: "USD", to: "EUR" },
    fx: { deviation_bps: 8 },
    settlement: { t_plus: 1 },
  },
  "security-token-transfer": {
    from: { identity_verified: true, claims: { accredited: true } },
    to: { identity_verified: true, claims: { accredited: true } },
    lockup: { days_remaining: 0 },
    captable: { holders_after: 47 },
  },
  "governance-vote": {
    voter: { registered: true, snapshot_balance: 1500, has_voted: false },
    proposal: { status: "active" },
  },
  "settlement-window": {
    market: { is_open: true, is_business_day: true },
    inventory: { available: 1000 },
    trade: { quantity: 100, notional: 50000 },
    counterparty: { standing: "good", credit_remaining: 500000 },
  },
  "rbac-starter": {
    user: { role: "editor" },
    action: "write",
  },
  "maker-checker-approval": {
    maker: { id: "alice@firm.com", active: true },
    checker: { id: "bob@firm.com", active: true, signed: true, signed_within_minutes: 12 },
    action: { risk_tier: "medium" },
  },
  "nested-quorum-approval": {
    amount: 5000000,
    tier_ops: { approvals_count: 2 },
    tier_risk: { approvals_count: 1 },
    tier_board: { approvals_count: 0 },
    compliance: { signed: true },
    cooling_period_hours_elapsed: 0,
  },
  "treasury-rebalance": {
    allocation: {
      cash_pct_after: 12,
      t_bills_pct_after: 55,
      crypto_pct_after: 18,
      stablecoin_pct_after: 15,
    },
    counterparty: { exposure_pct_after: 14, rating: "AA" },
    window: { is_rebalance_day: true },
    policy: { signed_by_cfo: true },
  },
  "otc-swap-execution": {
    counterparty: {
      whitelisted: true,
      isda_signed: true,
      csa_in_place: true,
      notional_limit_usd: 50000000,
    },
    trade: { price_deviation_bps: 18, notional_usd: 12000000 },
    collateral: { initial_margin_posted: true, haircut_pct: 5 },
    product: { type: "irs" },
  },
  "token-lifecycle-control": {
    action: "mint",
    actor: { role: "minter", authorized: true },
    supply: { after: 950000000, cap: 1000000000 },
    target: { frozen: false, balance: 0 },
    amount: 1000,
    order: { signed: false, type: "internal_compliance" },
  },
  "margin-collateral-health": {
    action: "open",
    position: { ltv_after: 0.42, liquidation_active: false },
    collateral: { type: "USDC", haircut_pct: 2 },
    margin_call: { open: false, cure_window_minutes_remaining: 0 },
  },
  "bridge-cross-chain": {
    source_chain: "ethereum",
    dest_chain: "arbitrum",
    bridge: { paused: false, daily_volume_usd_after: 2500000 },
    transfer: { amount_usd: 75000 },
    peg: { deviation_bps: 8 },
    user: { kyc_status: "verified" },
  },
  "vesting-timelock-release": {
    now_ts: 1746662400,
    schedule: {
      cliff_ts: 1735689600,
      next_unlock_ts: 1746576000,
      vested_amount: 25000,
    },
    beneficiary: { kyc_status: "verified", terminated_for_cause: false },
    clawback: { active: false },
    request: { amount: 5000 },
  },
  "oracle-price-validity": {
    feed: {
      staleness_seconds: 12,
      reporter_count: 7,
      deviation_bps_vs_reference: 22,
      circuit_breaker_tripped: false,
    },
    asset: { symbol: "ETH-USD" },
  },
  "emergency-kill-switch": {
    action: "trade",
    incident: { active: false },
    system: { health: "green" },
    signoff: { ciso: false, cto: false, ciso_id: "", cto_id: "" },
    justification: { recorded: false },
  },
  "regulatory-reporting-trigger": {
    tx: {
      cash_equivalent_usd: 12500,
      amount_eur: 0,
      jurisdiction: "US",
      risk_flagged: false,
      casp_to_casp: false,
    },
    product: { type: "spot" },
  },
  "smart-contract-upgrade": {
    timelock: { elapsed: true, delay_hours_observed: 72 },
    proposer: { authorized: true },
    multisig: { signatures_count: 5, threshold: 4 },
    audit: { attested: true, age_days: 30 },
    upgrade: { target_chain: "ethereum" },
  },
  "rbac-matrix": {
    user: { role: "auditor", tenant_id: "tenant-007" },
    action: "list",
    resource: { tenant_id: "tenant-007", classification: "internal" },
  },
  "pre-trade-risk-check": {
    order: { notional_usd: 200000, qty: 5, price_deviation_bps: 35 },
    limits: {
      fat_finger_usd: 1000000,
      fat_finger_qty: 50,
      position_max: 500,
      daily_loss_floor_usd: -100000,
    },
    position: { size_after: 120 },
    daily: { realized_pnl_usd: -15000 },
    rate: { orders_last_minute: 12 },
    symbol: "ETH-USD",
  },
  "lending-origination": {
    borrower: { kyc_status: "verified", risk_score: 35, outstanding_loans_count: 1 },
    collateral: { type: "ETH" },
    loan: {
      ltv_origination: 0.4,
      term_days: 90,
      principal_usd: 250000,
      rate_apr: 0.085,
    },
    book: { available_liquidity_usd: 25000000, min_rate_apr: 0.06 },
  },
  "nft-royalty-transfer": {
    action: "transfer",
    collection: { paused: false, royalty_bps: 500 },
    marketplace: { whitelisted: true },
    royalty: { paid_bps: 500 },
    token: { id: "NFT-001", locked_until_ts: 1700000000 },
    now_ts: Math.floor(Date.now() / 1000),
    from: { sanctioned: false },
    to: { sanctioned: false },
    order: { signed: false, type: "internal_compliance" },
  },
  "insider-trading-blackout": {
    trader: { is_insider: true, on_restricted_list: false },
    window: { in_blackout: false },
    plan: {
      is_10b5_1: false,
      compliance_signed: false,
      cooldown_days_elapsed: 0,
      symbol: "ACME",
      qty_remaining: 0,
    },
    order: { symbol: "ACME", qty: 10 },
    symbol: "ACME",
  },
  "fund-subscription-redemption": {
    action: "subscribe",
    fund: {
      status: "open",
      next_cutoff_ts: Math.floor(Date.now() / 1000) + 86400,
      min_ticket_usd: 100000,
      notice_period_days: 30,
      gate_active: false,
    },
    investor: {
      accredited: true,
      kyc_status: "verified",
      units_held: 0,
    },
    now_ts: Math.floor(Date.now() / 1000),
    nav: { staleness_hours: 4 },
    subscription: { amount_usd: 250000 },
    redemption: { notice_days_observed: 0, amount_units: 0, amount_pct_of_nav: 0 },
  },

  "fee-rate-check": {
    amount: 100000,
    rate_bps: 30,
    max_fee: 500,
    daily_limit: 1000000,
  },

  "batch-tx-limits": {
    batch_id: "batch-001",
    per_tx_limit: 50000,
    transactions: [
      { amount: 10000, status: "cleared" },
      { amount: 25000, status: "cleared" },
      { amount: 5000,  status: "cleared" },
    ],
  },

  "daily-volume-cap": {
    amount: 200000,
    daily_cap: 1000000,
    today_amounts: [150000, 250000, 100000],
  },

  "multi-sig-quorum-live": {
    amount: 75000,
    quorum_limit: 250000,
    signatures: [
      { signer: "alice", valid: true },
      { signer: "bob",   valid: true },
      { signer: "carol", valid: true },
      { signer: "dave",  valid: false },
    ],
  },

  "vesting-unlock-live": {
    beneficiary: { kyc_status: "verified" },
    clawback_active: false,
    cliff_elapsed: true,
    unlock_ts_ns: (Date.now() - 3600000) * 1e6,
  },

  "business-hours-trading": {
    ts_ns: Date.now() * 1e6,
    hour_utc: 10,
    amount: 50000,
    session_limit: 500000,
  },

  "asset-symbol-normalized": {
    asset_symbol: "ETH",
    amount: 1000,
    user: { kyc_status: "verified" },
  },

  "ip-allowlist-access": {
    client_ip: "10.1.2.3",
    user: { role: "trader" },
  },

  "input-type-guard": {
    amount: 5000,
    user_id: "usr-001",
    metadata: { version: "1.0" },
    line_items: [],
  },

  "partial-risk-violations": {
    amount: 50000,
    trade_limit: 100000,
    counterparty: { kyc_status: "verified" },
    asset: "ETH",
  },

  "object-safe-config": {
    user: { active: true },
    config: { risk_level: "medium", max_tx_usd: 500000 },
    amount: 75000,
  },

  "set-permission-check": {
    user: { active: true, roles: ["trade", "view"] },
  },

  "jwt-claims-verify": {
    jwt_token: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c3ItMDAxIiwiZXhwIjo5OTk5OTk5OTk5fQ.",
    user_id: "usr-001",
  },

  "partial-batch-validation": {
    max_batch_size: 100,
    submitter: { authorized: true },
    transactions: [
      { id: "tx-1", amount: 10000 },
      { id: "tx-2", amount: 25000 },
    ],
  },
};
