# Policy Template Catalog

> Generated reference for the bundled policy templates in [`backend/src/templates/`](../backend/src/templates/). Every template is a **JSON policy spec** that Aegis Studio compiles to Rego v1 — this catalog documents each one with a plain-language explanation, two diagrams, and the **actual compiled Rego** (produced by running each spec through [`regoCompiler.js`](../backend/src/services/regoCompiler.js), not hand-written).

**70 policies** across **4 template files**. Pick any from the New-policy → *Template Gallery* flow in the UI; each clones into a new, editable policy.

## How to read this catalog

Each entry has:

- **Decision logic** — the rules the spec declares (`allow` / violation sets / result objects) and the branch conditions under which each fires.
- **Use-case scenario** — a flowchart of the request path: who calls, what `input` they send, and which branch leads to *allow* vs *deny*.
- **State — when the decision is applied** — a lifecycle state diagram: what happens to the request/resource when the policy passes (state committed) versus fails (blocked, no state change).
- **Compiled Rego** *(collapsible)* — the exact Rego emitted by the compiler for this spec, plus the sandbox sample input where one ships.

> [!NOTE]
> The compiler is the security boundary: every condition is validated against per-op whitelists before it becomes Rego, so a template can never emit arbitrary Rego. See [CLAUDE.md → *Compiler*](../CLAUDE.md) for the invariants.

### Diagram legend

```mermaid
flowchart LR
    a(["actor / caller"]) -->|"input"| b{{"PDP · OPA<br/>data.&lt;package&gt;"}}
    b -->|"a branch matches"| ok(["✅ allow → proceed"])
    b -->|"no branch matches"| no(["⛔ default → blocked"])
```

- Rounded nodes are actors/outcomes, `{{hexagons}}` are the OPA decision point, `[/parallelograms/]` are emitted documents.
- In the state diagrams, **Applied** = the guarded action ran and state changed; **Rejected** = blocked with no side effect. Policies that emit a violation set surface **reasons** to the caller on denial.
- These are **synchronous authorization gates** — OPA returns *allow / deny* (+ optional reasons); it never mutates state itself. "Applied" is the caller's downstream commit once allowed.

---

## Contents


### Custody Hierarchy — `custodyHierarchy.js` (11)

1. [Custody Onboarding Request Validity](#policy-custody-onboarding-request) — `Custody`
2. [Custody Onboarding Approval Quorum](#policy-custody-onboarding-quorum) — `Custody`
3. [Custody Legal Entity Create](#policy-custody-legal-entity-create) — `Custody`
4. [Custody Business Unit Create](#policy-custody-business-unit-create) — `Custody`
5. [Custody Portfolio Create](#policy-custody-portfolio-create) — `Custody`
6. [Custody Vault Create](#policy-custody-vault-create) — `Custody`
7. [Custody Wallet Create](#policy-custody-wallet-create) — `Custody`
8. [Custody Withdrawal — Request Validity](#policy-custody-withdrawal-request) — `Custody`
9. [Custody Withdrawal — Approval Quorum](#policy-custody-withdrawal-quorum) — `Custody`
10. [Custody Withdrawal — Execute](#policy-custody-withdrawal-execute) — `Custody`
11. [Custody Emergency Override (Break-Glass)](#policy-custody-emergency-override) — `Custody`

### Digital Assets — `digitalAssets.js` (45)

12. [KYC / AML Baseline](#policy-kyc-aml-baseline) — `Compliance`
13. [Tiered Transaction Limits](#policy-tx-limits-tiered) — `TradFi`
14. [Sanctions Screening (OFAC/EU/UN)](#policy-sanctions-screening) — `Compliance`
15. [Stablecoin Mint Authorization](#policy-stablecoin-mint) — `Stablecoins`
16. [Stablecoin Redemption Gate](#policy-stablecoin-redeem) — `Stablecoins`
17. [DeFi Protocol Access Control](#policy-defi-protocol-access) — `DeFi`
18. [Custody Withdrawal — M-of-N Approval](#policy-custody-withdrawal) — `Institutional`
19. [FATF Travel Rule](#policy-travel-rule) — `Compliance`
20. [Cross-Border Payment Rules](#policy-cross-border-payment) — `TradFi`
21. [Security Token Transfer (ERC-3643)](#policy-security-token-transfer) — `TradFi`
22. [DAO Governance Voting Rights](#policy-governance-vote) — `DeFi`
23. [Trade Settlement Window](#policy-settlement-window) — `Institutional`
24. [RBAC Starter (Generic)](#policy-rbac-starter) — `Generic`
25. [Maker-Checker Approval](#policy-maker-checker-approval) — `Approvals`
26. [Nested Quorum Approval](#policy-nested-quorum-approval) — `Approvals`
27. [Treasury Rebalance Guardrails](#policy-treasury-rebalance) — `Treasury`
28. [OTC Swap Execution (ISDA Pre-Trade)](#policy-otc-swap-execution) — `Trading`
29. [Token Lifecycle Control](#policy-token-lifecycle-control) — `Tokens`
30. [Margin & Collateral Health](#policy-margin-collateral-health) — `Risk`
31. [Cross-Chain Bridge Guardrails](#policy-bridge-cross-chain) — `DeFi`
32. [Vesting / Timelock Release](#policy-vesting-timelock-release) — `Operations`
33. [Oracle Price Feed Validity](#policy-oracle-price-validity) — `Risk`
34. [Emergency Kill-Switch](#policy-emergency-kill-switch) — `Operations`
35. [Regulatory Reporting Trigger](#policy-regulatory-reporting-trigger) — `Compliance`
36. [Pre-Trade Risk Check](#policy-pre-trade-risk-check) — `Trading`
37. [Crypto Lending Origination](#policy-lending-origination) — `Risk`
38. [NFT Transfer & Royalty Enforcement](#policy-nft-royalty-transfer) — `Tokens`
39. [Insider Trading Blackout](#policy-insider-trading-blackout) — `Compliance`
40. [Fund Subscription / Redemption Gate](#policy-fund-subscription-redemption) — `Institutional`
41. [RBAC Matrix (AND of ORs)](#policy-rbac-matrix) — `Approvals`
42. [Smart-Contract Upgrade Governance](#policy-smart-contract-upgrade) — `DeFi`
43. [Fee Rate Check](#policy-fee-rate-check) — `Trading`
44. [Batch Transaction Limits](#policy-batch-tx-limits) — `Operations`
45. [Daily Volume Cap](#policy-daily-volume-cap) — `Risk`
46. [Multi-Sig Quorum (Live)](#policy-multi-sig-quorum-live) — `Approvals`
47. [Vesting Unlock (Live Clock)](#policy-vesting-unlock-live) — `Operations`
48. [Business Hours Trading Gate](#policy-business-hours-trading) — `Trading`
49. [Asset Symbol (Case-Insensitive)](#policy-asset-symbol-normalized) — `Compliance`
50. [IP Allowlist (CIDR)](#policy-ip-allowlist-access) — `Generic`
51. [Input Type Guard](#policy-input-type-guard) — `Generic`
52. [Partial Set: Risk Violations](#policy-partial-risk-violations) — `Compliance`
53. [Object.get: Safe Config Access](#policy-object-safe-config) — `Generic`
54. [Set Intersection: Permission Check](#policy-set-permission-check) — `Generic`
55. [JWT Claims Verification](#policy-jwt-claims-verify) — `Generic`
56. [Partial Set: Batch Validation](#policy-partial-batch-validation) — `Operations`

### SaaS Multi-Tenancy — `saasMultitenant.js` (10)

57. [Tenant Resource Isolation](#policy-mt-tenant-isolation) — `Multitenancy`
58. [Tenant Provisioning & Lifecycle](#policy-mt-tenant-provisioning) — `Multitenancy`
59. [Organization Member Access](#policy-mt-org-member-access) — `Multitenancy`
60. [Domain-Scoped Resource Access](#policy-mt-domain-resource-gate) — `Multitenancy`
61. [Group Permission Enforcement](#policy-mt-group-permission-check) — `Multitenancy`
62. [Role Assignment Guard](#policy-mt-role-assignment-guard) — `Multitenancy`
63. [User Lifecycle Management](#policy-mt-user-lifecycle) — `Multitenancy`
64. [Cross-Org Resource Sharing](#policy-mt-cross-org-sharing) — `Multitenancy`
65. [Multitenant Access Violation Collector](#policy-mt-access-violations) — `Multitenancy`
66. [Platform Admin Break-Glass Access](#policy-mt-platform-admin-access) — `Multitenancy`

### Trusted Auth (crypto) — `trustedAuth.js` (4)

67. [Trusted JWT Gate](#policy-trusted-jwt-gate) — `AuthN`
68. [Multi-Tenant JWT (dynamic kid)](#policy-trusted-jwt-multitenant) — `AuthN`
69. [Webhook HMAC Signature](#policy-trusted-webhook-hmac) — `AuthN`
70. [Trusted JWT + Tier Amount Cap](#policy-trusted-jwt-with-amount-cap) — `AuthN`


---

## Custody Hierarchy

Source: [`backend/src/templates/custodyHierarchy.js`](../backend/src/templates/custodyHierarchy.js) · 11 policies.

A full institutional digital-asset custody stack — legal entity → business unit → portfolio → vault → wallet — plus the withdrawal and break-glass flows layered on top. Every level is a synchronous create/authorize gate, and the withdrawal path is split into request-validity, approval-quorum, and execute stages.

<a id="policy-custody-onboarding-request"></a>

### 1. Custody Onboarding Request Validity

`Custody` &nbsp;·&nbsp; package `custody.onboarding.request_validity` &nbsp;·&nbsp; id `custody-onboarding-request`

Validates a custody-onboarding request bundle covering the full hierarchy (legal entity, business unit, portfolio, vault, wallet). Requires a platform admin with MFA, an approved jurisdiction, sane quorum bounds, and a whitelist of at most 100 addresses.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Platform admin (MFA) submits a fully populated, in-bounds onboarding request

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Custody operator"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.custody.onboarding.request_validity"}}
    pdp -->|"Platform admin (MFA) submits a fully populated, in-bounds onboarding request"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Custody Onboarding Request Validity — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package custody.onboarding.request_validity

import rego.v1

# Validates a custody-onboarding request bundle covering the full hierarchy (legal entity, business unit, portfolio, vault, wallet). Requires a platform admin with MFA, an approved jurisdiction, sane quorum bounds, and a whitelist of at most 100 addresses.

default allow := false

# Platform admin (MFA) submits a fully populated, in-bounds onboarding request
allow if {
    input.actor.platform_role == "platform_admin"
    input.actor.mfa_verified == true
    input.request.legal_entity.name
    input.request.legal_entity.jurisdiction in ["US-DE", "US-NY", "UK", "SG", "CH", "AE"]
    input.request.business_unit.name
    input.request.portfolio.name
    input.request.vault.name
    input.request.wallet.chain
    input.request.quorum_m >= 1
    input.request.quorum_m <= 7
    count(input.request.vault.whitelist) <= 100
}
```

Sample sandbox input:

```json
{
  "actor": {
    "id": "u-1",
    "platform_role": "platform_admin",
    "mfa_verified": true
  },
  "request": {
    "legal_entity": {
      "name": "Aristo Capital LLC",
      "jurisdiction": "US-DE"
    },
    "business_unit": {
      "name": "Prop Desk",
      "kind": "prop_trading"
    },
    "portfolio": {
      "name": "Flagship Fund",
      "beneficial_owner": "ACME LP",
      "kind": "fund"
    },
    "vault": {
      "name": "Cold Vault A",
      "quorum_m": 2,
      "quorum_n": 3,
      "daily_limit_usd": 1000000,
      "whitelist": [
        "0xfeedfacefeedfacefeedfacefeedfacefeedface"
      ]
    },
    "wallet": {
      "chain": "ethereum",
      "address": "0xfeedfacefeedfacefeedfacefeedfacefeedface"
    },
    "quorum_m": 2
  }
}
```

</details>

---
<a id="policy-custody-onboarding-quorum"></a>

### 2. Custody Onboarding Approval Quorum

`Custody` &nbsp;·&nbsp; package `custody.onboarding.approval_quorum` &nbsp;·&nbsp; id `custody-onboarding-quorum`

Verifies the approval quorum for an onboarding request. Accumulates violations into a partial set: insufficient approvals, missing MFA on an approver, wrong approver role, duplicate approver, or an explicit reject. The allow rule fires only when no violations are present.

**Decision logic**

- **`violations`** — *partial set* (violation/reason collector). A member is added when:
  - input.request.quorum_m is missing or not a number
  - input.request.approvals is missing or not an array
  - input.request.requester_user_id is missing or not a string
  - input.request.prior_level_approvers is missing or not an array
  - Number of NON-SELF approve decisions is less than the required quorum_m (self-votes are silently excluded — separation of duties)
  - At least one approver did not complete MFA
  - At least one approver does not hold the onboarding_approver role
  - Same approver appears more than once in the approve set
  - At least one approver explicitly rejected the request
  - Approver also signed at a prior cascade level (separation of duties)
- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - No quorum violations — request meets the approval bar
- **`result`** — *result object* emitting `{ allow, rejection_reasons }` — Decision document — bundles the verdict and the rejection-reason set for the caller's audit log.

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Custody operator"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.custody.onboarding.approval_quorum"}}
    pdp -->|"No quorum violations — request meets the approval bar"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
    ok --> doc[/"result = { allow, rejection_reasons }"/]
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Violations: one or more checks fail
    Evaluating --> Clean: violations = {}
    Clean --> Allowed: allow = true
    Violations --> Denied: reasons returned to caller
    Allowed --> Applied: Custody Onboarding Approval Quorum — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> Recorded: result document written to caller audit log
    Applied --> [*]
    Rejected --> [*]
    Recorded --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package custody.onboarding.approval_quorum

import rego.v1

# Verifies the approval quorum for an onboarding request. Accumulates violations into a partial set: insufficient approvals, missing MFA on an approver, wrong approver role, duplicate approver, or an explicit reject. The allow rule fires only when no violations are present.

# input.request.quorum_m is missing or not a number
violations contains "malformed_request" if {
    not is_number(object.get(object.get(input, "request", {}), "quorum_m", null))
}

# input.request.approvals is missing or not an array
violations contains "malformed_request" if {
    not is_array(object.get(object.get(input, "request", {}), "approvals", null))
}

# input.request.requester_user_id is missing or not a string
violations contains "malformed_request" if {
    not is_string(object.get(object.get(input, "request", {}), "requester_user_id", null))
}

# input.request.prior_level_approvers is missing or not an array
violations contains "malformed_request" if {
    not is_array(object.get(object.get(input, "request", {}), "prior_level_approvers", null))
}

# Number of NON-SELF approve decisions is less than the required quorum_m (self-votes are silently excluded — separation of duties)
violations contains "quorum_below_threshold" if {
    count([item | some item in input.request.approvals; item.decision == "approve"; item.approver_user_id != input.request.requester_user_id]) < input.request.quorum_m
}

# At least one approver did not complete MFA
violations contains "approver_missing_mfa" if {
    count([item | some item in input.request.approvals; item.decision == "approve"; item.approver_mfa != true]) > 0
}

# At least one approver does not hold the onboarding_approver role
violations contains "approver_wrong_role" if {
    count([item | some item in input.request.approvals; item.decision == "approve"; item.approver_role != "onboarding_approver"]) > 0
}

# Same approver appears more than once in the approve set
violations contains "duplicate_approver" if {
    approve_ids := {a.approver_user_id | some a in input.request.approvals; a.decision == "approve"}
    approve_rows := [a | some a in input.request.approvals; a.decision == "approve"]
    count(approve_ids) != count(approve_rows)
}

# At least one approver explicitly rejected the request
violations contains "explicit_reject_present" if {
    count([item | some item in input.request.approvals; item.decision == "reject"]) > 0
}

# Approver also signed at a prior cascade level (separation of duties)
violations contains "cross_level_approval" if {
    some prior in input.request.prior_level_approvers
    some current in input.request.approvals
    current.decision == "approve"
    current.approver_user_id == prior
}

default allow := false

# No quorum violations — request meets the approval bar
allow if {
    count(violations) == 0
}

# Decision document — bundles the verdict and the rejection-reason set for the caller's audit log.
result := {
    "allow": allow,
    "rejection_reasons": violations
}
```

Sample sandbox input:

```json
{
  "request": {
    "quorum_m": 2,
    "requester_user_id": "u-1",
    "prior_level_approvers": [],
    "approvals": [
      {
        "approver_user_id": "u-2",
        "approver_role": "onboarding_approver",
        "approver_mfa": true,
        "decision": "approve"
      },
      {
        "approver_user_id": "u-3",
        "approver_role": "onboarding_approver",
        "approver_mfa": true,
        "decision": "approve"
      }
    ]
  }
}
```

</details>

---
<a id="policy-custody-legal-entity-create"></a>

### 3. Custody Legal Entity Create

`Custody` &nbsp;·&nbsp; package `custody.legal_entity.create` &nbsp;·&nbsp; id `custody-legal-entity-create`

Gates creation of a Legal Entity (top of the custody hierarchy). Requires a platform admin with MFA, an approved request status, an allowed jurisdiction, and a non-empty entity name.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Platform admin (MFA) creates an approved legal entity in an allowed jurisdiction

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Custody operator"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.custody.legal_entity.create"}}
    pdp -->|"Platform admin (MFA) creates an approved legal entity in an allowed jurisdiction"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Custody Legal Entity Create — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package custody.legal_entity.create

import rego.v1

# Gates creation of a Legal Entity (top of the custody hierarchy). Requires a platform admin with MFA, an approved request status, an allowed jurisdiction, and a non-empty entity name.

default allow := false

# Platform admin (MFA) creates an approved legal entity in an allowed jurisdiction
allow if {
    input.actor.platform_role == "platform_admin"
    input.actor.mfa_verified == true
    input.request.status == "approved"
    input.request.legal_entity.jurisdiction in ["US-DE", "US-NY", "UK", "SG", "CH", "AE"]
    input.request.legal_entity.name
}
```

Sample sandbox input:

```json
{
  "actor": {
    "id": "u-1",
    "platform_role": "platform_admin",
    "mfa_verified": true
  },
  "request": {
    "status": "approved",
    "legal_entity": {
      "name": "Aristo Capital LLC",
      "jurisdiction": "US-DE"
    }
  }
}
```

</details>

---
<a id="policy-custody-business-unit-create"></a>

### 4. Custody Business Unit Create

`Custody` &nbsp;·&nbsp; package `custody.business_unit.create` &nbsp;·&nbsp; id `custody-business-unit-create`

Gates creation of a Business Unit under an active Legal Entity. Requires an org admin at the legal entity level, an allowed business-unit kind, and a non-empty name.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Legal-entity org admin creates a typed BU under an active legal entity

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Custody operator"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.custody.business_unit.create"}}
    pdp -->|"Legal-entity org admin creates a typed BU under an active legal entity"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Custody Business Unit Create — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package custody.business_unit.create

import rego.v1

# Gates creation of a Business Unit under an active Legal Entity. Requires an org admin at the legal entity level, an allowed business-unit kind, and a non-empty name.

default allow := false

# Legal-entity org admin creates a typed BU under an active legal entity
allow if {
    input.actor.legal_entity_role == "org_admin"
    input.legal_entity.active == true
    input.business_unit.kind in ["retail", "institutional", "prop_trading", "ops"]
    input.business_unit.name
}
```

Sample sandbox input:

```json
{
  "actor": {
    "id": "u-1",
    "legal_entity_role": "org_admin"
  },
  "legal_entity": {
    "id": "le-1",
    "active": true
  },
  "business_unit": {
    "name": "Prop Desk",
    "kind": "prop_trading"
  }
}
```

</details>

---
<a id="policy-custody-portfolio-create"></a>

### 5. Custody Portfolio Create

`Custody` &nbsp;·&nbsp; package `custody.portfolio.create` &nbsp;·&nbsp; id `custody-portfolio-create`

Gates creation of a Portfolio under an active Business Unit. Requires a BU admin, an allowed portfolio kind, a named beneficial owner, and a non-empty portfolio name.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - BU admin creates a typed portfolio with a beneficial owner under an active BU

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Custody operator"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.custody.portfolio.create"}}
    pdp -->|"BU admin creates a typed portfolio with a beneficial owner under an active BU"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Custody Portfolio Create — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package custody.portfolio.create

import rego.v1

# Gates creation of a Portfolio under an active Business Unit. Requires a BU admin, an allowed portfolio kind, a named beneficial owner, and a non-empty portfolio name.

default allow := false

# BU admin creates a typed portfolio with a beneficial owner under an active BU
allow if {
    input.actor.business_unit_role == "bu_admin"
    input.business_unit.active == true
    input.portfolio.kind in ["fund", "client_account", "internal"]
    input.portfolio.beneficial_owner
    input.portfolio.name
}
```

Sample sandbox input:

```json
{
  "actor": {
    "id": "u-1",
    "business_unit_role": "bu_admin"
  },
  "business_unit": {
    "id": "bu-1",
    "active": true
  },
  "portfolio": {
    "name": "Flagship Fund",
    "kind": "fund",
    "beneficial_owner": "ACME LP"
  }
}
```

</details>

---
<a id="policy-custody-vault-create"></a>

### 6. Custody Vault Create

`Custody` &nbsp;·&nbsp; package `custody.vault.create` &nbsp;·&nbsp; id `custody-vault-create`

Gates creation of a Vault under a Portfolio. Requires a portfolio admin with MFA, a valid m-of-n quorum (m ≤ n, n in [2,7]), a daily-limit cap of $10M, and at least one whitelisted address.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Portfolio admin (MFA) creates a bounded m-of-n vault with at least one whitelisted address

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Custody operator"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.custody.vault.create"}}
    pdp -->|"Portfolio admin (MFA) creates a bounded m-of-n vault with at least one whitelisted address"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Custody Vault Create — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package custody.vault.create

import rego.v1

# Gates creation of a Vault under a Portfolio. Requires a portfolio admin with MFA, a valid m-of-n quorum (m ≤ n, n in [2,7]), a daily-limit cap of $10M, and at least one whitelisted address.

default allow := false

# Portfolio admin (MFA) creates a bounded m-of-n vault with at least one whitelisted address
allow if {
    input.actor.portfolio_role == "portfolio_admin"
    input.actor.mfa_verified == true
    input.vault.quorum_m >= 1
    input.vault.quorum_n >= 2
    input.vault.quorum_n <= 7
    input.vault.quorum_m <= input.vault.quorum_n
    input.vault.daily_limit_usd <= 10000000
    count(input.vault.whitelist) >= 1
}
```

Sample sandbox input:

```json
{
  "actor": {
    "id": "u-1",
    "portfolio_role": "portfolio_admin",
    "mfa_verified": true
  },
  "vault": {
    "name": "Cold Vault A",
    "quorum_m": 2,
    "quorum_n": 3,
    "daily_limit_usd": 1000000,
    "whitelist": [
      "0xfeedfacefeedfacefeedfacefeedfacefeedface"
    ]
  }
}
```

</details>

---
<a id="policy-custody-wallet-create"></a>

### 7. Custody Wallet Create

`Custody` &nbsp;·&nbsp; package `custody.wallet.create` &nbsp;·&nbsp; id `custody-wallet-create`

Gates creation of a Wallet under a Vault. Requires a vault admin, an allowed chain, and a chain-specific address format. Address validation is delegated to a chain_addr_valid helper rule that has one branch per supported chain.

**Decision logic**

- **`chain_addr_valid`** — boolean, default `false` — True when the wallet's address matches the regex for its declared chain. Evaluates **true** if any of:
  - Ethereum — 0x-prefixed 40-hex-character address
  - Bitcoin — bech32 (bc1...) or legacy base58check (1.../3...) address
  - Solana — base58 string of 32–44 characters
  - Polygon — 0x-prefixed 40-hex-character address (EVM-compatible)
- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Vault admin creates a wallet on a supported chain with a well-formed address

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Custody operator"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.custody.wallet.create"}}
    pdp -->|"Vault admin creates a wallet on a supported chain with a well-formed address"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Custody Wallet Create — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package custody.wallet.create

import rego.v1

# Gates creation of a Wallet under a Vault. Requires a vault admin, an allowed chain, and a chain-specific address format. Address validation is delegated to a chain_addr_valid helper rule that has one branch per supported chain.

# True when the wallet's address matches the regex for its declared chain
default chain_addr_valid := false

# Ethereum — 0x-prefixed 40-hex-character address
chain_addr_valid if {
    input.wallet.chain == "ethereum"
    regex.match(`^0x[a-fA-F0-9]{40}$`, input.wallet.address)
}

# Bitcoin — bech32 (bc1...) or legacy base58check (1.../3...) address
chain_addr_valid if {
    input.wallet.chain == "bitcoin"
    regex.match(`^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$`, input.wallet.address)
}

# Solana — base58 string of 32–44 characters
chain_addr_valid if {
    input.wallet.chain == "solana"
    regex.match(`^[1-9A-HJ-NP-Za-km-z]{32,44}$`, input.wallet.address)
}

# Polygon — 0x-prefixed 40-hex-character address (EVM-compatible)
chain_addr_valid if {
    input.wallet.chain == "polygon"
    regex.match(`^0x[a-fA-F0-9]{40}$`, input.wallet.address)
}

default allow := false

# Vault admin creates a wallet on a supported chain with a well-formed address
allow if {
    input.actor.vault_role == "vault_admin"
    input.wallet.chain in ["ethereum", "bitcoin", "solana", "polygon"]
    chain_addr_valid == true
}
```

Sample sandbox input:

```json
{
  "actor": {
    "id": "u-1",
    "vault_role": "vault_admin"
  },
  "wallet": {
    "chain": "ethereum",
    "address": "0xfeedfacefeedfacefeedfacefeedfacefeedface"
  }
}
```

</details>

---
<a id="policy-custody-withdrawal-request"></a>

### 8. Custody Withdrawal — Request Validity

`Custody` &nbsp;·&nbsp; package `custody.withdrawal.request_validity` &nbsp;·&nbsp; id `custody-withdrawal-request`

Synchronous gate for a wallet → external-address transfer. Enforces vault admin + MFA, whitelist, daily limit, 60s timelock, chain-format regex, and non-zero amount. Partial-set violations with companion allow.

**Decision logic**

- **`chain_addr_valid`** — boolean, default `false` — True when the destination address matches the regex for its declared chain. Evaluates **true** if any of:
  - Ethereum — 0x-prefixed 40-hex-character address
  - Bitcoin — bech32 (bc1...) or legacy base58check (1.../3...) address
  - Solana — base58 string of 32–44 characters
  - Polygon — 0x-prefixed 40-hex-character address (EVM-compatible)
- **`violations`** — *partial set* (violation/reason collector). A member is added when:
  - input.actor.vault_role is missing or not a string
  - input.actor.mfa_verified is missing or not a boolean
  - input.request.amount is missing or not a number
  - input.request.destination_address is missing or not a string
  - input.request.chain is missing or not a string
  - input.vault.daily_limit_usd is missing or not a number
  - input.vault.whitelist_addresses is missing or not an array
  - input.vault.last_withdrawal_at_ns is missing or not a number
  - Actor is not a vault admin
  - Actor did not complete MFA
  - Amount is zero or negative
  - Requested amount exceeds the vault's daily limit
  - Destination address is not in the vault's whitelist
  - Less than 60 seconds since the vault's last withdrawal
  - Destination address does not match its declared chain format
- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - No validity violations — withdrawal request is well-formed and within bounds
- **`result`** — *result object* emitting `{ allow, rejection_reasons }` — Decision document — bundles the boolean verdict, the rejection-reason set, and the originating request id for logging/audit.

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Custody operator"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.custody.withdrawal.request_validity"}}
    pdp -->|"No validity violations — withdrawal request is well-formed and within bounds"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
    ok --> doc[/"result = { allow, rejection_reasons }"/]
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Violations: one or more checks fail
    Evaluating --> Clean: violations = {}
    Clean --> Allowed: allow = true
    Violations --> Denied: reasons returned to caller
    Allowed --> Applied: Custody Withdrawal — Request Validity — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> Recorded: result document written to caller audit log
    Applied --> [*]
    Rejected --> [*]
    Recorded --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package custody.withdrawal.request_validity

import rego.v1

# Synchronous gate for a wallet → external-address transfer. Enforces vault admin + MFA, whitelist, daily limit, 60s timelock, chain-format regex, and non-zero amount. Partial-set violations with companion allow.

# True when the destination address matches the regex for its declared chain
default chain_addr_valid := false

# Ethereum — 0x-prefixed 40-hex-character address
chain_addr_valid if {
    input.request.chain == "ethereum"
    regex.match(`^0x[a-fA-F0-9]{40}$`, input.request.destination_address)
}

# Bitcoin — bech32 (bc1...) or legacy base58check (1.../3...) address
chain_addr_valid if {
    input.request.chain == "bitcoin"
    regex.match(`^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$`, input.request.destination_address)
}

# Solana — base58 string of 32–44 characters
chain_addr_valid if {
    input.request.chain == "solana"
    regex.match(`^[1-9A-HJ-NP-Za-km-z]{32,44}$`, input.request.destination_address)
}

# Polygon — 0x-prefixed 40-hex-character address (EVM-compatible)
chain_addr_valid if {
    input.request.chain == "polygon"
    regex.match(`^0x[a-fA-F0-9]{40}$`, input.request.destination_address)
}

# input.actor.vault_role is missing or not a string
violations contains "malformed_request" if {
    not is_string(object.get(object.get(input, "actor", {}), "vault_role", null))
}

# input.actor.mfa_verified is missing or not a boolean
violations contains "malformed_request" if {
    not is_boolean(object.get(object.get(input, "actor", {}), "mfa_verified", null))
}

# input.request.amount is missing or not a number
violations contains "malformed_request" if {
    not is_number(object.get(object.get(input, "request", {}), "amount", null))
}

# input.request.destination_address is missing or not a string
violations contains "malformed_request" if {
    not is_string(object.get(object.get(input, "request", {}), "destination_address", null))
}

# input.request.chain is missing or not a string
violations contains "malformed_request" if {
    not is_string(object.get(object.get(input, "request", {}), "chain", null))
}

# input.vault.daily_limit_usd is missing or not a number
violations contains "malformed_request" if {
    not is_number(object.get(object.get(input, "vault", {}), "daily_limit_usd", null))
}

# input.vault.whitelist_addresses is missing or not an array
violations contains "malformed_request" if {
    not is_array(object.get(object.get(input, "vault", {}), "whitelist_addresses", null))
}

# input.vault.last_withdrawal_at_ns is missing or not a number
violations contains "malformed_request" if {
    not is_number(object.get(object.get(input, "vault", {}), "last_withdrawal_at_ns", null))
}

# Actor is not a vault admin
violations contains "not_vault_admin" if {
    input.actor.vault_role != "vault_admin"
}

# Actor did not complete MFA
violations contains "missing_mfa" if {
    input.actor.mfa_verified != true
}

# Amount is zero or negative
violations contains "amount_invalid" if {
    input.request.amount <= 0
}

# Requested amount exceeds the vault's daily limit
violations contains "amount_exceeds_limit" if {
    input.request.amount > input.vault.daily_limit_usd
}

# Destination address is not in the vault's whitelist
violations contains "address_not_whitelisted" if {
    not input.request.destination_address in input.vault.whitelist_addresses
}

# Less than 60 seconds since the vault's last withdrawal
violations contains "timelock_violation" if {
    time.now_ns() - input.vault.last_withdrawal_at_ns < 60000000000
}

# Destination address does not match its declared chain format
violations contains "invalid_chain_format" if {
    chain_addr_valid != true
}

default allow := false

# No validity violations — withdrawal request is well-formed and within bounds
allow if {
    count(violations) == 0
}

# Decision document — bundles the boolean verdict, the rejection-reason set, and the originating request id for logging/audit.
result := {
    "allow": allow,
    "rejection_reasons": violations
}
```

Sample sandbox input:

```json
{
  "actor": {
    "user_id": "u-1",
    "vault_role": "vault_admin",
    "mfa_verified": true
  },
  "request": {
    "id": "req-w-001",
    "amount": 500000,
    "destination_address": "0xfeedfacefeedfacefeedfacefeedfacefeedface",
    "chain": "ethereum"
  },
  "vault": {
    "daily_limit_usd": 1000000,
    "whitelist_addresses": [
      "0xfeedfacefeedfacefeedfacefeedfacefeedface"
    ],
    "last_withdrawal_at_ns": 0
  }
}
```

</details>

---
<a id="policy-custody-withdrawal-quorum"></a>

### 9. Custody Withdrawal — Approval Quorum

`Custody` &nbsp;·&nbsp; package `custody.withdrawal.approval_quorum` &nbsp;·&nbsp; id `custody-withdrawal-quorum`

Verifies the approval quorum for a withdrawal request. Mirrors the onboarding quorum but requires the `withdrawal_approver` role and blocks self-approval. Allow rule fires only when no violations are present.

**Decision logic**

- **`violations`** — *partial set* (violation/reason collector). A member is added when:
  - input.request.quorum_m is missing or not a number
  - input.request.approvals is missing or not an array
  - input.request.requester_user_id is missing or not a string
  - Number of NON-SELF approve decisions is less than the required quorum_m (self-votes are silently excluded — separation of duties)
  - At least one approver did not complete MFA
  - At least one approver does not hold the withdrawal_approver role
  - Same approver appears more than once in the approve set
  - At least one approver explicitly rejected the request
- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - No quorum violations — withdrawal meets the approval bar
- **`result`** — *result object* emitting `{ allow, rejection_reasons }` — Decision document — bundles the verdict and the rejection-reason set for the caller's audit log.

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Custody operator"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.custody.withdrawal.approval_quorum"}}
    pdp -->|"No quorum violations — withdrawal meets the approval bar"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
    ok --> doc[/"result = { allow, rejection_reasons }"/]
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Violations: one or more checks fail
    Evaluating --> Clean: violations = {}
    Clean --> Allowed: allow = true
    Violations --> Denied: reasons returned to caller
    Allowed --> Applied: Custody Withdrawal — Approval Quorum — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> Recorded: result document written to caller audit log
    Applied --> [*]
    Rejected --> [*]
    Recorded --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package custody.withdrawal.approval_quorum

import rego.v1

# Verifies the approval quorum for a withdrawal request. Mirrors the onboarding quorum but requires the `withdrawal_approver` role and blocks self-approval. Allow rule fires only when no violations are present.

# input.request.quorum_m is missing or not a number
violations contains "malformed_request" if {
    not is_number(object.get(object.get(input, "request", {}), "quorum_m", null))
}

# input.request.approvals is missing or not an array
violations contains "malformed_request" if {
    not is_array(object.get(object.get(input, "request", {}), "approvals", null))
}

# input.request.requester_user_id is missing or not a string
violations contains "malformed_request" if {
    not is_string(object.get(object.get(input, "request", {}), "requester_user_id", null))
}

# Number of NON-SELF approve decisions is less than the required quorum_m (self-votes are silently excluded — separation of duties)
violations contains "quorum_below_threshold" if {
    count([item | some item in input.request.approvals; item.decision == "approve"; item.approver_user_id != input.request.requester_user_id]) < input.request.quorum_m
}

# At least one approver did not complete MFA
violations contains "approver_missing_mfa" if {
    count([item | some item in input.request.approvals; item.decision == "approve"; item.approver_mfa != true]) > 0
}

# At least one approver does not hold the withdrawal_approver role
violations contains "approver_wrong_role" if {
    count([item | some item in input.request.approvals; item.decision == "approve"; item.approver_role != "withdrawal_approver"]) > 0
}

# Same approver appears more than once in the approve set
violations contains "duplicate_approver" if {
    approve_ids := {a.approver_user_id | some a in input.request.approvals; a.decision == "approve"}
    approve_rows := [a | some a in input.request.approvals; a.decision == "approve"]
    count(approve_ids) != count(approve_rows)
}

# At least one approver explicitly rejected the request
violations contains "explicit_reject_present" if {
    count([item | some item in input.request.approvals; item.decision == "reject"]) > 0
}

default allow := false

# No quorum violations — withdrawal meets the approval bar
allow if {
    count(violations) == 0
}

# Decision document — bundles the verdict and the rejection-reason set for the caller's audit log.
result := {
    "allow": allow,
    "rejection_reasons": violations
}
```

Sample sandbox input:

```json
{
  "request": {
    "quorum_m": 2,
    "requester_user_id": "u-1",
    "approvals": [
      {
        "approver_user_id": "u-2",
        "approver_role": "withdrawal_approver",
        "approver_mfa": true,
        "decision": "approve"
      },
      {
        "approver_user_id": "u-3",
        "approver_role": "withdrawal_approver",
        "approver_mfa": true,
        "decision": "approve"
      }
    ]
  }
}
```

</details>

---
<a id="policy-custody-withdrawal-execute"></a>

### 10. Custody Withdrawal — Execute

`Custody` &nbsp;·&nbsp; package `custody.withdrawal.execute` &nbsp;·&nbsp; id `custody-withdrawal-execute`

Final pre-execution gate for a withdrawal. Requires the request to be in 'approved' status, the amount to match what was approved, and the wallet to not be frozen.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Approved request with unchanged amount executes against a non-frozen wallet

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Custody operator"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.custody.withdrawal.execute"}}
    pdp -->|"Approved request with unchanged amount executes against a non-frozen wallet"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Custody Withdrawal — Execute — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package custody.withdrawal.execute

import rego.v1

# Final pre-execution gate for a withdrawal. Requires the request to be in 'approved' status, the amount to match what was approved, and the wallet to not be frozen.

default allow := false

# Approved request with unchanged amount executes against a non-frozen wallet
allow if {
    input.request.status == "approved"
    input.request.amount == input.request.approved_amount
    input.wallet.frozen == false
}
```

Sample sandbox input:

```json
{
  "request": {
    "status": "approved",
    "amount": 500000,
    "approved_amount": 500000
  },
  "wallet": {
    "frozen": false
  }
}
```

</details>

---
<a id="policy-custody-emergency-override"></a>

### 11. Custody Emergency Override (Break-Glass)

`Custody` &nbsp;·&nbsp; package `custody.emergency.override` &nbsp;·&nbsp; id `custody-emergency-override`

Synchronous gate for a time-bound emergency override. Requires a platform admin with MFA, a substantive justification (≥ 20 chars), an allowed scope, a duration cap of 10 minutes, and either business hours or a co-signer. Partial-set violations with companion allow.

**Decision logic**

- **`violations`** — *partial set* (violation/reason collector). A member is added when:
  - input.actor.platform_role is missing or not a string
  - input.actor.mfa_verified is missing or not a boolean
  - input.request.reason is missing or not a string
  - input.request.scope is missing or not a string
  - input.request.duration_seconds is missing or not a number
  - input.request.business_hours is missing or not a boolean
  - input.request.cosigner_approvals is missing or not an array
  - Actor is not a platform admin
  - Actor did not complete MFA
  - Justification reason is shorter than 20 characters
  - Override scope is not in the allowed set
  - Override duration exceeds the 10-minute cap
  - Override invoked after business hours without a co-signer approval
- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - No override violations — emergency grant may be issued
- **`result`** — *result object* emitting `{ allow, rejection_reasons }` — Decision document — bundles the verdict and the rejection-reason set for the caller's audit log.

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Custody operator"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.custody.emergency.override"}}
    pdp -->|"No override violations — emergency grant may be issued"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
    ok --> doc[/"result = { allow, rejection_reasons }"/]
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Violations: one or more checks fail
    Evaluating --> Clean: violations = {}
    Clean --> Allowed: allow = true
    Violations --> Denied: reasons returned to caller
    Allowed --> Applied: Custody Emergency Override — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> Recorded: result document written to caller audit log
    Applied --> [*]
    Rejected --> [*]
    Recorded --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package custody.emergency.override

import rego.v1

# Synchronous gate for a time-bound emergency override. Requires a platform admin with MFA, a substantive justification (≥ 20 chars), an allowed scope, a duration cap of 10 minutes, and either business hours or a co-signer. Partial-set violations with companion allow.

# input.actor.platform_role is missing or not a string
violations contains "malformed_request" if {
    not is_string(object.get(object.get(input, "actor", {}), "platform_role", null))
}

# input.actor.mfa_verified is missing or not a boolean
violations contains "malformed_request" if {
    not is_boolean(object.get(object.get(input, "actor", {}), "mfa_verified", null))
}

# input.request.reason is missing or not a string
violations contains "malformed_request" if {
    not is_string(object.get(object.get(input, "request", {}), "reason", null))
}

# input.request.scope is missing or not a string
violations contains "malformed_request" if {
    not is_string(object.get(object.get(input, "request", {}), "scope", null))
}

# input.request.duration_seconds is missing or not a number
violations contains "malformed_request" if {
    not is_number(object.get(object.get(input, "request", {}), "duration_seconds", null))
}

# input.request.business_hours is missing or not a boolean
violations contains "malformed_request" if {
    not is_boolean(object.get(object.get(input, "request", {}), "business_hours", null))
}

# input.request.cosigner_approvals is missing or not an array
violations contains "malformed_request" if {
    not is_array(object.get(object.get(input, "request", {}), "cosigner_approvals", null))
}

# Actor is not a platform admin
violations contains "not_platform_admin" if {
    input.actor.platform_role != "platform_admin"
}

# Actor did not complete MFA
violations contains "missing_mfa" if {
    input.actor.mfa_verified != true
}

# Justification reason is shorter than 20 characters
violations contains "reason_too_short" if {
    count(input.request.reason) < 20
}

# Override scope is not in the allowed set
violations contains "invalid_scope" if {
    not input.request.scope in ["vault_unfreeze", "limit_override", "whitelist_emergency_add"]
}

# Override duration exceeds the 10-minute cap
violations contains "duration_too_long" if {
    input.request.duration_seconds > 600
}

# Override invoked after business hours without a co-signer approval
violations contains "after_hours_no_cosigner" if {
    input.request.business_hours == false
    count(input.request.cosigner_approvals) < 1
}

default allow := false

# No override violations — emergency grant may be issued
allow if {
    count(violations) == 0
}

# Decision document — bundles the verdict and the rejection-reason set for the caller's audit log.
result := {
    "allow": allow,
    "rejection_reasons": violations
}
```

Sample sandbox input:

```json
{
  "actor": {
    "user_id": "u-1",
    "platform_role": "platform_admin",
    "mfa_verified": true
  },
  "request": {
    "reason": "vault stuck on x — need to unfreeze for ops",
    "scope": "vault_unfreeze",
    "duration_seconds": 300,
    "business_hours": true,
    "cosigner_approvals": []
  }
}
```

</details>

---

---

## Digital Assets

Source: [`backend/src/templates/digitalAssets.js`](../backend/src/templates/digitalAssets.js) · 45 policies.

The broad library: KYC/AML, transaction limits, sanctions, stablecoin mint/redeem, DeFi access, treasury, trading, tokens, risk, and a set of "language feature" demos (arithmetic, aggregates, `every`, partial sets, `object.get`, set intersection, JWT decode).

<a id="policy-kyc-aml-baseline"></a>

### 12. KYC / AML Baseline

`Compliance` &nbsp;·&nbsp; package `digital_assets.kyc_aml` &nbsp;·&nbsp; id `kyc-aml-baseline`

Block any transaction unless the user has completed KYC, is not on a sanctions list, and is below their per-user risk-score threshold.

**Decision logic**

- **`allow`** — boolean, default `false` — User must clear KYC, sanctions, and risk gates. Evaluates **true** if any of:
  - All gates pass simultaneously
- **`deny_reasons`** — object — Set of failed gates for explainability.

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Transacting user"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.kyc_aml"}}
    pdp -->|"All gates pass simultaneously"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: KYC / AML Baseline — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.kyc_aml

import rego.v1

# Block any transaction unless the user has completed KYC, is not on a sanctions list, and is below their per-user risk-score threshold.

# User must clear KYC, sanctions, and risk gates
default allow := false

# All gates pass simultaneously
allow if {
    input.user.kyc_status == "verified"
    input.user.sanctioned == false
    input.user.risk_score <= 70
}

# Set of failed gates for explainability
default deny_reasons := {}
```

Sample sandbox input:

```json
{
  "user": {
    "kyc_status": "verified",
    "sanctioned": false,
    "risk_score": 25
  }
}
```

</details>

---
<a id="policy-tx-limits-tiered"></a>

### 13. Tiered Transaction Limits

`TradFi` &nbsp;·&nbsp; package `digital_assets.tx_limits` &nbsp;·&nbsp; id `tx-limits-tiered`

Per-tier daily transaction caps. Retail < $10k, Pro < $250k, Institutional unlimited. Off-hours apply tighter caps.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Retail tier under $10k
  - Pro tier under $250k
  - Institutional tier — no cap, but must have approval

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Trader / payer"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.tx_limits"}}
    pdp -->|"Retail tier under $10k"| ok(["✅ allow = true → proceed"])
    pdp -->|"Pro tier under $250k"| ok(["✅ allow = true → proceed"])
    pdp -->|"Institutional tier — no cap, but must have approval"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Tiered Transaction Limits — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.tx_limits

import rego.v1

# Per-tier daily transaction caps. Retail < $10k, Pro < $250k, Institutional unlimited. Off-hours apply tighter caps.

default allow := false

# Retail tier under $10k
allow if {
    input.user.tier == "retail"
    input.amount <= 10000
}

# Pro tier under $250k
allow if {
    input.user.tier == "pro"
    input.amount <= 250000
}

# Institutional tier — no cap, but must have approval
allow if {
    input.user.tier == "institutional"
    input.approval.signed == true
}
```

Sample sandbox input:

```json
{
  "user": {
    "tier": "pro"
  },
  "amount": 50000,
  "approval": {
    "signed": false
  }
}
```

</details>

---
<a id="policy-sanctions-screening"></a>

### 14. Sanctions Screening (OFAC/EU/UN)

`Compliance` &nbsp;·&nbsp; package `digital_assets.sanctions` &nbsp;·&nbsp; id `sanctions-screening`

Reject any transaction touching a sanctioned jurisdiction, address, or counterparty. Lists supplied via input.lists.*

**Decision logic**

- **`deny`** — boolean, default `false` — Triggers if any sanctioned entity is involved. Evaluates **true** if any of:
  - Sender wallet on sanctions list
  - Recipient wallet on sanctions list
  - User country in sanctioned list
  - Counterparty matches a sanctioned name

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Transacting user"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.sanctions"}}
    pdp -->|"Sender wallet on sanctions list"| ok(["✅ deny = true → proceed"])
    pdp -->|"Recipient wallet on sanctions list"| ok(["✅ deny = true → proceed"])
    pdp -->|"User country in sanctioned list"| ok(["✅ deny = true → proceed"])
    pdp -->|"Counterparty matches a sanctioned name"| ok(["✅ deny = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default deny = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of deny matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Sanctions Screening — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.sanctions

import rego.v1

# Reject any transaction touching a sanctioned jurisdiction, address, or counterparty. Lists supplied via input.lists.*

# Triggers if any sanctioned entity is involved
default deny := false

# Sender wallet on sanctions list
deny if {
    input.tx.from_address in input.lists.sanctioned_addresses
}

# Recipient wallet on sanctions list
deny if {
    input.tx.to_address in input.lists.sanctioned_addresses
}

# User country in sanctioned list
deny if {
    input.user.country in input.lists.sanctioned_countries
}

# Counterparty matches a sanctioned name
deny if {
    input.counterparty.name in input.lists.sanctioned_names
}
```

Sample sandbox input:

```json
{
  "tx": {
    "from_address": "0xabc",
    "to_address": "0xdef"
  },
  "user": {
    "country": "US"
  },
  "counterparty": {
    "name": "ACME Corp"
  },
  "lists": {
    "sanctioned_addresses": [
      "0xbad1",
      "0xbad2"
    ],
    "sanctioned_countries": [
      "IR",
      "KP",
      "CU"
    ],
    "sanctioned_names": [
      "BadActor LLC"
    ]
  }
}
```

</details>

---
<a id="policy-stablecoin-mint"></a>

### 15. Stablecoin Mint Authorization

`Stablecoins` &nbsp;·&nbsp; package `digital_assets.stablecoin.mint` &nbsp;·&nbsp; id `stablecoin-mint`

Authorize a mint only if the requester is an approved minter, the reserve ratio is healthy, and the mint stays within the daily ceiling.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Approved minter, reserves healthy, within ceiling
- **`requires_multisig`** — boolean, default `false` — Mints over $5M require 3-of-5 multisig. Evaluates **true** if any of:
  - a branch matches

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Issuer / holder"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.stablecoin.mint"}}
    pdp -->|"Approved minter, reserves healthy, within ceiling"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Stablecoin Mint Authorization — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.stablecoin.mint

import rego.v1

# Authorize a mint only if the requester is an approved minter, the reserve ratio is healthy, and the mint stays within the daily ceiling.

default allow := false

# Approved minter, reserves healthy, within ceiling
allow if {
    input.requester.role == "minter"
    input.requester.approved == true
    input.reserves.ratio >= 1
    input.mint.amount <= input.limits.daily_remaining
    input.mint.amount > 0
}

# Mints over $5M require 3-of-5 multisig
default requires_multisig := false

requires_multisig if {
    input.mint.amount > 5000000
}
```

Sample sandbox input:

```json
{
  "requester": {
    "role": "minter",
    "approved": true
  },
  "reserves": {
    "ratio": 1.02
  },
  "mint": {
    "amount": 1000000
  },
  "limits": {
    "daily_remaining": 10000000
  }
}
```

</details>

---
<a id="policy-stablecoin-redeem"></a>

### 16. Stablecoin Redemption Gate

`Stablecoins` &nbsp;·&nbsp; package `digital_assets.stablecoin.redeem` &nbsp;·&nbsp; id `stablecoin-redeem`

Allow redemption when the holder is whitelisted, the system isn't paused, and slippage is acceptable.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Standard redemption flow

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Issuer / holder"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.stablecoin.redeem"}}
    pdp -->|"Standard redemption flow"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Stablecoin Redemption Gate — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.stablecoin.redeem

import rego.v1

# Allow redemption when the holder is whitelisted, the system isn't paused, and slippage is acceptable.

default allow := false

# Standard redemption flow
allow if {
    input.holder.whitelisted == true
    input.system.paused == false
    input.redeem.slippage_bps <= 50
    input.redeem.amount <= input.holder.balance
}
```

Sample sandbox input:

```json
{
  "holder": {
    "whitelisted": true,
    "balance": 50000
  },
  "system": {
    "paused": false
  },
  "redeem": {
    "slippage_bps": 12,
    "amount": 10000
  }
}
```

</details>

---
<a id="policy-defi-protocol-access"></a>

### 17. DeFi Protocol Access Control

`DeFi` &nbsp;·&nbsp; package `digital_assets.defi.access` &nbsp;·&nbsp; id `defi-protocol-access`

Restrict access to a DeFi protocol based on wallet provenance, geo-fencing, and protocol risk classification.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Whitelisted wallet from allowed jurisdiction
  - High-risk protocols open only to accredited / pro users

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Wallet / protocol user"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.defi.access"}}
    pdp -->|"Whitelisted wallet from allowed jurisdiction"| ok(["✅ allow = true → proceed"])
    pdp -->|"High-risk protocols open only to accredited / pro users"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: DeFi Protocol Access Control — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.defi.access

import rego.v1

# Restrict access to a DeFi protocol based on wallet provenance, geo-fencing, and protocol risk classification.

default allow := false

# Whitelisted wallet from allowed jurisdiction
allow if {
    input.wallet.verified == true
    input.wallet.country in ["US", "GB", "DE", "FR", "JP", "SG", "CH"]
    input.protocol.risk_tier <= 3
}

# High-risk protocols open only to accredited / pro users
allow if {
    input.wallet.verified == true
    input.protocol.risk_tier >= 4
    input.user.accredited == true
}
```

Sample sandbox input:

```json
{
  "wallet": {
    "verified": true,
    "country": "DE"
  },
  "protocol": {
    "risk_tier": 2
  },
  "user": {
    "accredited": false
  }
}
```

</details>

---
<a id="policy-custody-withdrawal"></a>

### 18. Custody Withdrawal — M-of-N Approval

`Institutional` &nbsp;·&nbsp; package `digital_assets.custody.withdrawal` &nbsp;·&nbsp; id `custody-withdrawal`

Withdrawals require N approvers. Threshold scales with amount. Whitelisted destinations only.

**Decision logic**

- **`malformed_inputs`** — *partial set* (violation/reason collector) — Set of malformed-input reasons. Non-empty → allow denies and the caller sees the reasons. A member is added when:
  - input.amount is missing or not a number
  - input.approvals.count is missing or not a number
  - input.destination.whitelisted is missing or not a boolean
- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Small withdrawal: 2 approvers, whitelisted destination
  - Mid-tier withdrawal: 3 approvers + compliance sign-off
  - Large withdrawal: 5 approvers, board sign-off, cooling period elapsed
- **`result`** — *result object* emitting `{ allow, rejection_reasons }` — Decision document — bundles the verdict and any malformed-input reasons for the caller's audit log.

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Institution"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.custody.withdrawal"}}
    pdp -->|"Small withdrawal: 2 approvers, whitelisted destination"| ok(["✅ allow = true → proceed"])
    pdp -->|"Mid-tier withdrawal: 3 approvers + compliance sign-off"| ok(["✅ allow = true → proceed"])
    pdp -->|"Large withdrawal: 5 approvers, board sign-off, cooling period elapsed"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
    ok --> doc[/"result = { allow, rejection_reasons }"/]
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Violations: one or more checks fail
    Evaluating --> Clean: malformed_inputs = {}
    Clean --> Allowed: allow = true
    Violations --> Denied: reasons returned to caller
    Allowed --> Applied: Custody Withdrawal — M-of-N Approval — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> Recorded: result document written to caller audit log
    Applied --> [*]
    Rejected --> [*]
    Recorded --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.custody.withdrawal

import rego.v1

# Withdrawals require N approvers. Threshold scales with amount. Whitelisted destinations only.

# Set of malformed-input reasons. Non-empty → allow denies and the caller sees the reasons.
# input.amount is missing or not a number
malformed_inputs contains "malformed_request" if {
    not is_number(object.get(input, "amount", null))
}

# input.approvals.count is missing or not a number
malformed_inputs contains "malformed_request" if {
    not is_number(object.get(object.get(input, "approvals", {}), "count", null))
}

# input.destination.whitelisted is missing or not a boolean
malformed_inputs contains "malformed_request" if {
    not is_boolean(object.get(object.get(input, "destination", {}), "whitelisted", null))
}

default allow := false

# Small withdrawal: 2 approvers, whitelisted destination
allow if {
    count(malformed_inputs) == 0
    input.amount <= 100000
    input.approvals.count >= 2
    input.destination.whitelisted == true
}

# Mid-tier withdrawal: 3 approvers + compliance sign-off
allow if {
    count(malformed_inputs) == 0
    input.amount > 100000
    input.amount <= 5000000
    input.approvals.count >= 3
    input.compliance.signed == true
    input.destination.whitelisted == true
}

# Large withdrawal: 5 approvers, board sign-off, cooling period elapsed
allow if {
    count(malformed_inputs) == 0
    input.amount > 5000000
    input.approvals.count >= 5
    input.board.signed == true
    input.cooling_period_hours_elapsed >= 24
    input.destination.whitelisted == true
}

# Decision document — bundles the verdict and any malformed-input reasons for the caller's audit log.
result := {
    "allow": allow,
    "rejection_reasons": malformed_inputs
}
```

Sample sandbox input:

```json
{
  "amount": 250000,
  "approvals": {
    "count": 3
  },
  "compliance": {
    "signed": true
  },
  "board": {
    "signed": false
  },
  "destination": {
    "whitelisted": true
  },
  "cooling_period_hours_elapsed": 0
}
```

</details>

---
<a id="policy-travel-rule"></a>

### 19. FATF Travel Rule

`Compliance` &nbsp;·&nbsp; package `digital_assets.travel_rule` &nbsp;·&nbsp; id `travel-rule`

Transactions over the FATF threshold must include originator + beneficiary VASP information.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Below FATF threshold — pass through
  - Above threshold but full originator/beneficiary metadata present

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Transacting user"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.travel_rule"}}
    pdp -->|"Below FATF threshold — pass through"| ok(["✅ allow = true → proceed"])
    pdp -->|"Above threshold but full originator/beneficiary metadata present"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: FATF Travel Rule — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.travel_rule

import rego.v1

# Transactions over the FATF threshold must include originator + beneficiary VASP information.

default allow := false

# Below FATF threshold — pass through
allow if {
    input.tx.amount_usd < 1000
}

# Above threshold but full originator/beneficiary metadata present
allow if {
    input.tx.amount_usd >= 1000
    input.originator.name
    input.originator.address
    input.originator.vasp_id
    input.beneficiary.name
    input.beneficiary.account
    input.beneficiary.vasp_id
}
```

Sample sandbox input:

```json
{
  "tx": {
    "amount_usd": 5000
  },
  "originator": {
    "name": "Alice",
    "address": "1 Main St",
    "vasp_id": "VASP-A"
  },
  "beneficiary": {
    "name": "Bob",
    "account": "ACC-001",
    "vasp_id": "VASP-B"
  }
}
```

</details>

---
<a id="policy-cross-border-payment"></a>

### 20. Cross-Border Payment Rules

`TradFi` &nbsp;·&nbsp; package `digital_assets.cross_border` &nbsp;·&nbsp; id `cross-border-payment`

Cross-border payments: corridor allowed, currencies supported, FX rate within tolerance, settlement window valid.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Approved corridor and supported currency pair

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Trader / payer"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.cross_border"}}
    pdp -->|"Approved corridor and supported currency pair"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Cross-Border Payment Rules — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.cross_border

import rego.v1

# Cross-border payments: corridor allowed, currencies supported, FX rate within tolerance, settlement window valid.

default allow := false

# Approved corridor and supported currency pair
allow if {
    input.corridor in ["US-EU", "US-UK", "US-SG", "EU-UK", "EU-SG", "UK-SG"]
    input.currency.from in ["USD", "EUR", "GBP", "SGD", "USDC", "EURC"]
    input.currency.to in ["USD", "EUR", "GBP", "SGD", "USDC", "EURC"]
    input.fx.deviation_bps <= 25
    input.settlement.t_plus <= 2
}
```

Sample sandbox input:

```json
{
  "corridor": "US-EU",
  "currency": {
    "from": "USD",
    "to": "EUR"
  },
  "fx": {
    "deviation_bps": 8
  },
  "settlement": {
    "t_plus": 1
  }
}
```

</details>

---
<a id="policy-security-token-transfer"></a>

### 21. Security Token Transfer (ERC-3643)

`TradFi` &nbsp;·&nbsp; package `digital_assets.security_token` &nbsp;·&nbsp; id `security-token-transfer`

Permissioned security token: investor must hold valid identity claim, comply with lock-up, and respect cap-table limits.

**Decision logic**

- **`allow_transfer`** — boolean, default `false`. Evaluates **true** if any of:
  - Both parties verified; lock-up cleared; cap-table not breached

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Trader / payer"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.security_token"}}
    pdp -->|"Both parties verified; lock-up cleared; cap-table not breached"| ok(["✅ allow_transfer = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow_transfer = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow_transfer matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Security Token Transfer — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.security_token

import rego.v1

# Permissioned security token: investor must hold valid identity claim, comply with lock-up, and respect cap-table limits.

default allow_transfer := false

# Both parties verified; lock-up cleared; cap-table not breached
allow_transfer if {
    input.from.identity_verified == true
    input.to.identity_verified == true
    input.from.claims.accredited == true
    input.to.claims.accredited == true
    input.lockup.days_remaining <= 0
    input.captable.holders_after <= 99
}
```

Sample sandbox input:

```json
{
  "from": {
    "identity_verified": true,
    "claims": {
      "accredited": true
    }
  },
  "to": {
    "identity_verified": true,
    "claims": {
      "accredited": true
    }
  },
  "lockup": {
    "days_remaining": 0
  },
  "captable": {
    "holders_after": 47
  }
}
```

</details>

---
<a id="policy-governance-vote"></a>

### 22. DAO Governance Voting Rights

`DeFi` &nbsp;·&nbsp; package `digital_assets.governance` &nbsp;·&nbsp; id `governance-vote`

Votes require minimum stake, registered wallet, and stake-weighted snapshot at proposal start.

**Decision logic**

- **`allow_vote`** — boolean, default `false`. Evaluates **true** if any of:
  - a branch matches
- **`vote_weight`** — number — Quadratic vote weight = sqrt(snapshot_balance).

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Wallet / protocol user"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.governance"}}
    pdp -->|"branch 1"| ok(["✅ allow_vote = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow_vote = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow_vote matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: DAO Governance Voting Rights — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.governance

import rego.v1

# Votes require minimum stake, registered wallet, and stake-weighted snapshot at proposal start.

default allow_vote := false

allow_vote if {
    input.voter.registered == true
    input.voter.snapshot_balance >= 100
    input.proposal.status == "active"
    input.voter.has_voted == false
}

# Quadratic vote weight = sqrt(snapshot_balance)
default vote_weight := 0
```

Sample sandbox input:

```json
{
  "voter": {
    "registered": true,
    "snapshot_balance": 1500,
    "has_voted": false
  },
  "proposal": {
    "status": "active"
  }
}
```

</details>

---
<a id="policy-settlement-window"></a>

### 23. Trade Settlement Window

`Institutional` &nbsp;·&nbsp; package `digital_assets.settlement` &nbsp;·&nbsp; id `settlement-window`

Settlement only during exchange hours, on business days, with sufficient inventory and counterparty in good standing.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - a branch matches

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Institution"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.settlement"}}
    pdp -->|"branch 1"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Trade Settlement Window — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.settlement

import rego.v1

# Settlement only during exchange hours, on business days, with sufficient inventory and counterparty in good standing.

default allow := false

allow if {
    input.market.is_open == true
    input.market.is_business_day == true
    input.inventory.available >= input.trade.quantity
    input.counterparty.standing == "good"
    input.counterparty.credit_remaining >= input.trade.notional
}
```

Sample sandbox input:

```json
{
  "market": {
    "is_open": true,
    "is_business_day": true
  },
  "inventory": {
    "available": 1000
  },
  "trade": {
    "quantity": 100,
    "notional": 50000
  },
  "counterparty": {
    "standing": "good",
    "credit_remaining": 500000
  }
}
```

</details>

---
<a id="policy-rbac-starter"></a>

### 24. RBAC Starter (Generic)

`Generic` &nbsp;·&nbsp; package `generic.rbac` &nbsp;·&nbsp; id `rbac-starter`

Generic role-based access control template — adapt for any system.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Admins can do anything
  - Editors can read or write
  - Viewers can only read

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Caller"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.generic.rbac"}}
    pdp -->|"Admins can do anything"| ok(["✅ allow = true → proceed"])
    pdp -->|"Editors can read or write"| ok(["✅ allow = true → proceed"])
    pdp -->|"Viewers can only read"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: RBAC Starter — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package generic.rbac

import rego.v1

# Generic role-based access control template — adapt for any system.

default allow := false

# Admins can do anything
allow if {
    input.user.role == "admin"
}

# Editors can read or write
allow if {
    input.user.role == "editor"
    input.action in ["read", "write"]
}

# Viewers can only read
allow if {
    input.user.role == "viewer"
    input.action == "read"
}
```

Sample sandbox input:

```json
{
  "user": {
    "role": "editor"
  },
  "action": "write"
}
```

</details>

---
<a id="policy-maker-checker-approval"></a>

### 25. Maker-Checker Approval

`Approvals` &nbsp;·&nbsp; package `digital_assets.approvals.maker_checker` &nbsp;·&nbsp; id `maker-checker-approval`

Separation of duties: the user who initiated the action cannot also approve it. Both must be active employees and the checker must sign within the dual-control window.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Maker and checker are distinct active employees and checker has signed in time

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Initiator + approvers"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.approvals.maker_checker"}}
    pdp -->|"Maker and checker are distinct active employees and checker has signed in time"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Maker-Checker Approval — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.approvals.maker_checker

import rego.v1

# Separation of duties: the user who initiated the action cannot also approve it. Both must be active employees and the checker must sign within the dual-control window.

default allow := false

# Maker and checker are distinct active employees and checker has signed in time
allow if {
    input.maker.id
    input.checker.id
    input.maker.id != input.checker.id
    input.maker.active == true
    input.checker.active == true
    input.checker.signed == true
    input.checker.signed_within_minutes <= 60
    input.action.risk_tier in ["low", "medium", "high"]
}
```

Sample sandbox input:

```json
{
  "maker": {
    "id": "alice@firm.com",
    "active": true
  },
  "checker": {
    "id": "bob@firm.com",
    "active": true,
    "signed": true,
    "signed_within_minutes": 12
  },
  "action": {
    "risk_tier": "medium"
  }
}
```

</details>

---
<a id="policy-nested-quorum-approval"></a>

### 26. Nested Quorum Approval

`Approvals` &nbsp;·&nbsp; package `digital_assets.approvals.nested_quorum` &nbsp;·&nbsp; id `nested-quorum-approval`

Multi-tier approval where each tier independently meets a quorum. Each branch represents an amount tier; gates ANDed within a branch, branches ORed across the rule.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Tier 1 (≤ $250k): Ops 2-of-3 quorum only
  - Tier 2 (≤ $10M): Ops 2-of-3 ∧ Risk 1-of-2 ∧ compliance sign-off
  - Tier 3 (> $10M): Ops 2-of-3 ∧ Risk 1-of-2 ∧ Board 1-of-3 ∧ cooling period elapsed

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Initiator + approvers"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.approvals.nested_quorum"}}
    pdp -->|"Tier 1 (≤ $250k): Ops 2-of-3 quorum only"| ok(["✅ allow = true → proceed"])
    pdp -->|"Tier 2 (≤ $10M): Ops 2-of-3 ∧ Risk 1-of-2 ∧ compliance sign-off"| ok(["✅ allow = true → proceed"])
    pdp -->|"Tier 3 (&gt; $10M): Ops 2-of-3 ∧ Risk 1-of-2 ∧ Board 1-of-3 ∧ cooling period elapsed"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Nested Quorum Approval — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.approvals.nested_quorum

import rego.v1

# Multi-tier approval where each tier independently meets a quorum. Each branch represents an amount tier; gates ANDed within a branch, branches ORed across the rule.

default allow := false

# Tier 1 (≤ $250k): Ops 2-of-3 quorum only
allow if {
    input.amount <= 250000
    input.tier_ops.approvals_count >= 2
}

# Tier 2 (≤ $10M): Ops 2-of-3 ∧ Risk 1-of-2 ∧ compliance sign-off
allow if {
    input.amount > 250000
    input.amount <= 10000000
    input.tier_ops.approvals_count >= 2
    input.tier_risk.approvals_count >= 1
    input.compliance.signed == true
}

# Tier 3 (> $10M): Ops 2-of-3 ∧ Risk 1-of-2 ∧ Board 1-of-3 ∧ cooling period elapsed
allow if {
    input.amount > 10000000
    input.tier_ops.approvals_count >= 2
    input.tier_risk.approvals_count >= 1
    input.tier_board.approvals_count >= 1
    input.cooling_period_hours_elapsed >= 24
}
```

Sample sandbox input:

```json
{
  "amount": 5000000,
  "tier_ops": {
    "approvals_count": 2
  },
  "tier_risk": {
    "approvals_count": 1
  },
  "tier_board": {
    "approvals_count": 0
  },
  "compliance": {
    "signed": true
  },
  "cooling_period_hours_elapsed": 0
}
```

</details>

---
<a id="policy-treasury-rebalance"></a>

### 27. Treasury Rebalance Guardrails

`Treasury` &nbsp;·&nbsp; package `digital_assets.treasury.rebalance` &nbsp;·&nbsp; id `treasury-rebalance`

Constrain treasury rebalances: per-asset-class allocation bands, single-counterparty exposure cap, idle-cash floor, execution within rebalance window.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Allocation within bands, exposure cap respected, idle-cash floor preserved

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Treasury desk"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.treasury.rebalance"}}
    pdp -->|"Allocation within bands, exposure cap respected, idle-cash floor preserved"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Treasury Rebalance Guardrails — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.treasury.rebalance

import rego.v1

# Constrain treasury rebalances: per-asset-class allocation bands, single-counterparty exposure cap, idle-cash floor, execution within rebalance window.

default allow := false

# Allocation within bands, exposure cap respected, idle-cash floor preserved
allow if {
    input.allocation.cash_pct_after >= 5
    input.allocation.t_bills_pct_after <= 70
    input.allocation.crypto_pct_after <= 25
    input.allocation.stablecoin_pct_after <= 40
    input.counterparty.exposure_pct_after <= 20
    input.counterparty.rating in ["A", "AA", "AAA"]
    input.window.is_rebalance_day == true
    input.policy.signed_by_cfo == true
}
```

Sample sandbox input:

```json
{
  "allocation": {
    "cash_pct_after": 12,
    "t_bills_pct_after": 55,
    "crypto_pct_after": 18,
    "stablecoin_pct_after": 15
  },
  "counterparty": {
    "exposure_pct_after": 14,
    "rating": "AA"
  },
  "window": {
    "is_rebalance_day": true
  },
  "policy": {
    "signed_by_cfo": true
  }
}
```

</details>

---
<a id="policy-otc-swap-execution"></a>

### 28. OTC Swap Execution (ISDA Pre-Trade)

`Trading` &nbsp;·&nbsp; package `digital_assets.trading.otc_swap` &nbsp;·&nbsp; id `otc-swap-execution`

Pre-trade gate for OTC swaps: counterparty whitelisted under signed ISDA, price within market band, initial margin posted, notional within counterparty limit.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - All ISDA, pricing, collateral, and exposure gates pass

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Trader"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.trading.otc_swap"}}
    pdp -->|"All ISDA, pricing, collateral, and exposure gates pass"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: OTC Swap Execution — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.trading.otc_swap

import rego.v1

# Pre-trade gate for OTC swaps: counterparty whitelisted under signed ISDA, price within market band, initial margin posted, notional within counterparty limit.

default allow := false

# All ISDA, pricing, collateral, and exposure gates pass
allow if {
    input.counterparty.whitelisted == true
    input.counterparty.isda_signed == true
    input.counterparty.csa_in_place == true
    input.trade.price_deviation_bps <= 50
    input.trade.notional_usd <= input.counterparty.notional_limit_usd
    input.collateral.initial_margin_posted == true
    input.collateral.haircut_pct <= 8
    input.product.type in ["irs", "fx_swap", "tr_swap", "perp_swap"]
}
```

Sample sandbox input:

```json
{
  "counterparty": {
    "whitelisted": true,
    "isda_signed": true,
    "csa_in_place": true,
    "notional_limit_usd": 50000000
  },
  "trade": {
    "price_deviation_bps": 18,
    "notional_usd": 12000000
  },
  "collateral": {
    "initial_margin_posted": true,
    "haircut_pct": 5
  },
  "product": {
    "type": "irs"
  }
}
```

</details>

---
<a id="policy-token-lifecycle-control"></a>

### 29. Token Lifecycle Control

`Tokens` &nbsp;·&nbsp; package `digital_assets.tokens.lifecycle` &nbsp;·&nbsp; id `token-lifecycle-control`

Authorize token mint/burn/freeze actions: action is permitted, actor holds the right role, supply cap not breached, target holder not on the freeze list.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Mint: authorized minter and supply remains under cap
  - Burn: authorized burner with sufficient balance
  - Freeze: compliance role with signed regulatory or court order

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Token operator"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.tokens.lifecycle"}}
    pdp -->|"Mint: authorized minter and supply remains under cap"| ok(["✅ allow = true → proceed"])
    pdp -->|"Burn: authorized burner with sufficient balance"| ok(["✅ allow = true → proceed"])
    pdp -->|"Freeze: compliance role with signed regulatory or court order"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Token Lifecycle Control — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.tokens.lifecycle

import rego.v1

# Authorize token mint/burn/freeze actions: action is permitted, actor holds the right role, supply cap not breached, target holder not on the freeze list.

default allow := false

# Mint: authorized minter and supply remains under cap
allow if {
    input.action == "mint"
    input.actor.role == "minter"
    input.actor.authorized == true
    input.supply.after <= input.supply.cap
    input.target.frozen == false
}

# Burn: authorized burner with sufficient balance
allow if {
    input.action == "burn"
    input.actor.role in ["burner", "minter"]
    input.actor.authorized == true
    input.target.balance >= input.amount
}

# Freeze: compliance role with signed regulatory or court order
allow if {
    input.action == "freeze"
    input.actor.role == "compliance"
    input.order.signed == true
    input.order.type in ["regulatory", "court", "internal_compliance"]
}
```

Sample sandbox input:

```json
{
  "action": "mint",
  "actor": {
    "role": "minter",
    "authorized": true
  },
  "supply": {
    "after": 950000000,
    "cap": 1000000000
  },
  "target": {
    "frozen": false,
    "balance": 0
  },
  "amount": 1000,
  "order": {
    "signed": false,
    "type": "internal_compliance"
  }
}
```

</details>

---
<a id="policy-margin-collateral-health"></a>

### 30. Margin & Collateral Health

`Risk` &nbsp;·&nbsp; package `digital_assets.risk.margin` &nbsp;·&nbsp; id `margin-collateral-health`

Block trades or withdrawals that would breach LTV, use unapproved collateral, or fire while a margin call cure window is active.

**Decision logic**

- **`malformed_inputs`** — *partial set* (violation/reason collector) — Set of malformed-input reasons. Non-empty → allow denies and the caller sees the reasons. A member is added when:
  - input.position.ltv_after is missing or not a number
  - input.margin_call.open is missing or not a boolean
- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - LTV under threshold, approved collateral, no active liquidation, no open margin call
  - Margin-call cure: top-up that brings LTV back inside threshold during the cure window
- **`result`** — *result object* emitting `{ allow, rejection_reasons }` — Decision document — bundles the verdict and any malformed-input reasons for the caller's audit log.

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Trader / borrower"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.risk.margin"}}
    pdp -->|"LTV under threshold, approved collateral, no active liquidation, no open margin call"| ok(["✅ allow = true → proceed"])
    pdp -->|"Margin-call cure: top-up that brings LTV back inside threshold during the cure window"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
    ok --> doc[/"result = { allow, rejection_reasons }"/]
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Violations: one or more checks fail
    Evaluating --> Clean: malformed_inputs = {}
    Clean --> Allowed: allow = true
    Violations --> Denied: reasons returned to caller
    Allowed --> Applied: Margin and Collateral Health — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> Recorded: result document written to caller audit log
    Applied --> [*]
    Rejected --> [*]
    Recorded --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.risk.margin

import rego.v1

# Block trades or withdrawals that would breach LTV, use unapproved collateral, or fire while a margin call cure window is active.

# Set of malformed-input reasons. Non-empty → allow denies and the caller sees the reasons.
# input.position.ltv_after is missing or not a number
malformed_inputs contains "malformed_request" if {
    not is_number(object.get(object.get(input, "position", {}), "ltv_after", null))
}

# input.margin_call.open is missing or not a boolean
malformed_inputs contains "malformed_request" if {
    not is_boolean(object.get(object.get(input, "margin_call", {}), "open", null))
}

default allow := false

# LTV under threshold, approved collateral, no active liquidation, no open margin call
allow if {
    count(malformed_inputs) == 0
    input.position.ltv_after <= 0.65
    input.collateral.type in ["USDC", "USDT", "BTC", "ETH", "TBILL"]
    input.collateral.haircut_pct <= 15
    input.position.liquidation_active == false
    input.margin_call.open == false
}

# Margin-call cure: top-up that brings LTV back inside threshold during the cure window
allow if {
    count(malformed_inputs) == 0
    input.action == "top_up"
    input.margin_call.open == true
    input.margin_call.cure_window_minutes_remaining > 0
    input.position.ltv_after <= 0.55
}

# Decision document — bundles the verdict and any malformed-input reasons for the caller's audit log.
result := {
    "allow": allow,
    "rejection_reasons": malformed_inputs
}
```

Sample sandbox input:

```json
{
  "action": "open",
  "position": {
    "ltv_after": 0.42,
    "liquidation_active": false
  },
  "collateral": {
    "type": "USDC",
    "haircut_pct": 2
  },
  "margin_call": {
    "open": false,
    "cure_window_minutes_remaining": 0
  }
}
```

</details>

---
<a id="policy-bridge-cross-chain"></a>

### 31. Cross-Chain Bridge Guardrails

`DeFi` &nbsp;·&nbsp; package `digital_assets.defi.bridge` &nbsp;·&nbsp; id `bridge-cross-chain`

Cross-chain bridge transfers: source/destination chain pair allowed, daily aggregate cap not breached, peg deviation within tolerance, bridge contract not paused.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Allowed chain pair, within caps, peg healthy, bridge live

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Wallet / protocol user"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.defi.bridge"}}
    pdp -->|"Allowed chain pair, within caps, peg healthy, bridge live"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Cross-Chain Bridge Guardrails — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.defi.bridge

import rego.v1

# Cross-chain bridge transfers: source/destination chain pair allowed, daily aggregate cap not breached, peg deviation within tolerance, bridge contract not paused.

default allow := false

# Allowed chain pair, within caps, peg healthy, bridge live
allow if {
    input.source_chain in ["ethereum", "polygon", "arbitrum", "base", "optimism", "solana"]
    input.dest_chain in ["ethereum", "polygon", "arbitrum", "base", "optimism", "solana"]
    input.source_chain != input.dest_chain
    input.bridge.paused == false
    input.transfer.amount_usd <= 500000
    input.bridge.daily_volume_usd_after <= 10000000
    input.peg.deviation_bps <= 30
    input.user.kyc_status == "verified"
}
```

Sample sandbox input:

```json
{
  "source_chain": "ethereum",
  "dest_chain": "arbitrum",
  "bridge": {
    "paused": false,
    "daily_volume_usd_after": 2500000
  },
  "transfer": {
    "amount_usd": 75000
  },
  "peg": {
    "deviation_bps": 8
  },
  "user": {
    "kyc_status": "verified"
  }
}
```

</details>

---
<a id="policy-vesting-timelock-release"></a>

### 32. Vesting / Timelock Release

`Operations` &nbsp;·&nbsp; package `digital_assets.ops.vesting` &nbsp;·&nbsp; id `vesting-timelock-release`

Release vested tokens only after the cliff has passed, the unlock timestamp is reached, the beneficiary is KYC-current, and no clawback is active.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Cliff elapsed, unlock reached, beneficiary in good standing, requested ≤ vested

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Operator"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.ops.vesting"}}
    pdp -->|"Cliff elapsed, unlock reached, beneficiary in good standing, requested ≤ vested"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Vesting / Timelock Release — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.ops.vesting

import rego.v1

# Release vested tokens only after the cliff has passed, the unlock timestamp is reached, the beneficiary is KYC-current, and no clawback is active.

default allow := false

# Cliff elapsed, unlock reached, beneficiary in good standing, requested ≤ vested
allow if {
    input.now_ts >= input.schedule.cliff_ts
    input.now_ts >= input.schedule.next_unlock_ts
    input.beneficiary.kyc_status == "verified"
    input.beneficiary.terminated_for_cause == false
    input.clawback.active == false
    input.request.amount <= input.schedule.vested_amount
}
```

Sample sandbox input:

```json
{
  "now_ts": 1746662400,
  "schedule": {
    "cliff_ts": 1735689600,
    "next_unlock_ts": 1746576000,
    "vested_amount": 25000
  },
  "beneficiary": {
    "kyc_status": "verified",
    "terminated_for_cause": false
  },
  "clawback": {
    "active": false
  },
  "request": {
    "amount": 5000
  }
}
```

</details>

---
<a id="policy-oracle-price-validity"></a>

### 33. Oracle Price Feed Validity

`Risk` &nbsp;·&nbsp; package `digital_assets.risk.oracle` &nbsp;·&nbsp; id `oracle-price-validity`

Trust an oracle price only when the feed is fresh, multiple reporters agree, deviation from a reference is bounded, and the circuit breaker has not tripped.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Heartbeat fresh, enough reporters, deviation bounded, breaker untripped

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Trader / borrower"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.risk.oracle"}}
    pdp -->|"Heartbeat fresh, enough reporters, deviation bounded, breaker untripped"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Oracle Price Feed Validity — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.risk.oracle

import rego.v1

# Trust an oracle price only when the feed is fresh, multiple reporters agree, deviation from a reference is bounded, and the circuit breaker has not tripped.

default allow := false

# Heartbeat fresh, enough reporters, deviation bounded, breaker untripped
allow if {
    input.feed.staleness_seconds <= 60
    input.feed.reporter_count >= 3
    input.feed.deviation_bps_vs_reference <= 75
    input.feed.circuit_breaker_tripped == false
    input.asset.symbol
}
```

Sample sandbox input:

```json
{
  "feed": {
    "staleness_seconds": 12,
    "reporter_count": 7,
    "deviation_bps_vs_reference": 22,
    "circuit_breaker_tripped": false
  },
  "asset": {
    "symbol": "ETH-USD"
  }
}
```

</details>

---
<a id="policy-emergency-kill-switch"></a>

### 34. Emergency Kill-Switch

`Operations` &nbsp;·&nbsp; package `digital_assets.ops.kill_switch` &nbsp;·&nbsp; id `emergency-kill-switch`

Block all activity while an incident is active. The only path to allow is a break-glass resume signed by both the CISO and the CTO with a justification on file.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - No incident active and system healthy
  - Break-glass resume: dual sign-off (CISO + CTO) with justification recorded

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Operator"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.ops.kill_switch"}}
    pdp -->|"No incident active and system healthy"| ok(["✅ allow = true → proceed"])
    pdp -->|"Break-glass resume: dual sign-off (CISO + CTO) with justification recorded"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Emergency Kill-Switch — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.ops.kill_switch

import rego.v1

# Block all activity while an incident is active. The only path to allow is a break-glass resume signed by both the CISO and the CTO with a justification on file.

default allow := false

# No incident active and system healthy
allow if {
    input.incident.active == false
    input.system.health == "green"
}

# Break-glass resume: dual sign-off (CISO + CTO) with justification recorded
allow if {
    input.action == "resume"
    input.signoff.ciso == true
    input.signoff.cto == true
    input.signoff.ciso_id != input.signoff.cto_id
    input.justification.recorded == true
}
```

Sample sandbox input:

```json
{
  "action": "trade",
  "incident": {
    "active": false
  },
  "system": {
    "health": "green"
  },
  "signoff": {
    "ciso": false,
    "cto": false,
    "ciso_id": "",
    "cto_id": ""
  },
  "justification": {
    "recorded": false
  }
}
```

</details>

---
<a id="policy-regulatory-reporting-trigger"></a>

### 35. Regulatory Reporting Trigger

`Compliance` &nbsp;·&nbsp; package `digital_assets.compliance.reporting` &nbsp;·&nbsp; id `regulatory-reporting-trigger`

Flag transactions that trip a reporting obligation: BSA/CTR, SAR risk, MiCA significant CASP, EMIR derivative, or FinCEN crypto threshold.

**Decision logic**

- **`report_required`** — boolean, default `false`. Evaluates **true** if any of:
  - BSA Currency Transaction Report (CTR) — cash-equivalent ≥ $10,000
  - Suspicious Activity Report (SAR) — risk flag set or structuring suspected
  - MiCA significant transfer — CASP-to-CASP ≥ €1,000 within EEA
  - EMIR — derivative trade requires trade-repository reporting

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Transacting user"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.compliance.reporting"}}
    pdp -->|"BSA Currency Transaction Report (CTR) — cash-equivalent ≥ $10,000"| ok(["✅ report_required = true → proceed"])
    pdp -->|"Suspicious Activity Report (SAR) — risk flag set or structuring suspected"| ok(["✅ report_required = true → proceed"])
    pdp -->|"MiCA significant transfer — CASP-to-CASP ≥ €1,000 within EEA"| ok(["✅ report_required = true → proceed"])
    pdp -->|"EMIR — derivative trade requires trade-repository reporting"| ok(["✅ report_required = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default report_required = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of report_required matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Regulatory Reporting Trigger — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.compliance.reporting

import rego.v1

# Flag transactions that trip a reporting obligation: BSA/CTR, SAR risk, MiCA significant CASP, EMIR derivative, or FinCEN crypto threshold.

default report_required := false

# BSA Currency Transaction Report (CTR) — cash-equivalent ≥ $10,000
report_required if {
    input.tx.cash_equivalent_usd >= 10000
    input.tx.jurisdiction == "US"
}

# Suspicious Activity Report (SAR) — risk flag set or structuring suspected
report_required if {
    input.tx.risk_flagged == true
}

# MiCA significant transfer — CASP-to-CASP ≥ €1,000 within EEA
report_required if {
    input.tx.amount_eur >= 1000
    input.tx.jurisdiction in ["EU", "EEA"]
    input.tx.casp_to_casp == true
}

# EMIR — derivative trade requires trade-repository reporting
report_required if {
    input.product.type in ["irs", "fx_swap", "tr_swap", "future", "option"]
    input.tx.jurisdiction in ["EU", "EEA", "UK"]
}
```

Sample sandbox input:

```json
{
  "tx": {
    "cash_equivalent_usd": 12500,
    "amount_eur": 0,
    "jurisdiction": "US",
    "risk_flagged": false,
    "casp_to_casp": false
  },
  "product": {
    "type": "spot"
  }
}
```

</details>

---
<a id="policy-pre-trade-risk-check"></a>

### 36. Pre-Trade Risk Check

`Trading` &nbsp;·&nbsp; package `digital_assets.trading.pre_trade_risk` &nbsp;·&nbsp; id `pre-trade-risk-check`

Block orders that would breach fat-finger, position, daily-loss, or order-rate limits before they reach the venue.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Order within all pre-trade risk envelopes

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Trader"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.trading.pre_trade_risk"}}
    pdp -->|"Order within all pre-trade risk envelopes"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Pre-Trade Risk Check — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.trading.pre_trade_risk

import rego.v1

# Block orders that would breach fat-finger, position, daily-loss, or order-rate limits before they reach the venue.

default allow := false

# Order within all pre-trade risk envelopes
allow if {
    input.order.notional_usd <= input.limits.fat_finger_usd
    input.order.qty <= input.limits.fat_finger_qty
    input.order.price_deviation_bps <= 200
    input.position.size_after <= input.limits.position_max
    input.daily.realized_pnl_usd >= input.limits.daily_loss_floor_usd
    input.rate.orders_last_minute <= 60
    input.symbol in ["BTC-USD", "ETH-USD", "SOL-USD", "USDC-USD"]
}
```

Sample sandbox input:

```json
{
  "order": {
    "notional_usd": 200000,
    "qty": 5,
    "price_deviation_bps": 35
  },
  "limits": {
    "fat_finger_usd": 1000000,
    "fat_finger_qty": 50,
    "position_max": 500,
    "daily_loss_floor_usd": -100000
  },
  "position": {
    "size_after": 120
  },
  "daily": {
    "realized_pnl_usd": -15000
  },
  "rate": {
    "orders_last_minute": 12
  },
  "symbol": "ETH-USD"
}
```

</details>

---
<a id="policy-lending-origination"></a>

### 37. Crypto Lending Origination

`Risk` &nbsp;·&nbsp; package `digital_assets.risk.lending_origination` &nbsp;·&nbsp; id `lending-origination`

Approve a new collateralised loan: borrower KYC, approved collateral, origination LTV, term within bounds, sufficient liquidity in the loan book.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - All origination gates pass and risk score acceptable

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Trader / borrower"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.risk.lending_origination"}}
    pdp -->|"All origination gates pass and risk score acceptable"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Crypto Lending Origination — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.risk.lending_origination

import rego.v1

# Approve a new collateralised loan: borrower KYC, approved collateral, origination LTV, term within bounds, sufficient liquidity in the loan book.

default allow := false

# All origination gates pass and risk score acceptable
allow if {
    input.borrower.kyc_status == "verified"
    input.borrower.risk_score <= 60
    input.borrower.outstanding_loans_count < 5
    input.collateral.type in ["BTC", "ETH", "USDC", "TBILL", "STETH"]
    input.loan.ltv_origination <= 0.5
    input.loan.term_days >= 7
    input.loan.term_days <= 365
    input.loan.principal_usd <= input.book.available_liquidity_usd
    input.loan.rate_apr >= input.book.min_rate_apr
}
```

Sample sandbox input:

```json
{
  "borrower": {
    "kyc_status": "verified",
    "risk_score": 35,
    "outstanding_loans_count": 1
  },
  "collateral": {
    "type": "ETH"
  },
  "loan": {
    "ltv_origination": 0.4,
    "term_days": 90,
    "principal_usd": 250000,
    "rate_apr": 0.085
  },
  "book": {
    "available_liquidity_usd": 25000000,
    "min_rate_apr": 0.06
  }
}
```

</details>

---
<a id="policy-nft-royalty-transfer"></a>

### 38. NFT Transfer & Royalty Enforcement

`Tokens` &nbsp;·&nbsp; package `digital_assets.tokens.nft_transfer` &nbsp;·&nbsp; id `nft-royalty-transfer`

Allow an NFT transfer when the marketplace honours the on-chain royalty, the buyer is sanctions-clear, the lockup has elapsed, and the collection is not paused.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Royalty paid in full, marketplace whitelisted, lockup elapsed, parties clear
  - Compliance-mandated forced transfer (court order on file)

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Token operator"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.tokens.nft_transfer"}}
    pdp -->|"Royalty paid in full, marketplace whitelisted, lockup elapsed, parties clear"| ok(["✅ allow = true → proceed"])
    pdp -->|"Compliance-mandated forced transfer (court order on file)"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: NFT Transfer and Royalty Enforcement — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.tokens.nft_transfer

import rego.v1

# Allow an NFT transfer when the marketplace honours the on-chain royalty, the buyer is sanctions-clear, the lockup has elapsed, and the collection is not paused.

default allow := false

# Royalty paid in full, marketplace whitelisted, lockup elapsed, parties clear
allow if {
    input.collection.paused == false
    input.marketplace.whitelisted == true
    input.royalty.paid_bps >= input.collection.royalty_bps
    input.token.locked_until_ts <= input.now_ts
    input.from.sanctioned == false
    input.to.sanctioned == false
    input.token.id
}

# Compliance-mandated forced transfer (court order on file)
allow if {
    input.action == "forced_transfer"
    input.order.signed == true
    input.order.type in ["court", "regulatory"]
}
```

Sample sandbox input:

```json
{
  "action": "transfer",
  "collection": {
    "paused": false,
    "royalty_bps": 500
  },
  "marketplace": {
    "whitelisted": true
  },
  "royalty": {
    "paid_bps": 500
  },
  "token": {
    "id": "NFT-001",
    "locked_until_ts": 1700000000
  },
  "now_ts": 1782913876,
  "from": {
    "sanctioned": false
  },
  "to": {
    "sanctioned": false
  },
  "order": {
    "signed": false,
    "type": "internal_compliance"
  }
}
```

</details>

---
<a id="policy-insider-trading-blackout"></a>

### 39. Insider Trading Blackout

`Compliance` &nbsp;·&nbsp; package `digital_assets.compliance.blackout` &nbsp;·&nbsp; id `insider-trading-blackout`

Restrict trading by insiders during blackout windows or while on the restricted list, with a narrow 10b5-1 plan exception.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Trader is not an insider — normal market access
  - Insider, outside blackout window and not on restricted list
  - Insider trading under a pre-approved 10b5-1 plan

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Transacting user"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.compliance.blackout"}}
    pdp -->|"Trader is not an insider — normal market access"| ok(["✅ allow = true → proceed"])
    pdp -->|"Insider, outside blackout window and not on restricted list"| ok(["✅ allow = true → proceed"])
    pdp -->|"Insider trading under a pre-approved 10b5-1 plan"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Insider Trading Blackout — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.compliance.blackout

import rego.v1

# Restrict trading by insiders during blackout windows or while on the restricted list, with a narrow 10b5-1 plan exception.

default allow := false

# Trader is not an insider — normal market access
allow if {
    input.trader.is_insider == false
}

# Insider, outside blackout window and not on restricted list
allow if {
    input.trader.is_insider == true
    input.window.in_blackout == false
    input.trader.on_restricted_list == false
    input.symbol
}

# Insider trading under a pre-approved 10b5-1 plan
allow if {
    input.trader.is_insider == true
    input.plan.is_10b5_1 == true
    input.plan.compliance_signed == true
    input.plan.cooldown_days_elapsed >= 30
    input.order.symbol == input.plan.symbol
    input.order.qty <= input.plan.qty_remaining
}
```

Sample sandbox input:

```json
{
  "trader": {
    "is_insider": true,
    "on_restricted_list": false
  },
  "window": {
    "in_blackout": false
  },
  "plan": {
    "is_10b5_1": false,
    "compliance_signed": false,
    "cooldown_days_elapsed": 0,
    "symbol": "ACME",
    "qty_remaining": 0
  },
  "order": {
    "symbol": "ACME",
    "qty": 10
  },
  "symbol": "ACME"
}
```

</details>

---
<a id="policy-fund-subscription-redemption"></a>

### 40. Fund Subscription / Redemption Gate

`Institutional` &nbsp;·&nbsp; package `digital_assets.institutional.fund_flows` &nbsp;·&nbsp; id `fund-subscription-redemption`

Enforce subscription cutoff, redemption notice period, NAV freshness, gating thresholds, and accreditation for institutional funds (private credit, hedge fund, tokenised RWA).

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Subscription before cutoff, accredited investor, fund open, NAV fresh
  - Redemption with notice period observed and gate not active

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Institution"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.institutional.fund_flows"}}
    pdp -->|"Subscription before cutoff, accredited investor, fund open, NAV fresh"| ok(["✅ allow = true → proceed"])
    pdp -->|"Redemption with notice period observed and gate not active"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Fund Subscription / Redemption Gate — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.institutional.fund_flows

import rego.v1

# Enforce subscription cutoff, redemption notice period, NAV freshness, gating thresholds, and accreditation for institutional funds (private credit, hedge fund, tokenised RWA).

default allow := false

# Subscription before cutoff, accredited investor, fund open, NAV fresh
allow if {
    input.action == "subscribe"
    input.fund.status == "open"
    input.investor.accredited == true
    input.investor.kyc_status == "verified"
    input.now_ts < input.fund.next_cutoff_ts
    input.nav.staleness_hours <= 24
    input.subscription.amount_usd >= input.fund.min_ticket_usd
}

# Redemption with notice period observed and gate not active
allow if {
    input.action == "redeem"
    input.fund.gate_active == false
    input.redemption.notice_days_observed >= input.fund.notice_period_days
    input.redemption.amount_units <= input.investor.units_held
    input.redemption.amount_pct_of_nav <= 5
    input.nav.staleness_hours <= 24
}
```

Sample sandbox input:

```json
{
  "action": "subscribe",
  "fund": {
    "status": "open",
    "next_cutoff_ts": 1783000276,
    "min_ticket_usd": 100000,
    "notice_period_days": 30,
    "gate_active": false
  },
  "investor": {
    "accredited": true,
    "kyc_status": "verified",
    "units_held": 0
  },
  "now_ts": 1782913876,
  "nav": {
    "staleness_hours": 4
  },
  "subscription": {
    "amount_usd": 250000
  },
  "redemption": {
    "notice_days_observed": 0,
    "amount_units": 0,
    "amount_pct_of_nav": 0
  }
}
```

</details>

---
<a id="policy-rbac-matrix"></a>

### 41. RBAC Matrix (AND of ORs)

`Approvals` &nbsp;·&nbsp; package `digital_assets.approvals.rbac_matrix` &nbsp;·&nbsp; id `rbac-matrix`

Authorise an action when (role is privileged) AND (action is read-style) AND (resource is in scope). Each clause is an OR-group of alternatives — a worked example of the AND-of-ORs pattern.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Privileged role × read-style action × in-scope resource

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Initiator + approvers"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.approvals.rbac_matrix"}}
    pdp -->|"Privileged role × read-style action × in-scope resource"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: RBAC Matrix — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.approvals.rbac_matrix

import rego.v1

# Authorise an action when (role is privileged) AND (action is read-style) AND (resource is in scope). Each clause is an OR-group of alternatives — a worked example of the AND-of-ORs pattern.

default allow := false

# Privileged role × read-style action × in-scope resource
allow if {
    _allow_b0_g0
    _allow_b0_g1
    input.resource.tenant_id == input.user.tenant_id
    input.resource.classification in ["public", "internal"]
}

_allow_b0_g0 if {
    input.user.role == "admin"
}
_allow_b0_g0 if {
    input.user.role == "owner"
}
_allow_b0_g0 if {
    input.user.role == "auditor"
}
_allow_b0_g1 if {
    input.action == "read"
}
_allow_b0_g1 if {
    input.action == "list"
}
_allow_b0_g1 if {
    input.action == "describe"
}
```

Sample sandbox input:

```json
{
  "user": {
    "role": "auditor",
    "tenant_id": "tenant-007"
  },
  "action": "list",
  "resource": {
    "tenant_id": "tenant-007",
    "classification": "internal"
  }
}
```

</details>

---
<a id="policy-smart-contract-upgrade"></a>

### 42. Smart-Contract Upgrade Governance

`DeFi` &nbsp;·&nbsp; package `digital_assets.defi.upgrade` &nbsp;·&nbsp; id `smart-contract-upgrade`

Allow a contract upgrade only when timelock has elapsed, the proposer is on the authorized list, the multi-sig quorum is met, and a recent independent audit is on file.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Timelock elapsed, authorized proposer, multi-sig quorum met, audit attested within 90 days

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Wallet / protocol user"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.defi.upgrade"}}
    pdp -->|"Timelock elapsed, authorized proposer, multi-sig quorum met, audit attested within 90 days"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Smart-Contract Upgrade Governance — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.defi.upgrade

import rego.v1

# Allow a contract upgrade only when timelock has elapsed, the proposer is on the authorized list, the multi-sig quorum is met, and a recent independent audit is on file.

default allow := false

# Timelock elapsed, authorized proposer, multi-sig quorum met, audit attested within 90 days
allow if {
    input.timelock.elapsed == true
    input.timelock.delay_hours_observed >= 48
    input.proposer.authorized == true
    input.multisig.signatures_count >= 4
    input.multisig.threshold >= 4
    input.audit.attested == true
    input.audit.age_days <= 90
    input.upgrade.target_chain in ["ethereum", "polygon", "arbitrum", "base", "optimism"]
}
```

Sample sandbox input:

```json
{
  "timelock": {
    "elapsed": true,
    "delay_hours_observed": 72
  },
  "proposer": {
    "authorized": true
  },
  "multisig": {
    "signatures_count": 5,
    "threshold": 4
  },
  "audit": {
    "attested": true,
    "age_days": 30
  },
  "upgrade": {
    "target_chain": "ethereum"
  }
}
```

</details>

---
<a id="policy-fee-rate-check"></a>

### 43. Fee Rate Check

`Trading` &nbsp;·&nbsp; package `digital_assets.trading.fee_rate_check` &nbsp;·&nbsp; id `fee-rate-check`

Validates that the fee charged on a transaction does not exceed the maximum allowed. Uses arithmetic expressions: fee = amount × rate_bps / 10000 must be ≤ max_fee.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Fee does not exceed maximum and amount is within daily limit

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Trader"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.trading.fee_rate_check"}}
    pdp -->|"Fee does not exceed maximum and amount is within daily limit"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Fee Rate Check — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.trading.fee_rate_check

import rego.v1

# Validates that the fee charged on a transaction does not exceed the maximum allowed. Uses arithmetic expressions: fee = amount × rate_bps / 10000 must be ≤ max_fee.

default allow := false

# Fee does not exceed maximum and amount is within daily limit
allow if {
    input.amount
    input.rate_bps
    input.max_fee
    input.amount >= 1
    input.amount * input.rate_bps / 10000 <= input.max_fee
    input.amount <= input.daily_limit
}
```

Sample sandbox input:

```json
{
  "amount": 100000,
  "rate_bps": 30,
  "max_fee": 500,
  "daily_limit": 1000000
}
```

</details>

---
<a id="policy-batch-tx-limits"></a>

### 44. Batch Transaction Limits

`Operations` &nbsp;·&nbsp; package `digital_assets.operations.batch_tx_limits` &nbsp;·&nbsp; id `batch-tx-limits`

All transactions in a batch must individually be within the per-transaction limit and have a cleared status. Uses the 'every' universal quantifier.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Every transaction in the batch is cleared and within per-tx cap

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Operator"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.operations.batch_tx_limits"}}
    pdp -->|"Every transaction in the batch is cleared and within per-tx cap"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Batch Transaction Limits — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.operations.batch_tx_limits

import rego.v1

# All transactions in a batch must individually be within the per-transaction limit and have a cleared status. Uses the 'every' universal quantifier.

default allow := false

# Every transaction in the batch is cleared and within per-tx cap
allow if {
    input.batch_id
    is_array(input.transactions)
    input.per_tx_limit
    every tx in input.transactions {
        tx.amount > 0
        tx.amount <= input.per_tx_limit
        tx.status == "cleared"
    }
}
```

Sample sandbox input:

```json
{
  "batch_id": "batch-001",
  "per_tx_limit": 50000,
  "transactions": [
    {
      "amount": 10000,
      "status": "cleared"
    },
    {
      "amount": 25000,
      "status": "cleared"
    },
    {
      "amount": 5000,
      "status": "cleared"
    }
  ]
}
```

</details>

---
<a id="policy-daily-volume-cap"></a>

### 45. Daily Volume Cap

`Risk` &nbsp;·&nbsp; package `digital_assets.risk.daily_volume_cap` &nbsp;·&nbsp; id `daily-volume-cap`

Rejects a transaction if adding it to today's volume would breach the daily cap. Uses sum() aggregate over the day's transaction amounts.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Today's total volume plus this transaction stays within the cap

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Trader / borrower"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.risk.daily_volume_cap"}}
    pdp -->|"Today's total volume plus this transaction stays within the cap"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Daily Volume Cap — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.risk.daily_volume_cap

import rego.v1

# Rejects a transaction if adding it to today's volume would breach the daily cap. Uses sum() aggregate over the day's transaction amounts.

default allow := false

# Today's total volume plus this transaction stays within the cap
allow if {
    input.amount > 0
    input.daily_cap
    input.amount <= input.daily_cap
    sum(input.today_amounts) <= input.daily_cap
}
```

Sample sandbox input:

```json
{
  "amount": 200000,
  "daily_cap": 1000000,
  "today_amounts": [
    150000,
    250000,
    100000
  ]
}
```

</details>

---
<a id="policy-multi-sig-quorum-live"></a>

### 46. Multi-Sig Quorum (Live)

`Approvals` &nbsp;·&nbsp; package `digital_assets.approvals.multi_sig_quorum_live` &nbsp;·&nbsp; id `multi-sig-quorum-live`

Requires at least 3 valid signatures out of those submitted. Uses a filtered count aggregate: count(signatures where valid==true) ≥ 3.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - At least 3 valid signatures present and amount within threshold

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Initiator + approvers"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.approvals.multi_sig_quorum_live"}}
    pdp -->|"At least 3 valid signatures present and amount within threshold"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Multi-Sig Quorum — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.approvals.multi_sig_quorum_live

import rego.v1

# Requires at least 3 valid signatures out of those submitted. Uses a filtered count aggregate: count(signatures where valid==true) ≥ 3.

default allow := false

# At least 3 valid signatures present and amount within threshold
allow if {
    is_array(input.signatures)
    input.amount <= input.quorum_limit
    count([item | some item in input.signatures; item.valid == true]) >= 3
}
```

Sample sandbox input:

```json
{
  "amount": 75000,
  "quorum_limit": 250000,
  "signatures": [
    {
      "signer": "alice",
      "valid": true
    },
    {
      "signer": "bob",
      "valid": true
    },
    {
      "signer": "carol",
      "valid": true
    },
    {
      "signer": "dave",
      "valid": false
    }
  ]
}
```

</details>

---
<a id="policy-vesting-unlock-live"></a>

### 47. Vesting Unlock (Live Clock)

`Operations` &nbsp;·&nbsp; package `digital_assets.operations.vesting_unlock_live` &nbsp;·&nbsp; id `vesting-unlock-live`

Releases vested tokens only when the OPA server's wall clock has passed the unlock timestamp. Uses time.now_ns() compared directly to the unlock field — no pre-computed timestamp needed.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Cliff elapsed, beneficiary KYC live, no clawback, unlock time passed

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Operator"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.operations.vesting_unlock_live"}}
    pdp -->|"Cliff elapsed, beneficiary KYC live, no clawback, unlock time passed"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Vesting Unlock — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.operations.vesting_unlock_live

import rego.v1

# Releases vested tokens only when the OPA server's wall clock has passed the unlock timestamp. Uses time.now_ns() compared directly to the unlock field — no pre-computed timestamp needed.

default allow := false

# Cliff elapsed, beneficiary KYC live, no clawback, unlock time passed
allow if {
    input.beneficiary.kyc_status == "verified"
    input.clawback_active == false
    input.cliff_elapsed == true
    time.now_ns() >= input.unlock_ts_ns
}
```

Sample sandbox input:

```json
{
  "beneficiary": {
    "kyc_status": "verified"
  },
  "clawback_active": false,
  "cliff_elapsed": true,
  "unlock_ts_ns": 1782910276149000000
}
```

</details>

---
<a id="policy-business-hours-trading"></a>

### 48. Business Hours Trading Gate

`Trading` &nbsp;·&nbsp; package `digital_assets.trading.business_hours` &nbsp;·&nbsp; id `business-hours-trading`

Restricts trading to weekdays (Mon–Fri) between 08:00 and 17:00 UTC. Uses time.weekday() for the day check and standard numeric comparison for the hour field (caller supplies hour-of-day).

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Weekday AND within trading hours AND within per-session limit

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Trader"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.trading.business_hours"}}
    pdp -->|"Weekday AND within trading hours AND within per-session limit"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Business Hours Trading Gate — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.trading.business_hours

import rego.v1

# Restricts trading to weekdays (Mon–Fri) between 08:00 and 17:00 UTC. Uses time.weekday() for the day check and standard numeric comparison for the hour field (caller supplies hour-of-day).

default allow := false

# Weekday AND within trading hours AND within per-session limit
allow if {
    input.hour_utc >= 8
    input.hour_utc < 17
    input.amount <= input.session_limit
    _allow_b0_g1
}

_allow_b0_g1 if {
    time.weekday(input.ts_ns) == "Monday"
}
_allow_b0_g1 if {
    time.weekday(input.ts_ns) == "Tuesday"
}
_allow_b0_g1 if {
    time.weekday(input.ts_ns) == "Wednesday"
}
_allow_b0_g1 if {
    time.weekday(input.ts_ns) == "Thursday"
}
_allow_b0_g1 if {
    time.weekday(input.ts_ns) == "Friday"
}
```

Sample sandbox input:

```json
{
  "ts_ns": 1782913876149000000,
  "hour_utc": 10,
  "amount": 50000,
  "session_limit": 500000
}
```

</details>

---
<a id="policy-asset-symbol-normalized"></a>

### 49. Asset Symbol (Case-Insensitive)

`Compliance` &nbsp;·&nbsp; package `digital_assets.compliance.asset_symbol_normalized` &nbsp;·&nbsp; id `asset-symbol-normalized`

Accepts a trade only if the asset symbol normalises to an approved token, using lower() for case-insensitive matching. Demonstrates the lower_eq and upper_eq operators.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Symbol (case-normalised) is an approved token and amount is within tier limit

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Transacting user"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.compliance.asset_symbol_normalized"}}
    pdp -->|"Symbol (case-normalised) is an approved token and amount is within tier limit"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Asset Symbol — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.compliance.asset_symbol_normalized

import rego.v1

# Accepts a trade only if the asset symbol normalises to an approved token, using lower() for case-insensitive matching. Demonstrates the lower_eq and upper_eq operators.

default allow := false

# Symbol (case-normalised) is an approved token and amount is within tier limit
allow if {
    input.user.kyc_status == "verified"
    input.amount > 0
    input.amount <= 5000000
    _allow_b0_g1
}

_allow_b0_g1 if {
    lower(input.asset_symbol) == "eth"
}
_allow_b0_g1 if {
    lower(input.asset_symbol) == "btc"
}
_allow_b0_g1 if {
    lower(input.asset_symbol) == "usdc"
}
_allow_b0_g1 if {
    lower(input.asset_symbol) == "usdt"
}
```

Sample sandbox input:

```json
{
  "asset_symbol": "ETH",
  "amount": 1000,
  "user": {
    "kyc_status": "verified"
  }
}
```

</details>

---
<a id="policy-ip-allowlist-access"></a>

### 50. IP Allowlist (CIDR)

`Generic` &nbsp;·&nbsp; package `digital_assets.access.ip_allowlist` &nbsp;·&nbsp; id `ip-allowlist-access`

Restricts API or custody access to requests originating from within an approved CIDR range. Uses net.cidr_contains() for subnet membership. Two branches cover internal corporate and a secondary DR subnet.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Primary corporate network
  - DR / secondary network

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Caller"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.access.ip_allowlist"}}
    pdp -->|"Primary corporate network"| ok(["✅ allow = true → proceed"])
    pdp -->|"DR / secondary network"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: IP Allowlist — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.access.ip_allowlist

import rego.v1

# Restricts API or custody access to requests originating from within an approved CIDR range. Uses net.cidr_contains() for subnet membership. Two branches cover internal corporate and a secondary DR subnet.

default allow := false

# Primary corporate network
allow if {
    input.client_ip
    net.cidr_contains("10.0.0.0/8", input.client_ip)
    input.user.role in ["trader", "admin", "compliance"]
}

# DR / secondary network
allow if {
    input.client_ip
    net.cidr_contains("172.16.0.0/12", input.client_ip)
    input.user.role in ["admin"]
}
```

Sample sandbox input:

```json
{
  "client_ip": "10.1.2.3",
  "user": {
    "role": "trader"
  }
}
```

</details>

---
<a id="policy-input-type-guard"></a>

### 51. Input Type Guard

`Generic` &nbsp;·&nbsp; package `digital_assets.guards.input_types` &nbsp;·&nbsp; id `input-type-guard`

Validates the shape of the input document before any numeric policy runs. Ensures amount, user_id, and metadata are the expected types. Prevents type-confusion exploits and compiler errors.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Input has the correct types for all required fields
  - Structured payload variant — metadata must be an object

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Caller"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.guards.input_types"}}
    pdp -->|"Input has the correct types for all required fields"| ok(["✅ allow = true → proceed"])
    pdp -->|"Structured payload variant — metadata must be an object"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Input Type Guard — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.guards.input_types

import rego.v1

# Validates the shape of the input document before any numeric policy runs. Ensures amount, user_id, and metadata are the expected types. Prevents type-confusion exploits and compiler errors.

default allow := false

# Input has the correct types for all required fields
allow if {
    is_number(input.amount)
    is_string(input.user_id)
    input.amount > 0
    input.amount <= 10000000
    input.user_id != ""
}

# Structured payload variant — metadata must be an object
allow if {
    is_number(input.amount)
    is_string(input.user_id)
    is_object(input.metadata)
    is_array(input.line_items)
    input.amount > 0
    input.metadata.version
}
```

Sample sandbox input:

```json
{
  "amount": 5000,
  "user_id": "usr-001",
  "metadata": {
    "version": "1.0"
  },
  "line_items": []
}
```

</details>

---
<a id="policy-partial-risk-violations"></a>

### 52. Partial Set: Risk Violations

`Compliance` &nbsp;·&nbsp; package `digital_assets.compliance.risk_violations` &nbsp;·&nbsp; id `partial-risk-violations`

Accumulates compliance violations into a set using OPA partial set rules. Each branch produces a distinct violation code; allow is derived as violations being empty.

**Decision logic**

- **`violations`** — *partial set* (violation/reason collector). A member is added when:
  - Trade amount exceeds per-trade limit
  - Counterparty KYC status is not verified
  - Asset is not on the approved trading list
- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - No violations — all checks pass
- **`result`** — *result object* emitting `{ allow, rejection_reasons }` — Decision document — bundles the verdict and the rejection-reason set for the caller's audit log.

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Transacting user"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.compliance.risk_violations"}}
    pdp -->|"No violations — all checks pass"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
    ok --> doc[/"result = { allow, rejection_reasons }"/]
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Violations: one or more checks fail
    Evaluating --> Clean: violations = {}
    Clean --> Allowed: allow = true
    Violations --> Denied: reasons returned to caller
    Allowed --> Applied: Partial Set: Risk Violations — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> Recorded: result document written to caller audit log
    Applied --> [*]
    Rejected --> [*]
    Recorded --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.compliance.risk_violations

import rego.v1

# Accumulates compliance violations into a set using OPA partial set rules. Each branch produces a distinct violation code; allow is derived as violations being empty.

# Trade amount exceeds per-trade limit
violations contains "amount_exceeds_limit" if {
    input.amount > input.trade_limit
}

# Counterparty KYC status is not verified
violations contains "kyc_not_verified" if {
    input.counterparty.kyc_status != "verified"
}

# Asset is not on the approved trading list
violations contains "asset_not_allowed" if {
    not input.asset in ["BTC", "ETH", "USDC", "USDT", "SOL"]
}

default allow := false

# No violations — all checks pass
allow if {
    count(violations) == 0
}

# Decision document — bundles the verdict and the rejection-reason set for the caller's audit log.
result := {
    "allow": allow,
    "rejection_reasons": violations
}
```

Sample sandbox input:

```json
{
  "amount": 50000,
  "trade_limit": 100000,
  "counterparty": {
    "kyc_status": "verified"
  },
  "asset": "ETH"
}
```

</details>

---
<a id="policy-object-safe-config"></a>

### 53. Object.get: Safe Config Access

`Generic` &nbsp;·&nbsp; package `digital_assets.generic.object_safe_config` &nbsp;·&nbsp; id `object-safe-config`

Demonstrates safe key access with fallback defaults using object.get(). Prevents policy failures when optional input fields are absent.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Risk level within allowed values (default: low), amount within config max

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Caller"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.generic.object_safe_config"}}
    pdp -->|"Risk level within allowed values (default: low), amount within config max"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Object.get: Safe Config Access — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.generic.object_safe_config

import rego.v1

# Demonstrates safe key access with fallback defaults using object.get(). Prevents policy failures when optional input fields are absent.

default allow := false

# Risk level within allowed values (default: low), amount within config max
allow if {
    input.user.active == true
    object.get(input.config, "risk_level", "low") in ["low", "medium"]
    object.get(input.config, "max_tx_usd", 100000) >= input.amount
}
```

Sample sandbox input:

```json
{
  "user": {
    "active": true
  },
  "config": {
    "risk_level": "medium",
    "max_tx_usd": 500000
  },
  "amount": 75000
}
```

</details>

---
<a id="policy-set-permission-check"></a>

### 54. Set Intersection: Permission Check

`Generic` &nbsp;·&nbsp; package `digital_assets.generic.set_permission` &nbsp;·&nbsp; id `set-permission-check`

Verifies that the user holds at least one required role using Rego set intersection (&). Expert-mode template: edit conditions in the JSON Spec tab.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - User is active and holds at least one required role (set intersection non-empty)
  - Admin bypass — explicit admin role always grants access

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Caller"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.generic.set_permission"}}
    pdp -->|"User is active and holds at least one required role (set intersection non-empty)"| ok(["✅ allow = true → proceed"])
    pdp -->|"Admin bypass — explicit admin role always grants access"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Set Intersection: Permission Check — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.generic.set_permission

import rego.v1

# Verifies that the user holds at least one required role using Rego set intersection (&). Expert-mode template: edit conditions in the JSON Spec tab.

default allow := false

# User is active and holds at least one required role (set intersection non-empty)
allow if {
    input.user.active == true
    user_roles := {r | some r in input.user.roles}
    required_roles := {"trade", "execute"}
    count(user_roles & required_roles) > 0
}

# Admin bypass — explicit admin role always grants access
allow if {
    input.user.active == true
    "admin" in input.user.roles
}
```

Sample sandbox input:

```json
{
  "user": {
    "active": true,
    "roles": [
      "trade",
      "view"
    ]
  }
}
```

</details>

---
<a id="policy-jwt-claims-verify"></a>

### 55. JWT Claims Verification

`Generic` &nbsp;·&nbsp; package `digital_assets.generic.jwt_claims` &nbsp;·&nbsp; id `jwt-claims-verify`

Structurally decodes a JWT and verifies subject and expiry claims using io.jwt.decode(). Expert-mode template: edit in the JSON Spec tab.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - JWT decodes successfully, subject matches user_id, token not expired

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Caller"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.generic.jwt_claims"}}
    pdp -->|"JWT decodes successfully, subject matches user_id, token not expired"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: JWT Claims Verification — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.generic.jwt_claims

import rego.v1

# Structurally decodes a JWT and verifies subject and expiry claims using io.jwt.decode(). Expert-mode template: edit in the JSON Spec tab.

default allow := false

# JWT decodes successfully, subject matches user_id, token not expired
allow if {
    input.jwt_token
    input.user_id
    [_, payload, _] := io.jwt.decode(input.jwt_token)
    payload.sub == input.user_id
    payload.exp > time.now_ns() / 1000000000
}
```

Sample sandbox input:

```json
{
  "jwt_token": "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c3ItMDAxIiwiZXhwIjo5OTk5OTk5OTk5fQ.",
  "user_id": "usr-001"
}
```

</details>

---
<a id="policy-partial-batch-validation"></a>

### 56. Partial Set: Batch Validation

`Operations` &nbsp;·&nbsp; package `digital_assets.operations.batch_validation` &nbsp;·&nbsp; id `partial-batch-validation`

Collects all batch validation failures into a set using partial set rules. Checks batch size, submitter authorization, and individual transaction count.

**Decision logic**

- **`batch_violations`** — *partial set* (violation/reason collector). A member is added when:
  - Batch contains no transactions
  - Batch exceeds maximum allowed size
  - Submitter is not authorized to submit batches
- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - No batch violations detected
- **`result`** — *result object* emitting `{ allow, rejection_reasons }` — Decision document — bundles the verdict and the rejection-reason set (batch_violations) for the caller's audit log.

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Operator"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.digital_assets.operations.batch_validation"}}
    pdp -->|"No batch violations detected"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
    ok --> doc[/"result = { allow, rejection_reasons }"/]
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Violations: one or more checks fail
    Evaluating --> Clean: batch_violations = {}
    Clean --> Allowed: allow = true
    Violations --> Denied: reasons returned to caller
    Allowed --> Applied: Partial Set: Batch Validation — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> Recorded: result document written to caller audit log
    Applied --> [*]
    Rejected --> [*]
    Recorded --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package digital_assets.operations.batch_validation

import rego.v1

# Collects all batch validation failures into a set using partial set rules. Checks batch size, submitter authorization, and individual transaction count.

# Batch contains no transactions
batch_violations contains "empty_batch" if {
    count(input.transactions) == 0
}

# Batch exceeds maximum allowed size
batch_violations contains "batch_too_large" if {
    count(input.transactions) > input.max_batch_size
}

# Submitter is not authorized to submit batches
batch_violations contains "unauthorized_submitter" if {
    input.submitter.authorized != true
}

default allow := false

# No batch violations detected
allow if {
    count(batch_violations) == 0
}

# Decision document — bundles the verdict and the rejection-reason set (batch_violations) for the caller's audit log.
result := {
    "allow": allow,
    "rejection_reasons": batch_violations
}
```

Sample sandbox input:

```json
{
  "max_batch_size": 100,
  "submitter": {
    "authorized": true
  },
  "transactions": [
    {
      "id": "tx-1",
      "amount": 10000
    },
    {
      "id": "tx-2",
      "amount": 25000
    }
  ]
}
```

</details>

---

---

## SaaS Multi-Tenancy

Source: [`backend/src/templates/saasMultitenant.js`](../backend/src/templates/saasMultitenant.js) · 10 policies.

Tenant-isolation building blocks for a multi-tenant SaaS: resource scoping, provisioning, org/domain/group membership, role assignment, user lifecycle, cross-org sharing, and platform-admin break-glass.

<a id="policy-mt-tenant-isolation"></a>

### 57. Tenant Resource Isolation

`Multitenancy` &nbsp;·&nbsp; package `saas.multitenancy.tenant_isolation` &nbsp;·&nbsp; id `mt-tenant-isolation`

Core tenant scoping gate: users can only access resources within their own tenant. Tenant must be active and not suspended. Platform admins get a read-only override (MFA required) for operational support.

**Decision logic**

- **`malformed_inputs`** — *partial set* (violation/reason collector) — Set of malformed-input reasons. Non-empty → allow denies and the caller sees the reasons. A member is added when:
  - input.user.tenant_id is missing or not a string
  - input.user.active is missing or not a boolean
  - input.action is missing or not a string
- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - User in same tenant, both active, tenant not suspended
  - Platform admin read-only cross-tenant override (MFA required)
- **`result`** — *result object* emitting `{ allow, rejection_reasons }` — Decision document — bundles the verdict and any malformed-input reasons for the caller's audit log.

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Tenant user"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.saas.multitenancy.tenant_isolation"}}
    pdp -->|"User in same tenant, both active, tenant not suspended"| ok(["✅ allow = true → proceed"])
    pdp -->|"Platform admin read-only cross-tenant override (MFA required)"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
    ok --> doc[/"result = { allow, rejection_reasons }"/]
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Violations: one or more checks fail
    Evaluating --> Clean: malformed_inputs = {}
    Clean --> Allowed: allow = true
    Violations --> Denied: reasons returned to caller
    Allowed --> Applied: Tenant Resource Isolation — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> Recorded: result document written to caller audit log
    Applied --> [*]
    Rejected --> [*]
    Recorded --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package saas.multitenancy.tenant_isolation

import rego.v1

# Core tenant scoping gate: users can only access resources within their own tenant. Tenant must be active and not suspended. Platform admins get a read-only override (MFA required) for operational support.

# Set of malformed-input reasons. Non-empty → allow denies and the caller sees the reasons.
# input.user.tenant_id is missing or not a string
malformed_inputs contains "malformed_request" if {
    not is_string(object.get(object.get(input, "user", {}), "tenant_id", null))
}

# input.user.active is missing or not a boolean
malformed_inputs contains "malformed_request" if {
    not is_boolean(object.get(object.get(input, "user", {}), "active", null))
}

# input.action is missing or not a string
malformed_inputs contains "malformed_request" if {
    not is_string(object.get(input, "action", null))
}

default allow := false

# User in same tenant, both active, tenant not suspended
allow if {
    count(malformed_inputs) == 0
    input.user.tenant_id == input.resource.tenant_id
    input.user.active == true
    input.tenant.status == "active"
    input.tenant.suspended == false
}

# Platform admin read-only cross-tenant override (MFA required)
allow if {
    count(malformed_inputs) == 0
    input.user.platform_role == "platform_admin"
    input.user.mfa_verified == true
    input.action in ["read", "list", "audit"]
}

# Decision document — bundles the verdict and any malformed-input reasons for the caller's audit log.
result := {
    "allow": allow,
    "rejection_reasons": malformed_inputs
}
```

Sample sandbox input:

```json
{
  "user": {
    "tenant_id": "tenant-abc",
    "active": true,
    "platform_role": null,
    "mfa_verified": false
  },
  "resource": {
    "tenant_id": "tenant-abc"
  },
  "tenant": {
    "status": "active",
    "suspended": false
  },
  "action": "read"
}
```

</details>

---
<a id="policy-mt-tenant-provisioning"></a>

### 58. Tenant Provisioning & Lifecycle

`Multitenancy` &nbsp;·&nbsp; package `saas.multitenancy.tenant_provisioning` &nbsp;·&nbsp; id `mt-tenant-provisioning`

Controls who can create, update, archive, and deactivate tenants. Creation is platform-admin-only with quota enforcement. Updates are owned by the tenant owner. Archival/deactivation requires platform admin sign-off with a recorded reason.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Create: platform admin + MFA + tenant quota not breached
  - Update: tenant owner within their own tenant, account active
  - Archive or deactivate: platform admin + approval signed + reason on file

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Tenant user"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.saas.multitenancy.tenant_provisioning"}}
    pdp -->|"Create: platform admin + MFA + tenant quota not breached"| ok(["✅ allow = true → proceed"])
    pdp -->|"Update: tenant owner within their own tenant, account active"| ok(["✅ allow = true → proceed"])
    pdp -->|"Archive or deactivate: platform admin + approval signed + reason on file"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Tenant Provisioning and Lifecycle — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package saas.multitenancy.tenant_provisioning

import rego.v1

# Controls who can create, update, archive, and deactivate tenants. Creation is platform-admin-only with quota enforcement. Updates are owned by the tenant owner. Archival/deactivation requires platform admin sign-off with a recorded reason.

default allow := false

# Create: platform admin + MFA + tenant quota not breached
allow if {
    input.action == "create"
    input.actor.platform_role == "platform_admin"
    input.actor.mfa_verified == true
    input.platform.tenant_count < input.platform.tenant_quota
}

# Update: tenant owner within their own tenant, account active
allow if {
    input.action == "update"
    input.actor.role == "tenant_owner"
    input.actor.tenant_id == input.target_tenant.id
    input.actor.active == true
}

# Archive or deactivate: platform admin + approval signed + reason on file
allow if {
    input.action in ["deactivate", "archive"]
    input.actor.platform_role == "platform_admin"
    input.actor.mfa_verified == true
    input.approval.signed == true
    input.approval.reason
}
```

Sample sandbox input:

```json
{
  "action": "create",
  "actor": {
    "platform_role": "platform_admin",
    "mfa_verified": true,
    "role": "platform_admin",
    "tenant_id": null,
    "active": true,
    "id": "admin-001"
  },
  "platform": {
    "tenant_count": 42,
    "tenant_quota": 100
  },
  "target_tenant": {
    "id": "tenant-xyz"
  },
  "approval": {
    "signed": false,
    "reason": null
  }
}
```

</details>

---
<a id="policy-mt-org-member-access"></a>

### 59. Organization Member Access

`Multitenancy` &nbsp;·&nbsp; package `saas.multitenancy.org_member_access` &nbsp;·&nbsp; id `mt-org-member-access`

Resource access gated on org membership within a tenant. Uses AND-of-ORs: (org_admin OR org_member OR org_viewer) AND (tenant + org scope + user active). Write actions require at least org_member; archive/manage actions require org_admin.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Read/list: any org role, full tenant + org scope enforced
  - Write/update: org_admin or org_member, same tenant + org
  - Archive/manage members: org_admin only, same tenant + org

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Tenant user"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.saas.multitenancy.org_member_access"}}
    pdp -->|"Read/list: any org role, full tenant + org scope enforced"| ok(["✅ allow = true → proceed"])
    pdp -->|"Write/update: org_admin or org_member, same tenant + org"| ok(["✅ allow = true → proceed"])
    pdp -->|"Archive/manage members: org_admin only, same tenant + org"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Organization Member Access — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package saas.multitenancy.org_member_access

import rego.v1

# Resource access gated on org membership within a tenant. Uses AND-of-ORs: (org_admin OR org_member OR org_viewer) AND (tenant + org scope + user active). Write actions require at least org_member; archive/manage actions require org_admin.

default allow := false

# Read/list: any org role, full tenant + org scope enforced
allow if {
    _allow_b0_g0
    input.user.tenant_id == input.resource.tenant_id
    input.user.org_id == input.resource.org_id
    input.user.active == true
    input.org.active == true
    input.action in ["read", "list", "describe"]
}

# Write/update: org_admin or org_member, same tenant + org
allow if {
    _allow_b1_g0
    input.user.tenant_id == input.resource.tenant_id
    input.user.org_id == input.resource.org_id
    input.user.active == true
    input.org.active == true
    input.action in ["create", "update", "write"]
}

# Archive/manage members: org_admin only, same tenant + org
allow if {
    input.user.org_role == "org_admin"
    input.user.tenant_id == input.resource.tenant_id
    input.user.org_id == input.resource.org_id
    input.user.active == true
    input.action in ["archive", "manage_members"]
}

_allow_b0_g0 if {
    input.user.org_role == "org_admin"
}
_allow_b0_g0 if {
    input.user.org_role == "org_member"
}
_allow_b0_g0 if {
    input.user.org_role == "org_viewer"
}
_allow_b1_g0 if {
    input.user.org_role == "org_admin"
}
_allow_b1_g0 if {
    input.user.org_role == "org_member"
}
```

Sample sandbox input:

```json
{
  "user": {
    "tenant_id": "tenant-abc",
    "org_id": "org-001",
    "org_role": "org_member",
    "active": true
  },
  "resource": {
    "tenant_id": "tenant-abc",
    "org_id": "org-001"
  },
  "org": {
    "active": true
  },
  "action": "read"
}
```

</details>

---
<a id="policy-mt-domain-resource-gate"></a>

### 60. Domain-Scoped Resource Access

`Multitenancy` &nbsp;·&nbsp; package `saas.multitenancy.domain_access` &nbsp;·&nbsp; id `mt-domain-resource-gate`

Resources belong to domains within an org. Access requires domain membership and a compatible domain role, or a cross-domain elevated role (org_admin / tenant_admin) within the same tenant. Archived and restricted domains are blocked.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Domain member — tenant + org + domain scope all match, domain active
  - Cross-domain elevated role: org_admin or tenant_admin, same tenant, domain not restricted

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Tenant user"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.saas.multitenancy.domain_access"}}
    pdp -->|"Domain member — tenant + org + domain scope all match, domain active"| ok(["✅ allow = true → proceed"])
    pdp -->|"Cross-domain elevated role: org_admin or tenant_admin, same tenant, domain not restricted"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Domain-Scoped Resource Access — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package saas.multitenancy.domain_access

import rego.v1

# Resources belong to domains within an org. Access requires domain membership and a compatible domain role, or a cross-domain elevated role (org_admin / tenant_admin) within the same tenant. Archived and restricted domains are blocked.

default allow := false

# Domain member — tenant + org + domain scope all match, domain active
allow if {
    input.user.tenant_id == input.resource.tenant_id
    input.user.org_id == input.resource.org_id
    input.user.domain_id == input.resource.domain_id
    input.user.active == true
    input.domain.status == "active"
    _allow_b0_g1
}

# Cross-domain elevated role: org_admin or tenant_admin, same tenant, domain not restricted
allow if {
    input.user.tenant_id == input.resource.tenant_id
    input.user.active == true
    input.domain.restricted == false
    _allow_b1_g1
}

_allow_b0_g1 if {
    input.action in ["read", "list"]
}
_allow_b0_g1 if {
    input.user.domain_role in ["domain_editor", "domain_admin"]
}
_allow_b1_g1 if {
    input.user.role == "org_admin"
}
_allow_b1_g1 if {
    input.user.role == "tenant_admin"
}
```

Sample sandbox input:

```json
{
  "user": {
    "tenant_id": "tenant-abc",
    "org_id": "org-001",
    "domain_id": "domain-us",
    "domain_role": "domain_editor",
    "role": "org_member",
    "active": true
  },
  "resource": {
    "tenant_id": "tenant-abc",
    "org_id": "org-001",
    "domain_id": "domain-us"
  },
  "domain": {
    "status": "active",
    "restricted": false
  },
  "action": "read"
}
```

</details>

---
<a id="policy-mt-group-permission-check"></a>

### 61. Group Permission Enforcement

`Multitenancy` &nbsp;·&nbsp; package `saas.multitenancy.group_permissions` &nbsp;·&nbsp; id `mt-group-permission-check`

Permission is derived from group membership. Uses set intersection to verify the user's group grants at least one required permission for the requested action. User, group, and org must all be active within the same tenant. A super_admin role bypasses the group check.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Group grants at least one required permission (set intersection non-empty)
  - Super-admin bypass — explicit super_admin role in the user's roles set

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Tenant user"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.saas.multitenancy.group_permissions"}}
    pdp -->|"Group grants at least one required permission (set intersection non-empty)"| ok(["✅ allow = true → proceed"])
    pdp -->|"Super-admin bypass — explicit super_admin role in the user's roles set"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Group Permission Enforcement — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package saas.multitenancy.group_permissions

import rego.v1

# Permission is derived from group membership. Uses set intersection to verify the user's group grants at least one required permission for the requested action. User, group, and org must all be active within the same tenant. A super_admin role bypasses the group check.

default allow := false

# Group grants at least one required permission (set intersection non-empty)
allow if {
    input.user.active == true
    input.group.active == true
    input.user.tenant_id == input.resource.tenant_id
    input.user.group_id == input.group.id
    granted_perms  := {p | some p in input.group.permissions}
    required_perms := {p | some p in input.required_permissions}
    count(granted_perms & required_perms) > 0
}

# Super-admin bypass — explicit super_admin role in the user's roles set
allow if {
    input.user.active == true
    input.user.tenant_id == input.resource.tenant_id
    "super_admin" in input.user.roles
}
```

Sample sandbox input:

```json
{
  "user": {
    "active": true,
    "tenant_id": "tenant-abc",
    "group_id": "grp-traders",
    "roles": []
  },
  "group": {
    "id": "grp-traders",
    "active": true,
    "permissions": [
      "view_portfolio",
      "submit_order",
      "view_reports"
    ]
  },
  "resource": {
    "tenant_id": "tenant-abc"
  },
  "required_permissions": [
    "submit_order"
  ]
}
```

</details>

---
<a id="policy-mt-role-assignment-guard"></a>

### 62. Role Assignment Guard

`Multitenancy` &nbsp;·&nbsp; package `saas.multitenancy.role_assignment` &nbsp;·&nbsp; id `mt-role-assignment-guard`

Controls who can assign or revoke roles. Assignments must stay within the same tenant; an assigner can only grant roles equal to or below their own privilege level. Self-assignment is blocked. Platform admins can assign cross-tenant (requires MFA + audit ticket).

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Org admin assigns member/viewer roles — same tenant + same org, no self-assign
  - Tenant owner assigns any non-owner role — same tenant, MFA, no self-assign
  - Platform admin — cross-tenant role assignment, MFA + audit ticket required

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Tenant user"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.saas.multitenancy.role_assignment"}}
    pdp -->|"Org admin assigns member/viewer roles — same tenant + same org, no self-assign"| ok(["✅ allow = true → proceed"])
    pdp -->|"Tenant owner assigns any non-owner role — same tenant, MFA, no self-assign"| ok(["✅ allow = true → proceed"])
    pdp -->|"Platform admin — cross-tenant role assignment, MFA + audit ticket required"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Role Assignment Guard — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package saas.multitenancy.role_assignment

import rego.v1

# Controls who can assign or revoke roles. Assignments must stay within the same tenant; an assigner can only grant roles equal to or below their own privilege level. Self-assignment is blocked. Platform admins can assign cross-tenant (requires MFA + audit ticket).

default allow := false

# Org admin assigns member/viewer roles — same tenant + same org, no self-assign
allow if {
    input.action in ["assign_role", "revoke_role"]
    input.assigner.role == "org_admin"
    input.assigner.tenant_id == input.target_user.tenant_id
    input.assigner.org_id == input.target_user.org_id
    input.target_role.name in ["org_member", "org_viewer", "domain_editor", "domain_viewer"]
    input.assigner.id != input.target_user.id
}

# Tenant owner assigns any non-owner role — same tenant, MFA, no self-assign
allow if {
    input.action in ["assign_role", "revoke_role"]
    input.assigner.role == "tenant_owner"
    input.assigner.tenant_id == input.target_user.tenant_id
    input.assigner.mfa_verified == true
    input.target_role.name in ["org_admin", "org_member", "org_viewer", "tenant_admin", "domain_admin", "domain_editor", "domain_viewer"]
    input.assigner.id != input.target_user.id
}

# Platform admin — cross-tenant role assignment, MFA + audit ticket required
allow if {
    input.action in ["assign_role", "revoke_role"]
    input.assigner.platform_role == "platform_admin"
    input.assigner.mfa_verified == true
    input.audit.ticket_id
}
```

Sample sandbox input:

```json
{
  "action": "assign_role",
  "assigner": {
    "role": "org_admin",
    "tenant_id": "tenant-abc",
    "org_id": "org-001",
    "mfa_verified": true,
    "id": "user-admin",
    "platform_role": null
  },
  "target_user": {
    "tenant_id": "tenant-abc",
    "org_id": "org-001",
    "id": "user-bob"
  },
  "target_role": {
    "name": "org_member"
  },
  "audit": {
    "ticket_id": null
  }
}
```

</details>

---
<a id="policy-mt-user-lifecycle"></a>

### 63. User Lifecycle Management

`Multitenancy` &nbsp;·&nbsp; package `saas.multitenancy.user_lifecycle` &nbsp;·&nbsp; id `mt-user-lifecycle`

Controls invite, activate, deactivate, archive, and promote actions on user accounts. Each action requires a specific actor role and scope. Actors cannot modify users with a higher privilege level, and self-mutations are blocked.

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Invite: org_admin or above, same tenant, seat quota not exceeded
  - Activate: org_admin or above, same tenant, not self
  - Deactivate: org_admin or above, same tenant, not self, target is non-admin
  - Archive: tenant_owner + MFA, same tenant, not self
  - Promote: tenant_owner + MFA, same tenant, not self, target role is an admin tier

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Tenant user"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.saas.multitenancy.user_lifecycle"}}
    pdp -->|"Invite: org_admin or above, same tenant, seat quota not exceeded"| ok(["✅ allow = true → proceed"])
    pdp -->|"Activate: org_admin or above, same tenant, not self"| ok(["✅ allow = true → proceed"])
    pdp -->|"Deactivate: org_admin or above, same tenant, not self, target is non-admin"| ok(["✅ allow = true → proceed"])
    pdp -->|"Archive: tenant_owner + MFA, same tenant, not self"| ok(["✅ allow = true → proceed"])
    pdp -->|"Promote: tenant_owner + MFA, same tenant, not self, target role is an admin tier"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: User Lifecycle Management — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package saas.multitenancy.user_lifecycle

import rego.v1

# Controls invite, activate, deactivate, archive, and promote actions on user accounts. Each action requires a specific actor role and scope. Actors cannot modify users with a higher privilege level, and self-mutations are blocked.

default allow := false

# Invite: org_admin or above, same tenant, seat quota not exceeded
allow if {
    input.action == "invite"
    input.actor.role in ["org_admin", "tenant_admin", "tenant_owner"]
    input.actor.tenant_id == input.target_tenant.id
    input.actor.active == true
    input.tenant.seats_used < input.tenant.seats_quota
}

# Activate: org_admin or above, same tenant, not self
allow if {
    input.action == "activate"
    input.actor.role in ["org_admin", "tenant_admin", "tenant_owner"]
    input.actor.tenant_id == input.target_user.tenant_id
    input.actor.active == true
    input.actor.id != input.target_user.id
}

# Deactivate: org_admin or above, same tenant, not self, target is non-admin
allow if {
    input.action == "deactivate"
    input.actor.role in ["org_admin", "tenant_admin", "tenant_owner"]
    input.actor.tenant_id == input.target_user.tenant_id
    input.actor.id != input.target_user.id
    input.target_user.role in ["org_member", "org_viewer", "domain_editor", "domain_viewer"]
}

# Archive: tenant_owner + MFA, same tenant, not self
allow if {
    input.action == "archive"
    input.actor.role == "tenant_owner"
    input.actor.tenant_id == input.target_user.tenant_id
    input.actor.mfa_verified == true
    input.actor.id != input.target_user.id
}

# Promote: tenant_owner + MFA, same tenant, not self, target role is an admin tier
allow if {
    input.action == "promote"
    input.actor.role == "tenant_owner"
    input.actor.tenant_id == input.target_user.tenant_id
    input.actor.mfa_verified == true
    input.actor.id != input.target_user.id
    input.new_role in ["org_admin", "tenant_admin", "domain_admin"]
}
```

Sample sandbox input:

```json
{
  "action": "invite",
  "actor": {
    "role": "org_admin",
    "tenant_id": "tenant-abc",
    "active": true,
    "mfa_verified": true,
    "id": "admin-001"
  },
  "target_tenant": {
    "id": "tenant-abc"
  },
  "target_user": {
    "tenant_id": "tenant-abc",
    "role": "org_member",
    "id": "user-new"
  },
  "tenant": {
    "seats_used": 8,
    "seats_quota": 50
  },
  "new_role": null
}
```

</details>

---
<a id="policy-mt-cross-org-sharing"></a>

### 64. Cross-Org Resource Sharing

`Multitenancy` &nbsp;·&nbsp; package `saas.multitenancy.cross_org_sharing` &nbsp;·&nbsp; id `mt-cross-org-sharing`

Within the same tenant, one org can share resources with another via a sharing agreement. Read access requires only an active share agreement. Write access additionally requires at least 2 approvals on the agreement (filtered count).

**Decision logic**

- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Cross-org read: active share agreement, resource marked shared, same tenant
  - Cross-org write: share agreement includes write access + quorum of 2 approvals

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Tenant user"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.saas.multitenancy.cross_org_sharing"}}
    pdp -->|"Cross-org read: active share agreement, resource marked shared, same tenant"| ok(["✅ allow = true → proceed"])
    pdp -->|"Cross-org write: share agreement includes write access + quorum of 2 approvals"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Cross-Org Resource Sharing — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package saas.multitenancy.cross_org_sharing

import rego.v1

# Within the same tenant, one org can share resources with another via a sharing agreement. Read access requires only an active share agreement. Write access additionally requires at least 2 approvals on the agreement (filtered count).

default allow := false

# Cross-org read: active share agreement, resource marked shared, same tenant
allow if {
    input.user.tenant_id == input.resource.tenant_id
    input.user.active == true
    input.resource.shared == true
    input.share_agreement.active == true
    input.share_agreement.from_org_id == input.resource.org_id
    input.share_agreement.to_org_id == input.user.org_id
    input.action in ["read", "list"]
}

# Cross-org write: share agreement includes write access + quorum of 2 approvals
allow if {
    input.user.tenant_id == input.resource.tenant_id
    input.user.active == true
    input.resource.shared == true
    input.share_agreement.active == true
    input.share_agreement.write_access == true
    input.action in ["create", "update"]
    count([item | some item in input.share_agreement.approvers; item.approved == true]) >= 2
}
```

Sample sandbox input:

```json
{
  "user": {
    "tenant_id": "tenant-abc",
    "org_id": "org-002",
    "active": true
  },
  "resource": {
    "tenant_id": "tenant-abc",
    "org_id": "org-001",
    "shared": true,
    "cross_org_shared": true
  },
  "share_agreement": {
    "active": true,
    "from_org_id": "org-001",
    "to_org_id": "org-002",
    "write_access": false,
    "approvers": [
      {
        "name": "alice",
        "approved": true
      },
      {
        "name": "bob",
        "approved": true
      }
    ]
  },
  "action": "read"
}
```

</details>

---
<a id="policy-mt-access-violations"></a>

### 65. Multitenant Access Violation Collector

`Multitenancy` &nbsp;·&nbsp; package `saas.multitenancy.access_violations` &nbsp;·&nbsp; id `mt-access-violations`

Accumulates all violated access-control gates into a set using partial set rules. Covers: tenant mismatch, inactive user, org non-membership, domain restriction, permission denial (set intersection), and archived resource. The allow rule derives from violations being empty.

**Decision logic**

- **`violations`** — *partial set* (violation/reason collector). A member is added when:
  - input.user.tenant_id is missing or not a string
  - input.user.active is missing or not a boolean
  - input.user.org_id is missing or not a string
  - input.user.domain_id is missing or not a string
  - input.user.permissions is missing or not an array
  - input.resource.tenant_id is missing or not a string
  - input.resource.org_id is missing or not a string
  - input.resource.domain_id is missing or not a string
  - input.resource.cross_org_shared is missing or not a boolean
  - input.resource.archived is missing or not a boolean
  - input.domain.restricted is missing or not a boolean
  - input.required_permissions is missing or not an array
  - User's tenant does not match resource's tenant
  - User account is inactive or suspended
  - User does not belong to the resource's org and no cross-org share is active
  - Resource domain is restricted and user is not a domain member
  - User's effective permissions do not satisfy any required permission
  - Target resource has been archived
- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - No access violations — all gates pass
- **`result`** — *result object* emitting `{ allow, rejection_reasons }` — Decision document — bundles the verdict and the rejection-reason set for the caller's audit log.

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Tenant user"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.saas.multitenancy.access_violations"}}
    pdp -->|"No access violations — all gates pass"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
    ok --> doc[/"result = { allow, rejection_reasons }"/]
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Violations: one or more checks fail
    Evaluating --> Clean: violations = {}
    Clean --> Allowed: allow = true
    Violations --> Denied: reasons returned to caller
    Allowed --> Applied: Multitenant Access Violation Collector — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> Recorded: result document written to caller audit log
    Applied --> [*]
    Rejected --> [*]
    Recorded --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package saas.multitenancy.access_violations

import rego.v1

# Accumulates all violated access-control gates into a set using partial set rules. Covers: tenant mismatch, inactive user, org non-membership, domain restriction, permission denial (set intersection), and archived resource. The allow rule derives from violations being empty.

# input.user.tenant_id is missing or not a string
violations contains "malformed_request" if {
    not is_string(object.get(object.get(input, "user", {}), "tenant_id", null))
}

# input.user.active is missing or not a boolean
violations contains "malformed_request" if {
    not is_boolean(object.get(object.get(input, "user", {}), "active", null))
}

# input.user.org_id is missing or not a string
violations contains "malformed_request" if {
    not is_string(object.get(object.get(input, "user", {}), "org_id", null))
}

# input.user.domain_id is missing or not a string
violations contains "malformed_request" if {
    not is_string(object.get(object.get(input, "user", {}), "domain_id", null))
}

# input.user.permissions is missing or not an array
violations contains "malformed_request" if {
    not is_array(object.get(object.get(input, "user", {}), "permissions", null))
}

# input.resource.tenant_id is missing or not a string
violations contains "malformed_request" if {
    not is_string(object.get(object.get(input, "resource", {}), "tenant_id", null))
}

# input.resource.org_id is missing or not a string
violations contains "malformed_request" if {
    not is_string(object.get(object.get(input, "resource", {}), "org_id", null))
}

# input.resource.domain_id is missing or not a string
violations contains "malformed_request" if {
    not is_string(object.get(object.get(input, "resource", {}), "domain_id", null))
}

# input.resource.cross_org_shared is missing or not a boolean
violations contains "malformed_request" if {
    not is_boolean(object.get(object.get(input, "resource", {}), "cross_org_shared", null))
}

# input.resource.archived is missing or not a boolean
violations contains "malformed_request" if {
    not is_boolean(object.get(object.get(input, "resource", {}), "archived", null))
}

# input.domain.restricted is missing or not a boolean
violations contains "malformed_request" if {
    not is_boolean(object.get(object.get(input, "domain", {}), "restricted", null))
}

# input.required_permissions is missing or not an array
violations contains "malformed_request" if {
    not is_array(object.get(input, "required_permissions", null))
}

# User's tenant does not match resource's tenant
violations contains "tenant_mismatch" if {
    input.user.tenant_id != input.resource.tenant_id
}

# User account is inactive or suspended
violations contains "user_inactive" if {
    input.user.active != true
}

# User does not belong to the resource's org and no cross-org share is active
violations contains "org_not_member" if {
    input.user.org_id != input.resource.org_id
    input.resource.cross_org_shared != true
}

# Resource domain is restricted and user is not a domain member
violations contains "domain_restricted" if {
    input.domain.restricted == true
    input.user.domain_id != input.resource.domain_id
}

# User's effective permissions do not satisfy any required permission
violations contains "permission_denied" if {
    granted  := {p | some p in input.user.permissions}
    required := {p | some p in input.required_permissions}
    count(granted & required) == 0
}

# Target resource has been archived
violations contains "resource_archived" if {
    input.resource.archived == true
}

default allow := false

# No access violations — all gates pass
allow if {
    count(violations) == 0
}

# Decision document — bundles the verdict and the rejection-reason set for the caller's audit log.
result := {
    "allow": allow,
    "rejection_reasons": violations
}
```

Sample sandbox input:

```json
{
  "user": {
    "tenant_id": "tenant-abc",
    "org_id": "org-001",
    "domain_id": "domain-us",
    "active": true,
    "permissions": [
      "view_portfolio",
      "submit_order"
    ]
  },
  "resource": {
    "tenant_id": "tenant-abc",
    "org_id": "org-001",
    "domain_id": "domain-us",
    "shared": false,
    "cross_org_shared": false,
    "archived": false
  },
  "domain": {
    "restricted": false
  },
  "required_permissions": [
    "submit_order"
  ]
}
```

</details>

---
<a id="policy-mt-platform-admin-access"></a>

### 66. Platform Admin Break-Glass Access

`Multitenancy` &nbsp;·&nbsp; package `saas.multitenancy.platform_admin_access` &nbsp;·&nbsp; id `mt-platform-admin-access`

Emergency cross-tenant access for platform support engineers. Requires platform_admin role, MFA, an open support ticket, at least one supervisor co-sign (filtered aggregate count), and restricts to read-only actions. A companion audit_required rule always fires for any platform admin action.

**Decision logic**

- **`malformed_inputs`** — *partial set* (violation/reason collector) — Set of malformed-input reasons. Non-empty → allow denies and the caller sees the reasons. A member is added when:
  - input.actor.platform_role is missing or not a string
  - input.actor.active is missing or not a boolean
  - input.actor.mfa_verified is missing or not a boolean
  - input.ticket.status is missing or not a string
  - input.ticket.id is missing or not a string
  - input.action is missing or not a string
  - input.ticket.approvals is missing or not an array
- **`allow`** — boolean, default `false`. Evaluates **true** if any of:
  - Break-glass: platform admin + MFA + open ticket + supervisor approved + read-only
- **`audit_required`** — boolean, default `true` — All platform admin actions must be logged — evaluates true whenever the actor is a platform admin. Evaluates **true** if any of:
  - Actor is a platform admin — always trigger audit logging
- **`result`** — *result object* emitting `{ allow, rejection_reasons, audit_required }` — Decision document — bundles the verdict and any malformed-input reasons for the caller's audit log.

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Tenant user"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.saas.multitenancy.platform_admin_access"}}
    pdp -->|"Break-glass: platform admin + MFA + open ticket + supervisor approved + read-only"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
    ok --> doc[/"result = { allow, rejection_reasons, audit_required }"/]
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Violations: one or more checks fail
    Evaluating --> Clean: malformed_inputs = {}
    Clean --> Allowed: allow = true
    Violations --> Denied: reasons returned to caller
    Allowed --> Applied: Platform Admin Break-Glass Access — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> Recorded: result document written to caller audit log
    Applied --> [*]
    Rejected --> [*]
    Recorded --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package saas.multitenancy.platform_admin_access

import rego.v1

# Emergency cross-tenant access for platform support engineers. Requires platform_admin role, MFA, an open support ticket, at least one supervisor co-sign (filtered aggregate count), and restricts to read-only actions. A companion audit_required rule always fires for any platform admin action.

# Set of malformed-input reasons. Non-empty → allow denies and the caller sees the reasons.
# input.actor.platform_role is missing or not a string
malformed_inputs contains "malformed_request" if {
    not is_string(object.get(object.get(input, "actor", {}), "platform_role", null))
}

# input.actor.active is missing or not a boolean
malformed_inputs contains "malformed_request" if {
    not is_boolean(object.get(object.get(input, "actor", {}), "active", null))
}

# input.actor.mfa_verified is missing or not a boolean
malformed_inputs contains "malformed_request" if {
    not is_boolean(object.get(object.get(input, "actor", {}), "mfa_verified", null))
}

# input.ticket.status is missing or not a string
malformed_inputs contains "malformed_request" if {
    not is_string(object.get(object.get(input, "ticket", {}), "status", null))
}

# input.ticket.id is missing or not a string
malformed_inputs contains "malformed_request" if {
    not is_string(object.get(object.get(input, "ticket", {}), "id", null))
}

# input.action is missing or not a string
malformed_inputs contains "malformed_request" if {
    not is_string(object.get(input, "action", null))
}

# input.ticket.approvals is missing or not an array
malformed_inputs contains "malformed_request" if {
    not is_array(object.get(object.get(input, "ticket", {}), "approvals", null))
}

default allow := false

# Break-glass: platform admin + MFA + open ticket + supervisor approved + read-only
allow if {
    count(malformed_inputs) == 0
    input.actor.platform_role == "platform_admin"
    input.actor.active == true
    input.actor.mfa_verified == true
    input.ticket.status == "open"
    input.ticket.id
    input.action in ["read", "list", "audit", "describe"]
    count([item | some item in input.ticket.approvals; item.role == "supervisor"; item.approved == true]) >= 1
}

# All platform admin actions must be logged — evaluates true whenever the actor is a platform admin
default audit_required := true

# Actor is a platform admin — always trigger audit logging
audit_required if {
    input.actor.platform_role == "platform_admin"
}

# Decision document — bundles the verdict and any malformed-input reasons for the caller's audit log.
result := {
    "allow": allow,
    "rejection_reasons": malformed_inputs,
    "audit_required": audit_required
}
```

Sample sandbox input:

```json
{
  "action": "read",
  "actor": {
    "platform_role": "platform_admin",
    "active": true,
    "mfa_verified": true,
    "id": "admin-001"
  },
  "ticket": {
    "id": "TICKET-4892",
    "status": "open",
    "approvals": [
      {
        "role": "supervisor",
        "approved": true,
        "approver_id": "sup-007"
      }
    ]
  }
}
```

</details>

---

---

## Trusted Auth (crypto)

Source: [`backend/src/templates/trustedAuth.js`](../backend/src/templates/trustedAuth.js) · 4 policies.

Policies that consume the platform **trust store** published at `data.studio.keys` — JWT gates, multi-tenant dynamic-`kid` routing, and webhook HMAC verification. Add the referenced `kid` on the **Trust keys** admin page before tokens will verify.

<a id="policy-trusted-jwt-gate"></a>

### 67. Trusted JWT Gate

`AuthN` &nbsp;·&nbsp; package `trusted_auth.jwt_gate` &nbsp;·&nbsp; id `trusted-jwt-gate`

Allow when input.token is a valid EdDSA JWT verified against trust key kid='platform-1'. Requires a non-revoked trust key with kid='platform-1' on the Trust Keys admin page before tokens will verify.

**Decision logic**

- **`allow`** — boolean, default `false` — Bearer token must be a valid EdDSA JWT signed by the platform's trust key. Evaluates **true** if any of:
  - Token verifies against data.studio.keys['platform-1']

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Client / caller"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.trusted_auth.jwt_gate"}}
    pdp -->|"Token verifies against data.studio.keys'platform-1'"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Trusted JWT Gate — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package trusted_auth.jwt_gate

import rego.v1

# Allow when input.token is a valid EdDSA JWT verified against trust key kid='platform-1'. Requires a non-revoked trust key with kid='platform-1' on the Trust Keys admin page before tokens will verify.

# Bearer token must be a valid EdDSA JWT signed by the platform's trust key
default allow := false

# Token verifies against data.studio.keys['platform-1']
allow if {
    [__verify_valid_1, __verify_header_1, __verify_payload_1] := io.jwt.decode_verify(input.token, {"alg": "EdDSA", "cert": data.studio.keys["platform-1"]})
    __verify_valid_1
    __verify_payload_1.exp
}
```

Sample sandbox input:

```json
{
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6InBsYXRmb3JtLTEifQ.eyJzdWIiOiJ1c2VyLTQyIiwiZXhwIjo5OTk5OTk5OTk5fQ.REPLACE_WITH_REAL_SIGNATURE"
}
```

</details>

---
<a id="policy-trusted-jwt-multitenant"></a>

### 68. Multi-Tenant JWT (dynamic kid)

`AuthN` &nbsp;·&nbsp; package `trusted_auth.multitenant` &nbsp;·&nbsp; id `trusted-jwt-multitenant`

Routes each request to a per-tenant trust key. The kid is taken from input.kid at evaluation time and looked up in data.studio.keys, so adding a new tenant is a Trust Keys CRUD action — no policy change needed. Useful for SaaS workloads where every tenant signs its own JWTs.

**Decision logic**

- **`allow`** — boolean, default `false` — JWT validates against the trust key keyed by input.kid. Evaluates **true** if any of:
  - Tenant's key (input.kid) signs the bearer JWT

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Client / caller"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.trusted_auth.multitenant"}}
    pdp -->|"Tenant's key (input.kid) signs the bearer JWT"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Multi-Tenant JWT — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package trusted_auth.multitenant

import rego.v1

# Routes each request to a per-tenant trust key. The kid is taken from input.kid at evaluation time and looked up in data.studio.keys, so adding a new tenant is a Trust Keys CRUD action — no policy change needed. Useful for SaaS workloads where every tenant signs its own JWTs.

# JWT validates against the trust key keyed by input.kid
default allow := false

# Tenant's key (input.kid) signs the bearer JWT
allow if {
    [__verify_valid_1, __verify_header_1, __verify_payload_1] := io.jwt.decode_verify(input.token, {"alg": "EdDSA", "cert": data.studio.keys[input.kid], "iss": "tenant", "aud": "studio"})
    __verify_valid_1
    __verify_payload_1.exp
}
```

Sample sandbox input:

```json
{
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6InRlbmFudC1hY21lIn0.eyJzdWIiOiJ1c2VyLTQyIiwiaXNzIjoidGVuYW50IiwiYXVkIjoic3R1ZGlvIiwiZXhwIjo5OTk5OTk5OTk5fQ.REPLACE_WITH_REAL_SIGNATURE",
  "kid": "tenant-acme"
}
```

</details>

---
<a id="policy-trusted-webhook-hmac"></a>

### 69. Webhook HMAC Signature

`AuthN` &nbsp;·&nbsp; package `trusted_auth.webhook` &nbsp;·&nbsp; id `trusted-webhook-hmac`

Allow when the inbound webhook body's HMAC-SHA256 signature matches the platform secret. The secret lives in the trust store at kid='webhook-1' (HS256 algorithm); rotate it from the Trust Keys admin page without redeploying. Expects the request to carry the raw payload and the hex-encoded signature.

**Decision logic**

- **`allow`** — boolean, default `false` — Computed HMAC equals the signature header (constant-time compare). Evaluates **true** if any of:
  - HMAC of input.payload using kid='webhook-1' matches input.signature

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Client / caller"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.trusted_auth.webhook"}}
    pdp -->|"HMAC of input.payload using kid='webhook-1' matches input.signature"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Allowed: a branch of allow matches
    Evaluating --> Denied: no branch matches (default)
    Allowed --> Applied: Webhook HMAC Signature — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> [*]
    Rejected --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package trusted_auth.webhook

import rego.v1

# Allow when the inbound webhook body's HMAC-SHA256 signature matches the platform secret. The secret lives in the trust store at kid='webhook-1' (HS256 algorithm); rotate it from the Trust Keys admin page without redeploying. Expects the request to carry the raw payload and the hex-encoded signature.

# Computed HMAC equals the signature header (constant-time compare)
default allow := false

# HMAC of input.payload using kid='webhook-1' matches input.signature
allow if {
    __verify_expected_1 := crypto.hmac.sha256(input.payload, data.studio.keys["webhook-1"])
    crypto.hmac.equal(__verify_expected_1, input.signature)
}
```

Sample sandbox input:

```json
{
  "payload": "{\"event\":\"payment.completed\",\"id\":\"evt_123\",\"amount\":4200}",
  "signature": "REPLACE_WITH_HEX_HMAC_SHA256_OF_PAYLOAD"
}
```

</details>

---
<a id="policy-trusted-jwt-with-amount-cap"></a>

### 70. Trusted JWT + Tier Amount Cap

`AuthN` &nbsp;·&nbsp; package `trusted_auth.tiered_jwt` &nbsp;·&nbsp; id `trusted-jwt-with-amount-cap`

Realistic combination: the caller must present a valid JWT signed by kid='platform-1' AND the request amount must be within the tier limit asserted in input.user.tier. Demonstrates layering business rules on top of cryptographic identity.

**Decision logic**

- **`malformed_inputs`** — *partial set* (violation/reason collector) — Set of malformed-input reasons. Non-empty → allow denies and the caller sees the reasons. A member is added when:
  - input.token is missing or not a string
  - input.user.tier is missing or not a string
  - input.amount is missing or not a number
- **`allow`** — boolean, default `false` — Valid JWT + tier-appropriate amount. Evaluates **true** if any of:
  - Retail tier under $10k with valid JWT
  - Pro tier under $250k with valid JWT
- **`result`** — *result object* emitting `{ allow, rejection_reasons }` — Decision document — bundles the verdict and any malformed-input reasons for the caller's audit log.

**Use-case scenario**

```mermaid
flowchart TD
    actor(["Client / caller"]) -->|submits| input["input document"]
    input --> pdp{{"Aegis Sentry → OPA<br/>data.trusted_auth.tiered_jwt"}}
    pdp -->|"Retail tier under $10k with valid JWT"| ok(["✅ allow = true → proceed"])
    pdp -->|"Pro tier under $250k with valid JWT"| ok(["✅ allow = true → proceed"])
    pdp -->|"no branch matches"| no(["⛔ default allow = false → blocked"])
    ok --> doc[/"result = { allow, rejection_reasons }"/]
```

**State — when the decision is applied**

```mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Evaluating: PDP receives input
    Evaluating --> Violations: one or more checks fail
    Evaluating --> Clean: malformed_inputs = {}
    Clean --> Allowed: allow = true
    Violations --> Denied: reasons returned to caller
    Allowed --> Applied: Trusted JWT + Tier Amount Cap — state committed
    Denied --> Rejected: action blocked, no state change
    Applied --> Recorded: result document written to caller audit log
    Applied --> [*]
    Rejected --> [*]
    Recorded --> [*]
```

<details><summary><b>Compiled Rego</b> (click to expand)</summary>

```rego
package trusted_auth.tiered_jwt

import rego.v1

# Realistic combination: the caller must present a valid JWT signed by kid='platform-1' AND the request amount must be within the tier limit asserted in input.user.tier. Demonstrates layering business rules on top of cryptographic identity.

# Set of malformed-input reasons. Non-empty → allow denies and the caller sees the reasons.
# input.token is missing or not a string
malformed_inputs contains "malformed_request" if {
    not is_string(object.get(input, "token", null))
}

# input.user.tier is missing or not a string
malformed_inputs contains "malformed_request" if {
    not is_string(object.get(object.get(input, "user", {}), "tier", null))
}

# input.amount is missing or not a number
malformed_inputs contains "malformed_request" if {
    not is_number(object.get(input, "amount", null))
}

# Valid JWT + tier-appropriate amount
default allow := false

# Retail tier under $10k with valid JWT
allow if {
    count(malformed_inputs) == 0
    [__verify_valid_1, __verify_header_1, __verify_payload_1] := io.jwt.decode_verify(input.token, {"alg": "EdDSA", "cert": data.studio.keys["platform-1"]})
    __verify_valid_1
    __verify_payload_1.exp
    input.user.tier == "retail"
    input.amount <= 10000
}

# Pro tier under $250k with valid JWT
allow if {
    count(malformed_inputs) == 0
    [__verify_valid_2, __verify_header_2, __verify_payload_2] := io.jwt.decode_verify(input.token, {"alg": "EdDSA", "cert": data.studio.keys["platform-1"]})
    __verify_valid_2
    __verify_payload_2.exp
    input.user.tier == "pro"
    input.amount <= 250000
}

# Decision document — bundles the verdict and any malformed-input reasons for the caller's audit log.
result := {
    "allow": allow,
    "rejection_reasons": malformed_inputs
}
```

Sample sandbox input:

```json
{
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6InBsYXRmb3JtLTEifQ.eyJzdWIiOiJ1c2VyLTQyIiwiZXhwIjo5OTk5OTk5OTk5fQ.REPLACE_WITH_REAL_SIGNATURE",
  "user": {
    "tier": "pro"
  },
  "amount": 50000
}
```

</details>

---
