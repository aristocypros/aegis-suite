// templates/trustedAuth.js
// CRY-03 demo templates — policies that consume the platform trust store
// published at `data.studio.keys`. Each template compiles to runnable Rego
// out of the box; to actually pass verification, an admin must first add the
// referenced kid via the "Trust keys" admin menu (paste a PEM/JWK, or point
// at a JWKS URL). Until a matching key exists, evaluation returns the rule's
// default (false / null result), so the seed is always safe to load.

export const templates = [
  // ──────────────────────────────────────────────────────────────────────────
  // SINGLE-TENANT JWT GATE
  // ──────────────────────────────────────────────────────────────────────────
  {
    id: "trusted-jwt-gate",
    name: "Trusted JWT Gate",
    category: "AuthN",
    description:
      "Allow when input.token is a valid EdDSA JWT verified against trust key kid='platform-1'. Requires a non-revoked trust key with kid='platform-1' on the Trust Keys admin page before tokens will verify.",
    package: "trusted_auth.jwt_gate",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        description: "Bearer token must be a valid EdDSA JWT signed by the platform's trust key",
        branches: [
          {
            description: "Token verifies against data.studio.keys['platform-1']",
            groups: [
              {
                mode: "and",
                conditions: [
                  {
                    condType: "verify",
                    kind: "jwt",
                    tokenRef: "input.token",
                    alg: "EdDSA",
                    keyRef: { source: "data.studio.keys", selector: "platform-1" },
                    constraints: { exp_required: true },
                  },
                ],
              },
            ],
          },
        ],
      },
    ],
  },

  // ──────────────────────────────────────────────────────────────────────────
  // MULTI-TENANT JWT — DYNAMIC KID SELECTION
  // ──────────────────────────────────────────────────────────────────────────
  {
    id: "trusted-jwt-multitenant",
    name: "Multi-Tenant JWT (dynamic kid)",
    category: "AuthN",
    description:
      "Routes each request to a per-tenant trust key. The kid is taken from input.kid at evaluation time and looked up in data.studio.keys, so adding a new tenant is a Trust Keys CRUD action — no policy change needed. Useful for SaaS workloads where every tenant signs its own JWTs.",
    package: "trusted_auth.multitenant",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        description: "JWT validates against the trust key keyed by input.kid",
        branches: [
          {
            description: "Tenant's key (input.kid) signs the bearer JWT",
            groups: [
              {
                mode: "and",
                conditions: [
                  {
                    condType: "verify",
                    kind: "jwt",
                    tokenRef: "input.token",
                    alg: "EdDSA",
                    keyRef: { source: "data.studio.keys", selector: "input.kid" },
                    constraints: { iss: "tenant", aud: "studio", exp_required: true },
                  },
                ],
              },
            ],
          },
        ],
      },
    ],
  },

  // ──────────────────────────────────────────────────────────────────────────
  // WEBHOOK HMAC VERIFICATION
  // ──────────────────────────────────────────────────────────────────────────
  {
    id: "trusted-webhook-hmac",
    name: "Webhook HMAC Signature",
    category: "AuthN",
    description:
      "Allow when the inbound webhook body's HMAC-SHA256 signature matches the platform secret. The secret lives in the trust store at kid='webhook-1' (HS256 algorithm); rotate it from the Trust Keys admin page without redeploying. Expects the request to carry the raw payload and the hex-encoded signature.",
    package: "trusted_auth.webhook",
    rules: [
      {
        name: "allow",
        type: "boolean",
        default: false,
        description: "Computed HMAC equals the signature header (constant-time compare)",
        branches: [
          {
            description: "HMAC of input.payload using kid='webhook-1' matches input.signature",
            groups: [
              {
                mode: "and",
                conditions: [
                  {
                    condType: "verify",
                    kind: "raw",
                    alg: "HS256",
                    payloadRef: "input.payload",
                    signatureRef: "input.signature",
                    keyRef: { source: "data.studio.keys", selector: "webhook-1" },
                  },
                ],
              },
            ],
          },
        ],
      },
    ],
  },

  // ──────────────────────────────────────────────────────────────────────────
  // JWT + BUSINESS RULE COMBO
  // ──────────────────────────────────────────────────────────────────────────
  {
    id: "trusted-jwt-with-amount-cap",
    name: "Trusted JWT + Tier Amount Cap",
    category: "AuthN",
    description:
      "Realistic combination: the caller must present a valid JWT signed by kid='platform-1' AND the request amount must be within the tier limit asserted in input.user.tier. Demonstrates layering business rules on top of cryptographic identity.",
    package: "trusted_auth.tiered_jwt",
    rules: [
      // ── Defensive: required-input type checks ──
      // Without these, missing input.user.tier or input.amount silently fail both branches; the caller
      // gets allow=false but cannot distinguish "wrong tier for amount" from "you forgot a field".
      {
        name: "malformed_inputs",
        kind: "partial_set",
        description: "Set of malformed-input reasons. Non-empty → allow denies and the caller sees the reasons.",
        branches: [
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.token is missing or not a string",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_string(object.get(input, "token", null))` }] }],
          },
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.user.tier is missing or not a string",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_string(object.get(object.get(input, "user", {}), "tier", null))` }] }],
          },
          {
            value: "malformed_request",
            valueType: "string",
            description: "input.amount is missing or not a number",
            groups: [{ mode: "and", conditions: [{ condType: "raw", rego: `not is_number(object.get(input, "amount", null))` }] }],
          },
        ],
      },
      {
        name: "allow",
        type: "boolean",
        default: false,
        description: "Valid JWT + tier-appropriate amount",
        branches: [
          {
            description: "Retail tier under $10k with valid JWT",
            groups: [
              {
                mode: "and",
                conditions: [
                  { condType: "arith", leftExpr: "count(malformed_inputs)", op: "==", right: 0, rightType: "number" },
                  {
                    condType: "verify",
                    kind: "jwt",
                    tokenRef: "input.token",
                    alg: "EdDSA",
                    keyRef: { source: "data.studio.keys", selector: "platform-1" },
                    constraints: { exp_required: true },
                  },
                  { left: "input.user.tier", op: "==", right: "retail", rightType: "string" },
                  { left: "input.amount", op: "<=", right: 10000, rightType: "number" },
                ],
              },
            ],
          },
          {
            description: "Pro tier under $250k with valid JWT",
            groups: [
              {
                mode: "and",
                conditions: [
                  { condType: "arith", leftExpr: "count(malformed_inputs)", op: "==", right: 0, rightType: "number" },
                  {
                    condType: "verify",
                    kind: "jwt",
                    tokenRef: "input.token",
                    alg: "EdDSA",
                    keyRef: { source: "data.studio.keys", selector: "platform-1" },
                    constraints: { exp_required: true },
                  },
                  { left: "input.user.tier", op: "==", right: "pro", rightType: "string" },
                  { left: "input.amount", op: "<=", right: 250000, rightType: "number" },
                ],
              },
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
];

// Sample inputs shown in the sandbox. The JWTs are placeholders that won't
// verify (no matching private key) — the point is to give the user a
// runnable shape to swap their own token into. The webhook example uses
// realistic-looking payload + signature strings.
export const sampleInputs = {
  "trusted-jwt-gate": {
    token: "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6InBsYXRmb3JtLTEifQ.eyJzdWIiOiJ1c2VyLTQyIiwiZXhwIjo5OTk5OTk5OTk5fQ.REPLACE_WITH_REAL_SIGNATURE",
  },
  "trusted-jwt-multitenant": {
    token: "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6InRlbmFudC1hY21lIn0.eyJzdWIiOiJ1c2VyLTQyIiwiaXNzIjoidGVuYW50IiwiYXVkIjoic3R1ZGlvIiwiZXhwIjo5OTk5OTk5OTk5fQ.REPLACE_WITH_REAL_SIGNATURE",
    kid: "tenant-acme",
  },
  "trusted-webhook-hmac": {
    payload: "{\"event\":\"payment.completed\",\"id\":\"evt_123\",\"amount\":4200}",
    signature: "REPLACE_WITH_HEX_HMAC_SHA256_OF_PAYLOAD",
  },
  "trusted-jwt-with-amount-cap": {
    token: "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6InBsYXRmb3JtLTEifQ.eyJzdWIiOiJ1c2VyLTQyIiwiZXhwIjo5OTk5OTk5OTk5fQ.REPLACE_WITH_REAL_SIGNATURE",
    user: { tier: "pro" },
    amount: 50000,
  },
};
