// auditCrypto.js — pure crypto primitives for the tamper-evident audit chain.
// No I/O, no global state. Hashes use SHA-256 (matching pgcrypto.digest()
// in the Postgres-side verifier) and signatures use Ed25519.
//
// The hash construction is:
//
//   entry_hash = sha256( prev_hash_or_zero32 || utf8(canonical_payload) )
//
// where canonical_payload is a deterministic, key-sorted JSON string.
//
// Postgres reproduces the same hash via:
//
//   digest( coalesce(prev_hash, decode(repeat('00',32),'hex'))
//           || convert_to(payload_canonical, 'UTF8'),
//           'sha256')
import crypto from "node:crypto";

export const ZERO_32 = Buffer.alloc(32);

// Recursive key-sorted JSON serializer. The output is the exact byte sequence
// that gets hashed and signed, so determinism matters.
//
// Supported: null, boolean, finite number, string, array, plain object.
// Rejects: undefined, NaN, Infinity, functions, symbols, cycles. Buffers are
// rejected too — convert to base64 / hex strings before passing in.
export function canonicalize(value) {
  const seen = new WeakSet();
  return _serialize(value, seen);
}

function _serialize(v, seen) {
  if (v === null) return "null";
  const t = typeof v;
  if (t === "boolean") return v ? "true" : "false";
  if (t === "number") {
    if (!Number.isFinite(v)) {
      throw new Error("canonicalize: non-finite number");
    }
    return JSON.stringify(v);
  }
  if (t === "string") return JSON.stringify(v);
  if (t === "bigint") return JSON.stringify(v.toString());
  if (Array.isArray(v)) {
    if (seen.has(v)) throw new Error("canonicalize: cycle detected");
    seen.add(v);
    const parts = v.map((x) => _serialize(x, seen));
    seen.delete(v);
    return "[" + parts.join(",") + "]";
  }
  if (t === "object") {
    if (Buffer.isBuffer(v)) {
      throw new Error("canonicalize: raw Buffer not allowed (encode as hex/base64 string)");
    }
    if (seen.has(v)) throw new Error("canonicalize: cycle detected");
    seen.add(v);
    const keys = Object.keys(v).filter((k) => v[k] !== undefined).sort();
    const parts = keys.map(
      (k) => JSON.stringify(k) + ":" + _serialize(v[k], seen)
    );
    seen.delete(v);
    return "{" + parts.join(",") + "}";
  }
  throw new Error(`canonicalize: unsupported type ${t}`);
}

// SHA-256 of (prev_hash || utf8 canonical_payload). Returns a Buffer (32 B).
export function entryHash(prevHashBuf, canonicalPayload) {
  const h = crypto.createHash("sha256");
  h.update(prevHashBuf || ZERO_32);
  h.update(Buffer.from(canonicalPayload, "utf8"));
  return h.digest();
}

// Fingerprint = sha256 of the public key DER bytes. Stored on every audit
// row and indexed by audit_signing_keys.fp.
export function keyFingerprint(pubkeyDer) {
  return crypto.createHash("sha256").update(pubkeyDer).digest();
}

// Ed25519 sign/verify. Node's crypto.sign with `null` algorithm uses the
// curve baked into the key object.
export function sign(privateKey, hashBuf) {
  return crypto.sign(null, hashBuf, privateKey);
}

export function verify(publicKey, hashBuf, signatureBuf) {
  return crypto.verify(null, hashBuf, publicKey, signatureBuf);
}

// Generate a fresh Ed25519 keypair. Returns:
//   { privateKey, publicKey, privateKeyPem, pubkeyDer, fingerprint }
// Where privateKey/publicKey are KeyObjects ready for sign/verify, and
// privateKeyPem is a string ready to write to disk (PKCS#8).
export function generateKeyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const privateKeyPem = privateKey
    .export({ type: "pkcs8", format: "pem" })
    .toString();
  const pubkeyDer = publicKey.export({ type: "spki", format: "der" });
  return {
    privateKey,
    publicKey,
    privateKeyPem,
    pubkeyDer,
    fingerprint: keyFingerprint(pubkeyDer),
  };
}

// Reload a private/public key pair from a stored PEM. Used at backend boot.
export function loadKeyPairFromPem(privateKeyPem) {
  const privateKey = crypto.createPrivateKey({ key: privateKeyPem, format: "pem" });
  const publicKey = crypto.createPublicKey(privateKey);
  const pubkeyDer = publicKey.export({ type: "spki", format: "der" });
  return {
    privateKey,
    publicKey,
    pubkeyDer,
    fingerprint: keyFingerprint(pubkeyDer),
  };
}

// Reconstruct a public KeyObject from the DER bytes we stored in
// audit_signing_keys.pubkey. Used by the full-chain verifier when validating
// historical entries that may have been signed by a now-retired key.
export function publicKeyFromDer(pubkeyDer) {
  return crypto.createPublicKey({ key: pubkeyDer, format: "der", type: "spki" });
}
