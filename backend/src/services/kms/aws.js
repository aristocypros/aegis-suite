// kms/aws.js — STUB. AWS KMS provider lands in a follow-up task.
//
// When implemented, this will use @aws-sdk/client-kms for asymmetric sign
// (EdDSA when GA; ECDSA P-256 fallback per FEATURES.md L213). The SDK is
// NOT imported here so that the default `KMS_PROVIDER=vault` deployment
// pulls no AWS dependencies (FEATURES.md L700: "No cloud SDK imports in
// core code").
import { KmsProviderNotImplemented } from "./index.js";

export async function create() {
  throw new KmsProviderNotImplemented("aws");
}
