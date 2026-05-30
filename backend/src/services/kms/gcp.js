// kms/gcp.js — STUB. GCP Cloud KMS provider lands in a follow-up task.
//
// When implemented, will use @google-cloud/kms for asymmetric sign. The SDK
// is NOT imported here so the default deployment pulls no GCP dependencies
// (FEATURES.md L700).
import { KmsProviderNotImplemented } from "./index.js";

export async function create() {
  throw new KmsProviderNotImplemented("gcp");
}
