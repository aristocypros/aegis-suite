// kms/azure.js — STUB. Azure Key Vault provider lands in a follow-up task.
//
// When implemented, will use @azure/keyvault-keys + @azure/identity. The
// SDK is NOT imported here so the default deployment pulls no Azure
// dependencies (FEATURES.md L700).
import { KmsProviderNotImplemented } from "./index.js";

export async function create() {
  throw new KmsProviderNotImplemented("azure");
}
