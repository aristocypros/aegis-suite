// kms/pkcs11.js — STUB. PKCS#11 / HSM provider lands in a follow-up task.
//
// When implemented, will use pkcs11js (or graphene-pk11) to talk to any
// PKCS#11-conformant HSM (YubiHSM, Thales, AWS CloudHSM, SoftHSM). The
// native binding is NOT imported here so the default deployment pulls no
// PKCS#11 dependencies (FEATURES.md L700).
import { KmsProviderNotImplemented } from "./index.js";

export async function create() {
  throw new KmsProviderNotImplemented("pkcs11");
}
