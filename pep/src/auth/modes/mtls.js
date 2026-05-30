// mtls.js — mTLS verifier reached by the dispatcher when the request
// presented a client TLS certificate. The PEP's HTTPS listener was set up
// with requestCert:true and rejectUnauthorized:false, so handshakes succeed
// without a cert; this verifier rejects requests that either:
//   - presented a cert that doesn't chain to PEP_TLS_CA,
//   - presented a cert whose CN is not in the configured allowlist,
//   - presented a cert whose CN matches a row whose auth_mode is not mtls.
//
// The CN allowlist comes from two sources, ORed:
//   - PEP_ALLOWED_CALLERS (CSV) — bootstrap list, lets ops admit a caller
//     before the platform's pep_callers table is populated.
//   - pep_callers rows with auth_mode='mtls' and allowed_cn set.

export function createMtlsAuth({ allowedCns, callerStore, logger = console }) {
  const allowlist = new Set(allowedCns || []);

  return async function mtlsAuth(req, res, next) {
    // express → http(s) connection chain. With requestCert:true, the cert
    // is on req.socket.getPeerCertificate(); req.client.authorized tracks
    // whether the cert chained to our CA bundle.
    let authorized = false;
    let cert = null;
    try {
      authorized = req.client?.authorized === true ||
        req.socket?.authorized === true;
      cert = typeof req.socket?.getPeerCertificate === "function"
        ? req.socket.getPeerCertificate(true)
        : null;
    } catch (_e) {
      // Unreachable on a TLS socket. Leave authorized=false and fall through.
    }

    if (!cert || Object.keys(cert).length === 0) {
      return res.status(401).json({ error: "client_cert_required" });
    }
    if (!authorized) {
      // Cert didn't chain to our CA bundle (or expired etc.) — surface the
      // exact authorization error from Node for ops, but return a stable
      // shape to clients.
      const reason = req.client?.authorizationError ||
        req.socket?.authorizationError || "untrusted_client_cert";
      logger.warn?.(`[pep-auth] mtls reject: ${reason}`);
      return res.status(401).json({ error: "untrusted_client_cert", reason });
    }

    const cn = cert.subject?.CN;
    if (typeof cn !== "string" || cn.length === 0) {
      return res.status(401).json({ error: "client_cert_missing_cn" });
    }

    // Bootstrap allowlist OR provisioned mtls-mode row.
    const inBootstrap = allowlist.has(cn);
    const provisioned = await callerStore.findByAllowedCn(cn);
    if (provisioned && provisioned.row?.auth_mode !== "mtls") {
      // The CN happens to be on a row that was provisioned for a different
      // mode (e.g. a tenant-tag field). The dispatcher must not let mtls
      // bypass that row's declared mode.
      logger.warn?.(`[pep-auth] mtls reject: CN '${cn}' belongs to a ${provisioned.row?.auth_mode} caller`);
      return res.status(401).json({ error: "auth_mode_mismatch" });
    }
    if (!inBootstrap && !provisioned) {
      logger.warn?.(`[pep-auth] mtls reject: CN '${cn}' not allowed`);
      return res.status(401).json({ error: "caller_not_allowed" });
    }

    req.caller = {
      id: provisioned?.callerId || cn,
      mode: "mtls",
      cn,
      tenant: provisioned?.row?.tenant,
      orgId: provisioned?.row?.org_id ?? null,
    };
    next();
  };
}
