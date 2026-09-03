import { Router } from "express";
import { config } from "./config";
import { db, type CertificateRow } from "./db";
import {
  clearSessionCookie,
  extractToken,
  getSession,
  login,
  loginWithOidc,
  logout,
  oidcConfigured,
  requireAuth,
  setSessionCookie,
} from "./auth";
import { runIssueJob, renewalSweep } from "./jobs";
import * as bind from "./services/bind";
import { npm } from "./services/npm";
import { oidc } from "./services/oidc";
import { scoreCertificate } from "./services/health";
import { runDiscovery } from "./services/discovery";
import { auditDomain } from "./services/audit";
import { vault } from "./services/vault";

const router = Router();

function asyncHandler(
  fn: (req: import("express").Request, res: import("express").Response) => Promise<unknown>,
) {
  return (
    req: import("express").Request,
    res: import("express").Response,
    next: import("express").NextFunction,
  ) => {
    fn(req, res).catch(next);
  };
}

function certToJson(c: CertificateRow) {
  const domains = JSON.parse(c.domains_json) as string[];
  const health = scoreCertificate({
    expiresAt: c.expires_at,
    issuedAt: c.issued_at,
    domains,
    hasMaterial: Boolean(c.certificate && c.key),
    certificate: c.certificate,
    key: c.key,
  });
  return {
    id: c.id,
    name: c.name,
    domain: c.domain,
    wildcard: c.wildcard === 1,
    status: c.status,
    error: c.error,
    domains,
    expiresAt: c.expires_at,
    issuedAt: c.issued_at,
    autoRenew: c.auto_renew === 1,
    createdAt: c.created_at,
    hasMaterial: Boolean(c.certificate && c.key),
    health: { score: health.score, grade: health.grade },
  };
}

// ── Auth ────────────────────────────────────────────────────────────────
router.post("/auth/login", (req, res) => {
  const { password } = req.body || {};
  const token = login(password);
  if (!token) {
    res.status(401).json({ error: "Invalid password" });
    return;
  }
  res.json({ token });
});

router.post("/auth/logout", requireAuth, (req, res) => {
  logout(extractToken(req) || "");
  clearSessionCookie(res);
  res.json({ ok: true });
});

/** Public — tells the login page how to offer sign-in. */
router.get("/auth/config", (_req, res) => {
  res.json({
    localEnabled: config.auth.localEnabled,
    oidc: {
      enabled: oidcConfigured(),
      issuerUrl: config.auth.issuerUrl,
      redirectUri: config.auth.redirectUri,
    },
  });
});

/** Who is the current session? */
router.get("/auth/me", requireAuth, (req, res) => {
  const session = getSession(extractToken(req));
  res.json({ user: session?.user ?? null });
});

/** Start an Authentik OIDC authorization-code + PKCE flow. */
router.get(
  "/auth/oidc/authorize",
  asyncHandler(async (req, res) => {
    if (!oidcConfigured()) {
      res.status(404).json({ error: "Authentik OIDC is not configured (see AUTHENTIK_* in .env)" });
      return;
    }
    const redirectTo =
      typeof req.query.redirect === "string" && req.query.redirect.startsWith("/")
        ? req.query.redirect
        : "/";
    const { url } = await oidc.authorizeUrl(redirectTo);
    res.redirect(url);
  }),
);

/** Authentik redirects back here with an authorization code. */
router.get(
  "/auth/oidc/callback",
  asyncHandler(async (req, res) => {
    const state = typeof req.query.state === "string" ? req.query.state : "";
    const code = typeof req.query.code === "string" ? req.query.code : "";
    if (req.query.error) {
      res.redirect(`/?auth_error=${encodeURIComponent(String(req.query.error))}`);
      return;
    }
    const pending = oidc.consumeState(state);
    if (!pending || !code) {
      res.status(400).json({ error: "Invalid or expired OIDC state" });
      return;
    }
    const user = await oidc.exchangeCode(code, pending.verifier);
    const token = loginWithOidc(user);
    setSessionCookie(res, token);
    db.addActivity(
      "auth-login",
      `Signed in via Authentik: ${user.email || user.name}`,
    );
    res.redirect(pending.redirectTo);
  }),
);

// ── Status ──────────────────────────────────────────────────────────────
router.get(
  "/status",
  requireAuth,
  asyncHandler(async (_req, res) => {
    let bindStatus = "not-configured";
    let bindDetail = "";
    if (config.bind.host && (config.bind.keyPath || config.bind.password)) {
      try {
        const result = await import("./services/ssh").then((m) =>
          m.sshExec("true"),
        );
        bindStatus = result.code === 0 ? "ok" : "error";
        bindDetail = result.stderr || "";
      } catch (err) {
        bindStatus = "error";
        bindDetail = err instanceof Error ? err.message : String(err);
      }
    }
    const npmStatus = await npm.test();
    const vaultStatus = await vault.test();

    res.json({
      bind: { status: bindStatus, detail: bindDetail },
      npm: { status: npmStatus },
      auth: {
        oidcEnabled: oidcConfigured(),
        localEnabled: config.auth.localEnabled,
        issuerUrl: config.auth.issuerUrl,
        redirectUri: config.auth.redirectUri,
      },
      vault: {
        enabled: vault.isEnabled(),
        status: vaultStatus,
        addr: config.vault.addr,
      },
      discovery: {
        dirs: config.discovery.dirs,
        count: db.listDiscoveredCerts().length,
      },
      config: {
        zone: config.zone,
        acmeDirectoryUrl: config.acmeDirectoryUrl,
        acmeEmail: config.acmeEmail,
        bindHost: config.bind.host,
        npmApiUrl: config.npm.apiUrl,
        tsigConfigured: Boolean(config.bind.tsigSecret),
      },
    });
  }),
);

// ── Domains ─────────────────────────────────────────────────────────────
router.get("/domains", requireAuth, (_req, res) => {
  res.json(db.listDomains());
});

router.post(
  "/domains",
  requireAuth,
  asyncHandler(async (req, res) => {
    const name = String(req.body?.name || "").trim().toLowerCase().replace(/\.$/, "");
    if (!/^[a-z0-9.-]+$/.test(name) || !name.includes(".")) {
      res.status(400).json({ error: "Invalid domain name" });
      return;
    }
    if (db.getDomainByName(name)) {
      res.status(409).json({ error: `Domain ${name} is already registered` });
      return;
    }
    const domain = db.createDomain({ name });
    res.status(201).json(db.getDomain(domain.id));
  }),
);

router.delete("/domains/:id", requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const domain = db.getDomain(id);
  if (!domain) {
    res.status(404).json({ error: "Domain not found" });
    return;
  }
  db.deleteDomain(id);
  db.addActivity("domain-delete", `Removed domain ${domain.name}`);
  res.json({ ok: true });
});

router.get(
  "/domains/:id/records",
  requireAuth,
  asyncHandler(async (req, res) => {
    const domain = db.getDomain(Number(req.params.id));
    if (!domain) {
      res.status(404).json({ error: "Domain not found" });
      return;
    }
    const records = await bind.listZone(domain.name);
    res.json(records);
  }),
);

router.post(
  "/domains/:id/records",
  requireAuth,
  asyncHandler(async (req, res) => {
    const domain = db.getDomain(Number(req.params.id));
    if (!domain) {
      res.status(404).json({ error: "Domain not found" });
      return;
    }
    const { type, name, value, ttl, priority } = req.body || {};
    const recordType = String(type || "").toUpperCase();
    const allowed: string[] = ["A", "AAAA", "CNAME", "TXT", "MX", "NS", "SRV"];
    if (!allowed.includes(recordType)) {
      res.status(400).json({ error: `Unsupported record type: ${recordType}` });
      return;
    }
    if (!name || !value) {
      res.status(400).json({ error: "name and value are required" });
      return;
    }
    await bind.addRecord({
      zone: domain.name,
      type: recordType as bind.RecordType,
      name,
      value,
      ttl: Number(ttl || 300),
      priority: priority !== undefined ? Number(priority) : undefined,
    });
    db.addActivity(
      "record-add",
      `Added ${recordType} ${name}.${domain.name} → ${value}`,
    );
    res.status(201).json({ ok: true });
  }),
);

router.delete(
  "/domains/:id/records",
  requireAuth,
  asyncHandler(async (req, res) => {
    const domain = db.getDomain(Number(req.params.id));
    if (!domain) {
      res.status(404).json({ error: "Domain not found" });
      return;
    }
    const { type, name, value } = req.body || {};
    if (!type || !name) {
      res.status(400).json({ error: "type and name are required" });
      return;
    }
    await bind.deleteRecord({
      zone: domain.name,
      type: String(type).toUpperCase(),
      name,
      value: value !== undefined ? String(value) : undefined,
    });
    db.addActivity("record-delete", `Removed ${type} ${name}.${domain.name}`);
    res.json({ ok: true });
  }),
);

// ── Certificates ────────────────────────────────────────────────────────
router.get("/certificates", requireAuth, (_req, res) => {
  res.json(db.listCertificates().map(certToJson));
});

router.post(
  "/certificates",
  requireAuth,
  asyncHandler(async (req, res) => {
    const domain = String(req.body?.domain || "").trim().toLowerCase().replace(/\.$/, "");
    const wildcard = Boolean(req.body?.wildcard);
    const name = String(req.body?.name || "").trim() || `${wildcard ? "*." : ""}${domain}`;
    if (!/^[a-z0-9.-]+$/.test(domain) || !domain.includes(".")) {
      res.status(400).json({ error: "Invalid domain name" });
      return;
    }
    const cert = db.createCertificate({ name, domain, wildcard });
    // Fire-and-forget issuance; status is polled via GET /certificates/:id
    runIssueJob(cert.id).catch(() => undefined);
    res.status(202).json(certToJson(db.getCertificate(cert.id)!));
  }),
);

router.get("/certificates/:id", requireAuth, (req, res) => {
  const cert = db.getCertificate(Number(req.params.id));
  if (!cert) {
    res.status(404).json({ error: "Certificate not found" });
    return;
  }
  res.json(certToJson(cert));
});

router.get(
  "/certificates/:id/material",
  requireAuth,
  asyncHandler(async (req, res) => {
    const cert = db.getCertificate(Number(req.params.id));
    if (!cert) {
      res.status(404).json({ error: "Certificate not found" });
      return;
    }
    if (!cert.certificate || !cert.key) {
      res.status(409).json({ error: "Certificate material is not available yet" });
      return;
    }
    res.json({ certificate: cert.certificate, key: cert.key });
  }),
);

router.post(
  "/certificates/:id/renew",
  requireAuth,
  asyncHandler(async (req, res) => {
    const cert = db.getCertificate(Number(req.params.id));
    if (!cert) {
      res.status(404).json({ error: "Certificate not found" });
      return;
    }
    db.updateCertificateStatus(cert.id, "issuing");
    runIssueJob(cert.id).catch(() => undefined);
    res.status(202).json({ ok: true });
  }),
);

router.delete("/certificates/:id", requireAuth, (req, res) => {
  const cert = db.getCertificate(Number(req.params.id));
  if (!cert) {
    res.status(404).json({ error: "Certificate not found" });
    return;
  }
  db.deleteCertificate(cert.id);
  db.addActivity("cert-delete", `Deleted certificate for ${cert.domain}`);
  res.json({ ok: true });
});

// ── nginx proxy manager ────────────────────────────────────────────────
router.get(
  "/npm/hosts",
  requireAuth,
  asyncHandler(async (_req, res) => {
    res.json(await npm.listProxyHosts());
  }),
);

router.get(
  "/npm/certificates",
  requireAuth,
  asyncHandler(async (_req, res) => {
    res.json(await npm.listCertificates());
  }),
);

/** Import a Cerulean cert into NPM as a custom certificate. */
router.post(
  "/npm/export-cert",
  requireAuth,
  asyncHandler(async (req, res) => {
    const cert = db.getCertificate(Number(req.body?.certificate_id));
    if (!cert) {
      res.status(404).json({ error: "Certificate not found" });
      return;
    }
    if (!cert.certificate || !cert.key) {
      res.status(409).json({ error: "Certificate material is not available yet" });
      return;
    }
    const niceName =
      String(req.body?.nice_name || "").trim() ||
      `cerulean-${cert.domain}${cert.wildcard ? "-wildcard" : ""}`;
    const npmCertId = await npm.importCertificate({
      niceName,
      domainNames: JSON.parse(cert.domains_json),
      certificate: cert.certificate,
      key: cert.key,
    });
    db.addActivity("npm-export", `Exported certificate for ${cert.domain} to nginx proxy manager`, `npm-cert=${npmCertId}`);
    res.status(201).json({ npmCertificateId: npmCertId, niceName });
  }),
);

/** Create a proxy host in NPM (optionally with an imported cert). */
router.post(
  "/npm/hosts",
  requireAuth,
  asyncHandler(async (req, res) => {
    const {
      domain,
      forward_host,
      forward_port,
      forward_scheme = "http",
      certificate_id,
      ssl_forced = true,
      http2_support = true,
    } = req.body || {};
    if (!domain || !forward_host || !forward_port) {
      res.status(400).json({ error: "domain, forward_host and forward_port are required" });
      return;
    }
    const host = await npm.createProxyHost({
      domainNames: [String(domain).toLowerCase()],
      forwardScheme: forward_scheme === "https" ? "https" : "http",
      forwardHost: String(forward_host),
      forwardPort: Number(forward_port),
      certificateId: certificate_id !== undefined ? Number(certificate_id) : undefined,
      sslForced: Boolean(ssl_forced),
      http2Support: Boolean(http2_support),
    });
    db.addActivity(
      "npm-host",
      `Created NPM proxy host ${domain} → ${forward_host}:${forward_port}`,
    );
    res.status(201).json(host);
  }),
);

/** Update a proxy host in NPM in place (idempotent reconciliation). */
router.put(
  "/npm/hosts/:id",
  requireAuth,
  asyncHandler(async (req, res) => {
    const hosts = await npm.listProxyHosts();
    const existing = hosts.find((h) => h.id === Number(req.params.id));
    if (!existing) {
      res.status(404).json({ error: "Proxy host not found" });
      return;
    }
    const {
      forward_host,
      forward_port,
      forward_scheme,
      certificate_id,
      ssl_forced,
      http2_support,
      websocket_support,
    } = req.body || {};
    const updated = await npm.updateProxyHost(
      existing.id,
      {
        ...existing,
        forward_host:
          forward_host !== undefined ? String(forward_host) : existing.forward_host,
        forward_port:
          forward_port !== undefined ? Number(forward_port) : existing.forward_port,
        forward_scheme:
          forward_scheme === "https"
            ? "https"
            : forward_scheme !== undefined
              ? "http"
              : existing.forward_scheme,
        ssl_forced:
          ssl_forced !== undefined ? Boolean(ssl_forced) : existing.ssl_forced,
        http2_support:
          http2_support !== undefined
            ? Boolean(http2_support)
            : existing.http2_support,
        allow_websocket_upgrade:
          websocket_support !== undefined
            ? Boolean(websocket_support)
            : existing.allow_websocket_upgrade ?? true,
      },
      certificate_id !== undefined ? Number(certificate_id) : existing.certificate_id,
    );
    db.addActivity(
      "npm-host",
      `Updated NPM proxy host ${(existing.domain_names || []).join(", ")}`,
    );
    res.json(updated);
  }),
);

// ── Activities ──────────────────────────────────────────────────────────
router.get("/activities", requireAuth, (_req, res) => {
  res.json(db.listActivities(200));
});

// ── Certificate health ──────────────────────────────────────────────────
router.get(
  "/certificates/:id/health",
  requireAuth,
  (req, res) => {
    const cert = db.getCertificate(Number(req.params.id));
    if (!cert) {
      res.status(404).json({ error: "Certificate not found" });
      return;
    }
    const health = scoreCertificate({
      expiresAt: cert.expires_at,
      issuedAt: cert.issued_at,
      domains: JSON.parse(cert.domains_json),
      hasMaterial: Boolean(cert.certificate && cert.key),
      certificate: cert.certificate,
      key: cert.key,
    });
    res.json(health);
  },
);

// ── Certificate discovery ───────────────────────────────────────────────
router.get("/discovery/certificates", requireAuth, (_req, res) => {
  res.json(
    db.listDiscoveredCerts().map((c) => {
      const domains = JSON.parse(c.domains_json) as string[];
      const health = scoreCertificate({
        expiresAt: c.expires_at,
        issuedAt: c.issued_at,
        domains,
        certificate: c.certificate,
        key: c.key,
        issuer: c.issuer,
      });
      return {
        id: c.id,
        source: c.source,
        sourceId: c.source_id,
        name: c.name,
        domains,
        issuer: c.issuer,
        fingerprint: c.fingerprint,
        expiresAt: c.expires_at,
        issuedAt: c.issued_at,
        firstSeen: c.first_seen,
        lastSeen: c.last_seen,
        hasMaterial: Boolean(c.certificate && c.key),
        health: { score: health.score, grade: health.grade },
      };
    }),
  );
});

router.post(
  "/discovery/scan",
  requireAuth,
  asyncHandler(async (_req, res) => {
    const result = await runDiscovery();
    res.json({ ok: true, ...result });
  }),
);

router.delete("/discovery/certificates/:id", requireAuth, (req, res) => {
  const row = db
    .listDiscoveredCerts()
    .find((c) => c.id === Number(req.params.id));
  if (!row) {
    res.status(404).json({ error: "Certificate not found" });
    return;
  }
  db.deleteDiscoveredCert(row.id);
  db.addActivity("discovery-delete", `Removed discovered certificate ${row.name}`);
  res.json({ ok: true });
});

// ── DNS health auditing ─────────────────────────────────────────────────
router.get(
  "/audit/dns",
  requireAuth,
  asyncHandler(async (req, res) => {
    const requested =
      typeof req.query.domain === "string" ? req.query.domain.trim() : "";
    const targets = requested
      ? [requested]
      : db.listDomains().map((d) => d.name);
    const audits = [];
    for (const name of targets) {
      try {
        const audit = await auditDomain(name);
        db.saveDnsAudit(audit.domain, audit.score, audit.checks);
        audits.push(audit);
      } catch (err) {
        audits.push({
          domain: name,
          runAt: new Date().toISOString(),
          score: 0,
          grade: "F",
          checks: [
            {
              name: "error",
              status: "fail",
              detail: err instanceof Error ? err.message : String(err),
            },
          ],
        });
      }
    }
    res.json(audits);
  }),
);

router.get("/audit/dns/history", requireAuth, (_req, res) => {
  res.json(
    db.listDnsAudits(100).map((a) => ({
      id: a.id,
      domain: a.domain,
      runAt: a.run_at,
      score: a.score,
      checks: JSON.parse(a.checks_json),
    })),
  );
});

// ── Secret vault ────────────────────────────────────────────────────────
router.post(
  "/vault/sync",
  requireAuth,
  asyncHandler(async (_req, res) => {
    if (!vault.isEnabled()) {
      res.status(409).json({
        error: "Vault is not configured — set VAULT_ADDR and VAULT_TOKEN in .env",
      });
      return;
    }
    const { written } = await vault.sync();
    db.addActivity(
      "vault-sync",
      `Synced ${written.length} secret(s) to the vault (manual)`,
    );
    res.json({ ok: true, written });
  }),
);

// ── Maintenance ─────────────────────────────────────────────────────────
router.post(
  "/renewal-sweep",
  requireAuth,
  asyncHandler(async (_req, res) => {
    await renewalSweep();
    res.json({ ok: true });
  }),
);

export default router;
