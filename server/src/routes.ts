import { Router } from "express";
import { config } from "./config";
import { db, type CertificateRow } from "./db";
import { login, logout, requireAuth } from "./auth";
import { runIssueJob, renewalSweep } from "./jobs";
import * as bind from "./services/bind";
import { acmedns } from "./services/acmedns";
import { npm } from "./services/npm";
import { ensureAcmeDnsCreds } from "./services/acme";

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
  return {
    id: c.id,
    name: c.name,
    domain: c.domain,
    wildcard: c.wildcard === 1,
    strategy: c.strategy,
    status: c.status,
    error: c.error,
    domains: JSON.parse(c.domains_json),
    expiresAt: c.expires_at,
    issuedAt: c.issued_at,
    autoRenew: c.auto_renew === 1,
    createdAt: c.created_at,
    hasMaterial: Boolean(c.certificate && c.key),
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
  const header = req.headers.authorization || "";
  logout(header.startsWith("Bearer ") ? header.slice(7) : "");
  res.json({ ok: true });
});

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
    const acmednsStatus = await acmedns.test();
    const npmStatus = await npm.test();

    res.json({
      bind: { status: bindStatus, detail: bindDetail },
      acmedns: { status: acmednsStatus },
      npm: { status: npmStatus },
      config: {
        zone: config.zone,
        acmeDirectoryUrl: config.acmeDirectoryUrl,
        acmeEmail: config.acmeEmail,
        bindHost: config.bind.host,
        acmednsApiUrl: config.acmedns.apiUrl,
        acmednsDomain: config.acmedns.domain,
        acmednsPublicIp: config.acmedns.publicIp,
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
    const strategy: "acme-dns" | "bind" =
      req.body?.strategy === "bind" ? "bind" : "acme-dns";
    if (!/^[a-z0-9.-]+$/.test(name) || !name.includes(".")) {
      res.status(400).json({ error: "Invalid domain name" });
      return;
    }
    if (db.getDomainByName(name)) {
      res.status(409).json({ error: `Domain ${name} is already registered` });
      return;
    }
    const domain = db.createDomain({ name, strategy });
    if (strategy === "acme-dns") {
      // Register acme-dns credentials eagerly so the CNAME target is known.
      try {
        await ensureAcmeDnsCreds(domain);
      } catch (err) {
        res.status(502).json({
          error: `Domain saved but acme-dns registration failed: ${err instanceof Error ? err.message : err}`,
          domain,
        });
        return;
      }
    }
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
    const strategy: "acme-dns" | "bind" =
      req.body?.strategy === "bind" ? "bind" : "acme-dns";
    const name = String(req.body?.name || "").trim() || `${wildcard ? "*." : ""}${domain}`;
    if (!/^[a-z0-9.-]+$/.test(domain) || !domain.includes(".")) {
      res.status(400).json({ error: "Invalid domain name" });
      return;
    }
    if (strategy === "acme-dns" && !db.getDomainByName(domain)) {
      res
        .status(400)
        .json({ error: `Domain ${domain} is not registered — add it on the Domains page first` });
      return;
    }
    const cert = db.createCertificate({ name, domain, wildcard, strategy });
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

// ── Activities ──────────────────────────────────────────────────────────
router.get("/activities", requireAuth, (_req, res) => {
  res.json(db.listActivities(200));
});

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
