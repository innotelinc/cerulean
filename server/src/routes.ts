import { Router } from "express";
import { config } from "./config";
import { db, type CertificateRow } from "./db";
import {
  createProvider as createDnsProvider,
  deleteProvider as deleteDnsProvider,
  listProviders as listDnsProviders,
  ProviderError,
  providerConnectionForTenant,
  updateProvider as updateDnsProvider,
} from "./services/providers";
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
import * as technitium from "./services/technitium";
import { npm, materializeClientCaFile } from "./services/npm";
import { oidc } from "./services/oidc";
import { scoreCertificate } from "./services/health";
import { runDiscovery } from "./services/discovery";
import { auditDomain } from "./services/audit";
import { infisical, vault } from "./services/vault";
import * as pki from "./services/pki";
import * as enrollment from "./services/enrollment";
import * as dhcp from "./services/dhcp";
import * as blocking from "./services/blocking";
import * as serverIdentity from "./services/serverIdentity";
import {
  createTenant,
  isPlatform,
  renameTenant,
  resolveTenant,
  TenantError,
  tenantOf,
  tenantsForUser,
} from "./services/tenants";
import {
  adminConfigured as authentikAdminConfigured,
  listGroupMembers,
} from "./services/authentik";

const router = Router();

const tenantGuard = [requireAuth, resolveTenant] as unknown as import("express").RequestHandler;

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

function pkiHandler(
  fn: (req: import("express").Request, res: import("express").Response) => Promise<unknown>,
) {
  return (
    req: import("express").Request,
    res: import("express").Response,
    next: import("express").NextFunction,
  ) => {
    fn(req, res).catch((err) => {
      if (err instanceof pki.PkiError) {
        res.status(err.status).json({ error: err.message });
        return;
      }
      next(err);
    });
  };
}

function clientCertToJson(c: {
  id: number;
  name: string;
  email: string | null;
  serial_hex: string;
  status: string;
  fingerprint: string | null;
  expires_at: string | null;
  issued_at: string | null;
  revoked_at: string | null;
  created_at: string;
}) {
  return {
    id: c.id,
    name: c.name,
    email: c.email,
    serial: c.serial_hex,
    status: c.status,
    fingerprint: c.fingerprint,
    expiresAt: c.expires_at,
    issuedAt: c.issued_at,
    revokedAt: c.revoked_at,
    createdAt: c.created_at,
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
    source: (c as unknown as { source?: string }).source ?? null,
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

router.get("/auth/me", requireAuth, resolveTenant, (req, res) => {
  const session = getSession(extractToken(req));
  const tenant = tenantOf(res);
  const user = session?.user ?? null;
  res.json({
    user,
    tenant: user ? { id: tenant.id, slug: tenant.slug, name: tenant.name } : null,
    tenants: user ? tenantsForUser(user).map((t) => ({ id: t.id, slug: t.slug, name: t.name })) : [],
    platform: user ? isPlatform(res) : false,
  });
});

router.get(
  "/auth/oidc/authorize",
  asyncHandler(async (req, res) => {
    if (!oidcConfigured()) {
      res.status(404).json({ error: "Authentik OIDC is not configured (see AUTHENTIK_* in .env)" });
      return;
    }
    const redirectTo =
      typeof req.query.redirect === "string" && req.query.redirect.startsWith("/") ? req.query.redirect : "/";
    const { url } = await oidc.authorizeUrl(redirectTo);
    res.redirect(url);
  }),
);

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
    db.addActivity("auth-login", `Signed in via Authentik: ${user.email || user.name}`);
    res.redirect(pending.redirectTo);
  }),
);

// ── Status + orchestrator ───────────────────────────────────────────────
router.get(
  "/status",
  tenantGuard,
  asyncHandler(async (_req, res) => {
    const tenantId = tenantOf(res).id;
    const dnsProbe = await technitium.testConnection();
    const dhcpStatus = await dhcp.status().catch(() => ({ reachable: false, scopes: 0, leases: 0, detail: "error" }));
    const blockStatus = await blocking.getStatus().catch(() => ({ enabled: false, blockListUrls: [], blockedZones: 0, allowedZones: 0, detail: "error" }));
    const npmStatus = await npm.test();
    const vaultStatus = await vault.test();
    const ident = serverIdentity.currentIdentity();
    res.json({
      // Legacy "bind" key kept for backward-compat but now reports Technitium
      bind: { status: dnsProbe.ok ? "ok" : "error", detail: dnsProbe.detail },
      technitium: { status: dnsProbe.ok ? "ok" : "error", detail: dnsProbe.detail, url: config.technitium.url },
      dhcp: { status: dhcpStatus.reachable ? "ok" : dhcpStatus.detail.includes("disabled") ? "not-configured" : "error", detail: dhcpStatus.detail, scopes: dhcpStatus.scopes, leases: dhcpStatus.leases, enabled: config.orchestrator.dhcpEnabled },
      blocking: { status: blockStatus.detail === "disabled" ? "not-configured" : blockStatus.enabled ? "ok" : "off", detail: blockStatus.detail, enabled: blockStatus.enabled, blockedZones: blockStatus.blockedZones, allowedZones: blockStatus.allowedZones, urls: blockStatus.blockListUrls },
      npm: { status: npmStatus },
      auth: {
        oidcEnabled: oidcConfigured(),
        localEnabled: config.auth.localEnabled,
        issuerUrl: config.auth.issuerUrl,
        redirectUri: config.auth.redirectUri,
      },
      vault: { enabled: vault.isEnabled(), status: vaultStatus, addr: config.vault.addr },
      infisical: { enabled: infisical.isEnabled(), status: await infisical.test(), addr: config.infisical.addr },
      discovery: { dirs: config.discovery.dirs, count: db.listDiscoveredCerts(tenantId).length },
      pki: pki.pkiStatus(tenantId),
      server: {
        serverId: ident.serverId,
        labDomain: ident.labDomain,
        apex: ident.apex,
        wildcard: ident.wildcard,
        registered: ident.registered,
        wildcardCertId: ident.wildcardCertId,
        autoWildcard: config.server.autoWildcard,
        wildcardValidityDays: config.server.wildcardValidityDays,
        registerUrl: config.server.registerUrl || null,
      },
      orchestrator: {
        enabled: config.orchestrator.enabled,
        dhcpEnabled: config.orchestrator.dhcpEnabled,
        blockingEnabled: config.orchestrator.blockingEnabled,
      },
      config: {
        zone: config.zone,
        acmeDirectoryUrl: config.acmeDirectoryUrl,
        acmeEmail: config.acmeEmail,
        technitiumUrl: config.technitium.url,
        bindHost: config.technitium.url,
        bindMode: "technitium",
        npmMode: config.npm.mode,
        npmApiUrl: config.npm.apiUrl,
        tsigConfigured: false,
      },
    });
  }),
);

router.get("/server/identity", requireAuth, (_req, res) => {
  const ident = serverIdentity.ensureIdentity();
  const row = db.getServerIdentity();
  res.json({
    serverId: ident.serverId,
    labDomain: ident.labDomain,
    apex: ident.apex,
    wildcard: ident.wildcard,
    registered: ident.registered,
    wildcardCertId: ident.wildcardCertId,
    wildcardCert: ident.wildcardCertId ? db.getCertificate(ident.wildcardCertId) ? certToJson(db.getCertificate(ident.wildcardCertId)!) : null : null,
    centralUrl: row?.central_url ?? null,
    registeredAt: row?.registered_at ?? null,
    autoWildcard: config.server.autoWildcard,
    wildcardValidityDays: config.server.wildcardValidityDays,
    registerUrl: config.server.registerUrl || null,
    orchestrator: config.orchestrator,
  });
});

router.post(
  "/server/identity",
  requireAuth,
  asyncHandler(async (req, res) => {
    // Platform admin only for mutation (or local admin)
    // tenantGuard not needed — global identity
    const { serverId, labDomain } = req.body || {};
    if (!serverId && !labDomain) {
      res.status(400).json({ error: "Provide serverId or labDomain" });
      return;
    }
    const current = serverIdentity.currentIdentity();
    const newId = serverId ? String(serverId).trim().toLowerCase() : current.serverId;
    const newLab = labDomain ? String(labDomain).trim().toLowerCase().replace(/^\.+|\.+$/g, "") : current.labDomain;
    if (serverId) {
      const { sanitizeServerId } = await import("./config");
      if (!sanitizeServerId(newId)) {
        res.status(400).json({ error: "Invalid serverId — DNS-safe slug, 1-63 chars, a-z0-9 and dash, cannot start/end with dash" });
        return;
      }
    }
    db.upsertServerIdentity({ serverId: newId, labDomain: newLab, centralUrl: config.server.registerUrl || null });
    db.addActivity("server-identity", `Updated server identity → ${newId}.${newLab}`);
    res.json(serverIdentity.currentIdentity());
  }),
);

router.post(
  "/server/register",
  requireAuth,
  asyncHandler(async (_req, res) => {
    const result = await serverIdentity.registerServer();
    res.json(result);
  }),
);

router.post(
  "/server/wildcard/renew",
  requireAuth,
  asyncHandler(async (_req, res) => {
    const pkiResult = await serverIdentity.ensureWildcardPki();
    const acmeResult = await serverIdentity.tryUpgradeWildcardToAcme();
    const ident = serverIdentity.currentIdentity();
    res.json({ ok: true, pki: pkiResult, acme: acmeResult, identity: ident });
  }),
);

router.get(
  "/orchestrator/status",
  requireAuth,
  asyncHandler(async (_req, res) => {
    const ident = serverIdentity.currentIdentity();
    const dns = await technitium.testConnection();
    const dhcpS = await dhcp.status().catch(() => ({ reachable: false, scopes: 0, leases: 0, detail: "error" }));
    const blockS = await blocking.getStatus().catch(() => ({ enabled: false, blockListUrls: [], blockedZones: 0, allowedZones: 0, detail: "error" }));
    res.json({
      server: ident,
      technitium: { reachable: dns.ok, detail: dns.detail, url: config.technitium.url },
      dhcp: dhcpS,
      blocking: blockS,
      config: { orchestrator: config.orchestrator, server: config.server },
    });
  }),
);

// ── Domains (Technitium zones) ───────────────────────────────────────────
router.get("/domains", tenantGuard, (_req, res) => {
  res.json(db.listDomains(tenantOf(res).id));
});

router.post(
  "/domains",
  tenantGuard,
  asyncHandler(async (req, res) => {
    const name = String(req.body?.name || "").trim().toLowerCase().replace(/\.$/, "");
    if (!/^[a-z0-9.-]+$/.test(name) || !name.includes(".")) {
      res.status(400).json({ error: "Invalid domain name" });
      return;
    }
    const tenantId = tenantOf(res).id;
    if (db.getDomainByName(name, tenantId)) {
      res.status(409).json({ error: `Domain ${name} is already registered in this tenant` });
      return;
    }
    // Ensure zone exists in Technitium (authoritative)
    const conn = providerConnectionForTenant(tenantId) as unknown as Record<string, unknown> | null;
    try {
      await technitium.ensureZone(name, conn ?? undefined as never);
    } catch (err) {
      // Zone creation failure is soft — still register locally so retry works
      db.addActivity("dns-zone-error", `Technitium create zone ${name} failed`, err instanceof Error ? err.message : String(err));
    }
    const domain = db.createDomain({ name, tenantId });
    db.addActivity("domain-create", `Registered zone ${name} on Technitium`);
    res.status(201).json(db.getDomain(domain.id, tenantId));
  }),
);

router.delete("/domains/:id", tenantGuard, asyncHandler(async (req, res) => {
  const id = Number(req.params.id);
  const domain = db.getDomain(id, tenantOf(res).id);
  if (!domain) {
    res.status(404).json({ error: "Domain not found" });
    return;
  }
  // Best-effort delete zone from Technitium
  const conn = providerConnectionForTenant(tenantOf(res).id) as unknown as Record<string, unknown> | null;
  try {
    const { config: cfg } = await import("./config");
    const c = conn ? { url: (conn as { url?: string }).url || cfg.technitium.url, token: (conn as { apiToken?: string }).apiToken || cfg.technitium.token, user: (conn as { user?: string }).user || cfg.technitium.user, password: (conn as { password?: string }).password || cfg.technitium.password } : undefined;
    // Use raw request to delete zone — no helper yet
    if (c) {
      const token = c.token?.trim() ? c.token : await (async () => {
        const { vault } = await import("./services/vault");
        const pass = c.password ? await vault.resolveSecretValue(c.password) : "";
        const loginUrl = `${c.url.replace(/\/$/, "")}/api/user/login?user=${encodeURIComponent(c.user)}&pass=${encodeURIComponent(pass)}`;
        const lr = await fetch(loginUrl);
        const lt = await lr.text();
        const ld = JSON.parse(lt) as { token?: string };
        return ld.token || "";
      })();
      await fetch(`${c.url.replace(/\/$/, "")}/api/zones/delete?zone=${encodeURIComponent(domain.name)}`, { headers: { Authorization: `Bearer ${token}` } });
    }
  } catch { /* keep local delete even if Technitium fails */ }
  db.deleteDomain(id, tenantOf(res).id);
  db.addActivity("domain-delete", `Removed domain ${domain.name}`);
  res.json({ ok: true });
}));

router.get(
  "/domains/:id/records",
  tenantGuard,
  asyncHandler(async (req, res) => {
    const tenantId = tenantOf(res).id;
    const domain = db.getDomain(Number(req.params.id), tenantId);
    if (!domain) {
      res.status(404).json({ error: "Domain not found" });
      return;
    }
    const conn = providerConnectionForTenant(tenantId) as unknown as Record<string, unknown> | null;
    const records = await technitium.listZone(domain.name, (conn ?? undefined) as never);
    res.json(records);
  }),
);

router.post(
  "/domains/:id/records",
  tenantGuard,
  asyncHandler(async (req, res) => {
    const domain = db.getDomain(Number(req.params.id), tenantOf(res).id);
    if (!domain) {
      res.status(404).json({ error: "Domain not found" });
      return;
    }
    const { type, name, value, ttl, priority } = req.body || {};
    const recordType = String(type || "").toUpperCase();
    const allowed: string[] = ["A", "AAAA", "CNAME", "TXT", "MX", "NS", "SRV", "CAA", "PTR", "ANAME"];
    if (!allowed.includes(recordType)) {
      res.status(400).json({ error: `Unsupported record type: ${recordType}` });
      return;
    }
    if (!name || !value) {
      res.status(400).json({ error: "name and value are required" });
      return;
    }
    const conn = providerConnectionForTenant(tenantOf(res).id) as unknown as Record<string, unknown> | null;
    await technitium.addRecord(
      {
        zone: domain.name,
        type: recordType as technitium.RecordType,
        name,
        value,
        ttl: Number(ttl || 300),
        priority: priority !== undefined ? Number(priority) : undefined,
      },
      (conn ?? undefined) as never,
    );
    db.addActivity("record-add", `Added ${recordType} ${name}.${domain.name} → ${value} via Technitium`);
    res.status(201).json({ ok: true });
  }),
);

router.delete(
  "/domains/:id/records",
  tenantGuard,
  asyncHandler(async (req, res) => {
    const domain = db.getDomain(Number(req.params.id), tenantOf(res).id);
    if (!domain) {
      res.status(404).json({ error: "Domain not found" });
      return;
    }
    const { type, name, value } = req.body || {};
    if (!type || !name) {
      res.status(400).json({ error: "type and name are required" });
      return;
    }
    const conn = providerConnectionForTenant(tenantOf(res).id) as unknown as Record<string, unknown> | null;
    await technitium.deleteRecord(
      {
        zone: domain.name,
        type: String(type).toUpperCase(),
        name,
        value: value !== undefined ? String(value) : undefined,
      },
      (conn ?? undefined) as never,
    );
    db.addActivity("record-delete", `Removed ${type} ${name}.${domain.name} via Technitium`);
    res.json({ ok: true });
  }),
);

// ── DHCP (Technitium) ────────────────────────────────────────────────────
router.get(
  "/dhcp/scopes",
  requireAuth,
  asyncHandler(async (_req, res) => {
    res.json(await dhcp.listScopes());
  }),
);
router.get(
  "/dhcp/scopes/:name",
  requireAuth,
  asyncHandler(async (req, res) => {
    res.json(await dhcp.getScope(req.params.name));
  }),
);
router.post(
  "/dhcp/scopes",
  requireAuth,
  asyncHandler(async (req, res) => {
    const { name, startingAddress, endingAddress, subnetMask, routerAddress, domainName, dnsServers, useThisDnsServer, leaseTimeDays } = req.body || {};
    if (!name || !startingAddress || !endingAddress || !subnetMask) {
      res.status(400).json({ error: "name, startingAddress, endingAddress, subnetMask are required" });
      return;
    }
    await dhcp.setScope({ name, startingAddress, endingAddress, subnetMask, routerAddress, domainName, dnsServers, useThisDnsServer, leaseTimeDays });
    db.addActivity("dhcp-scope", `DHCP scope ${name}: ${startingAddress}–${endingAddress}/${subnetMask}`);
    res.status(201).json({ ok: true });
  }),
);
router.delete(
  "/dhcp/scopes/:name",
  requireAuth,
  asyncHandler(async (req, res) => {
    await dhcp.deleteScope(req.params.name);
    db.addActivity("dhcp-delete", `Deleted DHCP scope ${req.params.name}`);
    res.json({ ok: true });
  }),
);
router.post(
  "/dhcp/scopes/:name/enable",
  requireAuth,
  asyncHandler(async (req, res) => {
    await dhcp.enableScope(req.params.name);
    res.json({ ok: true });
  }),
);
router.post(
  "/dhcp/scopes/:name/disable",
  requireAuth,
  asyncHandler(async (req, res) => {
    await dhcp.disableScope(req.params.name);
    res.json({ ok: true });
  }),
);
router.get(
  "/dhcp/leases",
  requireAuth,
  asyncHandler(async (_req, res) => {
    res.json(await dhcp.listLeases());
  }),
);
router.delete(
  "/dhcp/leases",
  requireAuth,
  asyncHandler(async (req, res) => {
    const { scope, hardwareAddress } = req.body || {};
    if (!scope || !hardwareAddress) {
      res.status(400).json({ error: "scope and hardwareAddress are required" });
      return;
    }
    await dhcp.removeLease(scope, hardwareAddress);
    res.json({ ok: true });
  }),
);
router.post(
  "/dhcp/scopes/:name/reserved",
  requireAuth,
  asyncHandler(async (req, res) => {
    const { hardwareAddress, ipAddress, hostName } = req.body || {};
    if (!hardwareAddress || !ipAddress) {
      res.status(400).json({ error: "hardwareAddress and ipAddress are required" });
      return;
    }
    await dhcp.addReservedLease(req.params.name, hardwareAddress, ipAddress, hostName);
    res.status(201).json({ ok: true });
  }),
);
router.delete(
  "/dhcp/scopes/:name/reserved/:mac",
  requireAuth,
  asyncHandler(async (req, res) => {
    await dhcp.removeReservedLease(req.params.name, req.params.mac);
    res.json({ ok: true });
  }),
);

// ── Ad-blocking (Technitium) ─────────────────────────────────────────────
router.get(
  "/blocking/status",
  requireAuth,
  asyncHandler(async (_req, res) => {
    res.json(await blocking.getStatus());
  }),
);
router.post(
  "/blocking",
  requireAuth,
  asyncHandler(async (req, res) => {
    const { enableBlocking, blockListUrls, blockingType } = req.body || {};
    await blocking.setBlocking({ enableBlocking: enableBlocking !== undefined ? Boolean(enableBlocking) : undefined, blockListUrls: blockListUrls !== undefined ? String(blockListUrls) : undefined, blockingType: blockingType ? String(blockingType) : undefined });
    db.addActivity("blocking", `Blocking ${enableBlocking ? "enabled" : enableBlocking === false ? "disabled" : "updated"}`);
    res.json({ ok: true });
  }),
);
router.get(
  "/blocking/blocked",
  requireAuth,
  asyncHandler(async (_req, res) => {
    res.json(await blocking.listBlocked());
  }),
);
router.post(
  "/blocking/blocked",
  requireAuth,
  asyncHandler(async (req, res) => {
    const domain = String(req.body?.domain || "").trim().toLowerCase();
    if (!domain) { res.status(400).json({ error: "domain is required" }); return; }
    await blocking.addBlocked(domain);
    res.status(201).json({ ok: true });
  }),
);
router.delete(
  "/blocking/blocked/:domain",
  requireAuth,
  asyncHandler(async (req, res) => {
    await blocking.deleteBlocked(req.params.domain);
    res.json({ ok: true });
  }),
);
router.get(
  "/blocking/allowed",
  requireAuth,
  asyncHandler(async (_req, res) => {
    res.json(await blocking.listAllowed());
  }),
);
router.post(
  "/blocking/allowed",
  requireAuth,
  asyncHandler(async (req, res) => {
    const domain = String(req.body?.domain || "").trim().toLowerCase();
    if (!domain) { res.status(400).json({ error: "domain is required" }); return; }
    await blocking.addAllowed(domain);
    res.status(201).json({ ok: true });
  }),
);
router.delete(
  "/blocking/allowed/:domain",
  requireAuth,
  asyncHandler(async (req, res) => {
    await blocking.deleteAllowed(req.params.domain);
    res.json({ ok: true });
  }),
);
router.post(
  "/blocking/refresh",
  requireAuth,
  asyncHandler(async (_req, res) => {
    await blocking.forceUpdateBlockLists();
    res.json({ ok: true });
  }),
);

// ── Certificates — Technitium DNS-01 + 30-day wildcard default ───────────
router.get("/certificates", tenantGuard, (_req, res) => {
  res.json(db.listCertificates(tenantOf(res).id).map(certToJson));
});

router.post(
  "/certificates",
  tenantGuard,
  asyncHandler(async (req, res) => {
    // Default domain: <serverId>.lab.innotel.us with wildcard, 30-day PKI if no domain given
    const ident = serverIdentity.currentIdentity();
    const rawDomain = String(req.body?.domain || "").trim().toLowerCase().replace(/\.$/, "");
    const domain = rawDomain || ident.apex;
    let wildcard = Boolean(req.body?.wildcard);
    // No domain supplied → use server apex + wildcard (30-day cert per spec)
    const isDefaultWildcard = !rawDomain;
    if (isDefaultWildcard) wildcard = true;
    const name = String(req.body?.name || "").trim() || `${wildcard ? "*." : ""}${domain}`;
    if (!/^[a-z0-9.-]+$/.test(domain) || !domain.includes(".")) {
      res.status(400).json({ error: "Invalid domain name" });
      return;
    }
    const tenantId = tenantOf(res).id;
    const registered = db.listDomains(tenantId).map((d) => d.name);
    // For default wildcard, auto-register the apex zone
    if (isDefaultWildcard && !registered.includes(domain)) {
      try {
        const conn = providerConnectionForTenant(tenantId) as unknown as Record<string, unknown> | null;
        await technitium.ensureZone(domain, (conn ?? undefined) as never);
        db.createDomain({ name: domain, tenantId });
      } catch { /* ignore, cert flow will report */ }
    }
    const covered = registered.includes(domain) || registered.some((z) => domain === z || domain.endsWith(`.${z}`)) || isDefaultWildcard;
    if (!covered) {
      res.status(400).json({
        error: `Domain ${domain} is not covered by a registered zone (${registered.join(", ") || "none"}) — add the zone under Domains first`,
      });
      return;
    }
    const cert = db.createCertificate({ name, domain, wildcard, tenantId, source: isDefaultWildcard ? "pki" : undefined });
    // For default PKI wildcard, issue offline immediately (synchronous) so the caller gets material; otherwise fire ACME async
    if (isDefaultWildcard) {
      try {
        const pkiResult = await serverIdentity.ensureWildcardPki();
        // If our cert is the server wildcard row, it was updated in place — return it
        if (pkiResult && pkiResult.certId === cert.id) {
          res.status(201).json(certToJson(db.getCertificate(cert.id, tenantId)!));
          return;
        }
        // Otherwise fall through to ACME path for this separate cert
      } catch { /* fall through to ACME */ }
    }
    runIssueJob(cert.id).catch(() => undefined);
    res.status(202).json(certToJson(db.getCertificate(cert.id, tenantId)!));
  }),
);

router.get("/certificates/:id", tenantGuard, (req, res) => {
  const cert = db.getCertificate(Number(req.params.id), tenantOf(res).id);
  if (!cert) {
    res.status(404).json({ error: "Certificate not found" });
    return;
  }
  res.json(certToJson(cert));
});

router.get(
  "/certificates/:id/material",
  tenantGuard,
  asyncHandler(async (req, res) => {
    const cert = db.getCertificate(Number(req.params.id), tenantOf(res).id);
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
  tenantGuard,
  asyncHandler(async (req, res) => {
    const cert = db.getCertificate(Number(req.params.id), tenantOf(res).id);
    if (!cert) {
      res.status(404).json({ error: "Certificate not found" });
      return;
    }
    db.updateCertificateStatus(cert.id, "issuing");
    runIssueJob(cert.id).catch(() => undefined);
    res.status(202).json({ ok: true });
  }),
);

router.delete("/certificates/:id", tenantGuard, (req, res) => {
  const cert = db.getCertificate(Number(req.params.id), tenantOf(res).id);
  if (!cert) {
    res.status(404).json({ error: "Certificate not found" });
    return;
  }
  db.deleteCertificate(cert.id, tenantOf(res).id);
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

router.post(
  "/npm/export-cert",
  tenantGuard,
  asyncHandler(async (req, res) => {
    const cert = db.getCertificate(Number(req.body?.certificate_id), tenantOf(res).id);
    if (!cert) {
      res.status(404).json({ error: "Certificate not found" });
      return;
    }
    if (!cert.certificate || !cert.key) {
      res.status(409).json({ error: "Certificate material is not available yet" });
      return;
    }
    const niceName =
      String(req.body?.nice_name || "").trim() || `cerulean-${cert.domain}${cert.wildcard ? "-wildcard" : ""}`;
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

router.post(
  "/npm/hosts",
  requireAuth,
  asyncHandler(async (req, res) => {
    const { domain, forward_host, forward_port, forward_scheme = "http", certificate_id, ssl_forced = true, http2_support = true } = req.body || {};
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
    db.addActivity("npm-host", `Created NPM proxy host ${domain} → ${forward_host}:${forward_port}`);
    res.status(201).json(host);
  }),
);

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
    const { forward_host, forward_port, forward_scheme, certificate_id, ssl_forced, http2_support, websocket_support } = req.body || {};
    const updated = await npm.updateProxyHost(
      existing.id,
      {
        ...existing,
        forward_host: forward_host !== undefined ? String(forward_host) : existing.forward_host,
        forward_port: forward_port !== undefined ? Number(forward_port) : existing.forward_port,
        forward_scheme: forward_scheme === "https" ? "https" : forward_scheme !== undefined ? "http" : existing.forward_scheme,
        ssl_forced: ssl_forced !== undefined ? Boolean(ssl_forced) : existing.ssl_forced,
        http2_support: http2_support !== undefined ? Boolean(http2_support) : existing.http2_support,
        allow_websocket_upgrade: websocket_support !== undefined ? Boolean(websocket_support) : existing.allow_websocket_upgrade ?? true,
      },
      certificate_id !== undefined ? Number(certificate_id) : existing.certificate_id,
    );
    db.addActivity("npm-host", `Updated NPM proxy host ${(existing.domain_names || []).join(", ")}`);
    res.json(updated);
  }),
);

// ── Private PKI ─────────────────────────────────────────────────────────
router.get(
  "/pki/status",
  tenantGuard,
  asyncHandler(async (_req, res) => {
    res.json(pki.pkiStatus(tenantOf(res).id));
  }),
);

router.post(
  "/pki/init",
  requireAuth,
  pkiHandler(async (req, res) => {
    const existed = pki.pkiStatus().initialized;
    const commonName =
      typeof req.body?.commonName === "string" && req.body.commonName.trim() ? req.body.commonName.trim() : undefined;
    await pki.ensureCa(commonName);
    res.status(existed ? 200 : 201).json(pki.pkiStatus());
  }),
);

router.get("/pki/ca", requireAuth, (_req, res) => {
  const status = pki.pkiStatus();
  if (!status.initialized) {
    res.status(404).json({ error: "Internal CA not initialized yet" });
    return;
  }
  res.json({
    certificate: pki.caCertificatePem(),
    commonName: status.commonName,
    fingerprint: status.caFingerprint,
    expiresAt: status.caExpiresAt,
    createdAt: status.createdAt,
  });
});

router.get("/pki/certificates", tenantGuard, (_req, res) => {
  res.json(pki.listClientCertificates(tenantOf(res).id).map(clientCertToJson));
});

router.post(
  "/pki/certificates",
  tenantGuard,
  pkiHandler(async (req, res) => {
    const row = await pki.issueClientCertificate(
      {
        name: String(req.body?.name || ""),
        email: req.body?.email !== undefined ? String(req.body.email) : undefined,
        validityDays: req.body?.validity_days !== undefined ? Number(req.body.validity_days) : undefined,
      },
      tenantOf(res).id,
    );
    res.status(201).json(clientCertToJson(row));
  }),
);

router.get("/pki/certificates/:id", tenantGuard, (req, res) => {
  const row = pki.getClientCertificate(Number(req.params.id), tenantOf(res).id);
  if (!row) {
    res.status(404).json({ error: "Client certificate not found" });
    return;
  }
  res.json(clientCertToJson(row));
});

router.get(
  "/pki/certificates/:id/material",
  tenantGuard,
  pkiHandler(async (req, res) => {
    const row = pki.getClientCertificate(Number(req.params.id), tenantOf(res).id);
    if (!row) {
      res.status(404).json({ error: "Client certificate not found" });
      return;
    }
    if (row.status === "revoked") {
      res.status(409).json({ error: "Certificate is revoked — material is no longer available" });
      return;
    }
    const material = pki.clientCertificateMaterial(row);
    res.json({ certificate: material.certificate, key: material.key || null, ca: material.ca });
  }),
);

router.post(
  "/pki/certificates/:id/revoke",
  tenantGuard,
  pkiHandler(async (req, res) => {
    const row = pki.revokeClientCertificate(Number(req.params.id), tenantOf(res).id);
    res.json(clientCertToJson(row));
  }),
);

router.post(
  "/pki/enroll/csr",
  tenantGuard,
  pkiHandler(async (req, res) => {
    const row = await pki.enrollCsr(
      String(req.body?.csr ?? ""),
      { validityDays: req.body?.validity_days !== undefined ? Number(req.body.validity_days) : undefined },
      tenantOf(res).id,
    );
    res.status(201).json({
      certificate: clientCertToJson(row),
      material: { certificate: row.certificate, key: row.key || null, ca: pki.caCertificatePem() },
    });
  }),
);

router.get(
  "/pki/enrollment/profile",
  requireAuth,
  asyncHandler(async (req, res) => {
    const name = String(req.query.name ?? "").trim();
    if (!name) {
      res.status(400).json({ error: "Missing ?name= — the device/identity CN to enroll" });
      return;
    }
    let profile: enrollment.EnrollmentProfile;
    try {
      profile = enrollment.buildEnrollmentProfile({ name });
    } catch (err) {
      if (err instanceof enrollment.EnrollmentError) {
        res.status(err.status).json({ error: err.message });
        return;
      }
      throw err;
    }
    res.set("Content-Type", "application/x-apple-aspen-config");
    res.set("Content-Disposition", `attachment; filename="${profile.filename}"`);
    res.send(profile.xml);
  }),
);

router.post(
  "/npm/mtls",
  requireAuth,
  asyncHandler(async (req, res) => {
    const mode = String(req.body?.mode ?? "");
    const rawHosts = Array.isArray(req.body?.hosts) ? (req.body.hosts as unknown[]).map(String) : [];
    if (mode !== "on" && mode !== "off") {
      res.status(400).json({ error: 'mode must be "on" or "off"' });
      return;
    }
    if (!rawHosts.length) {
      res.status(400).json({ error: 'hosts is required — e.g. ["app.cerulean.innotel.us"]' });
      return;
    }
    if (config.npm.mode !== "local") {
      res.status(400).json({
        error: "This endpoint supports the bundled NPM (NPM_MODE=local). For remote NPM, place the root CA at /data/cerulean-client-ca.pem on the NPM host.",
      });
      return;
    }
    try {
      const hosts = await npm.listProxyHosts();
      const wanted = new Set(rawHosts.map((d) => d.toLowerCase()));
      const matched = hosts.filter((h) => h.domain_names.some((d) => wanted.has(d.toLowerCase())));
      if (!matched.length) {
        res.status(404).json({ error: `No proxy host matches: ${rawHosts.join(", ")}` });
        return;
      }
      if (mode === "on") materializeClientCaFile();
      const updated: string[] = [];
      for (const host of matched) {
        const result = await npm.setHostMtls(host, mode);
        updated.push(...result.domain_names);
      }
      res.json({ ok: true, mode, hosts: updated });
    } catch (err) {
      if (err instanceof Error && /not initialized|no SSL certificate/.test(err.message)) {
        res.status(409).json({ error: err.message });
        return;
      }
      throw err;
    }
  }),
);

// ── Tenants ─────────────────────────────────────────────────────────────
router.get("/tenants", tenantGuard, (_req, res) => {
  if (!isPlatform(res)) {
    res.status(403).json({ error: "Platform admin required" });
    return;
  }
  res.json(db.listTenants());
});

router.post("/tenants", tenantGuard, (req, res) => {
  if (!isPlatform(res)) {
    res.status(403).json({ error: "Platform admin required" });
    return;
  }
  try {
    const tenant = createTenant({ slug: String(req.body?.slug ?? ""), name: String(req.body?.name ?? "") });
    db.addActivity("tenant-create", `Created tenant "${tenant.name}" (${tenant.slug})`);
    res.status(201).json(tenant);
  } catch (err) {
    if (err instanceof TenantError) {
      res.status(err.status).json({ error: err.message });
      return;
    }
    throw err;
  }
});

router.patch("/tenants/:id", tenantGuard, (req, res) => {
  if (!isPlatform(res)) {
    res.status(403).json({ error: "Platform admin required" });
    return;
  }
  try {
    const tenant = renameTenant(Number(req.params.id), String(req.body?.name ?? ""));
    db.addActivity("tenant-rename", `Renamed tenant ${tenant.slug} → "${tenant.name}"`);
    res.json(tenant);
  } catch (err) {
    if (err instanceof TenantError) {
      res.status(err.status).json({ error: err.message });
      return;
    }
    throw err;
  }
});

router.get(
  "/tenants/:slug/members",
  tenantGuard,
  asyncHandler(async (req, res) => {
    if (!isPlatform(res)) {
      res.status(403).json({ error: "Platform admin required" });
      return;
    }
    const slug = String(req.params.slug ?? "");
    if (!db.getTenantBySlug(slug)) {
      res.status(404).json({ error: "Tenant not found" });
      return;
    }
    if (!authentikAdminConfigured()) {
      res.json({
        available: false,
        users: [],
        hint: "Member listing needs Authentik admin credentials — set AUTHENTIK_API_URL and AUTHENTIK_ADMIN_PASSWORD in .env",
      });
      return;
    }
    try {
      const { users, groupExists } = await listGroupMembers(slug);
      res.json({
        available: true,
        users,
        groupExists,
        hint: groupExists ? `Members are the users in the Authentik group "${slug}"` : `No Authentik group "${slug}" yet — create it and add users`,
      });
    } catch (err) {
      res.status(502).json({ error: err instanceof Error ? err.message : "Authentik query failed" });
    }
  }),
);

// ── Per-tenant DNS providers (Technitium) ───────────────────────────────
router.get("/dns/providers", tenantGuard, (_req, res) => {
  res.json(listDnsProviders(tenantOf(res).id));
});

router.post("/dns/providers", tenantGuard, (req, res) => {
  try {
    const b = req.body || {};
    const row = createDnsProvider(tenantOf(res).id, {
      name: String(b.name ?? ""),
      url: b.url !== undefined ? String(b.url) : b.host ? `http://${b.host}:${b.port ?? 5380}` : undefined,
      host: b.host !== undefined ? String(b.host) : undefined,
      port: b.port !== undefined ? Number(b.port) : undefined,
      apiToken: b.api_token ?? b.apiToken ?? b.token,
      user: b.user !== undefined ? String(b.user) : undefined,
      password: b.password !== undefined ? String(b.password) : undefined,
      isDefault: b.default === true || b.isDefault === true,
    });
    db.addActivity("dns-provider-create", `Added Technitium provider ${row.name}`);
    res.status(201).json(row);
  } catch (err) {
    if (err instanceof ProviderError) {
      res.status(err.status).json({ error: err.message });
      return;
    }
    throw err;
  }
});

router.patch("/dns/providers/:id", tenantGuard, (req, res) => {
  const b = (req.body ?? {}) as Record<string, unknown>;
  const input: Record<string, unknown> = {};
  if (b.name !== undefined) input.name = String(b.name);
  if (b.url !== undefined) input.url = String(b.url);
  if (b.host !== undefined) input.host = String(b.host);
  if (b.port !== undefined) input.port = Number(b.port);
  if (b.api_token !== undefined) input.apiToken = String(b.api_token);
  if (b.apiToken !== undefined) input.apiToken = String(b.apiToken);
  if (b.token !== undefined) input.apiToken = String(b.token);
  if (b.user !== undefined) input.user = String(b.user);
  if (b.password !== undefined) input.password = String(b.password);
  if (b.default !== undefined) input.isDefault = b.default === true;
  if (b.isDefault !== undefined) input.isDefault = b.isDefault === true;
  try {
    const row = updateDnsProvider(Number(req.params.id), tenantOf(res).id, input as Parameters<typeof updateDnsProvider>[2]);
    res.json(row);
  } catch (err) {
    if (err instanceof ProviderError) {
      res.status(err.status).json({ error: err.message });
      return;
    }
    throw err;
  }
});

router.delete("/dns/providers/:id", tenantGuard, (req, res) => {
  const id = Number(req.params.id);
  if (!db.getDnsProvider(id, tenantOf(res).id)) {
    res.status(404).json({ error: "DNS provider not found" });
    return;
  }
  deleteDnsProvider(id, tenantOf(res).id);
  db.addActivity("dns-provider-delete", `Removed DNS provider #${id}`);
  res.json({ ok: true });
});

// ── Activities ──────────────────────────────────────────────────────────
router.get("/activities", requireAuth, (_req, res) => {
  res.json(db.listActivities(200));
});

// ── Certificate health ──────────────────────────────────────────────────
router.get("/certificates/:id/health", tenantGuard, (req, res) => {
  const cert = db.getCertificate(Number(req.params.id), tenantOf(res).id);
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
});

// ── Discovery ───────────────────────────────────────────────────────────
router.get("/discovery/certificates", tenantGuard, (_req, res) => {
  res.json(
    db.listDiscoveredCerts(tenantOf(res).id).map((c) => {
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
  tenantGuard,
  asyncHandler(async (_req, res) => {
    const result = await runDiscovery(tenantOf(res).id);
    res.json({ ok: true, ...result });
  }),
);

router.delete("/discovery/certificates/:id", tenantGuard, (req, res) => {
  const row = db.listDiscoveredCerts(tenantOf(res).id).find((c) => c.id === Number(req.params.id));
  if (!row) {
    res.status(404).json({ error: "Certificate not found" });
    return;
  }
  db.deleteDiscoveredCert(row.id, tenantOf(res).id);
  db.addActivity("discovery-delete", `Removed discovered certificate ${row.name}`);
  res.json({ ok: true });
});

// ── DNS audit ───────────────────────────────────────────────────────────
router.get(
  "/audit/dns",
  tenantGuard,
  asyncHandler(async (req, res) => {
    const tenantId = tenantOf(res).id;
    const requested = typeof req.query.domain === "string" ? req.query.domain.trim() : "";
    if (requested && !db.getDomainByName(requested, tenantId)) {
      res.status(404).json({ error: "Domain not found in this tenant" });
      return;
    }
    const targets = requested ? [requested] : db.listDomains(tenantId).map((d) => d.name);
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
          checks: [{ name: "error", status: "fail", detail: err instanceof Error ? err.message : String(err) }],
        });
      }
    }
    res.json(audits);
  }),
);

router.get("/audit/dns/history", tenantGuard, (_req, res) => {
  const owned = new Set(db.listDomains(tenantOf(res).id).map((d) => d.name));
  res.json(
    db
      .listDnsAudits(200)
      .filter((a) => owned.has(a.domain))
      .map((a) => ({ id: a.id, domain: a.domain, runAt: a.run_at, score: a.score, checks: JSON.parse(a.checks_json) })),
  );
});

// ── Vault ───────────────────────────────────────────────────────────────
router.post(
  "/vault/sync",
  requireAuth,
  asyncHandler(async (_req, res) => {
    if (!vault.isEnabled()) {
      res.status(409).json({ error: "Vault is not configured — set VAULT_ADDR and VAULT_TOKEN in .env" });
      return;
    }
    const { written } = await vault.sync();
    db.addActivity("vault-sync", `Synced ${written.length} secret(s) to the vault (manual)`);
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
