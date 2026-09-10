/**
 * Central Registration Server (CRS) — master/slave + home replica.
 *
 * Home address: lab.innotel.us (CRS_HOME_URL defaults to https://lab.innotel.us).
 *
 * Roles
 *  - master: holds the authoritative registry, assigns serverIds, requires
 *    CRS_DOMAIN (e.g. lab.innotel.us). Other nodes register here.
 *  - slave: registers to a master (CRS_MASTER_URL, which defaults to
 *    CRS_HOME_URL = https://lab.innotel.us) when online, holds a local
 *    replica of every serverId.
 *  - auto (default): try to become a slave to the home/masters. If the
 *    master is unreachable (offline / air-gapped) become an isolated
 *    master: act as master locally *and* remain logically a slave to the
 *    home — it will re-sync the moment connectivity returns. No extra
 *    operator step.
 *
 * The master is the source of truth for <serverId>.lab.innotel.us. A slave
 * can be promoted to master simply by configuring it with CRS_ROLE=master +
 * CRS_DOMAIN (and it will retain its replica as the starting registry).
 *
 * Spec summary:
 *  - Master holds all records and assigns serverIds.
 *  - Slave registers to and holds a copy of all serverIds.
 *  - If CRS_ROLE=master but no CRS_DOMAIN → boot error.
 *  - If offline / air-gapped or master unreachable → isolated master-only.
 *  - Every CRS (even a master) logically registers as a slave to home
 *    lab.innotel.us when online — that is best-effort and queued.
 */

import crypto from "node:crypto";
import { config, sanitizeServerId, generateServerId } from "../config";
import { db } from "../db";

// ── Types ───────────────────────────────────────────────────────────────────

export type CrsDesiredRole = "auto" | "master" | "slave";
export type CrsResolvedRole = "master" | "slave" | "isolated-master" | "offline-slave";

export interface CrsStatus {
  homeUrl: string;
  masterUrl: string;
  desiredRole: CrsDesiredRole;
  resolvedRole: CrsResolvedRole;
  domain: string; // CRS authority domain (lab.innotel.us by default)
  isMaster: boolean;
  isSlave: boolean;
  isAirGapped: boolean;
  lastSyncAt: string | null;
  lastSyncStatus: string | null;
  reachable: boolean | null; // last probe to master
  registryCount: number;
  localCount: number; // how many came from master replica vs local
  error: string | null; // config error (master without domain)
}

export interface RegistryEntry {
  serverId: string;
  labDomain: string;
  apex: string;
  wildcard: string;
  role: string; // "master" | "slave" | "isolated-master"
  source: string; // "local" | "replica" | "master" | "home"
  firstSeen: string;
  lastSeen: string;
  metadata: Record<string, unknown> | null;
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function nowIso(): string { return new Date().toISOString(); }

function normalizeUrl(raw: string): string {
  if (!raw) return "";
  let s = raw.trim().replace(/\/+$/, "");
  if (!s) return "";
  if (!/^https?:\/\//i.test(s)) s = `https://${s}`;
  return s;
}

function isOnlineError(msg: string): boolean {
  return /fetch failed|ECONNREFUSED|ENOTFOUND|ETIMEDOUT|timeout|network|offline/i.test(msg);
}

// ── DB helpers are on db object — thin wrappers here ────────────────────────

export function getRegistry(): RegistryEntry[] {
  return db.listCrsRegistry().map((r) => ({
    serverId: r.server_id,
    labDomain: r.lab_domain,
    apex: r.apex,
    wildcard: r.wildcard,
    role: r.role,
    source: r.source,
    firstSeen: r.first_seen,
    lastSeen: r.last_seen,
    metadata: r.metadata_json ? JSON.parse(r.metadata_json) as Record<string, unknown> : null,
  }));
}

export function getRegistryEntry(serverId: string): RegistryEntry | undefined {
  const r = db.getCrsEntry(serverId);
  if (!r) return undefined;
  return {
    serverId: r.server_id, labDomain: r.lab_domain, apex: r.apex, wildcard: r.wildcard,
    role: r.role, source: r.source, firstSeen: r.first_seen, lastSeen: r.last_seen,
    metadata: r.metadata_json ? JSON.parse(r.metadata_json) as Record<string, unknown> : null,
  };
}

// ── Master: assign / upsert ─────────────────────────────────────────────────

export function upsertRegistryEntry(input: {
  serverId: string;
  labDomain?: string;
  apex?: string;
  wildcard?: string;
  role?: string;
  source?: string;
  metadata?: Record<string, unknown> | null;
}): RegistryEntry {
  const sid = sanitizeServerId(input.serverId);
  if (!sid) throw Object.assign(new Error(`Invalid serverId "${input.serverId}"`), { status: 400 });
  const lab = (input.labDomain || config.server.labDomain).trim().toLowerCase().replace(/^\.+|\.+$/g, "") || config.server.labDomain;
  const apex = input.apex || `${sid}.${lab}`;
  const wildcard = input.wildcard || `*.${apex}`;
  const role = input.role || "slave";
  const source = input.source || "local";
  db.upsertCrsEntry({
    serverId: sid, labDomain: lab, apex, wildcard, role, source,
    metadata: input.metadata ?? null,
  });
  return getRegistryEntry(sid)!;
}

/**
 * Assign a new serverId. If `requestedId` is provided and free, it is honored
 * (idempotent). Otherwise a fresh id is minted. Master is the only caller
 * that should mint; slaves call this only when isolated.
 */
export function assignServerId(requestedId?: string, meta?: Record<string, unknown> | null): RegistryEntry {
  const desired = requestedId ? sanitizeServerId(requestedId) : "";
  if (desired) {
    const existing = db.getCrsEntry(desired);
    if (existing) {
      // idempotent: touch lastSeen and return
      db.upsertCrsEntry({ serverId: desired, labDomain: existing.lab_domain, apex: existing.apex, wildcard: existing.wildcard, role: existing.role, source: existing.source, metadata: meta ?? (existing.metadata_json ? JSON.parse(existing.metadata_json) : null) });
      return getRegistryEntry(desired)!;
    }
    return upsertRegistryEntry({ serverId: desired, role: "slave", source: "master", metadata: meta ?? null });
  }
  // Mint loop — collision is astronomically unlikely but handle anyway
  for (let attempt = 0; attempt < 20; attempt++) {
    const candidate = generateServerId();
    if (!db.getCrsEntry(candidate)) {
      return upsertRegistryEntry({ serverId: candidate, role: "slave", source: "master", metadata: meta ?? null });
    }
  }
  throw new Error("assignServerId: too many collisions");
}

// ── Role resolution ─────────────────────────────────────────────────────────

let lastProbe: { ok: boolean | null; at: string | null; detail: string | null } = { ok: null, at: null, detail: null };
let resolvedRole: CrsResolvedRole | null = null;
let roleError: string | null = null;

function desiredRole(): CrsDesiredRole {
  const raw = (config as unknown as { crs?: { role?: string } }).crs?.role?.toLowerCase() as string | undefined;
  if (raw === "master" || raw === "slave" || raw === "auto") return raw;
  return "auto";
}

export function crsDomain(): string {
  const crs = (config as unknown as { crs?: { domain?: string; homeUrl?: string } }).crs;
  const d = (crs?.domain || (config.server.labDomain || "lab.innotel.us")).trim().toLowerCase().replace(/^\.+|\.+$/g, "");
  return d || "lab.innotel.us";
}

function homeUrl(): string { return normalizeUrl((config as unknown as { crs?: { homeUrl?: string } }).crs?.homeUrl || "https://lab.innotel.us"); }
function masterUrl(): string {
  const crs = (config as unknown as { crs?: { masterUrl?: string; homeUrl?: string } }).crs;
  const raw = (crs?.masterUrl || crs?.homeUrl || "https://lab.innotel.us").trim();
  return normalizeUrl(raw);
}

function isAirGappedFlag(): boolean {
  const crs = (config as unknown as { crs?: { airGapped?: boolean } }).crs;
  if (typeof crs?.airGapped === "boolean") return crs.airGapped;
  // Heuristic: if CRS_ROLE explicitly slave but master unreachable, not air-gapped; isolated-master is emergent
  return false;
}

export function validateMasterConfig(): string | null {
  const role = desiredRole();
  if (role === "master" && !crsDomain()) {
    return "CRS master requires CRS_DOMAIN (e.g. lab.innotel.us) — set it in .env";
  }
  // Auto that resolves to master also needs a domain, but we can derive it from labDomain so this is soft
  return null;
}

export async function probeMaster(url?: string): Promise<{ ok: boolean; detail: string }> {
  const target = normalizeUrl(url || masterUrl());
  const probeUrl = `${target.replace(/\/+$/, "")}/api/crs/status`;
  try {
    const res = await fetch(probeUrl, { method: "GET", signal: AbortSignal.timeout(5000) });
    const text = await res.text();
    if (!res.ok) return { ok: false, detail: `HTTP ${res.status}: ${text.slice(0, 200)}` };
    let data: unknown = null; try { data = JSON.parse(text); } catch { /* ignore */ }
    // Accept either status envelope or home's own CRS status
    return { ok: true, detail: typeof (data as { domain?: string })?.domain === "string" ? `reachable (${(data as { domain: string }).domain})` : "reachable" };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { ok: false, detail: msg };
  }
}

export async function resolveCrsRole(forceProbe = false): Promise<CrsResolvedRole> {
  roleError = validateMasterConfig();
  // If explicitly master, we are master regardless of connectivity — but still try to enslave to home when online
  const desired = desiredRole();
  const home = homeUrl();
  const master = masterUrl();

  if (desired === "master") {
    // Master always, even if isolated. We still record reachability to home/master for UI.
    if (forceProbe || lastProbe.ok === null) {
      const p = await probeMaster(home);
      lastProbe = { ok: p.ok, at: nowIso(), detail: p.detail };
    }
    resolvedRole = "master";
    persistCrsState();
    return resolvedRole;
  }
  if (desired === "slave") {
    const p = await probeMaster(master);
    lastProbe = { ok: p.ok, at: nowIso(), detail: p.detail };
    if (!p.ok && isOnlineError(p.detail)) {
      resolvedRole = "offline-slave";
    } else if (!p.ok) {
      resolvedRole = "offline-slave";
    } else {
      resolvedRole = "slave";
    }
    persistCrsState();
    return resolvedRole;
  }

  // auto (default): try to be a slave to master/home; if unreachable → isolated-master
  const p = await probeMaster(master);
  lastProbe = { ok: p.ok, at: nowIso(), detail: p.detail };
  if (p.ok) {
    resolvedRole = "slave";
  } else if (isAirGappedFlag()) {
    resolvedRole = "isolated-master";
  } else if (isOnlineError(p.detail)) {
    // Offline / air-gapped → become master-only, but logically still a slave to home
    resolvedRole = "isolated-master";
  } else {
    // Non-network error but master not happy — still fallback to isolated rather than fail
    resolvedRole = "isolated-master";
  }
  persistCrsState();
  return resolvedRole;
}

export function getResolvedRole(): CrsResolvedRole | null { return resolvedRole; }
export function getLastProbe() { return lastProbe; }
export function getRoleError(): string | null { return roleError; }

function persistCrsState(): void {
  try {
    db.upsertCrsState({
      desiredRole: desiredRole(),
      resolvedRole: resolvedRole || "isolated-master",
      domain: crsDomain(),
      homeUrl: homeUrl(),
      masterUrl: masterUrl(),
      isAirGapped: resolvedRole === "isolated-master" ? 1 : 0,
      lastSync: lastProbe.at,
      lastSyncStatus: lastProbe.detail,
    });
  } catch { /* ignore */ }
}

export function crsStatus(): CrsStatus {
  const desired = desiredRole();
  const resolved = resolvedRole || (desired === "master" ? "master" as const : "isolated-master" as const);
  const registry = db.listCrsRegistry();
  const isMaster = resolved === "master" || resolved === "isolated-master";
  const isSlave = resolved === "slave" || resolved === "offline-slave" || resolved === "isolated-master";
  return {
    homeUrl: homeUrl(),
    masterUrl: masterUrl(),
    desiredRole: desired,
    resolvedRole: resolved,
    domain: crsDomain(),
    isMaster,
    isSlave,
    isAirGapped: resolved === "isolated-master",
    lastSyncAt: lastProbe.at,
    lastSyncStatus: lastProbe.detail,
    reachable: lastProbe.ok,
    registryCount: registry.length,
    localCount: registry.filter((r) => r.source === "replica" || r.source === "home").length,
    error: roleError,
  };
}

// ── Slave → master registration ───────────────────────────────────────────

export interface RegistrationPayload {
  serverId?: string; // optional: if omitted, master assigns one
  labDomain?: string;
  apex?: string;
  wildcard?: string;
  role?: string;
  metadata?: Record<string, unknown>;
}

export interface RegistrationResult {
  assigned: boolean; // true if master minted a new id for us
  serverId: string;
  apex: string;
  wildcard: string;
  labDomain: string;
  domain: string; // CRS domain
}

/**
 * Slave calls this to register itself with its configured master (or home).
 * When `payload.serverId` is set, the master will honor it idempotently; when
 * omitted, a fresh id is minted. This is how slaves obtain their serverId on
 * first boot.
 *
 * On the *client* side (this instance as slave), call `registerToMaster()`.
 * On the *server* side (this instance as master), HTTP handler calls
 * `handleRegistrationRequest(payload)` directly.
 */
export async function registerToMaster(payload?: RegistrationPayload): Promise<RegistrationResult> {
  const ident = (() => { try { return db.getServerIdentity(); } catch { return undefined; } })();
  const localId = ident?.server_id || config.server.id;
  const lab = payload?.labDomain || ident?.lab_domain || config.server.labDomain;
  const target = masterUrl();
  const body: Record<string, unknown> = {
    serverId: payload?.serverId || localId,
    server_id: payload?.serverId || localId,
    labDomain: lab,
    apex: payload?.apex || `${payload?.serverId || localId}.${lab}`,
    wildcard: payload?.wildcard || `*.${payload?.serverId || localId}.${lab}`,
    role: payload?.role || "slave",
    metadata: payload?.metadata || {},
  };

  // Use CRS token if configured, else server register token
  const crs = (config as unknown as { crs?: { token?: string } }).crs;
  const token = crs?.token || (config.server as unknown as { registerToken?: string }).registerToken || (config as unknown as { crs?: { token?: string } }).crs?.token || "";

  const url = `${target.replace(/\/+$/, "")}/api/crs/register`;
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        "X-Cerulean-Role": "slave",
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(10_000),
    });
    const text = await res.text();
    let data: Record<string, unknown> = {};
    try { data = JSON.parse(text) as Record<string, unknown>; } catch { /* non-json */ }
    if (!res.ok) {
      const msg = (data as { error?: string }).error || text.slice(0, 500);
      throw new Error(`CRS register HTTP ${res.status}: ${msg}`);
    }
    const assigned = Boolean((data as { assigned?: boolean }).assigned);
    const serverId = String((data as { serverId?: string; server_id?: string }).serverId || (data as { server_id?: string }).server_id || body.serverId);
    const sid = sanitizeServerId(serverId);
    if (!sid) throw new Error(`CRS master returned invalid serverId "${serverId}"`);

    // Success: adopt the authoritative id locally if it differs (first-boot assignment)
    if (sid !== localId) {
      db.upsertServerIdentity({ serverId: sid, labDomain: lab, centralUrl: target });
    }
    db.setServerRegistered(true, target);
    // Record in our own replica as well
    db.upsertCrsEntry({
      serverId: sid,
      labDomain: lab,
      apex: String((data as { apex?: string }).apex || body.apex),
      wildcard: String((data as { wildcard?: string }).wildcard || body.wildcard),
      role: String((data as { role?: string }).role || "slave"),
      source: "home",
      metadata: body.metadata as Record<string, unknown>,
    });
    db.addActivity("crs-register", `Registered ${sid} (${lab}) with CRS master ${target}`, assigned ? "assigned by master" : "honored local id");
    lastProbe = { ok: true, at: nowIso(), detail: "registered" };
    persistCrsState();
    return {
      assigned,
      serverId: sid,
      apex: String((data as { apex?: string }).apex || body.apex),
      wildcard: String((data as { wildcard?: string }).wildcard || body.wildcard),
      labDomain: lab,
      domain: String((data as { domain?: string }).domain || crsDomain()),
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    // Offline or air-gapped — caller will fallback to isolated master; do not throw hard for network errors
    if (isOnlineError(msg)) {
      db.addActivity("crs-register-offline", `CRS master ${target} unreachable — operating as isolated master`, msg.slice(0, 500));
      lastProbe = { ok: false, at: nowIso(), detail: msg.slice(0, 500) };
      persistCrsState();
      // Return local identity as if we are our own master
      const sid = sanitizeServerId(String(body.serverId));
      const apex = String(body.apex);
      const wildcard = String(body.wildcard);
      // Ensure local registry contains ourselves as isolated master
      db.upsertCrsEntry({ serverId: sid, labDomain: lab, apex, wildcard, role: "isolated-master", source: "local", metadata: body.metadata as Record<string, unknown> });
      return { assigned: false, serverId: sid, apex, wildcard, labDomain: lab, domain: crsDomain() };
    }
    db.addActivity("crs-register-error", `CRS register to ${target} failed`, msg.slice(0, 500));
    throw err;
  }
}

// ── Master-side HTTP handler helper ───────────────────────────────────────

export function handleRegistrationRequest(payload: RegistrationPayload): RegistrationResult {
  // This runs *on the master*. It is called by the POST /api/crs/register handler
  // after auth (if CRS token is configured). It is the authority that holds all
  // records and assigns serverIds.
  const domain = crsDomain();
  const lab = (payload.labDomain || domain).trim().toLowerCase().replace(/^\.+|\.+$/g, "") || domain;
  const requested = payload.serverId ? sanitizeServerId(String(payload.serverId)) : "";
  let sid: string;
  let assigned = false;

  if (requested) {
    const existing = db.getCrsEntry(requested);
    if (existing) {
      // Idempotent re-register: refresh timestamps/metadata
      db.upsertCrsEntry({
        serverId: requested, labDomain: lab,
        apex: String(payload.apex || existing.apex), wildcard: String(payload.wildcard || existing.wildcard),
        role: String(payload.role || existing.role), source: "master",
        metadata: payload.metadata ?? (existing.metadata_json ? JSON.parse(existing.metadata_json) : null),
      });
      sid = requested;
    } else {
      // Honor the requested id (slave's local id) — allocate it
      db.upsertCrsEntry({
        serverId: requested, labDomain: lab,
        apex: String(payload.apex || `${requested}.${lab}`), wildcard: String(payload.wildcard || `*.${requested}.${lab}`),
        role: String(payload.role || "slave"), source: "master",
        metadata: payload.metadata ?? null,
      });
      sid = requested;
    }
  } else {
    const entry = assignServerId(undefined, payload.metadata ?? null);
    sid = entry.serverId;
    assigned = true;
  }

  const entry = db.getCrsEntry(sid)!;
  db.addActivity("crs-assign", `${assigned ? "Assigned" : "Registered"} ${sid} (${entry.apex}) in CRS registry (master=${domain})`);

  return {
    assigned,
    serverId: sid,
    apex: entry.apex,
    wildcard: entry.wildcard,
    labDomain: entry.lab_domain,
    domain,
  };
}

// ── Slave replica sync ────────────────────────────────────────────────────

export async function syncRegistryFromMaster(): Promise<{ pulled: number; detail: string }> {
  const target = masterUrl();
  const crs = (config as unknown as { crs?: { token?: string } }).crs;
  const token = crs?.token || (config.server as unknown as { registerToken?: string }).registerToken || "";
  const url = `${target.replace(/\/+$/, "")}/api/crs/registry`;
  try {
    const res = await fetch(url, {
      method: "GET",
      headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      signal: AbortSignal.timeout(15_000),
    });
    const text = await res.text();
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${text.slice(0, 500)}`);
    let data: unknown = null; try { data = JSON.parse(text); } catch { throw new Error(`CRS registry non-JSON: ${text.slice(0, 300)}`); }
    const entries = Array.isArray(data) ? data as RegistryEntry[]
      : Array.isArray((data as { entries?: unknown }).entries) ? (data as { entries: RegistryEntry[] }).entries
      : Array.isArray((data as { registry?: unknown }).registry) ? (data as { registry: RegistryEntry[] }).registry
      : [];
    let pulled = 0;
    for (const e of entries) {
      const sid = sanitizeServerId(String((e as unknown as { serverId?: string; server_id?: string }).serverId || (e as unknown as { server_id?: string }).server_id || "")) || sanitizeServerId(String((e as unknown as { serverId?: string }).serverId || ""));
      if (!sid) continue;
      const lab = String((e as unknown as { labDomain?: string }).labDomain || crsDomain());
      const apex = String((e as unknown as { apex?: string }).apex || `${sid}.${lab}`);
      const wildcard = String((e as unknown as { wildcard?: string }).wildcard || `*.${apex}`);
      db.upsertCrsEntry({ serverId: sid, labDomain: lab, apex, wildcard, role: String((e as unknown as { role?: string }).role || "slave"), source: "replica", metadata: (e as unknown as { metadata?: Record<string, unknown> }).metadata ?? null });
      pulled++;
    }
    lastProbe = { ok: true, at: nowIso(), detail: `synced ${pulled} entries from ${target}` };
    persistCrsState();
    if (pulled) db.addActivity("crs-sync", `Pulled ${pulled} registry entries from CRS master ${target}`);
    return { pulled, detail: `synced ${pulled} entries` };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (isOnlineError(msg)) {
      lastProbe = { ok: false, at: nowIso(), detail: msg.slice(0, 500) };
      persistCrsState();
      return { pulled: 0, detail: `offline: ${msg.slice(0, 200)}` };
    }
    throw err;
  }
}

export function generateServiceToken(): string {
  // ceru_<16 hex prefix>_<48 hex secret> — prefix is stored in clear for lookup, secret is hashed
  const prefix = crypto.randomBytes(8).toString("hex");
  const secret = crypto.randomBytes(24).toString("hex");
  return `ceru_${prefix}_${secret}`;
}

export function hashServiceToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}
