/**
 * Technitium DNS Server — HTTP API client.
 *
 * Replaces the legacy BIND-over-SSH (nsupdate + TSIG, dig AXFR) stack.
 * Every DNS mutation/records call now flows through Technitium's
 * /api/zones/* endpoints. Supports both the platform-level Technitium
 * (from .env: TECHNITIUM_URL / TECHNITIUM_TOKEN) and per-tenant
 * Technitium providers (kind = "technitium", stored in dns_providers.url+api_token+host).
 *
 * Docs: https://github.com/TechnitiumSoftware/DnsServer/blob/master/APIDOCS.md
 */

import { config } from "../config";
import { vault } from "./vault";

// ── Helpers ───────────────────────────────────────────────────────────────

export type RecordType = "A" | "AAAA" | "CNAME" | "TXT" | "MX" | "NS" | "SRV" | "CAA" | "PTR" | "ANAME" | "FWD";

export interface DnsRecord {
  name: string;
  type: string;
  ttl: number;
  value: string;
  disabled?: boolean;
}

export interface AddRecordInput {
  zone: string;
  type: RecordType;
  name: string; // relative to zone (e.g. "www" or "@")
  value: string;
  ttl?: number;
  priority?: number; // MX / SRV / etc
}

/** Quote handling identical to previous bind helpers (kept for compatibility). */
export function quoteTxt(value: string): string {
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

export function fqdn(name: string, zone: string): string {
  if (name === "@" || name === "") return `${zone}.`;
  const n = name.replace(/\.$/, "");
  const z = zone.replace(/\.$/, "");
  if (n.endsWith(`.${z}`) || n === z) return `${n}.`;
  return `${n}.${z}.`;
}

function ensureDot(name: string): string {
  return name.endsWith(".") ? name : `${name}.`;
}
function stripDot(name: string): string {
  return name.replace(/\.$/, "");
}

/**
 * Resolve the authoritative zone for a domain: longest matching zone suffix.
 */
export function resolveZone(domain: string, zones: string[]): string {
  const d = stripDot(domain).toLowerCase();
  let best: string | undefined;
  for (const zoneRaw of zones) {
    const raw = stripDot(zoneRaw);
    const z = raw.toLowerCase();
    if (!z) continue;
    if ((d === z || d.endsWith(`.${z}`)) && (!best || z.length > best.length)) best = raw;
  }
  if (!best) {
    const listed = zones.filter(Boolean).length ? zones.filter(Boolean).join(", ") : "none registered";
    throw new Error(
      `Domain "${domain}" is not covered by any managed Technitium zone (${listed}). ` +
        `Register the zone on the Domains page or set CERULEAN_ZONE in .env.`,
    );
  }
  return best;
}

// ── Connection resolution ─────────────────────────────────────────────────

export interface TechnitiumConnection {
  url: string;
  token: string;
  user: string;
  password: string;
  providerName: string | null;
}

function platformConnection(): TechnitiumConnection {
  return {
    url: config.technitium.url,
    token: config.technitium.token,
    user: config.technitium.user,
    password: config.technitium.password,
    providerName: null,
  };
}

/**
 * Resolve effective Technitium connection: per-tenant provider if present,
 * else platform from .env. `override` may be a dns_providers row translated
 * to connection fields.
 */
export function effectiveConnection(
  override?: Partial<TechnitiumConnection & { apiToken: string; host: string; port: number }>,
): TechnitiumConnection {
  if (!override) return platformConnection();
  const base = platformConnection();
  // Accept both url/api_token style and legacy host+port style
  let url = (override as { url?: string }).url || base.url;
  if (!url && (override as { host?: string }).host) {
    const host = (override as { host?: string }).host!;
    const port = (override as { port?: number }).port ?? 5380;
    url = `http://${host}:${port}`;
  }
  const token = (override as { apiToken?: string }).apiToken ?? (override as { token?: string }).token ?? base.token;
  return {
    url,
    token,
    user: (override as { user?: string }).user ?? base.user,
    password: (override as { password?: string }).password ?? base.password,
    providerName: (override as { providerName?: string | null }).providerName ?? null,
  };
}

// ── Low-level HTTP ────────────────────────────────────────────────────────

let cachedToken: string | null = null;
let tokenExpiry = 0;

async function getApiToken(conn: TechnitiumConnection): Promise<string> {
  // If a static API token is configured (Create API Token flow), use it directly — it never expires.
  const raw = conn.token?.trim();
  if (raw) {
    // Technitium API tokens are 64 hex chars; if it looks like a token, use as-is.
    // Otherwise treat as already-valid bearer.
    return await vault.resolveSecretValue(raw);
  }
  // Otherwise, login with user/pass to obtain a session token
  if (cachedToken && Date.now() < tokenExpiry - 60_000) return cachedToken;
  const user = conn.user || config.technitium.user;
  const passRaw = conn.password || config.technitium.password;
  if (!passRaw) throw new Error("Technitium credentials not configured — set TECHNITIUM_TOKEN or TECHNITIUM_USER/PASSWORD");
  const pass = await vault.resolveSecretValue(passRaw);
  const url = `${conn.url.replace(/\/$/, "")}/api/user/login?user=${encodeURIComponent(user)}&pass=${encodeURIComponent(pass)}`;
  const res = await fetch(url, { signal: AbortSignal.timeout(config.technitium.timeoutMs) });
  const text = await res.text();
  let data: Record<string, unknown> = {};
  try {
    data = JSON.parse(text);
  } catch { /* ignore */ }
  if (!res.ok || (data as { status?: string }).status === "error") {
    throw new Error(`Technitium login failed (HTTP ${res.status}): ${(data as { errorMessage?: string }).errorMessage || text.slice(0, 300)}`);
  }
  const token = (data as { token?: string }).token;
  if (!token) throw new Error("Technitium login: no token in response");
  cachedToken = token;
  tokenExpiry = Date.now() + 25 * 60 * 1000; // Technitium session default 30m, refresh early
  return token;
}

export function clearTechnitiumTokenCache(): void {
  cachedToken = null;
  tokenExpiry = 0;
}

interface TechnitiumResponse<T = unknown> {
  status: string;
  response?: T;
  errorMessage?: string;
  stackTrace?: string;
}

async function technitiumRequest<T>(
  conn: TechnitiumConnection,
  apiPath: string,
  params: Record<string, string | number | boolean | undefined> = {},
  opts: { method?: string; timeoutMs?: number } = {},
): Promise<T> {
  const token = await getApiToken(conn);
  const url = new URL(`${conn.url.replace(/\/$/, "")}${apiPath}`);
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== "") url.searchParams.set(k, String(v));
  }
  const method = opts.method ?? "GET";
  const res = await fetch(url.toString(), {
    method,
    headers: { Authorization: `Bearer ${token}` },
    signal: AbortSignal.timeout(opts.timeoutMs ?? config.technitium.timeoutMs),
  });
  const text = await res.text();
  let data: TechnitiumResponse<T> = { status: "error" };
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error(`Technitium ${apiPath} returned non-JSON (HTTP ${res.status}): ${text.slice(0, 300)}`);
  }
  if (data.status === "invalid-token") {
    clearTechnitiumTokenCache();
    throw new Error(`Technitium session expired for ${apiPath} — retry`);
  }
  if (data.status === "error" || !res.ok) {
    throw new Error(`Technitium ${apiPath} failed (HTTP ${res.status}): ${data.errorMessage || text.slice(0, 400)}`);
  }
  return (data.response ?? data) as T;
}

// ── Zone management ───────────────────────────────────────────────────────

export async function ensureZone(zone: string, conn?: Partial<TechnitiumConnection & { apiToken: string; host: string; port: number }>): Promise<void> {
  const c = effectiveConnection(conn);
  const z = stripDot(zone);
  // List to check existence
  try {
    const list = await technitiumRequest<{ zones: Array<{ name: string }> }>(c, "/api/zones/list", { pageNumber: 1, zonesPerPage: 100 });
    if (list.zones?.some((x) => x.name.toLowerCase() === z.toLowerCase())) return;
  } catch {
    // If list fails, try to create anyway
  }
  await technitiumRequest(c, "/api/zones/create", { zone: z, type: "Primary" });
}

export async function listZones(
  conn?: Partial<TechnitiumConnection & { apiToken: string; host: string; port: number }>,
): Promise<Array<{ name: string; type: string; disabled: boolean }>> {
  const c = effectiveConnection(conn);
  const res = await technitiumRequest<{ zones: Array<{ name: string; type: string; disabled: boolean }> }>(c, "/api/zones/list", {
    pageNumber: 1,
    zonesPerPage: 100,
  });
  return res.zones ?? [];
}

// ── Record CRUD via Technitium API ───────────────────────────────────────

function domainForInput(inputZone: string, inputName: string): string {
  if (inputName === "@" || inputName === "") return stripDot(inputZone);
  const n = inputName.replace(/\.$/, "");
  const z = inputZone.replace(/\.$/, "");
  if (n.toLowerCase() === z.toLowerCase() || n.toLowerCase().endsWith(`.${z.toLowerCase()}`)) return n;
  return `${n}.${z}`;
}

function recordValueForAdd(type: string, value: string, priority?: number): Record<string, string | number | boolean> {
  const t = type.toUpperCase();
  if (t === "A" || t === "AAAA") return { ipAddress: value };
  if (t === "CNAME") return { cname: value };
  if (t === "TXT") return { text: value, splitText: false };
  if (t === "MX") {
    // MX value may be "10 mail.example" or just "mail.example"; priority param overrides
    const m = value.trim().match(/^\s*(\d+)\s+(.+)$/);
    if (m) return { preference: Number(m[1]), exchange: m[2] };
    return { preference: priority ?? 10, exchange: value };
  }
  if (t === "NS") return { nameServer: value };
  if (t === "SRV") {
    // SRV value conventionally "priority weight port target" — parse if needed
    const parts = value.trim().split(/\s+/);
    if (parts.length >= 4) return { priority: Number(parts[0]), weight: Number(parts[1]), port: Number(parts[2]), target: parts[3] };
    return { priority: priority ?? 10, weight: 5, port: 80, target: value };
  }
  if (t === "CAA") {
    // CAA "0 issue \"letsencrypt.org\""
    const cm = value.match(/^\s*(\d+)\s+(\S+)\s+\"?(.+?)\"?\s*$/);
    if (cm) return { flags: Number(cm[1]), tag: cm[2], value: cm[3] };
    return { flags: 0, tag: "issue", value };
  }
  if (t === "PTR") return { ptrName: value };
  return { text: value };
}

function recordValueForDelete(type: string, value?: string): Record<string, string | number | boolean> {
  const t = type.toUpperCase();
  if (!value) return {};
  if (t === "A" || t === "AAAA") return { ipAddress: value };
  if (t === "CNAME") return { cname: value };
  if (t === "TXT") return { text: value };
  if (t === "MX") {
    const m = value.trim().match(/^\s*(\d+)\s+(.+)$/);
    if (m) return { preference: Number(m[1]), exchange: m[2] };
    return { exchange: value };
  }
  if (t === "NS") return { nameServer: value };
  return { text: value };
}

/** Shape returned by Technitium /api/zones/records/get */
interface TechnitiumRecord {
  name: string;
  type: string;
  ttl: number;
  disabled: boolean;
  rData: Record<string, unknown>;
}

function technitiumRecordToDnsRecord(r: TechnitiumRecord): DnsRecord {
  const t = r.type.toUpperCase();
  let value = "";
  const rd = r.rData as Record<string, unknown>;
  if (t === "A" || t === "AAAA") value = String(rd.ipAddress ?? rd.value ?? "");
  else if (t === "CNAME") value = String(rd.cname ?? "");
  else if (t === "TXT") {
    // rd.text or characterStrings
    value = String(rd.text ?? (rd.characterStrings as string[] | undefined)?.join("") ?? rd.value ?? "");
  } else if (t === "MX") value = `${rd.preference ?? 10} ${rd.exchange ?? ""}`.trim();
  else if (t === "NS") value = String(rd.nameServer ?? "");
  else if (t === "SRV") value = `${rd.priority ?? 0} ${rd.weight ?? 0} ${rd.port ?? 0} ${rd.target ?? ""}`.trim();
  else if (t === "SOA") value = `${rd.primaryNameServer ?? ""} ${rd.responsiblePerson ?? ""} ${rd.serial ?? ""}`;
  else if (t === "PTR") value = String(rd.ptrName ?? "");
  else if (t === "CAA") value = `${rd.flags ?? 0} ${rd.tag ?? ""} "${rd.value ?? ""}"`;
  else value = JSON.stringify(rd);
  return { name: r.name.replace(/\.$/, ""), type: r.type.toUpperCase(), ttl: r.ttl, value, disabled: r.disabled };
}

export async function addRecord(
  input: AddRecordInput,
  conn?: Partial<TechnitiumConnection & { apiToken: string; host: string; port: number }>,
): Promise<void> {
  const c = effectiveConnection(conn);
  const domain = domainForInput(input.zone, input.name);
  const zone = stripDot(input.zone);
  await ensureZone(zone, conn);
  const extra = recordValueForAdd(input.type, input.value, input.priority);
  await technitiumRequest(c, "/api/zones/records/add", {
    domain,
    zone,
    type: input.type.toUpperCase(),
    ttl: input.ttl ?? 300,
    ...extra,
  });
}

export async function deleteRecord(
  input: { zone: string; type: string; name: string; value?: string },
  conn?: Partial<TechnitiumConnection & { apiToken: string; host: string; port: number }>,
): Promise<void> {
  const c = effectiveConnection(conn);
  const domain = domainForInput(input.zone, input.name);
  const zone = stripDot(input.zone);
  const extra = recordValueForDelete(input.type, input.value);
  await technitiumRequest(c, "/api/zones/records/delete", {
    domain,
    zone,
    type: input.type.toUpperCase(),
    ...extra,
  });
}

/**
 * Add a TXT record idempotently (append, don't overwrite). If the exact value
 * already exists, Technitium returns an error that we treat as success.
 */
export async function setTxtRecord(
  zone: string,
  name: string,
  value: string,
  ttl = 60,
  conn?: Partial<TechnitiumConnection & { apiToken: string; host: string; port: number }>,
): Promise<void> {
  const domain = domainForInput(zone, name);
  const z = stripDot(zone);
  await ensureZone(z, conn);
  const c = effectiveConnection(conn);
  try {
    await technitiumRequest(c, "/api/zones/records/add", {
      domain,
      zone: z,
      type: "TXT",
      ttl,
      text: value,
    });
  } catch (err) {
    if (/already exists|duplicate/i.test(String(err))) return;
    throw err;
  }
}

export async function clearTxtRecord(
  zone: string,
  name: string,
  value?: string,
  conn?: Partial<TechnitiumConnection & { apiToken: string; host: string; port: number }>,
): Promise<void> {
  const domain = domainForInput(zone, name);
  const z = stripDot(zone);
  const c = effectiveConnection(conn);
  if (value === undefined) {
    // Delete all TXT at that name: fetch and delete each TXT
    const records = await listZone(z, conn);
    const txts = records.filter((r) => r.name.toLowerCase() === domain.toLowerCase() && r.type === "TXT");
    for (const r of txts) {
      try {
        await technitiumRequest(c, "/api/zones/records/delete", {
          domain,
          zone: z,
          type: "TXT",
          text: r.value,
        });
      } catch { /* ignore missing */ }
    }
    return;
  }
  await technitiumRequest(c, "/api/zones/records/delete", {
    domain,
    zone: z,
    type: "TXT",
    text: value,
  });
}

export async function ensureCname(
  zone: string,
  from: string,
  to: string,
  conn?: Partial<TechnitiumConnection & { apiToken: string; host: string; port: number }>,
): Promise<void> {
  const c = effectiveConnection(conn);
  const domain = domainForInput(zone, from);
  const z = stripDot(zone);
  const target = ensureDot(to);
  // Delete existing CNAME at that owner if any, then add
  try {
    await technitiumRequest(c, "/api/zones/records/delete", {
      domain,
      zone: z,
      type: "CNAME",
    });
  } catch { /* no existing CNAME is fine */ }
  await technitiumRequest(c, "/api/zones/records/add", {
    domain,
    zone: z,
    type: "CNAME",
    ttl: 300,
    cname: target,
  });
}

/**
 * List all records in a zone via Technitium's /api/zones/records/get.
 * Returns records filtered to the requested zone.
 */
export async function listZone(
  zone: string,
  conn?: Partial<TechnitiumConnection & { apiToken: string; host: string; port: number }>,
): Promise<DnsRecord[]> {
  const c = effectiveConnection(conn);
  const z = stripDot(zone);
  const res = await technitiumRequest<{ records: TechnitiumRecord[] }>(c, "/api/zones/records/get", {
    domain: z,
    zone: z,
    listZone: true,
  });
  const records: TechnitiumRecord[] = (res as { records?: TechnitiumRecord[] }).records ?? [];
  // Also handle alternate shape: response is array directly or nested
  if (!records.length && Array.isArray(res)) {
    return (res as unknown as TechnitiumRecord[]).map(technitiumRecordToDnsRecord);
  }
  return records.map(technitiumRecordToDnsRecord);
}

/** Health check for Technitium connectivity/auth */
export async function testConnection(
  conn?: Partial<TechnitiumConnection & { apiToken: string; host: string; port: number }>,
): Promise<{ ok: boolean; detail: string }> {
  const c = effectiveConnection(conn);
  try {
    await technitiumRequest(c, "/api/zones/list", { pageNumber: 1, zonesPerPage: 1 });
    return { ok: true, detail: "ok" };
  } catch (err) {
    return { ok: false, detail: err instanceof Error ? err.message : String(err) };
  }
}

/** Legacy helper still used by tests */
export function parseZoneTransfer(output: string): DnsRecord[] {
  const records: DnsRecord[] = [];
  for (const line of output.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith(";")) continue;
    const parts = trimmed.split(/\s+/);
    if (parts.length < 5) continue;
    const [name, ttl, cls, type, ...rest] = parts;
    if (cls !== "IN") continue;
    let value = rest.join(" ");
    if (type === "TXT") {
      value = value.replace(/^"(.*)"$/, "$1").replace(/"\s*"/g, "").replace(/\\"/g, '"');
    }
    records.push({ name: name.replace(/\.$/, ""), type, ttl: Number(ttl), value });
  }
  return records;
}
