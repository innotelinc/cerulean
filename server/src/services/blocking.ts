/**
 * Ad-blocking orchestration via Technitium DNS Server.
 * Centralized blocking controls: global enable, block lists, and per-domain allow/block.
 */

import { config } from "../config";

async function technitiumFetch(apiPath: string, params: Record<string, string | undefined> = {}, method: "GET"|"POST" = "GET"): Promise<Record<string, unknown>> {
  const { vault } = await import("./vault");
  const url = new URL(`${config.technitium.url.replace(/\/$/, "")}${apiPath}`);
  if (method === "GET") for (const [k, v] of Object.entries(params)) if (v !== undefined) url.searchParams.set(k, v);
  let token = config.technitium.token?.trim() || "";
  if (token) token = await vault.resolveSecretValue(token);
  if (!token) {
    const pass = config.technitium.password ? await vault.resolveSecretValue(config.technitium.password) : "";
    if (!pass) throw new Error("Blocking: Technitium credentials not configured");
    const loginUrl = `${config.technitium.url.replace(/\/$/, "")}/api/user/login?user=${encodeURIComponent(config.technitium.user)}&pass=${encodeURIComponent(pass)}`;
    const lres = await fetch(loginUrl, { signal: AbortSignal.timeout(config.technitium.timeoutMs) });
    const lt = await lres.text();
    let ld: Record<string, unknown> = {};
    try { ld = JSON.parse(lt); } catch {}
    if (!lres.ok || (ld as { status?: string }).status === "error") throw new Error(`Technitium login failed: ${(ld as { errorMessage?: string }).errorMessage || lt.slice(0, 200)}`);
    token = String((ld as { token?: string }).token || "");
  }
  const res = await fetch(url.toString(), {
    method,
    headers: { Authorization: `Bearer ${token}`, ...(method === "POST" ? { "Content-Type": "application/x-www-form-urlencoded" } : {}) },
    body: method === "POST" ? new URLSearchParams(params as Record<string,string>).toString() : undefined,
    signal: AbortSignal.timeout(config.technitium.timeoutMs),
  });
  const text = await res.text();
  let data: Record<string, unknown> = {};
  try { data = JSON.parse(text); } catch { throw new Error(`Blocking ${apiPath}: non-JSON ${text.slice(0, 200)}`); }
  if (data.status === "error" || !res.ok) throw new Error(`Blocking ${apiPath}: ${(data as { errorMessage?: string }).errorMessage || text.slice(0, 300)}`);
  return (data.response as Record<string, unknown>) ?? data;
}

export interface BlockingStatus {
  enabled: boolean;
  blockListUrls: string[];
  blockedZones: number;
  allowedZones: number;
  detail: string;
}

export async function getStatus(): Promise<BlockingStatus> {
  if (!config.orchestrator.blockingEnabled) return { enabled: false, blockListUrls: [], blockedZones: 0, allowedZones: 0, detail: "disabled" };
  // DnsSettings contains blocking flags
  const settings = await technitiumFetch("/api/settings/get") as Record<string, unknown>;
  // Also count zones
  let blockedZones = 0, allowedZones = 0;
  try {
    const bz = await technitiumFetch("/api/blocked/list", { domain: "" }) as { zones?: unknown[] };
    blockedZones = (bz.zones as unknown[])?.length ?? 0;
  } catch { /* ignore */ }
  try {
    const az = await technitiumFetch("/api/allowed/list", { domain: "" }) as { zones?: unknown[] };
    allowedZones = (az.zones as unknown[])?.length ?? 0;
  } catch { /* ignore */ }
  const enabled = (settings as { enableBlocking?: boolean }).enableBlocking ?? false;
  const urls = (settings as { blockListUrls?: string[] }).blockListUrls ?? [];
  return { enabled: Boolean(enabled), blockListUrls: urls, blockedZones, allowedZones, detail: enabled ? "blocking on" : "blocking off" };
}

export async function setBlocking(input: {
  enableBlocking?: boolean;
  blockListUrls?: string; // comma-separated or "false" to clear
  blockingType?: string; // AnyAddress | NxDomain | CustomAddress
}): Promise<void> {
  const params: Record<string, string | undefined> = {};
  if (input.enableBlocking !== undefined) params.enableBlocking = String(input.enableBlocking);
  if (input.blockListUrls !== undefined) params.blockListUrls = input.blockListUrls;
  if (input.blockingType) params.blockingType = input.blockingType;
  // Technitium settings/set expects many params; we only set what we change.
  await technitiumFetch("/api/settings/set", params, "GET");
}

export async function listBlocked(): Promise<string[]> {
  const data = await technitiumFetch("/api/blocked/list", { domain: "" }) as { zones?: Array<{ domain?: string; name?: string }> };
  const zones = (data.zones as Array<{ domain?: string; name?: string }> | undefined) ?? [];
  return zones.map((z) => z.domain ?? z.name ?? "").filter(Boolean);
}

export async function addBlocked(domain: string): Promise<void> {
  await technitiumFetch("/api/blocked/add", { domain });
}

export async function deleteBlocked(domain: string): Promise<void> {
  await technitiumFetch("/api/blocked/delete", { domain });
}

export async function listAllowed(): Promise<string[]> {
  const data = await technitiumFetch("/api/allowed/list", { domain: "" }) as { zones?: Array<{ domain?: string; name?: string }> };
  const zones = (data.zones as Array<{ domain?: string; name?: string }> | undefined) ?? [];
  return zones.map((z) => z.domain ?? z.name ?? "").filter(Boolean);
}

export async function addAllowed(domain: string): Promise<void> {
  await technitiumFetch("/api/allowed/add", { domain });
}

export async function deleteAllowed(domain: string): Promise<void> {
  await technitiumFetch("/api/allowed/delete", { domain });
}

export async function forceUpdateBlockLists(): Promise<void> {
  await technitiumFetch("/api/settings/forceUpdateBlockLists");
}
