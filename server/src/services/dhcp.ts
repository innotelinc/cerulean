/**
 * DHCP orchestration via Technitium DNS Server.
 * Cerulean is the master orchestrator: this module is the control-plane
 * for DHCP scopes/leases (Technitium DHCP). All state lives in Technitium;
 * Cerulean never runs its own dhcpd.
 */

import { config } from "../config";
import { db } from "../db";

export interface DhcpScope {
  name: string;
  enabled: boolean;
  startingAddress: string;
  endingAddress: string;
  subnetMask: string;
  networkAddress?: string;
  broadcastAddress?: string;
}

export interface DhcpLease {
  scope: string;
  type: string;
  hardwareAddress: string;
  address: string;
  hostName: string | null;
  leaseObtained: string;
  leaseExpires: string;
}

// Reuse Technitium auth/channel by importing its helpers
async function technitiumFetch(apiPath: string, params: Record<string, string | number | undefined> = {}): Promise<Record<string, unknown>> {
  const { config: cfg } = await import("../config");
  const { vault } = await import("./vault");
  // Inline minimal login/token logic to avoid circular deps
  const url = new URL(`${cfg.technitium.url.replace(/\/$/, "")}${apiPath}`);
  for (const [k, v] of Object.entries(params)) if (v !== undefined) url.searchParams.set(k, String(v));
  // Token resolution: prefer TECHNITIUM_TOKEN, else session
  let token = cfg.technitium.token?.trim() || "";
  if (token) token = await vault.resolveSecretValue(token);
  if (!token) {
    const pass = cfg.technitium.password ? await vault.resolveSecretValue(cfg.technitium.password) : "";
    if (!pass) throw new Error("DHCP: Technitium credentials not configured");
    const loginUrl = `${cfg.technitium.url.replace(/\/$/, "")}/api/user/login?user=${encodeURIComponent(cfg.technitium.user)}&pass=${encodeURIComponent(pass)}`;
    const lres = await fetch(loginUrl, { signal: AbortSignal.timeout(cfg.technitium.timeoutMs) });
    const ltext = await lres.text();
    let ldata: Record<string, unknown> = {};
    try { ldata = JSON.parse(ltext); } catch {}
    if (!lres.ok || (ldata as { status?: string }).status === "error") throw new Error(`Technitium login failed: ${(ldata as { errorMessage?: string }).errorMessage || ltext.slice(0, 200)}`);
    token = String((ldata as { token?: string }).token || "");
  }
  const res = await fetch(url.toString(), {
    headers: { Authorization: `Bearer ${token}` },
    signal: AbortSignal.timeout(cfg.technitium.timeoutMs),
  });
  const text = await res.text();
  let data: Record<string, unknown> = {};
  try { data = JSON.parse(text); } catch { throw new Error(`DHCP ${apiPath}: non-JSON ${text.slice(0, 200)}`); }
  if (data.status === "error" || !res.ok) throw new Error(`DHCP ${apiPath}: ${(data as { errorMessage?: string }).errorMessage || text.slice(0, 300)}`);
  return (data.response as Record<string, unknown>) ?? data;
}

export async function listScopes(): Promise<DhcpScope[]> {
  const data = await technitiumFetch("/api/dhcp/scopes/list");
  const scopes = (data.scopes as DhcpScope[] | undefined) ?? [];
  return scopes;
}

export async function getScope(name: string): Promise<Record<string, unknown>> {
  const data = await technitiumFetch("/api/dhcp/scopes/get", { name });
  return data as Record<string, unknown>;
}

export async function setScope(input: {
  name: string;
  startingAddress: string;
  endingAddress: string;
  subnetMask: string;
  routerAddress?: string;
  domainName?: string;
  dnsServers?: string; // comma-separated
  useThisDnsServer?: boolean;
  leaseTimeDays?: number;
  enabledAfter?: boolean;
}): Promise<void> {
  const params: Record<string, string | number | undefined> = {
    name: input.name,
    startingAddress: input.startingAddress,
    endingAddress: input.endingAddress,
    subnetMask: input.subnetMask,
  };
  if (input.routerAddress) params.routerAddress = input.routerAddress;
  if (input.domainName) params.domainName = input.domainName;
  if (input.dnsServers) params.dnsServers = input.dnsServers;
  if (input.useThisDnsServer !== undefined) (params as Record<string, string>).useThisDnsServer = String(input.useThisDnsServer);
  if (input.leaseTimeDays !== undefined) params.leaseTimeDays = input.leaseTimeDays;
  await technitiumFetch("/api/dhcp/scopes/set", params);
  if (input.enabledAfter ?? true) {
    try { await technitiumFetch("/api/dhcp/scopes/enable", { name: input.name }); } catch { /* already enabled */ }
  }
}

export async function deleteScope(name: string): Promise<void> {
  await technitiumFetch("/api/dhcp/scopes/delete", { name });
}

export async function enableScope(name: string): Promise<void> {
  await technitiumFetch("/api/dhcp/scopes/enable", { name });
}

export async function disableScope(name: string): Promise<void> {
  await technitiumFetch("/api/dhcp/scopes/disable", { name });
}

export async function listLeases(): Promise<DhcpLease[]> {
  const data = await technitiumFetch("/api/dhcp/leases/list");
  return ((data.leases as DhcpLease[] | undefined) ?? []) as DhcpLease[];
}

export async function removeLease(name: string, hardwareAddress: string): Promise<void> {
  await technitiumFetch("/api/dhcp/leases/remove", { name, hardwareAddress });
}

export async function addReservedLease(scope: string, hardwareAddress: string, ipAddress: string, hostName?: string): Promise<void> {
  const params: Record<string, string | undefined> = { name: scope, hardwareAddress, ipAddress };
  if (hostName) params.hostName = hostName;
  await technitiumFetch("/api/dhcp/scopes/addReservedLease", params as Record<string, string>);
}

export async function removeReservedLease(scope: string, hardwareAddress: string): Promise<void> {
  await technitiumFetch("/api/dhcp/scopes/removeReservedLease", { name: scope, hardwareAddress });
}

export async function status(): Promise<{ reachable: boolean; scopes: number; leases: number; detail: string }> {
  if (!config.orchestrator.dhcpEnabled) return { reachable: false, scopes: 0, leases: 0, detail: "disabled (ORCHESTRATOR_DHCP_ENABLED=false)" };
  try {
    const [scopes, leases] = await Promise.all([listScopes(), listLeases()]);
    return { reachable: true, scopes: scopes.length, leases: leases.length, detail: "ok" };
  } catch (err) {
    return { reachable: false, scopes: 0, leases: 0, detail: err instanceof Error ? err.message : String(err) };
  }
}
