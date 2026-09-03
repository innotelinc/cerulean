import { config } from "../config";

/**
 * Minimal Authentik admin-API client used by tenant administration: members
 * of a tenant are the users of the matching Authentik group (tenant slug =
 * group slug), so listing them requires the Authentik admin API
 * (AUTHENTIK_API_URL + AUTHENTIK_ADMIN_USER/AUTHENTIK_ADMIN_PASSWORD in .env —
 * the same credentials scripts/authentik-setup.py uses).
 */

export interface TenantMember {
  pk: string;
  username: string;
  email: string;
  name: string;
}

export interface GroupMembersResult {
  users: TenantMember[];
  groupExists: boolean;
}

/** True when Authentik admin credentials are configured in .env. */
export function adminConfigured(): boolean {
  return Boolean(
    config.authentikAdmin.apiUrl &&
      config.authentikAdmin.user &&
      config.authentikAdmin.password,
  );
}

let tokenCache: { token: string; expires: number } | null = null;

async function adminToken(): Promise<string> {
  if (tokenCache && Date.now() < tokenCache.expires - 30_000) {
    return tokenCache.token;
  }
  const url = `${config.authentikAdmin.apiUrl.replace(/\/$/, "")}/api/v3/core/auth/admin/`;
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: config.authentikAdmin.user,
      password: config.authentikAdmin.password,
    }),
    signal: AbortSignal.timeout(20_000),
  });
  if (!res.ok) {
    throw new Error(
      `Authentik admin login failed (HTTP ${res.status}) — check ` +
        "AUTHENTIK_API_URL/AUTHENTIK_ADMIN_USER/AUTHENTIK_ADMIN_PASSWORD in .env",
    );
  }
  const data = (await res.json()) as { token?: string };
  if (!data.token) throw new Error("Authentik admin login returned no token");
  // Authentik does not expire admin tokens via this endpoint; re-login every
  // few minutes to stay safe with rotated credentials.
  tokenCache = { token: data.token, expires: Date.now() + 5 * 60 * 1000 };
  return data.token;
}

/**
 * Users in the Authentik group whose slug is `slug`. A 404 means the group
 * does not exist (yet) — the tenant exists but nobody can join it until the
 * platform admin creates the matching group in Authentik.
 */
export async function listGroupMembers(slug: string): Promise<GroupMembersResult> {
  const token = await adminToken();
  const base = config.authentikAdmin.apiUrl.replace(/\/$/, "");
  const res = await fetch(
    `${base}/api/v3/core/groups/${encodeURIComponent(slug)}/users/`,
    { headers: { Authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(20_000) },
  );
  if (res.status === 404) return { users: [], groupExists: false };
  if (!res.ok) {
    throw new Error(`Authentik group query failed (HTTP ${res.status})`);
  }
  const data = (await res.json()) as {
    results?: { pk: number | string; username: string; email?: string; name?: string }[];
  };
  const users = (data.results ?? []).map((u) => ({
    pk: String(u.pk),
    username: u.username,
    email: u.email ?? "",
    name: u.name ?? u.username,
  }));
  return { users, groupExists: true };
}
