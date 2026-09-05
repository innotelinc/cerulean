import { config } from "../config";

/**
 * Minimal Authentik admin-API client used by tenant administration: members
 * of a tenant are the users of the matching Authentik group (tenant slug =
 * group slug), so listing them requires the Authentik admin API
 * (AUTHENTIK_API_URL + AUTHENTIK_BOOTSTRAP_TOKEN in .env).
 *
 * Authentik 2024.12 removed the POST /api/v3/core/auth/admin/ endpoint, so
 * all admin-API calls authenticate with the bootstrap API token as a Bearer
 * token (same token scripts/authentik-setup.py uses).
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
      config.authentikAdmin.bootstrapToken,
  );
}

let tokenCache: { token: string; expires: number } | null = null;

async function adminToken(): Promise<string> {
  if (tokenCache && Date.now() < tokenCache.expires - 30_000) {
    return tokenCache.token;
  }
  // The bootstrap API token authenticates directly as Bearer — no login round
  // trip needed (the admin-login endpoint was removed in Authentik 2024.12).
  const token = config.authentikAdmin.bootstrapToken;
  if (!token) {
    throw new Error(
      "Authentik admin API not configured — check AUTHENTIK_API_URL/" +
        "AUTHENTIK_BOOTSTRAP_TOKEN in .env",
    );
  }
  tokenCache = { token, expires: Date.now() + 5 * 60 * 1000 };
  return token;
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
