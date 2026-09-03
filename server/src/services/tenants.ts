import type { NextFunction, Request, Response } from "express";
import { extractToken, getSession, type SessionUser } from "../auth";
import { config } from "../config";
import { db, DEFAULT_TENANT_ID, type TenantRow } from "../db";

/**
 * Organizations/tenants. Identity comes from Authentik: **a tenant's slug is an
 * Authentik group**, and members of that group are members of the tenant (the
 * OIDC `groups` claim drives it). Local admin sessions are platform admins and
 * operate on the default tenant unless an `X-Cerulean-Tenant` header names
 * another one.
 *
 * Isolation is enforced by scoping every query on tenant-owned tables
 * (domains, certificates, client certificates, discovered certificates) to the
 * tenant resolved per request — see the `resolveTenant` middleware.
 */

export interface TenantScope {
  id: number;
  slug: string;
  name: string;
}

/** Platform admins see and manage every tenant. */
export function isPlatformAdmin(user: SessionUser): boolean {
  if (user.provider === "local") return true;
  const group = config.tenant.platformGroup;
  return Boolean(group && user.groups.includes(group));
}

/** Tenants a user may act in: platform admins → all, others → their groups. */
export function tenantsForUser(user: SessionUser): TenantRow[] {
  const all = db.listTenants();
  if (isPlatformAdmin(user)) return all;
  const slugs = new Set(user.groups);
  return all.filter((t) => slugs.has(t.slug));
}

/** Pick the effective tenant: an allowed `X-Cerulean-Tenant` header wins,
 * otherwise the first allowed tenant (default tenant for platform admins). */
export function effectiveTenant(
  user: SessionUser,
  header?: string,
): TenantScope | null {
  const allowed = tenantsForUser(user);
  if (!allowed.length) return null;
  let tenant = allowed[0];
  if (header) {
    const match = allowed.find((t) => t.slug === header);
    if (!match) return null;
    tenant = match;
  } else if (isPlatformAdmin(user)) {
    tenant = db.getTenant(DEFAULT_TENANT_ID) ?? allowed[0];
  }
  return { id: tenant.id, slug: tenant.slug, name: tenant.name };
}

/**
 * Express middleware: attach the caller's effective tenant (and platform
 * status) to `res.locals`. Always runs after `requireAuth`.
 */
export function resolveTenant(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  const session = getSession(extractToken(req));
  if (!session) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  const header = String(req.headers["x-cerulean-tenant"] || "");
  const tenant = effectiveTenant(session.user, header || undefined);
  if (!tenant) {
    res.status(403).json({
      error:
        "Your account has no tenant here — join an Authentik group whose slug " +
        "matches a Cerulean tenant (or ask a platform admin to add it).",
    });
    return;
  }
  res.locals.tenant = tenant;
  res.locals.platform = isPlatformAdmin(session.user);
  res.locals.user = session.user;
  next();
}

/** Current tenant scope for handlers running behind resolveTenant. */
export function tenantOf(res: Response): TenantScope {
  return res.locals.tenant as TenantScope;
}

/** True when the caller is a platform admin (behind resolveTenant). */
export function isPlatform(res: Response): boolean {
  return Boolean(res.locals.platform);
}

const SLUG_RE = /^[a-z0-9][a-z0-9-]{0,47}$/;

/** Create a tenant (platform admins). Returns a 409-style error on dupes. */
export function createTenant(input: {
  slug: string;
  name: string;
}): TenantRow {
  const slug = input.slug.trim().toLowerCase();
  if (!SLUG_RE.test(slug)) {
    throw new TenantError(
      400,
      "Invalid slug — lowercase letters, digits and '-', 1-48 chars",
    );
  }
  const name = input.name.trim();
  if (!name) throw new TenantError(400, "name is required");
  if (db.getTenantBySlug(slug)) {
    throw new TenantError(409, `Tenant \"${slug}\" already exists`);
  }
  return db.createTenant({ slug, name });
}

export class TenantError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "TenantError";
  }
}
