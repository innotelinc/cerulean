import crypto from "node:crypto";
import type { NextFunction, Request, Response } from "express";
import { config } from "../config";
import { db } from "../db";

export function generateServiceToken(): string {
  const prefix = crypto.randomBytes(8).toString("hex"); // 16 hex
  const secret = crypto.randomBytes(24).toString("hex"); // 48 hex
  return `ceru_${prefix}_${secret}`;
}

export function hashServiceToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

export function prefixOfServiceToken(token: string): string {
  const m = token.match(/^ceru_([0-9a-fA-F]{16})_/);
  return m ? m[1].toLowerCase() : "";
}

function extractBearer(req: Request): string | undefined {
  const h = (req.headers.authorization || "").trim();
  if (h.toLowerCase().startsWith("bearer ")) return h.slice(7).trim();
  const x = (req.headers["x-api-key"] as string | undefined)?.trim();
  if (x) return x;
  const x2 = (req.headers["x-cerulean-token"] as string | undefined)?.trim();
  if (x2) return x2;
  return undefined;
}

/** Return the validated service key row or undefined if token missing/invalid. */
export function getServiceKeyFromToken(token: string | undefined): import("../db").ServiceApiKeyRow | undefined {
  if (!token || !token.startsWith("ceru_")) return undefined;
  const hash = hashServiceToken(token);
  const row = db.getServiceKeyByHash(hash);
  if (!row) return undefined;
  if (row.revoked_at) return undefined;
  return row;
}

function scopesOf(row: import("../db").ServiceApiKeyRow): string[] {
  try {
    const arr = JSON.parse(row.scopes_json) as unknown;
    return Array.isArray(arr) ? (arr as string[]).map(String) : [];
  } catch {
    return [];
  }
}

function hasRequiredScope(have: string[], need: string[]): boolean {
  if (need.length === 0) return true;
  if (have.includes("*")) return true;
  const set = new Set(have.map((s) => s.toLowerCase().trim()));
  for (const r of need) {
    const n = r.toLowerCase().trim();
    if (set.has(n) || set.has("*")) return true;
    // wildcard sugar: "dns:*" matches "dns:read"
    const prefix = n.split(":")[0];
    if (set.has(`${prefix}:*`) || set.has(prefix)) return true;
  }
  return false;
}

/** Middleware that requires a valid Cerulean service API key. */
export function requireServiceAuth(requiredScopes: string[] = []): (req: Request, res: Response, next: NextFunction) => void {
  return (req, res, next) => {
    const token = extractBearer(req);
    if (!token || !token.startsWith("ceru_")) {
      res.status(401).json({ error: "Missing service API key (Bearer ceru_...)" });
      return;
    }
    const row = getServiceKeyFromToken(token);
    if (!row) {
      res.status(401).json({ error: "Invalid or revoked service API key" });
      return;
    }
    const scopes = scopesOf(row);
    if (!hasRequiredScope(scopes, requiredScopes)) {
      res.status(403).json({ error: `Insufficient scope — requires: ${requiredScopes.join(", ")}` });
      return;
    }
    // attach for handlers
    (req as unknown as { serviceKey: typeof row }).serviceKey = row;
    // best-effort last_used bump (does not block request)
    try {
      db.touchServiceKey(row.id);
    } catch { /* ignore */ }
    next();
  };
}

/**
 * CRS shared-secret guard. If CRS_TOKEN is set, the request must present
 * it as Bearer or X-CRS-Token. Service keys with crs:* scope are also
 * accepted regardless of the shared secret.
 */
export function crsMasterAuth(req: Request, res: Response, next: NextFunction): void {
  const token: string = String(config.crs?.token || "").trim();
  if (!token) {
    next();
    return;
  }
  const bearer = extractBearer(req) || "";
  const xCrs = String(req.headers["x-crs-token"] || req.headers["x-cerulean-token"] || "").trim();
  // Also accept the service-key form if someone configured a ceru_ key as CRS token?
  if (bearer === token || xCrs === token) {
    next();
    return;
  }
  // If bearer is a valid service key with crs:* scope, also accept it
  if (bearer.startsWith("ceru_")) {
    const row = getServiceKeyFromToken(bearer);
    if (row) {
      const scopes = scopesOf(row);
      if (hasRequiredScope(scopes, ["crs", "crs:register", "crs:*", "*"])) {
        (req as unknown as { serviceKey: typeof row }).serviceKey = row;
        try {
          db.touchServiceKey(row.id);
        } catch {}
        next();
        return;
      }
    }
  }
  res.status(401).json({ error: "Invalid CRS token" });
}

export function serviceKeyToJson(row: import("../db").ServiceApiKeyRow) {
  return {
    id: row.id,
    name: row.name,
    prefix: row.prefix,
    scopes: JSON.parse(row.scopes_json) as string[],
    tenantId: row.tenant_id,
    createdAt: row.created_at,
    lastUsedAt: row.last_used_at,
    revokedAt: row.revoked_at,
  };
}
