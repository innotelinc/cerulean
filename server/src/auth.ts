import crypto from "node:crypto";
import type { NextFunction, Request, Response } from "express";
import { config } from "./config";

export interface SessionUser {
  sub: string;
  email: string;
  name: string;
  groups: string[];
  provider: "local" | "authentik";
}

interface Session {
  token: string;
  expires: number;
  user: SessionUser;
}

const TOKEN_COOKIE = "cerulean_token";
const sessions = new Map<string, Session>();

function newToken(): string {
  return crypto.randomBytes(32).toString("hex");
}

function sessionTtlMs(): number {
  return config.tokenTtlHours * 60 * 60 * 1000;
}

/** Create a session and return its token. */
function createSession(user: SessionUser): string {
  const token = newToken();
  sessions.set(token, {
    token,
    expires: Date.now() + sessionTtlMs(),
    user,
  });
  return token;
}

/** Local admin-password login. */
export function login(password: string): string | null {
  if (!password || password !== config.adminPassword) return null;
  return createSession({
    sub: "admin",
    email: "",
    name: "admin",
    groups: ["admin"],
    provider: "local",
  });
}

/** Login after a successful Authentik (OIDC) flow. */
export function loginWithOidc(user: Omit<SessionUser, "provider">): string {
  return createSession({ ...user, provider: "authentik" });
}

export function logout(token: string): void {
  sessions.delete(token);
}

export function isAuthed(token: string | undefined): boolean {
  if (!token) return false;
  const session = sessions.get(token);
  if (!session) return false;
  if (Date.now() > session.expires) {
    sessions.delete(token);
    return false;
  }
  return true;
}

export function getSession(token: string | undefined): Session | undefined {
  if (!token) return undefined;
  const session = sessions.get(token);
  if (!session) return undefined;
  if (Date.now() > session.expires) {
    sessions.delete(token);
    return undefined;
  }
  return session;
}

/** Read the session token from the Authorization header or the session cookie. */
export function extractToken(req: Request): string | undefined {
  const header = req.headers.authorization || "";
  if (header.startsWith("Bearer ")) return header.slice(7);
  const cookie = req.headers.cookie || "";
  for (const part of cookie.split(";")) {
    const [name, ...rest] = part.trim().split("=");
    if (name === TOKEN_COOKIE) return rest.join("=");
  }
  return undefined;
}

export function requireAuth(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  const token = extractToken(req);
  if (!isAuthed(token)) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  next();
}

export function setSessionCookie(res: Response, token: string): void {
  const maxAge = config.tokenTtlHours * 60 * 60;
  // Not HttpOnly on purpose: the SPA reads the cookie once on boot and adopts
  // the token into localStorage (the same place a local login stores it), then
  // the cookie is cleared. SameSite=Lax keeps it from being sent on cross-site
  // POSTs, and the server still validates every session server-side.
  res.setHeader(
    "Set-Cookie",
    `${TOKEN_COOKIE}=${token}; Path=/; SameSite=Lax; Max-Age=${maxAge}`,
  );
}

export function clearSessionCookie(res: Response): void {
  res.setHeader(
    "Set-Cookie",
    `${TOKEN_COOKIE}=; Path=/; SameSite=Lax; Max-Age=0`,
  );
}

/** True when the Authentik OIDC integration is configured in .env. */
export function oidcConfigured(): boolean {
  return Boolean(
    config.auth.issuerUrl && config.auth.clientId && config.auth.clientSecret,
  );
}
