import crypto from "node:crypto";
import type { NextFunction, Request, Response } from "express";
import { config } from "./config";

interface Session {
  token: string;
  expires: number;
}

const sessions = new Map<string, Session>();

export function login(password: string): string | null {
  if (!password || password !== config.adminPassword) return null;
  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, {
    token,
    expires: Date.now() + config.tokenTtlHours * 60 * 60 * 1000,
  });
  return token;
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

export function requireAuth(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : undefined;
  if (!isAuthed(token)) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  next();
}
