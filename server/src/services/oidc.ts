import crypto from "node:crypto";
import { config } from "../config";
import { oidcConfigured } from "../auth";

export interface OidcUser {
  sub: string;
  email: string;
  name: string;
  groups: string[];
}

interface OidcDiscovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  end_session_endpoint?: string;
}

/** PKCE state kept between the authorize redirect and the callback. */
interface PendingAuth {
  verifier: string;
  redirectTo: string;
  expires: number;
}

const pending = new Map<string, PendingAuth>();

function b64url(buf: Buffer): string {
  return buf.toString("base64url");
}

class OidcClient {
  private discoveryCache: OidcDiscovery | null = null;

  private issuer(): string {
    return config.auth.issuerUrl.replace(/\/$/, "");
  }

  async discovery(): Promise<OidcDiscovery> {
    if (this.discoveryCache) return this.discoveryCache;
    const res = await fetch(
      `${this.issuer()}/.well-known/openid-configuration`,
      { signal: AbortSignal.timeout(15_000) },
    );
    if (!res.ok) {
      throw new Error(
        `OIDC discovery failed (HTTP ${res.status}) at ${this.issuer()}`,
      );
    }
    this.discoveryCache = (await res.json()) as OidcDiscovery;
    return this.discoveryCache;
  }

  /** Start an authorization-code + PKCE flow. Returns the redirect URL. */
  async authorizeUrl(redirectTo = "/"): Promise<{ url: string; state: string }> {
    const disc = await this.discovery();
    const state = b64url(crypto.randomBytes(24));
    const verifier = b64url(crypto.randomBytes(32));
    const challenge = b64url(crypto.createHash("sha256").update(verifier).digest());
    pending.set(state, {
      verifier,
      redirectTo,
      expires: Date.now() + 10 * 60 * 1000,
    });
    const params = new URLSearchParams({
      response_type: "code",
      client_id: config.auth.clientId,
      redirect_uri: config.auth.redirectUri,
      scope: config.auth.scopes,
      state,
      code_challenge: challenge,
      code_challenge_method: "S256",
    });
    return { url: `${disc.authorization_endpoint}?${params.toString()}`, state };
  }

  /**
   * Exchange an authorization code for tokens, then resolve the user via the
   * userinfo endpoint. The userinfo response is authoritative — the code + TLS
   * prove the browser session belongs to the Authentik user, and the state
   * binding (checked by the route) prevents CSRF on the callback.
   */
  async exchangeCode(
    code: string,
    verifier: string,
  ): Promise<OidcUser> {
    const disc = await this.discovery();
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: config.auth.redirectUri,
      client_id: config.auth.clientId,
      client_secret: config.auth.clientSecret,
      code_verifier: verifier,
    });
    const res = await fetch(disc.token_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) {
      throw new Error(`OIDC token exchange failed (HTTP ${res.status})`);
    }
    const tokens = (await res.json()) as { access_token?: string };
    if (!tokens.access_token) {
      throw new Error("OIDC token exchange returned no access token");
    }
    return this.userInfo(disc, tokens.access_token);
  }

  private async userInfo(
    disc: OidcDiscovery,
    accessToken: string,
  ): Promise<OidcUser> {
    const res = await fetch(disc.userinfo_endpoint, {
      headers: { Authorization: `Bearer ${accessToken}` },
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) {
      throw new Error(`OIDC userinfo failed (HTTP ${res.status})`);
    }
    const claims = (await res.json()) as Record<string, unknown>;
    const sub = String(claims.sub || "");
    if (!sub) throw new Error("OIDC userinfo returned no subject");
    return {
      sub,
      email: String(claims.email || ""),
      name: String(claims.name || claims.preferred_username || sub),
      groups: Array.isArray(claims.groups)
        ? (claims.groups as unknown[]).map(String)
        : [],
    };
  }

  /** Pop the PKCE state entry for a callback (returns undefined if unknown). */
  consumeState(state: string): PendingAuth | undefined {
    const entry = pending.get(state);
    if (!entry) return undefined;
    pending.delete(state);
    if (Date.now() > entry.expires) return undefined;
    return entry;
  }

  /** Connectivity probe for the /status endpoint. */
  async test(): Promise<string> {
    if (!oidcConfigured()) return "not-configured";
    try {
      const disc = await this.discovery();
      return disc.authorization_endpoint ? "ok" : "error";
    } catch (err) {
      return err instanceof Error ? err.message : "error";
    }
  }
}

export const oidc = new OidcClient();
