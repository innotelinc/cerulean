import { config } from "../config";

interface RegisterResponse {
  username: string;
  password: string;
  fulldomain: string;
  subdomain: string;
  allowfrom: string[];
}

/** Minimal HTTP client for the acme-dns REST API. */
class AcmeDnsClient {
  private baseUrl: string;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
    headers: Record<string, string> = {},
  ): Promise<{ status: number; data: T }> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers: {
        "Content-Type": "application/json",
        ...headers,
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    let data: T = null as T;
    if (text) {
      try {
        data = JSON.parse(text);
      } catch {
        data = text as unknown as T;
      }
    }
    return { status: res.status, data };
  }

  async health(): Promise<boolean> {
    try {
      const { status } = await this.request<unknown>("GET", "/health");
      return status === 200;
    } catch {
      return false;
    }
  }

  /** Register a new per-domain subdomain + credentials on the acme-dns server. */
  async register(allowFrom: string[] = []): Promise<RegisterResponse> {
    const { status, data } = await this.request<RegisterResponse>(
      "POST",
      "/register",
      { allowfrom: allowFrom },
    );
    if (status !== 201) {
      throw new Error(
        `acme-dns /register failed (HTTP ${status}): ${JSON.stringify(data)}`,
      );
    }
    return data;
  }

  /**
   * Set the TXT value for a registered subdomain. Empty string clears it.
   * Newer acme-dns builds use /update; older ones used POST /. We try both.
   */
  async updateTxt(
    subdomain: string,
    username: string,
    password: string,
    txt: string,
  ): Promise<void> {
    const headers = {
      "X-Api-User": username,
      "X-Api-Key": password,
    };
    const body = { subdomain, txt };
    let { status, data } = await this.request<unknown>(
      "POST",
      "/update",
      body,
      headers,
    );
    if (status === 404) {
      // Older acme-dns API: POST to the root path
      ({ status, data } = await this.request<unknown>(
        "POST",
        "/",
        body,
        headers,
      ));
    }
    if (status !== 200) {
      throw new Error(
        `acme-dns TXT update failed (HTTP ${status}): ${JSON.stringify(data)}`,
      );
    }
  }

  /** Verify connectivity + API auth with the configured acme-dns server. */
  async test(): Promise<string> {
    const ok = await this.health();
    if (!ok) return "unreachable";
    return "ok";
  }
}

export const acmedns = new AcmeDnsClient(config.acmedns.apiUrl);
