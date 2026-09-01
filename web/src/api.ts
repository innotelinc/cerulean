const TOKEN_KEY = "cerulean_token";

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY);
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const token = getToken();
  const res = await fetch(`/api${path}`, {
    method,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  let data: unknown = null;
  const text = await res.text();
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }
  if (res.status === 401) {
    clearToken();
    window.location.hash = "#/login";
    throw new Error("Session expired — please log in again");
  }
  if (!res.ok) {
    const message =
      typeof data === "object" && data !== null && "error" in (data as object)
        ? String((data as { error: unknown }).error)
        : `Request failed (HTTP ${res.status})`;
    throw new Error(message);
  }
  return data as T;
}

export const api = {
  login: (password: string) =>
    request<{ token: string }>("POST", "/auth/login", { password }),
  logout: () => request<{ ok: boolean }>("POST", "/auth/logout"),
  status: () => request<import("./types").StatusResponse>("GET", "/status"),
  activities: () => request<import("./types").Activity[]>("GET", "/activities"),

  listDomains: () => request<import("./types").Domain[]>("GET", "/domains"),
  createDomain: (input: { name: string; strategy: string }) =>
    request<import("./types").Domain>("POST", "/domains", input),
  deleteDomain: (id: number) =>
    request<{ ok: boolean }>("DELETE", `/domains/${id}`),
  listRecords: (id: number) =>
    request<import("./types").DnsRecord[]>("GET", `/domains/${id}/records`),
  addRecord: (
    id: number,
    input: {
      type: string;
      name: string;
      value: string;
      ttl?: number;
      priority?: number;
    },
  ) => request<{ ok: boolean }>("POST", `/domains/${id}/records`, input),
  deleteRecord: (
    id: number,
    input: { type: string; name: string; value?: string },
  ) => request<{ ok: boolean }>("DELETE", `/domains/${id}/records`, input),

  listCertificates: () =>
    request<import("./types").Certificate[]>("GET", "/certificates"),
  createCertificate: (input: {
    name?: string;
    domain: string;
    wildcard: boolean;
    strategy: string;
  }) => request<import("./types").Certificate>("POST", "/certificates", input),
  getCertificate: (id: number) =>
    request<import("./types").Certificate>("GET", `/certificates/${id}`),
  renewCertificate: (id: number) =>
    request<{ ok: boolean }>("POST", `/certificates/${id}/renew`),
  deleteCertificate: (id: number) =>
    request<{ ok: boolean }>("DELETE", `/certificates/${id}`),
  certMaterial: (id: number) =>
    request<{ certificate: string; key: string }>(
      "GET",
      `/certificates/${id}/material`,
    ),

  npmHosts: () => request<import("./types").NpmProxyHost[]>("GET", "/npm/hosts"),
  npmCertificates: () =>
    request<import("./types").NpmCertificate[]>("GET", "/npm/certificates"),
  exportCert: (input: { certificate_id: number; nice_name?: string }) =>
    request<{ npmCertificateId: number; niceName: string }>(
      "POST",
      "/npm/export-cert",
      input,
    ),
  createNpmHost: (input: {
    domain: string;
    forward_host: string;
    forward_port: number;
    forward_scheme?: string;
    certificate_id?: number;
    ssl_forced?: boolean;
    http2_support?: boolean;
  }) => request<import("./types").NpmProxyHost>("POST", "/npm/hosts", input),
};
