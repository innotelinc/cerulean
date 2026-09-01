import path from "node:path";
import dotenv from "dotenv";

// Load .env from the repo root (works when started from repo root or from server/)
dotenv.config({ path: path.resolve(__dirname, "../../../.env") });
dotenv.config();

export interface Config {
  port: number;
  adminPassword: string;
  tokenTtlHours: number;

  acmeDirectoryUrl: string;
  acmeEmail: string;

  bind: {
    host: string;
    port: number;
    user: string;
    keyPath: string;
    password: string;
    tsigName: string;
    tsigSecret: string;
  };
  zone: string;
  propagationBufferSeconds: number;

  acmedns: {
    apiUrl: string;
    publicIp: string;
    domain: string;
    allowFrom: string[];
  };

  npm: {
    apiUrl: string;
    email: string;
    password: string;
    wildcardAttach: boolean;
  };

  dataDir: string;
}

function bool(value: string | undefined, def: boolean): boolean {
  if (value === undefined) return def;
  return value.toLowerCase() === "true" || value === "1";
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const adminPassword = env.CERULEAN_ADMIN_PASSWORD || "";
  if (!adminPassword) {
    throw new Error(
      "CERULEAN_ADMIN_PASSWORD is not set. Copy .env.example to .env and set it before starting Cerulean.",
    );
  }

  return {
    port: Number(env.CERULEAN_PORT || 3000),
    adminPassword,
    tokenTtlHours: Number(env.CERULEAN_TOKEN_TTL_HOURS || 12),

    acmeDirectoryUrl:
      env.ACME_DIRECTORY_URL ||
      "https://acme-v02.api.letsencrypt.org/directory",
    acmeEmail: env.ACME_EMAIL || "admin@example.com",

    bind: {
      host: env.BIND_SSH_HOST || "",
      port: Number(env.BIND_SSH_PORT || 22),
      user: env.BIND_SSH_USER || "root",
      keyPath: env.BIND_SSH_KEY_PATH || "",
      password: env.BIND_SSH_PASSWORD || "",
      tsigName: env.BIND_TSIG_NAME || "cerulean.",
      tsigSecret: env.BIND_TSIG_SECRET || "",
    },
    zone: env.CERULEAN_ZONE || "innotel.us",
    propagationBufferSeconds: Number(env.PROPAGATION_BUFFER_SECONDS || 10),

    acmedns: {
      apiUrl: env.ACMEDNS_API_URL || "http://acme-dns:4443",
      publicIp: env.ACMEDNS_PUBLIC_IP || "",
      domain: env.ACMEDNS_DOMAIN || "auth.innotel.us",
      allowFrom: (env.ACMEDNS_ALLOW_FROM || "")
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
    },

    npm: {
      apiUrl: env.NPM_API_URL || "",
      email: env.NPM_EMAIL || "",
      password: env.NPM_PASSWORD || "",
      // Attach wildcard certificates (e.g. *.innotel.us) to every matching
      // subdomain proxy host, unless the host already has its own certificate.
      wildcardAttach: bool(env.NPM_WILDCARD_ATTACH, true),
    },

    dataDir: env.CERULEAN_DATA_DIR || path.resolve(__dirname, "../../../data"),
  };
}

export const config = loadConfig();

export { bool };
