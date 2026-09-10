import path from "node:path";
import dotenv from "dotenv";

// Load .env from the repo root (works when started from repo root or from server/)
dotenv.config({ path: path.resolve(__dirname, "../../../.env") });
dotenv.config();

export interface Config {
  port: number;
  adminPassword: string;
  tokenTtlHours: number;

  auth: {
    issuerUrl: string;
    clientId: string;
    clientSecret: string;
    redirectUri: string;
    scopes: string;
    localEnabled: boolean;
  };

  authentikAdmin: {
    apiUrl: string;
    user: string;
    password: string;
    bootstrapToken: string;
  };

  vault: {
    enabled: boolean;
    addr: string;
    token: string;
    prefix: string;
  };

  discovery: {
    dirs: string[];
  };

  audit: {
    enabled: boolean;
    resolvers: string[];
  };

  acmeDirectoryUrl: string;
  acmeEmail: string;

  technitium: {
    url: string;
    token: string;
    user: string;
    password: string;
    timeoutMs: number;
  };

  /** Server identity — the “plug anywhere” offline-first orchestrator ID. */
  server: {
    /** Stable slug for this installation, e.g. “alpha-7f3a”. Auto-generated if empty. */
    id: string;
    /** Lab base domain suffix, e.g. lab.innotel.us */
    labDomain: string;
    /** Optional central registration endpoint (POST {serverId,domain,wildcard}) — legacy; prefer CRS. */
    registerUrl: string;
    registerToken: string;
    /** Validity of the auto-issued wildcard for *.<id>.lab.innotel.us */
    wildcardValidityDays: number;
    /** Auto-issue/renew the lab wildcard on boot (PKI offline, ACME when online) */
    autoWildcard: boolean;
  };

  /** Central Registration Server (CRS) — master/slave to lab.innotel.us */
  crs: {
    role: string; // "auto" | "master" | "slave"
    domain: string; // authority domain for master (e.g. lab.innotel.us)
    homeUrl: string; // home address, defaults to https://lab.innotel.us
    masterUrl: string; // which master this slave registers to (defaults to home)
    token: string; // shared secret for CRS register/registry (Bearer)
    airGapped: boolean; // true → never try to reach home, stay isolated master
    timeoutMs: number;
  };

  /** Master orchestrator posture */
  orchestrator: {
    enabled: boolean;
    dhcpEnabled: boolean;
    blockingEnabled: boolean;
  };

  zone: string;
  propagationBufferSeconds: number;

  npm: {
    mode: string; // "remote" (default) | "local"
    apiUrl: string;
    email: string;
    password: string;
    wildcardAttach: boolean;
  };

  tenant: {
    platformGroup: string;
  };

  pki: {
    caCommonName: string;
    caValidityDays: number;
    certValidityDays: number;
    scepUrl: string;
    scepCaName: string;
    scepChallenge: string;
  };

  dataDir: string;
}

function bool(value: string | undefined, def: boolean): boolean {
  if (value === undefined) return def;
  return value.toLowerCase() === "true" || value === "1";
}

function list(value: string | undefined): string[] {
  return (value || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function sanitizeServerId(raw: string): string {
  const s = raw.trim().toLowerCase();
  // DNS-safe slug: a-z0-9, dash, 1-63 chars, cannot start/end with dash
  if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(s)) return "";
  return s;
}

function generateServerId(): string {
  // Short, human-friendly: 4-char prefix + 4 hex
  const hex = Math.random().toString(16).slice(2, 6);
  const num = Math.floor(Math.random() * 9000 + 1000);
  return `srv-${hex}${num}`.toLowerCase();
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const adminPassword = env.CERULEAN_ADMIN_PASSWORD || "";
  if (!adminPassword) {
    throw new Error(
      "CERULEAN_ADMIN_PASSWORD is not set. Copy .env.example to .env and set it before starting Cerulean.",
    );
  }

  const issuerUrl = env.AUTHENTIK_ISSUER_URL || "";
  const clientId = env.AUTHENTIK_CLIENT_ID || "";
  const clientSecret = env.AUTHENTIK_CLIENT_SECRET || "";
  const vaultAddr = env.VAULT_ADDR || "";
  const vaultToken = env.VAULT_TOKEN || "";

  const npmMode = (env.NPM_MODE || "remote").toLowerCase();
  if (npmMode !== "local" && npmMode !== "remote") {
    throw new Error('NPM_MODE must be "local" or "remote".');
  }
  // NPM local still requires a DNS backend, but now that's Technitium (bundled).
  // We keep the guard but point it at Technitium.
  const technitiumUrl =
    env.TECHNITIUM_URL ||
    env.TECHNITIUM_API_URL ||
    env.DNS_URL ||
    // Technitium is host-networked (port 53/67/5380), so the app reaches it
    // through the host gateway; the compose file maps host.docker.internal
    // for this. 127.0.0.1 here would be the app container itself.
    "http://host.docker.internal:5380";

  const npmApiUrl =
    npmMode === "local"
      ? env.NPM_INTERNAL_API_URL || "http://cerulean-npm:81"
      : env.NPM_API_URL || env.NPM_INTERNAL_API_URL || "";

  // Server identity: prefer explicit env, else auto-generate (persisted later in DB/file)
  const rawServerId = env.CERULEAN_SERVER_ID || env.SERVER_ID || "";
  let serverId = sanitizeServerId(rawServerId);
  if (!serverId && rawServerId) {
    console.warn(`[config] Invalid SERVER_ID "${rawServerId}" — ignoring (must be DNS-safe slug)`);
  }
  if (!serverId) {
    // For typecheck/test env we can generate ephemeral; real persistence happens in serverIdentity service
    serverId = sanitizeServerId(env.CERULEAN_SERVER_ID || "") || generateServerId();
    // Only warn in non-test
    if (!env.VITEST && !env.CERULEAN_DATA_DIR?.includes("test")) {
      console.warn(`[config] SERVER_ID not set — using ephemeral "${serverId}". Set SERVER_ID in .env for stable identity.`);
    }
  }

  const labDomain = (env.CERULEAN_LAB_DOMAIN || env.LAB_BASE_DOMAIN || "lab.innotel.us")
    .trim()
    .toLowerCase()
    .replace(/^\.+|\.+$/g, "") || "lab.innotel.us";

  return {
    port: Number(env.CERULEAN_PORT || 3000),
    adminPassword,
    tokenTtlHours: Number(env.CERULEAN_TOKEN_TTL_HOURS || 12),

    auth: {
      issuerUrl,
      clientId,
      clientSecret,
      redirectUri:
        env.AUTHENTIK_REDIRECT_URI ||
        `http://localhost:${env.CERULEAN_PORT || 3000}/api/auth/oidc/callback`,
      scopes: env.AUTHENTIK_SCOPES || "openid profile email",
      localEnabled: bool(env.AUTH_LOCAL_ENABLED, true),
    },

    authentikAdmin: {
      apiUrl: env.AUTHENTIK_API_URL || issuerUrl,
      user: env.AUTHENTIK_ADMIN_USER || "akadmin",
      password: env.AUTHENTIK_ADMIN_PASSWORD || "",
      bootstrapToken: env.AUTHENTIK_BOOTSTRAP_TOKEN || "",
    },

    vault: {
      enabled: bool(env.VAULT_ENABLED, Boolean(vaultAddr && vaultToken)),
      addr: vaultAddr,
      token: vaultToken,
      prefix: env.VAULT_PREFIX || "cerulean",
    },

    discovery: {
      dirs: list(env.CERT_DISCOVERY_DIRS),
    },

    audit: {
      enabled: bool(env.DNS_AUDIT_ENABLED, true),
      resolvers: list(env.DNS_AUDIT_RESOLVERS).length
        ? list(env.DNS_AUDIT_RESOLVERS)
        : ["8.8.8.8", "1.1.1.1", "9.9.9.9"],
    },

    acmeDirectoryUrl:
      env.ACME_DIRECTORY_URL || "https://acme-v02.api.letsencrypt.org/directory",
    acmeEmail: env.ACME_EMAIL || "admin@example.com",

    technitium: {
      url: technitiumUrl.replace(/\/$/, ""),
      token: env.TECHNITIUM_TOKEN || env.TECHNITIUM_API_TOKEN || "",
      user: env.TECHNITIUM_USER || env.TECHNITIUM_ADMIN_USER || "admin",
      password: env.TECHNITIUM_PASSWORD || env.TECHNITIUM_ADMIN_PASSWORD || "",
      timeoutMs: Number(env.TECHNITIUM_TIMEOUT_MS || 15000),
    },

    server: {
      id: serverId,
      labDomain,
      registerUrl: env.SERVER_REGISTER_URL || env.CERULEAN_REGISTER_URL || "",
      registerToken: env.SERVER_REGISTER_TOKEN || env.CERULEAN_REGISTER_TOKEN || "",
      wildcardValidityDays: Math.min(
        Math.max(Number(env.SERVER_WILDCARD_VALIDITY_DAYS || env.WILDCARD_CERT_VALIDITY_DAYS || 90), 1),
        90,
      ),
      autoWildcard: bool(env.SERVER_AUTO_WILDCARD, true),
    },

    crs: {
      role: (env.CRS_ROLE || env.CERULEAN_CRS_ROLE || "auto").toLowerCase(),
      domain: (env.CRS_DOMAIN || env.CRS_LAB_DOMAIN || "").trim().toLowerCase().replace(/^\.+|\.+$/g, ""),
      homeUrl: env.CRS_HOME_URL || env.CRS_HOME || "https://lab.innotel.us",
      masterUrl: env.CRS_MASTER_URL || env.CRS_URL || env.SERVER_REGISTER_URL || env.CERULEAN_REGISTER_URL || "https://lab.innotel.us",
      token: env.CRS_TOKEN || env.CRS_REGISTER_TOKEN || env.SERVER_REGISTER_TOKEN || env.CERULEAN_REGISTER_TOKEN || "",
      airGapped: bool(env.CRS_AIR_GAPPED ?? env.AIR_GAPPED, false),
      timeoutMs: Number(env.CRS_TIMEOUT_MS || 10_000),
    },

    orchestrator: {
      enabled: bool(env.ORCHESTRATOR_ENABLED, true),
      dhcpEnabled: bool(env.ORCHESTRATOR_DHCP_ENABLED ?? env.TECHNITIUM_DHCP_ENABLED, true),
      blockingEnabled: bool(env.ORCHESTRATOR_BLOCKING_ENABLED ?? env.TECHNITIUM_BLOCKING_ENABLED, true),
    },

    zone: env.CERULEAN_ZONE || `${serverId}.${labDomain}`,
    propagationBufferSeconds: Number(env.PROPAGATION_BUFFER_SECONDS || 10),

    npm: {
      mode: npmMode,
      apiUrl: npmApiUrl,
      email: env.NPM_EMAIL || "",
      password: env.NPM_PASSWORD || "",
      wildcardAttach: bool(env.NPM_WILDCARD_ATTACH, true),
    },

    tenant: {
      platformGroup: env.TENANT_PLATFORM_GROUP || "cerulean-platform",
    },

    pki: {
      caCommonName: env.CA_COMMON_NAME || "Cerulean Root CA",
      caValidityDays: Number(env.CA_VALIDITY_DAYS || 3650),
      certValidityDays: Number(env.PKI_CERT_VALIDITY_DAYS || 825),
      scepUrl: (env.PKI_SCEP_URL || "").trim(),
      scepCaName: env.PKI_SCEP_CA_NAME || "cerulean",
      scepChallenge: (env.PKI_SCEP_CHALLENGE || "").trim(),
    },

    dataDir: env.CERULEAN_DATA_DIR || path.resolve(__dirname, "../../data"),
  };
}

export const config = loadConfig();

export { bool, sanitizeServerId, generateServerId };
