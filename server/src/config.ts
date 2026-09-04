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

  // Admin API credentials (optional) used to inspect Authentik groups/users —
  // e.g. listing a tenant's members (a tenant is an Authentik group).
  authentikAdmin: {
    apiUrl: string;
    user: string;
    password: string;
  };

  vault: {
    enabled: boolean;
    addr: string;
    token: string;
    prefix: string;
  };

  infisical: {
    enabled: boolean;
    addr: string;
    token: string;
    workspaceId: string;
    environment: string;
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

  bind: {
    mode: string; // "remote" (default) | "local"
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

  npm: {
    mode: string; // "remote" (default) | "local"
    apiUrl: string;
    email: string;
    password: string;
    wildcardAttach: boolean;
  };

  tenant: {
    // Authentik group that grants platform-admin powers (all tenants, tenant
    // management). Local admin sessions are always platform admins.
    platformGroup: string;
  };

  pki: {
    // Internal private CA that issues TLS client certificates for managed
    // devices (mTLS at the reverse proxy, MDM enrollment, ...).
    caCommonName: string;
    caValidityDays: number;
    certValidityDays: number;
    // SCEP endpoint embedded in the Apple enrollment profile (.mobileconfig)
    // that MDM-managed devices use to obtain their client certificate.
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
  const infisicalAddr = env.INFISICAL_ADDR || "";
  const infisicalToken = env.INFISICAL_TOKEN || "";

  const bindMode = (env.BIND_MODE || "remote").toLowerCase();
  const npmMode = (env.NPM_MODE || "remote").toLowerCase();
  if (npmMode !== "local" && npmMode !== "remote") {
    throw new Error('NPM_MODE must be "local" or "remote".');
  }
  if (bindMode !== "local" && bindMode !== "remote") {
    throw new Error('BIND_MODE must be "local" or "remote".');
  }
  if (npmMode === "local" && bindMode !== "local") {
    throw new Error(
      "NPM_MODE=local requires BIND_MODE=local. Use NPM_MODE=remote with an external NPM instance when BIND_MODE=remote.",
    );
  }
  // In "local" mode the compose stack bundles BIND+sshd and the complete
  // NPM Edge component (NPM, MariaDB, and backup-ui). Their compose service
  // names are used as the default addresses; remote mode always uses an
  // operator-managed external endpoint.
  //
  // NPM_INTERNAL_API_URL is the address the portal container itself uses. A
  // local deployment deliberately prefers the bundled service over a stale
  // remote NPM_API_URL from a previous deployment.
  const bindHost =
    bindMode === "local"
      ? env.BIND_LOCAL_SSH_HOST || "cerulean-bind"
      : env.BIND_SSH_HOST || "";
  const npmApiUrl =
    npmMode === "local"
      ? env.NPM_INTERNAL_API_URL || "http://cerulean-npm:81"
      : env.NPM_API_URL || env.NPM_INTERNAL_API_URL || "";

  return {
    port: Number(env.CERULEAN_PORT || 3000),
    adminPassword,
    tokenTtlHours: Number(env.CERULEAN_TOKEN_TTL_HOURS || 12),

    auth: {
      issuerUrl,
      clientId,
      clientSecret,
      // The OIDC redirect URI. Defaults to the portal's own callback path so
      // the flow works out of the box when the dashboard is served here.
      redirectUri:
        env.AUTHENTIK_REDIRECT_URI ||
        `http://localhost:${env.CERULEAN_PORT || 3000}/api/auth/oidc/callback`,
      scopes: env.AUTHENTIK_SCOPES || "openid profile email",
      // Local admin-password login remains available as a bootstrap fallback
      // unless explicitly disabled (AUTH_LOCAL_ENABLED=0).
      localEnabled: bool(env.AUTH_LOCAL_ENABLED, true),
    },

    authentikAdmin: {
      apiUrl: env.AUTHENTIK_API_URL || issuerUrl,
      user: env.AUTHENTIK_ADMIN_USER || "akadmin",
      password: env.AUTHENTIK_ADMIN_PASSWORD || "",
    },

    vault: {
      enabled: bool(env.VAULT_ENABLED, Boolean(vaultAddr && vaultToken)),
      addr: vaultAddr,
      token: vaultToken,
      prefix: env.VAULT_PREFIX || "cerulean",
    },

    infisical: {
      enabled: bool(
        env.INFISICAL_ENABLED,
        Boolean(infisicalAddr && infisicalToken && env.INFISICAL_WORKSPACE_ID),
      ),
      addr: infisicalAddr,
      token: infisicalToken,
      workspaceId: env.INFISICAL_WORKSPACE_ID || "",
      environment: env.INFISICAL_ENVIRONMENT || "prod",
    },

    discovery: {
      // Extra directories scanned for PEM certificates (e.g. /etc/ssl/certs).
      dirs: list(env.CERT_DISCOVERY_DIRS),
    },

    audit: {
      enabled: bool(env.DNS_AUDIT_ENABLED, true),
      resolvers: list(env.DNS_AUDIT_RESOLVERS).length
        ? list(env.DNS_AUDIT_RESOLVERS)
        : ["8.8.8.8", "1.1.1.1", "9.9.9.9"],
    },

    acmeDirectoryUrl:
      env.ACME_DIRECTORY_URL ||
      "https://acme-v02.api.letsencrypt.org/directory",
    acmeEmail: env.ACME_EMAIL || "admin@example.com",

    bind: {
      mode: bindMode,
      host: bindHost,
      port: Number(env.BIND_SSH_PORT || 22),
      user: env.BIND_SSH_USER || "root",
      keyPath: env.BIND_SSH_KEY_PATH || "",
      password: env.BIND_SSH_PASSWORD || "",
      tsigName: env.BIND_TSIG_NAME || "cerulean.",
      tsigSecret: env.BIND_TSIG_SECRET || "",
    },
    zone: env.CERULEAN_ZONE || "innotel.us",
    propagationBufferSeconds: Number(env.PROPAGATION_BUFFER_SECONDS || 10),

    npm: {
      mode: npmMode,
      apiUrl: npmApiUrl,
      email: env.NPM_EMAIL || "",
      password: env.NPM_PASSWORD || "",
      // Attach wildcard certificates (e.g. *.innotel.us) to every matching
      // subdomain proxy host, unless the host already has its own certificate.
      wildcardAttach: bool(env.NPM_WILDCARD_ATTACH, true),
    },

    tenant: {
      platformGroup: env.TENANT_PLATFORM_GROUP || "cerulean-platform",
    },

    pki: {
      // Subject CN of the internally generated root CA (created on first use
      // via POST /api/pki/init or when the first device certificate is issued).
      caCommonName: env.CA_COMMON_NAME || "Cerulean Root CA",
      caValidityDays: Number(env.CA_VALIDITY_DAYS || 3650),
      // Default validity of issued device client certificates.
      certValidityDays: Number(env.PKI_CERT_VALIDITY_DAYS || 825),
      // SCEP endpoint for device enrollment (https://scep.example.com/scep),
      // CA name advertised to enrolling devices, and an optional shared
      // challenge. Empty until you point PKI_SCEP_URL at a SCEP server.
      scepUrl: (env.PKI_SCEP_URL || "").trim(),
      scepCaName: env.PKI_SCEP_CA_NAME || "cerulean",
      scepChallenge: (env.PKI_SCEP_CHALLENGE || "").trim(),
    },

    dataDir: env.CERULEAN_DATA_DIR || path.resolve(__dirname, "../../data"),
  };
}

export const config = loadConfig();

export { bool };
