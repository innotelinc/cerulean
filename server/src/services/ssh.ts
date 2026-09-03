import fs from "node:fs";
import { Client } from "ssh2";
import { config } from "../config";
import { vault } from "./vault";

export interface ExecResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

/** Connection override: lets a per-tenant DNS provider target another BIND.
 * Omitted fields fall back to the platform .env BIND. */
export interface SshConnection {
  host: string;
  port: number;
  user: string;
  keyPath: string;
  password: string;
}

/**
 * Run a command on a BIND server over SSH and pipe `stdin` to the remote
 * process. Supports key auth (preferred) or password auth. `conn` overrides
 * the platform BIND (.env) for per-tenant DNS providers.
 */
export async function sshExec(
  command: string,
  stdin?: string,
  timeoutMs = 30_000,
  conn?: Partial<SshConnection>,
): Promise<ExecResult> {
  const host = conn?.host || config.bind.host;
  const port = conn?.port ?? config.bind.port;
  const user = conn?.user || config.bind.user;
  const keyPath = conn?.keyPath ?? config.bind.keyPath;
  const passwordRaw = conn?.password ?? config.bind.password;
  if (!host) {
    return Promise.reject(
      new Error(
        conn
          ? "DNS provider is missing its host"
          : "BIND_SSH_HOST is not configured — set it in .env",
      ),
    );
  }
  if (!keyPath && !passwordRaw) {
    return Promise.reject(
      new Error(
        "No BIND SSH credentials configured — set BIND_SSH_KEY_PATH or BIND_SSH_PASSWORD in .env (or on the DNS provider)",
      ),
    );
  }
  // The password may be a vault:// reference resolved from the secret vault.
  const password = await vault.resolveSecretValue(passwordRaw);

  return new Promise((resolve, reject) => {
    const conn = new Client();
    const timer = setTimeout(() => {
      conn.end();
      reject(new Error(`SSH command timed out after ${timeoutMs}ms: ${command}`));
    }, timeoutMs);

    const finish = (result: ExecResult) => {
      clearTimeout(timer);
      conn.end();
      resolve(result);
    };

    conn.on("ready", () => {
      conn.exec(command, (err, stream) => {
        if (err) {
          clearTimeout(timer);
          conn.end();
          reject(err);
          return;
        }
        let stdout = "";
        let stderr = "";
        stream.on("close", (code: number | null) => {
          finish({ code, stdout, stderr });
        });
        stream.on("data", (data: Buffer) => {
          stdout += data.toString();
        });
        stream.stderr.on("data", (data: Buffer) => {
          stderr += data.toString();
        });
        if (stdin !== undefined) {
          stream.stdin.end(stdin);
        } else {
          stream.stdin.end();
        }
      });
    });

    conn.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });

    const connConfig: Record<string, unknown> = {
      host,
      port,
      username: user,
      readyTimeout: 15_000,
    };
    if (keyPath && fs.existsSync(keyPath)) {
      connConfig.privateKey = fs.readFileSync(keyPath);
    } else if (password) {
      connConfig.password = password;
    }
    conn.connect(connConfig);
  });
}
