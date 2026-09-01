import fs from "node:fs";
import { Client } from "ssh2";
import { config } from "../config";

export interface ExecResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

/**
 * Run a command on the BIND server over SSH and pipe `stdin` to the remote
 * process. Supports key auth (preferred) or password auth.
 */
export function sshExec(
  command: string,
  stdin?: string,
  timeoutMs = 30_000,
): Promise<ExecResult> {
  const { host, port, user, keyPath, password } = config.bind;
  if (!host) {
    return Promise.reject(
      new Error("BIND_SSH_HOST is not configured — set it in .env"),
    );
  }
  if (!keyPath && !password) {
    return Promise.reject(
      new Error(
        "No BIND SSH credentials configured — set BIND_SSH_KEY_PATH or BIND_SSH_PASSWORD in .env",
      ),
    );
  }

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
