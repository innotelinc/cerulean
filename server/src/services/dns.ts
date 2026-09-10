import { Resolver } from "node:dns";
import * as dns from "node:dns";
import net from "node:net";

/**
 * Resolve TXT records for `name` using a specific nameserver (not the system
 * resolver), so we can check an authoritative server directly.
 *
 * `server` may be an IP (e.g. 192.168.1.46, 172.22.0.2) or a Docker service
 * hostname (e.g. cerulean-technitium). Hostnames are resolved via the
 * system resolver (which inside Docker returns the bridge IP). Custom ports
 * like "127.0.0.1#5353" are also accepted (resolver syntax).
 */
export async function dnsResolveTxt(
  server: string,
  name: string,
): Promise<string[][]> {
  let target = server.trim();
  // Accept "host:port" or "host#port" syntax and extract port for Resolver
  let port: number | undefined;
  const hashIdx = target.indexOf("#");
  const colonIdx = target.lastIndexOf(":");
  // Detect host:port where port is numeric and target is not IPv6 with []
  if (hashIdx !== -1) {
    const maybePort = Number(target.slice(hashIdx + 1));
    if (Number.isFinite(maybePort)) {
      port = maybePort;
      target = target.slice(0, hashIdx);
    }
  } else if (colonIdx !== -1 && !target.startsWith("[") && target.indexOf(":") === colonIdx) {
    // Single colon → likely host:port (not IPv6)
    const maybePort = Number(target.slice(colonIdx + 1));
    if (Number.isFinite(maybePort) && maybePort > 0 && maybePort < 65536) {
      port = maybePort;
      target = target.slice(0, colonIdx);
    }
  }

  // If it's not a literal IP, resolve it (e.g. cerulean-technitium → 172.22.0.2)
  if (!net.isIP(target)) {
    try {
      const lookup = await dns.promises.lookup(target);
      target = lookup.address;
    } catch {
      // Leave as-is — Resolver will error with a clear message
    }
  }

  const serverSpec = port ? `${target}#${port}` : target;
  const resolver = new Resolver();
  resolver.setServers([serverSpec]);
  return new Promise((resolve, reject) => {
    resolver.resolveTxt(name, (err, records) => {
      if (err) reject(err);
      else resolve(records);
    });
  });
}
