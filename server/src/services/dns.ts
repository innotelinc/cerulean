import { Resolver } from "node:dns";

/**
 * Resolve TXT records for `name` using a specific nameserver (not the system
 * resolver), so we can check an authoritative server directly.
 */
export function dnsResolveTxt(
  serverIp: string,
  name: string,
): Promise<string[][]> {
  const resolver = new Resolver();
  resolver.setServers([serverIp]);
  return new Promise((resolve, reject) => {
    resolver.resolveTxt(name, (err, records) => {
      if (err) reject(err);
      else resolve(records);
    });
  });
}
