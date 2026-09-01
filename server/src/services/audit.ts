import { promises as dns } from "node:dns";
import { config } from "../config";
import { gradeFor, type HealthCheck } from "./health";

export interface DnsAudit {
  domain: string;
  runAt: string;
  score: number;
  grade: string;
  checks: HealthCheck[];
}

const RESOLVER_TIMEOUT = 4000;

function newResolver(server?: string): dns.Resolver {
  const r = new dns.Resolver({ timeout: RESOLVER_TIMEOUT, tries: 1 });
  if (server) r.setServers([server]);
  return r;
}

async function safe<T>(
  fn: () => Promise<T>,
): Promise<{ ok: true; value: T } | { ok: false; error: string }> {
  try {
    return { ok: true, value: await fn() };
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/** Pure score for a list of audit checks (used by the audit sweep + tests). */
export function scoreChecks(checks: HealthCheck[]): number {
  let score = 100;
  for (const c of checks) {
    if (c.status === "fail") score -= 25;
    else if (c.status === "warn") score -= 10;
  }
  return Math.max(0, Math.min(100, score));
}

/**
 * Audit the health of a domain's DNS: nameserver delegation, authoritative
 * SOA answers, serial consistency, apex reachability and propagation
 * consistency across public resolvers, and CAA policy. All queries are made
 * against public resolvers — no BIND access required.
 */
export async function auditDomain(domain: string): Promise<DnsAudit> {
  const checks: HealthCheck[] = [];
  const name = domain.toLowerCase().replace(/\.$/, "");

  // 1. Nameserver delegation
  const ns = await safe(() => dns.resolveNs(name));
  if (!ns.ok || ns.value.length === 0) {
    checks.push({
      name: "ns",
      status: "fail",
      detail: `No NS records found for ${name} (${ns.ok ? "empty" : ns.error})`,
    });
    const score = scoreChecks(checks);
    return {
      domain: name,
      runAt: new Date().toISOString(),
      score,
      grade: gradeFor(score),
      checks,
    };
  }
  checks.push({
    name: "ns",
    status: "ok",
    detail: `${ns.value.length} nameserver(s): ${ns.value.join(", ")}`,
  });

  // 2. Nameserver IPs (A, then AAAA)
  const nsIps: Record<string, string[]> = {};
  for (const host of ns.value) {
    const a = await safe(() => dns.resolve4(host));
    if (a.ok && a.value.length) {
      nsIps[host] = a.value;
      continue;
    }
    const aaaa = await safe(() => dns.resolve6(host));
    nsIps[host] = aaaa.ok ? aaaa.value : [];
  }

  // 3. Each nameserver answers SOA authoritatively
  const serials: number[] = [];
  let reachable = 0;
  for (const host of ns.value) {
    const ips = nsIps[host] || [];
    if (ips.length === 0) {
      checks.push({
        name: "soa",
        status: "fail",
        detail: `Nameserver ${host} has no resolvable IP`,
      });
      continue;
    }
    const soa = await safe(() => newResolver(ips[0]).resolveSoa(name));
    if (soa.ok) {
      reachable += 1;
      serials.push(soa.value.serial);
    } else {
      checks.push({
        name: "soa",
        status: "fail",
        detail: `Nameserver ${host} (${ips[0]}) did not answer authoritatively: ${soa.error}`,
      });
    }
  }
  if (serials.length > 0) {
    checks.push({
      name: "soa",
      status: reachable === ns.value.length ? "ok" : "warn",
      detail: `${reachable}/${ns.value.length} nameservers answer authoritatively`,
    });
  }

  // 4. SOA serial consistency
  if (serials.length > 1 && new Set(serials).size > 1) {
    checks.push({
      name: "soa-serial",
      status: "warn",
      detail: `SOA serials differ across nameservers: ${[...new Set(serials)].join(", ")}`,
    });
  } else if (serials.length > 1) {
    checks.push({
      name: "soa-serial",
      status: "ok",
      detail: `SOA serial consistent (${serials[0]})`,
    });
  }

  // 5. Apex reachability from public resolvers
  const apexAnswers: string[][] = [];
  for (const server of config.audit.resolvers) {
    const a = await safe(() => newResolver(server).resolve4(name));
    if (a.ok) apexAnswers.push(a.value);
  }
  const anyApex = apexAnswers.some((r) => r.length > 0);
  if (!anyApex) {
    checks.push({
      name: "apex",
      status: "fail",
      detail: "Apex has no A records resolvable from public resolvers",
    });
  } else if (apexAnswers.some((r) => r.length === 0)) {
    checks.push({
      name: "apex",
      status: "warn",
      detail: "Apex A record missing from some public resolvers",
    });
  } else {
    checks.push({
      name: "apex",
      status: "ok",
      detail: `Apex resolves to ${apexAnswers[0].join(", ")}`,
    });
  }

  // 6. Propagation consistency across resolvers
  const normalized = apexAnswers.map((ips) => [...ips].sort().join(","));
  if (normalized.length > 1 && new Set(normalized).size > 1) {
    checks.push({
      name: "propagation",
      status: "fail",
      detail: "Apex answers differ across public resolvers (propagation drift)",
    });
  } else if (normalized.length > 1) {
    checks.push({
      name: "propagation",
      status: "ok",
      detail: "Consistent answers across public resolvers",
    });
  }

  // 7. CAA policy
  const caa = await safe(() => newResolver().resolveCaa(name));
  if (caa.ok && caa.value.length > 0) {
    checks.push({
      name: "caa",
      status: "ok",
      detail: `CAA policy present: ${caa.value.map((c) => String((c as { value?: unknown }).value ?? (c as { tag?: unknown }).tag ?? "")).join(", ")}`,
    });
  } else {
    checks.push({
      name: "caa",
      status: "warn",
      detail: "No CAA records — any certificate authority may issue certificates",
    });
  }

  const score = scoreChecks(checks);
  return {
    domain: name,
    runAt: new Date().toISOString(),
    score,
    grade: gradeFor(score),
    checks,
  };
}
