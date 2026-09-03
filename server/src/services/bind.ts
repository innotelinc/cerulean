import { config } from "../config";
import { sshExec } from "./ssh";

export type RecordType = "A" | "AAAA" | "CNAME" | "TXT" | "MX" | "NS" | "SRV";

export interface DnsRecord {
  name: string;
  type: string;
  ttl: number;
  value: string;
}

export interface AddRecordInput {
  zone: string;
  type: RecordType;
  name: string; // relative to zone (e.g. "www" or "@" for apex)
  value: string;
  ttl?: number;
  priority?: number; // MX / SRV
}

/** Quote a string safely for nsupdate input. */
export function quoteTxt(value: string): string {
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

/** Fully-qualify a record name against the zone. */
export function fqdn(name: string, zone: string): string {
  if (name === "@" || name === "") return `${zone}.`;
  const n = name.replace(/\.$/, "");
  const z = zone.replace(/\.$/, "");
  if (n.endsWith(`.${z}`) || n === z) return `${n}.`;
  return `${n}.${z}.`;
}

/** Names used by nsupdate must end with a trailing dot. */
function ensureDot(name: string): string {
  return name.endsWith(".") ? name : `${name}.`;
}

/** Strip a single trailing dot, if present. */
function stripDot(name: string): string {
  return name.replace(/\.$/, "");
}

/**
 * Resolve the BIND zone that manages `domain`: the longest zone that is a
 * suffix of `domain` (e.g. "innotel.us" for "monarch.innotel.us"). Pass the
 * zones Cerulean manages — registered domains plus CERULEAN_ZONE. Throws if
 * none covers the domain.
 */
export function resolveZone(domain: string, zones: string[]): string {
  const d = stripDot(domain).toLowerCase();
  let best: string | undefined;
  for (const zoneRaw of zones) {
    const raw = stripDot(zoneRaw);
    const z = raw.toLowerCase();
    if (!z) continue;
    if ((d === z || d.endsWith(`.${z}`)) && (!best || z.length > best.length)) {
      best = raw;
    }
  }
  if (!best) {
    const listed = zones.filter(Boolean).length
      ? zones.filter(Boolean).join(", ")
      : "none registered";
    throw new Error(
      `Domain "${domain}" is not covered by any managed BIND zone (${listed}). ` +
        `Register the zone on the Domains page or set CERULEAN_ZONE in .env.`,
    );
  }
  return best;
}

function tsigFileCommand(): string {
  // The key name must match named.conf EXACTLY (no normalization) — nsupdate
  // rejects keys whose name differs from the server's by even a trailing dot.
  const name = config.bind.tsigName;
  const secret = config.bind.tsigSecret;
  return `key "${name}" { algorithm hmac-sha256; secret "${secret}"; };`;
}

function hasTsig(): boolean {
  return Boolean(config.bind.tsigName && config.bind.tsigSecret);
}

/**
 * Run a set of nsupdate commands against the configured BIND server.
 * A temporary TSIG key file is written on the remote host, used, and removed.
 */
export async function runNsupdate(commands: string[]): Promise<void> {
  if (!hasTsig()) {
    throw new Error(
      "BIND TSIG key is not configured — set BIND_TSIG_NAME and BIND_TSIG_SECRET in .env (generate with: tsig-keygen cerulean)",
    );
  }
  const keyFile = "/tmp/cerulean-tsig.key";
  const keySetup = `printf '%s\n' '${tsigFileCommand()}' > ${keyFile}`;
  const cleanup = `rm -f ${keyFile}`;
  const nsupdate = `nsupdate -k ${keyFile}`;
  const fullCommand = `${keySetup} && ${nsupdate}; rc=$?; ${cleanup}; exit $rc`;

  const script = commands.join("\n") + "\n";
  const result = await sshExec(fullCommand, script);
  if (result.code !== 0) {
    throw new Error(
      `nsupdate failed (exit ${result.code}):\n${result.stderr || result.stdout}`,
    );
  }
}

/**
 * Add a DNS record to the zone via nsupdate. Idempotent-ish: BIND errors on
 * duplicates, so callers that may re-add should delete first.
 */
export async function addRecord(input: AddRecordInput): Promise<void> {
  const { zone, type, name, value, ttl = 300, priority } = input;
  const owner = fqdn(name, zone);
  const commands = [
    `server ${config.bind.host}`,
    `zone ${ensureDot(zone)}`,
    `update add ${owner} ${ttl} ${type} ${type === "TXT" ? quoteTxt(value) : type === "MX" || type === "SRV" ? `${priority ?? 10} ${value}` : value}`,
    "send",
  ];
  await runNsupdate(commands);
}

/**
 * Delete a DNS record. If `value` is omitted, all records of `type` at `name`
 * are removed.
 */
export async function deleteRecord(input: {
  zone: string;
  type: string;
  name: string;
  value?: string;
}): Promise<void> {
  const { zone, type, name, value } = input;
  const owner = fqdn(name, zone);
  const rdata = type === "TXT" && value !== undefined ? ` ${quoteTxt(value)}` : value ? ` ${value}` : "";
  const commands = [
    `server ${config.bind.host}`,
    `zone ${ensureDot(zone)}`,
    `update delete ${owner} ${type}${rdata}`,
    "send",
  ];
  await runNsupdate(commands);
}

/**
 * Publish a TXT record at `name` WITHOUT removing existing TXT records there.
 *
 * DNS-01 challenges for a wildcard certificate produce two authorizations
 * (apex and the wildcard) that share the same _acme-challenge name but carry
 * DIFFERENT TXT values. Replacing the RRset would delete the first value
 * before Let's Encrypt validates it — instead we append, and the per-value
 * cleanup in `clearTxtRecord` removes each value after validation.
 *
 * BIND rejects a duplicate "update add"; if the value is already published
 * (e.g. a retry), that is fine and the duplicate error is ignored.
 */
export async function setTxtRecord(
  zone: string,
  name: string,
  value: string,
  ttl = 60,
): Promise<void> {
  const owner = fqdn(name, zone);
  const commands = [
    `server ${config.bind.host}`,
    `zone ${ensureDot(zone)}`,
    `update add ${owner} ${ttl} TXT ${quoteTxt(value)}`,
    "send",
  ];
  try {
    await runNsupdate(commands);
  } catch (err) {
    if (!/duplicate/i.test(String(err))) throw err;
  }
}

/** Remove a TXT record at `name` (all TXT records there if value is omitted). */
export async function clearTxtRecord(
  zone: string,
  name: string,
  value?: string,
): Promise<void> {
  const owner = fqdn(name, zone);
  const rdata = value !== undefined ? ` ${quoteTxt(value)}` : "";
  const commands = [
    `server ${config.bind.host}`,
    `zone ${ensureDot(zone)}`,
    `update delete ${owner} TXT${rdata}`,
    "send",
  ];
  await runNsupdate(commands);
}

/** Idempotently point `from` (a _acme-challenge name) at `to` via CNAME. */
export async function ensureCname(
  zone: string,
  from: string,
  to: string,
): Promise<void> {
  const owner = fqdn(from, zone);
  const target = ensureDot(to);
  const commands = [
    `server ${config.bind.host}`,
    `zone ${ensureDot(zone)}`,
    `update delete ${owner} CNAME`,
    `update add ${owner} 300 CNAME ${target}`,
    "send",
  ];
  await runNsupdate(commands);
}

/** Parse `dig AXFR` output into records. */
export function parseZoneTransfer(output: string): DnsRecord[] {
  const records: DnsRecord[] = [];
  for (const line of output.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith(";")) continue;
    // name ttl class type rdata...
    const parts = trimmed.split(/\s+/);
    if (parts.length < 5) continue;
    const [name, ttl, cls, type, ...rest] = parts;
    if (cls !== "IN") continue;
    let value = rest.join(" ");
    // Unquote TXT (may be split across multiple quoted chunks)
    if (type === "TXT") {
      value = value
        .replace(/^"(.*)"$/, "$1")
        .replace(/"\s*"/g, "")
        .replace(/\\"/g, '"');
    }
    records.push({
      name: name.replace(/\.$/, ""),
      type,
      ttl: Number(ttl),
      value,
    });
  }
  return records;
}

/**
 * List all records in a zone via an AXFR transfer run on the BIND server
 * (requires allow-transfer to permit the portal's host).
 */
export async function listZone(zone: string): Promise<DnsRecord[]> {
  const result = await sshExec(
    `dig @${config.bind.host} ${ensureDot(zone)} AXFR +noall +answer +time=10 +tries=1`,
  );
  if (result.code !== 0) {
    throw new Error(
      `Zone transfer failed (exit ${result.code}): ${result.stderr || result.stdout}`,
    );
  }
  if (!result.stdout.trim()) {
    throw new Error(
      `Zone transfer for ${zone} returned no records. Ensure 'allow-transfer' includes the portal host on the BIND server.`,
    );
  }
  return parseZoneTransfer(result.stdout);
}
