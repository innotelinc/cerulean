/* Stage B — NPM edge cutover: re-issue the edge's certificate set as wildcards.
 *
 * Runs INSIDE the cerulean container (docker cp this file in, then docker exec cerulean node /tmp/$(basename $0)) using the app's own compiled modules, so
 * every issuance takes the exact production path the API uses:
 *   db.createCertificate -> jobs.runIssueJob -> acme.issueCertificate
 *     (Technitium DNS-01) -> db.saveCertificateMaterial
 *     -> npm.syncCertificateToNpm (import into NPM + attach to matching hosts)
 *
 * Writes to the live SQLite DB in WAL mode as a short-lived second writer.
 * Idempotent: an existing row for the same (domain, wildcard) is reused, and
 * rows that already carry material are skipped unless FORCE=1.
 */
const path = "/app/server/dist/";

const dbMod = require(path + "db.js");
const db = dbMod.db || (dbMod.default && dbMod.default.db);
const jobsMod = require(path + "jobs.js");
const runIssueJob = jobsMod.runIssueJob || (jobsMod.default && jobsMod.default.runIssueJob);
if (!db || !runIssueJob) {
  console.error("FATAL: could not resolve db/runIssueJob exports", Object.keys(dbMod), Object.keys(jobsMod));
  process.exit(3);
}

// [domain, wildcard] pairs: 2 SLD wildcards, 17 sub-zone wildcards (multi-level
// hosts the SLD wildcard cannot cover), and apex certs for the SLDs themselves.
const ORDERS = [
  ["innotel.us", true],
  ["rizzaura.net", true],
  ["cerulean.innotel.us", true],
  ["zeus.innotel.us", true],
  ["capstone.innotel.us", true],
  ["monarch.innotel.us", true],
  ["onyx.innotel.us", true],
  ["rizz.innotel.us", true],
  ["atheniq.innotel.us", true],
  ["atlas.innotel.us", true],
  ["distro.innotel.us", true],
  ["learn.innotel.us", true],
  ["magnate.innotel.us", true],
  ["oasis.innotel.us", true],
  ["olympus.innotel.us", true],
  ["plutus.innotel.us", true],
  ["rizzaura.innotel.us", true],
  ["signara.innotel.us", true],
  ["zapit.innotel.us", true],
  ["internal.innotel.us", true],
  ["innotel.us", false],
  ["rizzaura.net", false],
];

const FORCE = process.env.FORCE === "1";

(async () => {
  const results = [];
  for (const [domain, wildcard] of ORDERS) {
    const label = `${wildcard ? "*." : ""}${domain}`;
    try {
      let row = db
        .listCertificates()
        .find((c) => c.domain === domain && (c.wildcard === 1) === wildcard);
      if (!row) {
        row = db.createCertificate({
          name: label,
          domain,
          wildcard,
        });
        console.log(`created cert row #${row.id} for ${label}`);
      }
      if (row.status === "issued" && row.certificate && !FORCE) {
        console.log(`skip ${label} — already issued (expires ${row.expires_at})`);
        results.push({ label, ok: true, skipped: true });
        continue;
      }
      console.log(`issuing ${label} ...`);
      await runIssueJob(row.id);
      const after = db.getCertificate(row.id);
      const ok = after.status === "issued";
      console.log(`  -> ${ok ? `ISSUED (expires ${after.expires_at})` : `FAILED: ${after.error}`}`);
      results.push({ label, ok, error: after.error });
    } catch (err) {
      console.error(`  ERROR ${label}:`, (err && err.message) || err);
      results.push({ label, ok: false, error: String((err && err.message) || err) });
    }
  }
  const failed = results.filter((r) => !r.ok);
  console.log(`\nDONE: ${results.length - failed.length}/${results.length} issued`);
  if (failed.length) {
    console.log("failures:\n  " + failed.map((f) => `${f.label}: ${f.error}`).join("\n  "));
    process.exitCode = 2;
  }
})();
