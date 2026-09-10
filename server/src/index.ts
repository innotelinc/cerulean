import fs from "node:fs";
import path from "node:path";
import express from "express";
import { config } from "./config";
import routes from "./routes";
import { startScheduler } from "./jobs";

const app = express();
app.use(express.json({ limit: "2mb" }));

app.use("/api", routes);

const webDist = path.resolve(__dirname, "../../web/dist");
if (fs.existsSync(webDist)) {
  app.use(express.static(webDist));
  app.get("*", (_req, res) => {
    res.sendFile(path.join(webDist, "index.html"));
  });
}

app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error(err);
  res.status(500).json({ error: err.message || "Internal server error" });
});

app.listen(config.port, async () => {
  const id = (() => {
    try { return require("./services/serverIdentity").ensureIdentity(); } catch { return null; }
  })();
  // Fail fast if configured as CRS master without a domain
  try {
    const { validateMasterConfig, resolveCrsRole } = require("./services/crs") as typeof import("./services/crs");
    const err = validateMasterConfig();
    if (err) {
      console.error(`[CRS] ${err}`);
      console.error("  Refusing to start as master — fix CRS_DOMAIN or set CRS_ROLE=auto/slave");
      process.exit(1);
    }
    await resolveCrsRole(true).catch(() => undefined);
    const { crsStatus } = require("./services/crs") as typeof import("./services/crs");
    const crsSt = crsStatus() as { resolvedRole: string; domain: string; homeUrl: string; masterUrl: string };
    if (id) {
      console.log(`Cerulean master orchestrator ${id.serverId} → ${id.apex} (+ ${id.wildcard}) @ http://0.0.0.0:${config.port}`);
      console.log(`  DNS: Technitium ${config.technitium.url}  DHCP:${config.orchestrator.dhcpEnabled ? " on" : " off"}  Blocking:${config.orchestrator.blockingEnabled ? " on" : " off"}`);
      console.log(`  CRS: ${crsSt.resolvedRole} domain=${crsSt.domain} master=${crsSt.masterUrl} home=${crsSt.homeUrl}`);
    } else {
      console.log(`Cerulean portal listening on http://0.0.0.0:${config.port} (Technitium: ${config.technitium.url}) — CRS ${crsSt.resolvedRole}`);
    }
  } catch {
    // config/crs not yet available is non-fatal
    if (id) {
      console.log(`Cerulean master orchestrator ${id.serverId} → ${id.apex} (+ ${id.wildcard}) @ http://0.0.0.0:${config.port}`);
      console.log(`  DNS: Technitium ${config.technitium.url}  DHCP:${config.orchestrator.dhcpEnabled ? " on" : " off"}  Blocking:${config.orchestrator.blockingEnabled ? " on" : " off"}`);
    } else {
      console.log(`Cerulean portal listening on http://0.0.0.0:${config.port} (Technitium: ${config.technitium.url})`);
    }
  }
});

startScheduler();
