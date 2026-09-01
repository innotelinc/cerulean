import fs from "node:fs";
import path from "node:path";
import express from "express";
import { config } from "./config";
import routes from "./routes";
import { startScheduler } from "./jobs";

const app = express();
app.use(express.json({ limit: "2mb" }));

app.use("/api", routes);

// Serve the built dashboard (web/dist) if present.
const webDist = path.resolve(__dirname, "../../web/dist");
if (fs.existsSync(webDist)) {
  app.use(express.static(webDist));
  app.get("*", (_req, res) => {
    res.sendFile(path.join(webDist, "index.html"));
  });
}

// Error handler
app.use(
  (
    err: Error,
    _req: express.Request,
    res: express.Response,
    _next: express.NextFunction,
  ) => {
    console.error(err);
    res.status(500).json({ error: err.message || "Internal server error" });
  },
);

app.listen(config.port, () => {
  console.log(`Cerulean portal listening on http://0.0.0.0:${config.port}`);
});

startScheduler();
