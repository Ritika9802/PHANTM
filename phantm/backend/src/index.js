import express from "express";
import cors from "cors";
import helmet from "helmet";
import { WebSocketServer } from "ws";
import { createServer } from "http";
import dotenv from "dotenv";
import { initDB } from "./db/sqlite.js";
import { scanRouter } from "./routers/scan.js";
import { intelRouter } from "./routers/intel.js";
import { reportsRouter } from "./routers/reports.js";
import { hunterRouter } from "./routers/hunter.js";
import { wsManager } from "./services/wsManager.js";
import { logger } from "./utils/logger.js";

dotenv.config();

const app = express();
const server = createServer(app);

// WebSocket server
const wss = new WebSocketServer({ server });
wsManager.init(wss);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: "*" }));
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true }));

// Health
app.get("/api/health", (_, res) => res.json({ status: "ok", version: "2.0.0", model: "llama-3.3-70b-versatile" }));

// Routers
app.use("/api/scan", scanRouter);
app.use("/api/intel", intelRouter);
app.use("/api/reports", reportsRouter);
app.use("/api/hunter", hunterRouter);

// Global error handler
app.use((err, req, res, next) => {
  logger.error(err.stack);
  res.status(500).json({ error: err.message });
});

const PORT = process.env.PORT || 3001;

async function start() {
  await initDB();
  server.listen(PORT, () => {
    logger.info(`PHANTM Backend running on :${PORT}`);
    logger.info(`WebSocket ready`);
  });
}

start();
