import { logger } from "../utils/logger.js";

class WSManager {
  constructor() {
    this.clients = new Map(); // scanId -> Set of ws clients
    this.wss = null;
  }

  init(wss) {
    this.wss = wss;
    wss.on("connection", (ws, req) => {
      const url = new URL(req.url, "http://localhost");
      const scanId = url.searchParams.get("scanId");

      if (scanId) {
        if (!this.clients.has(scanId)) this.clients.set(scanId, new Set());
        this.clients.get(scanId).add(ws);
        logger.info(`WS client connected for scan ${scanId}`);

        ws.on("close", () => {
          this.clients.get(scanId)?.delete(ws);
        });
      }

      ws.on("error", (err) => logger.error(`WS error: ${err.message}`));
    });
  }

  emit(scanId, event, data) {
    const clients = this.clients.get(scanId);
    if (!clients) return;
    const msg = JSON.stringify({ event, data, ts: new Date().toISOString() });
    clients.forEach((ws) => {
      if (ws.readyState === 1) ws.send(msg);
    });
  }

  log(scanId, agent, message, type = "info") {
    this.emit(scanId, "log", { agent, message, type });
  }

  finding(scanId, finding) {
    this.emit(scanId, "finding", finding);
  }

  stageUpdate(scanId, stage, status) {
    this.emit(scanId, "stage", { stage, status });
  }

  complete(scanId, summary) {
    this.emit(scanId, "complete", summary);
  }
}

export const wsManager = new WSManager();
