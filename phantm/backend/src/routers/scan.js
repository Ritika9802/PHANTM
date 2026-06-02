import { Router } from "express";
import { v4 as uuidv4 } from "uuid";
import { dbHelpers } from "../db/sqlite.js";
import { ScanOrchestrator } from "../services/scanOrchestrator.js";
import { wsManager } from "../services/wsManager.js";
import { logger } from "../utils/logger.js";
import { classifyTarget, pingHost, runLocalNmap, runPublicNmap } from "../utils/targetScan.js";

function createOpenPortFinding(target, port) {
  return {
    type: "open-port",
    title: `Open Port ${port.port}/${port.protocol}`,
    severity: "INFO",
    cvss: 0,
    port: port.port,
    service: port.service,
    version: port.version,
    evidence: `${target} exposes ${port.service}${port.version ? ` (${port.version})` : ""}`,
    falsePositiveRisk: "LOW",
  };
}

async function runHostScan(scanId, target, scanType) {
  try {
    const { kind, classification, host } = classifyTarget(target);
    const isPublicIp = kind === "ip" && classification === "public";
    const isPrivateIp = kind === "ip" && classification === "private";

    await dbHelpers.updateScan(scanId, { status: "running" });

    if (isPrivateIp) {
      wsManager.log(scanId, "SYS", `${target} classified as PRIVATE`, "sys");
      wsManager.log(scanId, "SYS", `Pinging ${target}…`, "info");

      const reachable = await pingHost(host);
      if (!reachable) {
        const summary = {
          scanMode: "host",
          target,
          classification: "private",
          reachable: false,
          totalOpenPorts: 0,
          openPorts: [],
          total: 1,
          unreachable: 1,
          mode: scanType,
        };

        await dbHelpers.updateScan(scanId, { status: "complete", findings_count: 0, risk_score: 0, summary: JSON.stringify(summary) });
        wsManager.complete(scanId, summary);
        wsManager.log(scanId, "SYS", `${target} — host unreachable`, "warn");
        return;
      }

      wsManager.log(scanId, "SYS", `${target} is reachable — running local nmap (${scanType})`, "info");
      const openPorts = await runLocalNmap(host, scanType);
      for (const port of openPorts) {
        const finding = createOpenPortFinding(target, port);
        await dbHelpers.insertFinding({ ...finding, id: uuidv4(), scan_id: scanId, created_at: new Date().toISOString() });
        wsManager.finding(scanId, finding);
      }

      const summary = {
        scanMode: "host",
        target,
        classification: "private",
        reachable: true,
        totalOpenPorts: openPorts.length,
        openPorts,
        total: 1,
        reachableTargets: 1,
        unreachable: 0,
        mode: scanType,
      };

      await dbHelpers.updateScan(scanId, { status: "complete", findings_count: openPorts.length, risk_score: 0, summary: JSON.stringify(summary) });
      wsManager.complete(scanId, summary);
      wsManager.log(scanId, "SYS", `${target} — ${openPorts.length} open ports found`, openPorts.length > 0 ? "success" : "warn");
      return;
    }

    if (isPublicIp) {
      wsManager.log(scanId, "SYS", `${target} classified as PUBLIC`, "sys");
      const openPorts = await runPublicNmap(host, (message, type) => wsManager.log(scanId, "SYS", message, type));

      for (const port of openPorts) {
        const finding = createOpenPortFinding(target, port);
        await dbHelpers.insertFinding({ ...finding, id: uuidv4(), scan_id: scanId, created_at: new Date().toISOString() });
        wsManager.finding(scanId, finding);
      }

      const summary = {
        scanMode: "host",
        target,
        classification: "public",
        reachable: true,
        totalOpenPorts: openPorts.length,
        openPorts,
        total: 1,
        reachableTargets: 1,
        unreachable: 0,
        mode: scanType,
      };

      await dbHelpers.updateScan(scanId, { status: "complete", findings_count: openPorts.length, risk_score: 0, summary: JSON.stringify(summary) });
      wsManager.complete(scanId, summary);
      wsManager.log(scanId, "SYS", `${target} — ${openPorts.length} open ports found`, openPorts.length > 0 ? "success" : "warn");
      return;
    }

  } catch (err) {
    logger.error(`Host scan ${scanId} failed: ${err.message}`);
    const summary = {
      scanMode: "host",
      target,
      classification: "error",
      reachable: false,
      totalOpenPorts: 0,
      openPorts: [],
      total: 1,
      unreachable: 1,
      mode: scanType,
      error: err.message,
    };

    await dbHelpers.updateScan(scanId, { status: "error", findings_count: 0, risk_score: 0, summary: JSON.stringify(summary) });
    wsManager.log(scanId, "SYS", `Host scan failed: ${err.message}`, "error");
    wsManager.complete(scanId, summary);
  }
}

export const scanRouter = Router();

scanRouter.post("/", async (req, res) => {
  try {
    const { target, scanType = "standard", apiKey } = req.body;
    if (!target) return res.status(400).json({ error: "target required" });

    const targetClass = classifyTarget(target);
    if (targetClass.kind !== "ip" && !apiKey) return res.status(400).json({ error: "apiKey required" });

    const id = uuidv4();
    await dbHelpers.insertScan({ id, target, status: "queued", scan_type: scanType, created_at: new Date().toISOString(), updated_at: new Date().toISOString(), findings_count: 0, risk_score: 0, summary: null });

    if (targetClass.kind === "ip") {
      runHostScan(id, target, scanType).catch(err => logger.error(`Scan ${id} failed: ${err.message}`));
    } else {
      const orchestrator = new ScanOrchestrator(id, target, scanType, apiKey);
      orchestrator.run().catch(err => logger.error(`Scan ${id} failed: ${err.message}`));
    }

    res.json({ scanId: id, status: "queued", target });
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: err.message });
  }
});

scanRouter.get("/", async (req, res) => {
  try {
    const scans = await dbHelpers.listScans();
    res.json(scans);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

scanRouter.get("/:id", async (req, res) => {
  try {
    const scan = await dbHelpers.getScan(req.params.id);
    if (!scan) return res.status(404).json({ error: "Scan not found" });
    const findings = await dbHelpers.getFindings(req.params.id);
    const chains = await dbHelpers.getChains(req.params.id);
    const summary = typeof scan.summary === "string" ? JSON.parse(scan.summary) : scan.summary;
    res.json({ ...scan, summary, findings, attackChains: chains });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

scanRouter.get("/:id/logs", async (req, res) => {
  try {
    const logs = await dbHelpers.getLogs(req.params.id);
    res.json(logs);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

scanRouter.delete("/:id", async (req, res) => {
  try {
    await dbHelpers.deleteScan(req.params.id);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
