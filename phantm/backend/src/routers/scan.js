import { Router } from "express";
import { v4 as uuidv4 } from "uuid";
import { dbHelpers } from "../db/sqlite.js";
import { ScanOrchestrator } from "../services/scanOrchestrator.js";
import { logger } from "../utils/logger.js";

export const scanRouter = Router();

scanRouter.post("/", async (req, res) => {
  try {
    const { target, scanType = "standard", apiKey } = req.body;
    if (!target) return res.status(400).json({ error: "target required" });
    if (!apiKey) return res.status(400).json({ error: "apiKey required" });

    const id = uuidv4();
    await dbHelpers.insertScan({ id, target, status: "queued", scan_type: scanType, created_at: new Date().toISOString(), updated_at: new Date().toISOString(), findings_count: 0, risk_score: 0, summary: null });

    const orchestrator = new ScanOrchestrator(id, target, scanType, apiKey);
    orchestrator.run().catch(err => logger.error(`Scan ${id} failed: ${err.message}`));

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
    res.json({ ...scan, findings, attackChains: chains });
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
