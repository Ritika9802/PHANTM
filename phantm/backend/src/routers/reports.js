import { Router } from "express";
import { dbHelpers } from "../db/sqlite.js";
export const reportsRouter = Router();
reportsRouter.get("/", async (req, res) => {
  try { const scans = await dbHelpers.getCompletedScans(); res.json(scans); }
  catch (err) { res.status(500).json({ error: err.message }); }
});
reportsRouter.get("/:scanId/findings", async (req, res) => {
  try { const findings = await dbHelpers.getFindings(req.params.scanId); res.json(findings); }
  catch (err) { res.status(500).json({ error: err.message }); }
});
