import { Router } from "express";
import { dbHelpers } from "../db/sqlite.js";
import { groqChat } from "../agents/llmAgent.js";

export const intelRouter = Router();

const SYSTEM = `You are PHANTM — senior penetration tester. Rules: Never invent CVEs. Never inflate severity. Be specific and technical. Reference only provided data.`;

intelRouter.post("/chat", async (req, res) => {
  try {
    const { messages, scanContext, apiKey } = req.body;
    if (!apiKey) return res.status(400).json({ error: "apiKey required" });
    const system = scanContext ? `${SYSTEM}\n\nSCAN CONTEXT:\n${JSON.stringify(scanContext, null, 2)}` : SYSTEM;
    const reply = await groqChat(messages, system, apiKey);
    res.json({ reply });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

intelRouter.get("/cve/:id", async (req, res) => {
  try {
    const cached = await dbHelpers.getCVECache(req.params.id);
    if (cached) return res.json(JSON.parse(cached.data));
    const fetch = (await import("node-fetch")).default;
    const nvdRes = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${req.params.id}`);
    if (!nvdRes.ok) return res.status(404).json({ error: "CVE not found" });
    const data = await nvdRes.json();
    const vuln = data.vulnerabilities?.[0]?.cve;
    if (!vuln) return res.status(404).json({ error: "CVE not found" });
    const cvssV3 = vuln.metrics?.cvssMetricV31?.[0]?.cvssData || vuln.metrics?.cvssMetricV30?.[0]?.cvssData;
    const result = { id: req.params.id, description: vuln.descriptions?.find(d => d.lang === "en")?.value || "", cvss: cvssV3?.baseScore, severity: cvssV3?.baseSeverity, vector: cvssV3?.vectorString, cwe: vuln.weaknesses?.[0]?.description?.[0]?.value, published: vuln.published, references: vuln.references?.slice(0, 5).map(r => r.url) || [] };
    await dbHelpers.setCVECache(req.params.id, JSON.stringify(result));
    res.json(result);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

intelRouter.post("/report", async (req, res) => {
  try {
    const { scanId, format, apiKey } = req.body;
    if (!apiKey || !scanId) return res.status(400).json({ error: "scanId and apiKey required" });
    const scan = await dbHelpers.getScan(scanId);
    const findings = await dbHelpers.getFindings(scanId);
    const chains = await dbHelpers.getChains(scanId);
    const summary = scan.summary ? JSON.parse(scan.summary) : {};
    const fmtMap = {
      executive: "Write a concise executive brief (600 words) for C-level. Business risk, financial exposure, 3 strategic actions. No jargon.",
      technical: "Write a detailed technical report. Include CVEs, CVSS, PoC steps, exact remediation commands.",
      compliance: "Map findings to ISO 27001:2022 Annex A, NIST CSF 2.0, PCI-DSS v4.0. Include compliance gap analysis.",
    };
    const prompt = `Generate a pentest ${format} report.\n${fmtMap[format] || ""}\n\nTarget: ${scan.target}\nRisk: ${summary.riskScore}/100 (${summary.riskRating})\nSummary: ${summary.executiveSummary || ""}\nFindings: ${JSON.stringify(findings.slice(0, 8))}\nChains: ${JSON.stringify(chains)}\nActions: ${JSON.stringify(summary.prioritizedActions || [])}`;
    const report = await groqChat([{ role: "user", content: prompt }], SYSTEM, apiKey);
    res.json({ report });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
