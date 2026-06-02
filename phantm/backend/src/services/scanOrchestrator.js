import { v4 as uuidv4 } from "uuid";
import { dbHelpers } from "../db/sqlite.js";
import { wsManager } from "./wsManager.js";
import { ReconAgent } from "../agents/reconAgent.js";
import { FingerprintAgent } from "../agents/fingerprintAgent.js";
import { CVEAgent } from "../agents/cVEAgent.js";
import { ValidatorAgent } from "../agents/validatorAgent.js";
import { SeverityAgent } from "../agents/severityAgent.js";
import { ChainAgent } from "../agents/chainAgent.js";
import { MitreAgent } from "../agents/mitreAgent.js";
import { LLMAgent } from "../agents/llmAgent.js";
import { logger } from "../utils/logger.js";

export class ScanOrchestrator {
  constructor(scanId, target, scanType, apiKey) {
    this.scanId = scanId; this.target = target; this.scanType = scanType; this.apiKey = apiKey;
  }

  async log(agent, message, type = "info") {
    const entry = { id: uuidv4(), scan_id: this.scanId, agent, message, log_type: type, created_at: new Date().toISOString() };
    await dbHelpers.insertLog(entry);
    wsManager.log(this.scanId, agent, message, type);
  }

  stage(name, status) { wsManager.stageUpdate(this.scanId, name, status); }

  async updateStatus(status) { await dbHelpers.updateScan(this.scanId, { status }); }

  async saveFinding(finding) {
    const f = { ...finding, id: uuidv4(), scan_id: this.scanId, created_at: new Date().toISOString() };
    await dbHelpers.insertFinding(f);
    wsManager.finding(this.scanId, f);
  }

  async saveChain(chain) {
    await dbHelpers.insertChain({ ...chain, id: uuidv4(), scan_id: this.scanId, created_at: new Date().toISOString() });
  }

  async run() {
    try {
      await this.updateStatus("running");
      await this.log("SYS", `PHANTM pipeline started for: ${this.target}`, "sys");
      await this.log("SYS", "Architecture: Deterministic → Validate → Calibrate → Chain → LLM", "sys");

      const domain = this.target.replace(/^https?:\/\//, "").replace(/\/$/, "").split("/")[0];

      this.stage("recon", "running");
      const recon = new ReconAgent(this.scanId, domain, this.log.bind(this));
      const reconData = await recon.run();
      this.stage("recon", "done");

      this.stage("fingerprint", "running");
      const fp = new FingerprintAgent(this.scanId, reconData, this.log.bind(this));
      const technologies = await fp.run();
      this.stage("fingerprint", "done");

      this.stage("cve", "running");
      const cveAgent = new CVEAgent(this.scanId, technologies, this.log.bind(this));
      const cveFindings = await cveAgent.run();
      this.stage("cve", "done");

      const rawFindings = [...this.buildReconFindings(reconData), ...cveFindings];

      this.stage("validate", "running");
      const validator = new ValidatorAgent(this.scanId, rawFindings, reconData, this.log.bind(this));
      const validated = await validator.run();
      this.stage("validate", "done");

      this.stage("severity", "running");
      const severity = new SeverityAgent(this.scanId, validated, this.log.bind(this));
      const calibrated = severity.run();
      this.stage("severity", "done");

      for (const f of calibrated) await this.saveFinding(f);

      this.stage("chains", "running");
      const chainAgent = new ChainAgent(this.scanId, calibrated, this.log.bind(this));
      const chains = chainAgent.run();
      for (const c of chains) await this.saveChain(c);
      this.stage("chains", "done");

      this.stage("mitre", "running");
      const mitreAgent = new MitreAgent(this.scanId, calibrated, this.log.bind(this));
      const mitreMatrix = mitreAgent.run();
      this.stage("mitre", "done");

      this.stage("llm", "running");
      const llmAgent = new LLMAgent(this.scanId, { domain, reconData, technologies, findings: calibrated, attackChains: chains, mitreMatrix }, this.apiKey, this.log.bind(this));
      const llmResult = await llmAgent.run();
      this.stage("llm", "done");

      const summary = {
        totalFindings: calibrated.length,
        critical: calibrated.filter(f => f.severity === "CRITICAL").length,
        high: calibrated.filter(f => f.severity === "HIGH").length,
        medium: calibrated.filter(f => f.severity === "MEDIUM").length,
        low: calibrated.filter(f => f.severity === "LOW").length,
        info: calibrated.filter(f => f.severity === "INFO").length,
        attackChains: chains.length,
        cisaKevCount: cveFindings.filter(f => f.inCisaKev).length,
        riskScore: llmResult?.riskScore || this.calcRiskScore(calibrated, chains),
        riskRating: llmResult?.riskRating || "MEDIUM",
        executiveSummary: llmResult?.executiveSummary || "",
        attackNarrative: llmResult?.attackNarrative || "",
        prioritizedActions: llmResult?.prioritizedActions || [],
      };

      await dbHelpers.updateScan(this.scanId, { status: "complete", findings_count: calibrated.length, risk_score: summary.riskScore, summary: JSON.stringify(summary) });
      wsManager.complete(this.scanId, summary);
      await this.log("SYS", `━━━ SCAN COMPLETE: ${calibrated.length} findings, ${chains.length} chains, Risk: ${summary.riskScore}/100 ━━━`, "sys");
    } catch (err) {
      logger.error(`Orchestrator error: ${err.message}`);
      await this.log("SYS", `Pipeline error: ${err.message}`, "error");
      await this.updateStatus("error");
    }
  }

  buildReconFindings(reconData) {
    const findings = [];
    const HMAP = {
      "strict-transport-security": { type: "missing-hsts", title: "Missing HSTS Header", severity: "LOW", cvss: 3.5 },
      "content-security-policy": { type: "missing-csp", title: "Missing Content Security Policy", severity: "LOW", cvss: 4.3 },
      "x-frame-options": { type: "missing-xframe", title: "Missing X-Frame-Options", severity: "LOW", cvss: 3.5 },
      "x-content-type-options": { type: "missing-xcontent", title: "Missing X-Content-Type-Options", severity: "INFO", cvss: 2.1 },
      "referrer-policy": { type: "missing-referrer", title: "Missing Referrer Policy", severity: "INFO", cvss: 1.8 },
    };
    (reconData.headers?.missing || []).forEach(h => { const d = HMAP[h]; if (d) findings.push({ ...d, evidence: `Header '${h}' absent`, falsePositiveRisk: "LOW" }); });
    if (reconData.dnsRecords && !reconData.dnsRecords.hasSPF) findings.push({ type: "missing-spf", title: "Missing SPF Record", severity: "MEDIUM", cvss: 5.3, evidence: "No v=spf1 TXT record", falsePositiveRisk: "LOW" });
    if (reconData.dnsRecords && !reconData.dnsRecords.hasDMARC) findings.push({ type: "missing-dmarc", title: "Missing DMARC Policy", severity: "MEDIUM", cvss: 5.3, evidence: "No _dmarc TXT record", falsePositiveRisk: "LOW" });
    if (reconData.headers?.server) findings.push({ type: "server-header-disclosure", title: "Server Version Disclosure", severity: "INFO", cvss: 2.7, evidence: `Server: ${reconData.headers.server}`, falsePositiveRisk: "LOW" });
    (reconData.ports || []).forEach(p => {
      if (p.service === "ftp" || p.port === "21") findings.push({ type: "ftp-exposed", title: `FTP Exposed (${p.port}/tcp)`, severity: "MEDIUM", cvss: 5.3, port: p.port, service: "ftp", evidence: `FTP on port ${p.port}`, falsePositiveRisk: "LOW" });
      if (p.port === "3389" || p.service === "ms-wbt-server" || p.service === "rdp") findings.push({ type: "rdp-exposed", title: "RDP Exposed to Internet", severity: "HIGH", cvss: 7.5, port: p.port, service: "rdp", evidence: `RDP on port ${p.port}`, falsePositiveRisk: "LOW" });
      if (p.service === "telnet") findings.push({ type: "telnet-exposed", title: "Telnet Cleartext Protocol", severity: "HIGH", cvss: 8.0, port: p.port, service: "telnet", evidence: `Telnet on port ${p.port}`, falsePositiveRisk: "LOW" });
      if (p.port === "27017") findings.push({ type: "mongodb-exposed", title: "MongoDB Port Exposed", severity: "CRITICAL", cvss: 9.8, port: p.port, service: "mongodb", evidence: `MongoDB on ${p.port}`, falsePositiveRisk: "MEDIUM" });
      if (p.port === "6379") findings.push({ type: "redis-exposed", title: "Redis Port Exposed", severity: "CRITICAL", cvss: 9.8, port: p.port, service: "redis", evidence: `Redis on ${p.port}`, falsePositiveRisk: "MEDIUM" });
      if (p.port === "9200") findings.push({ type: "elasticsearch-exposed", title: "Elasticsearch API Exposed", severity: "CRITICAL", cvss: 9.1, port: p.port, service: "elasticsearch", evidence: `ES on ${p.port}`, falsePositiveRisk: "MEDIUM" });
    });
    return findings;
  }

  calcRiskScore(findings, chains) {
    const c = findings.filter(f => f.severity === "CRITICAL").length;
    const h = findings.filter(f => f.severity === "HIGH").length;
    const m = findings.filter(f => f.severity === "MEDIUM").length;
    return Math.min(100, (c * 20) + (h * 8) + (m * 3) + (chains.length * 10));
  }
}
