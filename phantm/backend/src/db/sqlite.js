import { Low } from "lowdb";
import { JSONFile } from "lowdb/node";
import path from "path";
import { fileURLToPath } from "url";
import { mkdirSync } from "fs";
import { logger } from "../utils/logger.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DB_PATH = path.join(__dirname, "../../data/phantm.json");

let db;

const defaultData = { scans: [], findings: [], attack_chains: [], scan_logs: [], cve_cache: [] };

export async function initDB() {
  mkdirSync(path.dirname(DB_PATH), { recursive: true });
  const adapter = new JSONFile(DB_PATH);
  db = new Low(adapter, defaultData);
  await db.read();
  db.data ||= defaultData;
  await db.write();
  logger.info("Database (lowdb/JSON) initialized at " + DB_PATH);
}

export function getDB() {
  if (!db) throw new Error("DB not initialized");
  return db;
}

// Sync-style wrapper helpers used by routers
export const dbHelpers = {
  async insertScan(scan) {
    await db.read();
    db.data.scans.push(scan);
    await db.write();
  },
  async updateScan(id, updates) {
    await db.read();
    const idx = db.data.scans.findIndex(s => s.id === id);
    if (idx !== -1) { db.data.scans[idx] = { ...db.data.scans[idx], ...updates, updated_at: new Date().toISOString() }; }
    await db.write();
  },
  async getScan(id) {
    await db.read();
    return db.data.scans.find(s => s.id === id) || null;
  },
  async listScans() {
    await db.read();
    return [...db.data.scans].sort((a, b) => new Date(b.created_at) - new Date(a.created_at)).slice(0, 50);
  },
  async insertFinding(finding) {
    await db.read();
    db.data.findings.push(finding);
    await db.write();
  },
  async getFindings(scanId) {
    await db.read();
    return db.data.findings.filter(f => f.scan_id === scanId).sort((a, b) => (b.cvss || 0) - (a.cvss || 0));
  },
  async insertChain(chain) {
    await db.read();
    db.data.attack_chains.push(chain);
    await db.write();
  },
  async getChains(scanId) {
    await db.read();
    return db.data.attack_chains.filter(c => c.scan_id === scanId);
  },
  async insertLog(log) {
    await db.read();
    db.data.scan_logs.push(log);
    // Keep only last 5000 logs total
    if (db.data.scan_logs.length > 5000) db.data.scan_logs = db.data.scan_logs.slice(-5000);
    await db.write();
  },
  async getLogs(scanId) {
    await db.read();
    return db.data.scan_logs.filter(l => l.scan_id === scanId);
  },
  async getCVECache(id) {
    await db.read();
    return db.data.cve_cache.find(c => c.cve_id === id) || null;
  },
  async setCVECache(id, data) {
    await db.read();
    const idx = db.data.cve_cache.findIndex(c => c.cve_id === id);
    if (idx !== -1) db.data.cve_cache[idx].data = data;
    else db.data.cve_cache.push({ cve_id: id, data, cached_at: new Date().toISOString() });
    await db.write();
  },
  async deleteScan(id) {
    await db.read();
    db.data.scans = db.data.scans.filter(s => s.id !== id);
    db.data.findings = db.data.findings.filter(f => f.scan_id !== id);
    db.data.attack_chains = db.data.attack_chains.filter(c => c.scan_id !== id);
    db.data.scan_logs = db.data.scan_logs.filter(l => l.scan_id !== id);
    await db.write();
  },
  async getCompletedScans() {
    await db.read();
    return db.data.scans.filter(s => s.status === "complete").sort((a,b) => new Date(b.created_at)-new Date(a.created_at));
  },
};
