import { Router } from "express";
import { v4 as uuidv4 } from "uuid";
import { dbHelpers } from "../db/sqlite.js";
import { wsManager } from "../services/wsManager.js";
import { classifyTarget, parseTargets as parseTargetsFromInput, pingHost, runLocalNmap, runPublicNmap } from "../utils/targetScan.js";

export const hunterRouter = Router();

const SCAN_DEPTHS = [
  { id: "quick", label: "QUICK", description: "Top 100 ports" },
  { id: "standard", label: "STANDARD", description: "Top 1000 ports" },
  { id: "deep", label: "DEEP", description: "All ports" },
];

function parseTargets(input) {
  return parseTargetsFromInput(input);
}

async function scanTarget(huntId, target, mode) {
  const { classification, host, kind } = classifyTarget(target);

  if (kind === "ip" && classification === "private") {
    wsManager.log(huntId, "HUNTER", `${target} classified as PRIVATE`, "sys");
    wsManager.log(huntId, "HUNTER", `Pinging ${target}…`, "info");
    const reachable = await pingHost(host);

    if (!reachable) {
      wsManager.log(huntId, "HUNTER", `${target} — host unreachable`, "warn");
      return { target, classification: "private", scanMethod: "local-nmap", reachable: false, openPorts: [], error: "host unreachable" };
    }

    wsManager.log(huntId, "HUNTER", `${target} is reachable — running local nmap (${mode})`, "info");
    const openPorts = await runLocalNmap(host, mode);
    wsManager.log(huntId, "HUNTER", `${target} — ${openPorts.length} open ports found`, openPorts.length > 0 ? "success" : "warn");
    return { target, classification: "private", scanMethod: "local-nmap", reachable: true, openPorts };
  }

  if (kind === "ip") {
    wsManager.log(huntId, "HUNTER", `${target} classified as PUBLIC`, "sys");
    const openPorts = await runPublicNmap(host, (message, type) => wsManager.log(huntId, "HUNTER", message, type));
    wsManager.log(huntId, "HUNTER", `${target} — ${openPorts.length} open ports found`, openPorts.length > 0 ? "success" : "warn");
    return { target, classification: "public", scanMethod: "public-nmap", reachable: true, openPorts };
  }

  wsManager.log(huntId, "HUNTER", `${target} classified as HOSTNAME`, "sys");
  const openPorts = await runPublicNmap(host, (message, type) => wsManager.log(huntId, "HUNTER", message, type));
  wsManager.log(huntId, "HUNTER", `${target} — ${openPorts.length} open ports found`, openPorts.length > 0 ? "success" : "warn");
  return { target, classification: "host", scanMethod: "public-nmap", reachable: true, openPorts };
}

hunterRouter.get("/vulntypes", (req, res) => {
  res.json(SCAN_DEPTHS);
});

hunterRouter.post("/", async (req, res) => {
  try {
    const { targets, mode = "standard" } = req.body;
    const parsedTargets = parseTargets(targets);

    if (!parsedTargets.length) return res.status(400).json({ error: "targets required" });

    const huntId = uuidv4();
    await dbHelpers.insertScan({
      id: huntId,
      target: parsedTargets.join(",").slice(0, 500),
      status: "running",
      scan_type: `hunt:${mode}`,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      findings_count: 0,
      risk_score: 0,
      summary: null,
    });

    runHostScan(huntId, parsedTargets, mode).catch(console.error);

    res.json({ huntId, status: "running", targets: parsedTargets.length, mode });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

hunterRouter.get("/:id", async (req, res) => {
  try {
    const scan = await dbHelpers.getScan(req.params.id);
    if (!scan) return res.status(404).json({ error: "Hunt not found" });
    const summary = scan.summary ? JSON.parse(scan.summary) : null;
    res.json({ ...scan, results: summary });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

async function runHostScan(huntId, targets, mode) {
  const results = [];

  wsManager.log(huntId, "HUNTER", `HOST SCAN: ping first, then nmap (${mode})`, "sys");

  for (const target of targets.slice(0, 100)) {
    wsManager.log(huntId, "HUNTER", `─── Scanning ${target} ───`, "info");
    try {
      const result = await scanTarget(huntId, target, mode);
      results.push(result);
    } catch (err) {
      wsManager.log(huntId, "HUNTER", `${target} — scan failed: ${err.message}`, "error");
      results.push({ target, classification: "unknown", scanMethod: "error", reachable: false, openPorts: [], error: err.message });
    }
  }

  const reachable = results.filter(r => r.reachable).length;
  const unreachable = results.filter(r => !r.reachable).length;
  const totalOpenPorts = results.reduce((count, r) => count + (r.openPorts?.length || 0), 0);

  const summary = {
    mode,
    total: results.length,
    reachable,
    unreachable,
    totalOpenPorts,
    targets: results,
  };

  await dbHelpers.updateScan(huntId, {
    status: "complete",
    findings_count: totalOpenPorts,
    summary: JSON.stringify(summary),
  });

  wsManager.complete(huntId, summary);
  wsManager.log(huntId, "HUNTER", `━━━ HOST SCAN COMPLETE: ${reachable}/${results.length} reachable, ${totalOpenPorts} open ports ━━━`, "sys");
}