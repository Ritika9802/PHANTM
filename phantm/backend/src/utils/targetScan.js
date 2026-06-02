import { execFile } from "child_process";
import { promisify } from "util";
import net from "net";

const execFileAsync = promisify(execFile);

export function normalizeTarget(target) {
  return String(target || "")
    .trim()
    .replace(/^https?:\/\//i, "")
    .replace(/^\[(.*)\]$/, "$1")
    .replace(/\/.*$/, "")
    .replace(/:\d+$/, "");
}

export function classifyTarget(target) {
  const host = normalizeTarget(target);
  const version = net.isIP(host);

  if (version === 4) {
    const [a, b] = host.split(".").map(Number);
    const isPrivate =
      a === 10 ||
      a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) ||
      a >= 224;

    return { kind: "ip", host, classification: isPrivate ? "private" : "public" };
  }

  if (version === 6) {
    const lower = host.toLowerCase();
    const isPrivate = lower === "::1" || lower.startsWith("fe80:") || lower.startsWith("fc") || lower.startsWith("fd");
    return { kind: "ip", host, classification: isPrivate ? "private" : "public" };
  }

  return { kind: "host", host, classification: "host" };
}

export function parseTargets(input) {
  if (Array.isArray(input)) {
    return input.map(normalizeTarget).filter(Boolean);
  }

  return String(input || "")
    .split(/[\n,\s]+/)
    .map(normalizeTarget)
    .filter(Boolean);
}

export function parseNmapOutput(output) {
  const openPorts = [];

  for (const line of String(output || "").split("\n")) {
    const match = line.match(/^(\d+)\/(tcp|udp)\s+open\s+([^\s]+)?\s*(.*)$/i);
    if (!match) continue;

    const [, port, protocol, service = "unknown", version = ""] = match;
    openPorts.push({
      port,
      protocol: protocol.toLowerCase(),
      state: "open",
      service: service.toLowerCase(),
      version: version.trim(),
    });
  }

  openPorts.sort((a, b) => Number(a.port) - Number(b.port));
  return openPorts;
}

export async function pingHost(target) {
  const host = normalizeTarget(target);
  try {
    await execFileAsync("ping", ["-c", "1", "-W", "1", host]);
    return true;
  } catch {
    return false;
  }
}

export async function runLocalNmap(target, mode = "standard") {
  const host = normalizeTarget(target);
  const modeArgs = {
    quick: ["--top-ports", "100"],
    standard: ["--top-ports", "1000"],
    deep: ["-p-"],
  };

  const args = ["-sV", "-Pn", "--open", "-T4", ...(modeArgs[mode] || modeArgs.standard), host];

  try {
    const { stdout } = await execFileAsync("nmap", args, { maxBuffer: 10 * 1024 * 1024 });
    return parseNmapOutput(stdout);
  } catch (err) {
    if (err.code === "ENOENT") {
      throw new Error("nmap is not installed on this system");
    }
    throw err;
  }
}

export async function runPublicNmap(target, logFn) {
  const fetch = (await import("node-fetch")).default;
  const host = normalizeTarget(target);
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 15000);

  try {
    logFn?.(`${target} is public — using public nmap service`, "info");

    const res = await fetch(`https://api.hackertarget.com/nmap/?q=${host}`, { signal: controller.signal });
    if (!res.ok) {
      throw new Error(`public scan failed (${res.status})`);
    }

    const text = await res.text();
    if (text.includes("error") || text.includes("API count")) {
      throw new Error(text.split("\n")[0] || "public scan unavailable");
    }

    return parseNmapOutput(text);
  } finally {
    clearTimeout(timeoutId);
  }
}