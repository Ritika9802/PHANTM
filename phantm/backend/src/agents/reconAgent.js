import fetch from "node-fetch";

export class ReconAgent {
  constructor(scanId, domain, log) {
    this.scanId = scanId;
    this.domain = domain;
    this.log = log;
  }

  async run() {
    const results = { domain: this.domain, subdomains: [], dnsRecords: {}, headers: {}, ports: [] };

    // Subdomain enum via crt.sh
    this.log("RECON", `Querying crt.sh for ${this.domain}…`, "info");
    try {
      const res = await fetch(`https://crt.sh/?q=%.${this.domain}&output=json`, { timeout: 10000 });
      if (res.ok) {
        const data = await res.json();
        results.subdomains = [...new Set(
          data.map(e => e.name_value).flatMap(n => n.split("\n"))
            .filter(s => s.includes(this.domain) && !s.includes("*"))
        )].slice(0, 30);
        this.log("RECON", `Found ${results.subdomains.length} subdomains via crt.sh`, "success");
        results.subdomains.slice(0, 6).forEach(s => this.log("RECON", `  → ${s}`, "data"));
      }
    } catch { this.log("RECON", "crt.sh timeout — continuing", "warn"); }

    // DNS records
    this.log("RECON", "DNS enumeration…", "info");
    try {
      const res = await fetch(`https://api.hackertarget.com/dnslookup/?q=${this.domain}`, { timeout: 8000 });
      if (res.ok) {
        const text = await res.text();
        if (!text.includes("error")) {
          results.dnsRecords.raw = text;
          results.dnsRecords.hasSPF = text.toLowerCase().includes("v=spf");
          results.dnsRecords.hasDMARC = text.toLowerCase().includes("v=dmarc");
          results.dnsRecords.hasDKIM = text.toLowerCase().includes("dkim");
          this.log("RECON", `DNS — SPF:${results.dnsRecords.hasSPF} DMARC:${results.dnsRecords.hasDMARC} DKIM:${results.dnsRecords.hasDKIM}`,
            results.dnsRecords.hasSPF ? "success" : "warn");
        }
      }
    } catch { this.log("RECON", "DNS lookup failed", "warn"); }

    // HTTP Headers
    this.log("RECON", "Analyzing security headers…", "info");
    try {
      const res = await fetch(`https://api.hackertarget.com/httpheaders/?q=https://${this.domain}`, { timeout: 8000 });
      if (res.ok) {
        const text = await res.text();
        if (!text.includes("error")) {
          const SEC = ["strict-transport-security", "x-content-type-options", "x-frame-options",
            "content-security-policy", "x-xss-protection", "referrer-policy", "permissions-policy"];
          results.headers.raw = text;
          results.headers.present = SEC.filter(h => text.toLowerCase().includes(h));
          results.headers.missing = SEC.filter(h => !text.toLowerCase().includes(h));
          const srvMatch = text.match(/server:\s*([^\r\n]+)/i);
          if (srvMatch) results.headers.server = srvMatch[1].trim();
          const pbMatch = text.match(/x-powered-by:\s*([^\r\n]+)/i);
          if (pbMatch) results.headers.poweredBy = pbMatch[1].trim();
          this.log("RECON", `Headers: ${results.headers.present.length} present / ${results.headers.missing.length} missing`, "info");
          if (results.headers.server) this.log("RECON", `Server banner: ${results.headers.server}`, "data");
        }
      }
    } catch { this.log("RECON", "Header analysis failed", "warn"); }

    // Port scan via HackerTarget
    this.log("RECON", "Port scanning…", "info");
    try {
      const res = await fetch(`https://api.hackertarget.com/nmap/?q=${this.domain}`, { timeout: 15000 });
      if (res.ok) {
        const text = await res.text();
        if (!text.includes("error") && !text.includes("API count")) {
          results.ports = this.parseNmap(text);
          this.log("RECON", `Found ${results.ports.length} open ports`, results.ports.length > 8 ? "warn" : "success");
          results.ports.forEach(p => this.log("RECON", `  ${p.port}/tcp  ${p.service}  ${p.version || ""}`, "data"));
        } else {
          this.log("RECON", "Port scan rate-limited — passive mode", "warn");
        }
      }
    } catch { this.log("RECON", "Port scan error", "warn"); }

    return results;
  }

  parseNmap(text) {
    const ports = [];
    for (const line of text.split("\n")) {
      const m = line.match(/^(\d+)\/(tcp|udp)\s+(\w+)\s+(\S+)\s*(.*)/);
      if (m) ports.push({ port: m[1], protocol: m[2], state: m[3], service: m[4], version: m[5].trim() });
    }
    return ports;
  }
}
